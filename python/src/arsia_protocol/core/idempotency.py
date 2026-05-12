# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Idempotency primitive — key validation, scope tuples, store protocol.

This module is Layer 5 (Cross-cutting) in the SDK dependency graph.
It provides the pure-data building blocks for the idempotency
semantics defined in ARSIA-Core.md §10 and surfaced on the envelope
as ``idempotency.key`` / ``idempotency.expires_at``
(Core §4.3.2).

What this module provides
-------------------------

- :data:`IDEMPOTENCY_KEY_MIN_LENGTH` / :data:`IDEMPOTENCY_KEY_MAX_LENGTH`
  and :func:`validate_idempotency_key` — the 1-128 printable-ASCII
  (0x20-0x7E) key grammar from Core §10.2.
- :func:`scope_tuple` — extracts the
  ``(from, to, payload.type)`` scope tuple that qualifies an
  idempotency key per Core §10.1.
- :func:`resolve_idempotency_key` — header vs envelope precedence:
  header wins for key detection, envelope for ``expires_at``
  semantics (Core §10.4).
- :func:`is_idempotency_record_expired` — wall-clock check against
  the record's ``expires_at``.
- :class:`IdempotencyRecord` — a minimal Pydantic model for the
  persisted record (key + scope + response fingerprint + expiry).
- :class:`IdempotencyStore` — a :class:`typing.Protocol` describing
  the append-only store interface (``get`` / ``put``). The SDK does
  NOT provide production storage; consumers plug in Redis / Postgres
  / DynamoDB implementations behind this protocol.
What this module does NOT do
----------------------------

- No HTTP/transport handling. The header name
  (``Idempotency-Key``) is a Core §10.4 convention; this module
  accepts it as a string and lets the transport layer extract it.
- No response caching at the payload level. The record stores a
  fingerprint of the initial response so duplicates can be detected
  and short-circuited; the fingerprint is opaque to this module.
- No retry policy — retries use Core §11.3 via
  :func:`arsia_protocol.routing.compute_retry_delay`.

Spec: ARSIA-Core.md §10 and §4.3.2.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final, Literal, Mapping, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arsia_protocol._errors import ValidationError
from arsia_protocol.types.envelope import ArsiaIdempotency

logger = logging.getLogger(__name__)

IDEMPOTENCY_KEY_MIN_LENGTH: Final[int] = 1
"""Minimum idempotency-key length in characters (Core §10.2)."""

IDEMPOTENCY_KEY_MAX_LENGTH: Final[int] = 128
"""Maximum idempotency-key length in characters (Core §10.2)."""

HEADER_ONLY_RETENTION_HOURS: Final[int] = 24
"""Minimum retention window (hours) for header-only idempotency keys.

Per Core §10.2(2): "If the idempotency key is provided only via the
HTTP header (without a corresponding envelope field), the server MUST
retain the association for a minimum of 24 hours."
"""

IdempotencyKeySource = Literal["header", "envelope"]
"""Where a resolved idempotency key originated.

``"header"`` — key came from the ``Idempotency-Key`` HTTP header
(authoritative per §10.4, and triggers the 24 h retention floor of
§10.2(2) when no envelope sub-object is present).
``"envelope"`` — key came from ``envelope.idempotency.key`` (the
signed surface; ``expires_at`` is taken from the same sub-object).
"""

IdempotencyStatus = Literal["new", "pending", "completed"]
"""Lifecycle state of an idempotency entry (Core §10.3).

- ``"new"`` — the ``(scope, key)`` pair is unknown to the store.
- ``"pending"`` — the original request is being processed and no
  response has been stored yet. Duplicate arrivals SHOULD be rejected
  with HTTP 409 + ``Retry-After`` per §10.3(4) at the transport layer.
- ``"completed"`` — a response envelope has been stored; duplicate
  arrivals MUST receive the stored response (§10.3(1..3)).
"""

_PRINTABLE_ASCII_MIN: Final[int] = 0x20
_PRINTABLE_ASCII_MAX: Final[int] = 0x7E

_TS_PATTERN: Final[str] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"


def validate_idempotency_key(key: str) -> list[ValidationError]:
    """Return the list of errors for an idempotency-key string.

    Checks the three Core §10.2 rules:

    - non-empty (length >= :data:`IDEMPOTENCY_KEY_MIN_LENGTH`);
    - length <= :data:`IDEMPOTENCY_KEY_MAX_LENGTH`;
    - every character is printable ASCII (0x20..0x7E inclusive).

    Returns an empty list when valid. Prefer this function to
    :func:`ArsiaIdempotency` instantiation when you just need error
    reporting — the Pydantic model raises; this one lists.

    Args:
        key: The candidate idempotency-key string.

    Returns:
        Structured validation errors (empty when valid).

    Spec: ARSIA-Core.md §10.2.
    """
    errors: list[ValidationError] = []

    if not isinstance(key, str):
        errors.append(
            ValidationError(
                code="idempotency_key_type",
                message=f"idempotency key must be a string; got {type(key).__name__}",
                details={"expected_type": "str", "actual_type": type(key).__name__},
                spec_ref="Core §10.2",
            )
        )
        return errors

    if len(key) < IDEMPOTENCY_KEY_MIN_LENGTH:
        errors.append(
            ValidationError(
                code="idempotency_key_too_short",
                message=(
                    f"idempotency key must be at least "
                    f"{IDEMPOTENCY_KEY_MIN_LENGTH} character"
                ),
                details={
                    "min_length": IDEMPOTENCY_KEY_MIN_LENGTH,
                    "actual_length": len(key),
                },
                spec_ref="Core §10.2",
            )
        )
    if len(key) > IDEMPOTENCY_KEY_MAX_LENGTH:
        errors.append(
            ValidationError(
                code="idempotency_key_too_long",
                message=(
                    f"idempotency key must be at most "
                    f"{IDEMPOTENCY_KEY_MAX_LENGTH} characters; got {len(key)}"
                ),
                details={
                    "max_length": IDEMPOTENCY_KEY_MAX_LENGTH,
                    "actual_length": len(key),
                },
                spec_ref="Core §10.2",
            )
        )
    for idx, ch in enumerate(key):
        cp = ord(ch)
        if cp < _PRINTABLE_ASCII_MIN or cp > _PRINTABLE_ASCII_MAX:
            errors.append(
                ValidationError(
                    code="idempotency_key_invalid_char",
                    message=(
                        f"idempotency key contains non-printable-ASCII character "
                        f"U+{cp:04X} at offset {idx}"
                    ),
                    details={"char_code": cp, "offset": idx},
                    spec_ref="Core §10.2",
                )
            )
            break

    return errors


def is_valid_idempotency_key(key: str) -> bool:
    """Return ``True`` iff ``key`` satisfies the Core §10.2 grammar."""
    return not validate_idempotency_key(key)


@dataclass(frozen=True)
class IdempotencyScope:
    """Tuple that qualifies an idempotency key per Core §10.1.

    Two messages share the same idempotency entry iff they share the
    same ``(from, to, payload_type)`` triple AND the same ``key``.
    The scope is a value type so it can be used as a dict key
    alongside ``key`` in a store implementation.

    Attributes:
        from_agent: The sender agent ID (envelope ``from``).
        to_agent: The recipient agent ID (envelope ``to``).
        payload_type: The ``payload.type`` string.
    """

    from_agent: str
    to_agent: str
    payload_type: str


def scope_tuple(envelope: Mapping[str, Any]) -> IdempotencyScope:
    """Return the :class:`IdempotencyScope` for ``envelope``.

    Args:
        envelope: The ARSIA message envelope.

    Returns:
        The scope tuple.

    Raises:
        ValueError: on missing or mis-typed ``from`` / ``to`` /
            ``payload.type``.

    Spec: ARSIA-Core.md §10.1.
    """
    from_agent = envelope.get("from")
    to_agent = envelope.get("to")
    payload = envelope.get("payload")
    if not isinstance(from_agent, str):
        raise ValueError("envelope['from'] must be a string agent-id")
    if not isinstance(to_agent, str):
        raise ValueError("envelope['to'] must be a string agent-id")
    if not isinstance(payload, Mapping):
        raise ValueError("envelope['payload'] must be an object")
    payload_type = payload.get("type")
    if not isinstance(payload_type, str):
        raise ValueError("envelope['payload']['type'] must be a string")
    return IdempotencyScope(
        from_agent=from_agent,
        to_agent=to_agent,
        payload_type=payload_type,
    )


def resolve_idempotency_key(
    envelope: Mapping[str, Any],
    *,
    header_key: str | None = None,
) -> str | None:
    """Return the idempotency key to use for ``envelope``.

    Precedence per Core §10.4:

    1. When the transport surfaced an ``Idempotency-Key`` header
       (``header_key`` argument), that value wins for key detection —
       the header is authoritative because it identifies the caller's
       idempotent intent at the transport hop.
    2. Otherwise, ``envelope['idempotency']['key']`` is used.
    3. Otherwise, ``None`` (the caller has not requested idempotency).

    Note that ``expires_at`` is always taken from the envelope's
    ``idempotency`` sub-object — it is part of the signed message
    surface and the header carries no expiry semantics.

    Args:
        envelope: The ARSIA message envelope.
        header_key: Value of the ``Idempotency-Key`` HTTP header, if
            present.

    Returns:
        The resolved key, or ``None`` when idempotency is not
        requested.

    Spec: ARSIA-Core.md §10.4.
    """
    if header_key is not None and header_key != "":
        envelope_idem = envelope.get("idempotency")
        if isinstance(envelope_idem, Mapping):
            envelope_key = envelope_idem.get("key")
            if (
                isinstance(envelope_key, str)
                and envelope_key != ""
                and header_key != envelope_key
            ):
                logger.warning(
                    "Idempotency key discrepancy: header=%s, envelope=%s. Using header.",
                    header_key,
                    envelope_key,
                )
        return header_key

    idempotency = envelope.get("idempotency")
    if isinstance(idempotency, Mapping):
        key = idempotency.get("key")
        if isinstance(key, str) and key != "":
            return key

    return None


def resolve_idempotency_source(
    envelope: Mapping[str, Any],
    *,
    header_key: str | None = None,
) -> tuple[str | None, IdempotencyKeySource | None]:
    """Resolve the idempotency key and signal where it came from.

    Same precedence as :func:`resolve_idempotency_key` (header wins
    per §10.4) but also returns the source so the caller can apply
    the §10.2(2) 24-hour retention floor when the key was supplied
    only via the HTTP header (envelope sub-object absent or keyless).

    Args:
        envelope: The ARSIA message envelope.
        header_key: Value of the ``Idempotency-Key`` HTTP header, if
            present.

    Returns:
        ``(key, source)``. ``source`` is ``"header"`` when the key
        came from the HTTP header and the envelope does NOT carry a
        matching ``idempotency.key`` field; it is ``"envelope"`` when
        the key came from the envelope sub-object (including the case
        where both were supplied — the header value is returned as
        the resolved key, but the source is ``"envelope"`` because
        the signed surface authorises its own retention via
        ``expires_at``). ``(None, None)`` when idempotency is not
        requested.

    Spec: ARSIA-Core.md §10.2, §10.4.
    """
    envelope_idem = envelope.get("idempotency")
    envelope_has_key = (
        isinstance(envelope_idem, Mapping)
        and isinstance(envelope_idem.get("key"), str)
        and envelope_idem.get("key") != ""
    )

    if header_key is not None and header_key != "":
        source: IdempotencyKeySource = "envelope" if envelope_has_key else "header"
        return header_key, source

    if envelope_has_key:
        assert isinstance(envelope_idem, Mapping)
        return envelope_idem["key"], "envelope"

    return None, None


def compute_idempotency_expiry(
    envelope_expires_at: str | None,
    *,
    header_only: bool,
    now: datetime | None = None,
) -> str:
    """Compute the RFC 3339 expiry timestamp for an idempotency record.

    Applies the Core §10.2(2) retention rules:

    - If the envelope carries ``idempotency.expires_at``, that value
      is authoritative (§10.4(3): the envelope field determines
      retention regardless of which key source is used for detection).
    - Otherwise, when the key was supplied only via the HTTP header
      (``header_only=True``), the retention window MUST be at least
      24 hours (:data:`HEADER_ONLY_RETENTION_HOURS`).
    - When no envelope expiry is given and the key is not header-only
      (e.g. an envelope key with no ``expires_at``), the 24-hour floor
      is applied as a defensive default.

    Args:
        envelope_expires_at: ``envelope.idempotency.expires_at`` when
            present, else ``None``.
        header_only: ``True`` when the key came exclusively from the
            HTTP header (no envelope ``idempotency.key``).
        now: Reference instant. Defaults to ``datetime.now(UTC)``.

    Returns:
        An RFC 3339 millisecond UTC timestamp (``Z`` suffix, exactly
        3 fractional digits).

    Spec: ARSIA-Core.md §10.2(2), §10.4(3).
    """
    if envelope_expires_at is not None and envelope_expires_at != "":
        return envelope_expires_at
    del header_only  # currently both paths apply the 24-hour floor
    reference = now if now is not None else datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    expiry = reference + timedelta(hours=HEADER_ONLY_RETENTION_HOURS)
    return expiry.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expiry.microsecond // 1000:03d}Z"


def _parse_ts(value: str) -> datetime | None:
    """Parse an RFC 3339 ms UTC timestamp; return ``None`` on failure."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_idempotency_record_expired(
    expires_at: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` if the record's ``expires_at`` has elapsed.

    Args:
        expires_at: RFC 3339 ms UTC timestamp from
            ``idempotency.expires_at`` or from a stored record.
        now: Reference instant. Defaults to ``datetime.now(UTC)``.

    Returns:
        ``True`` iff ``now > expires_at``. When ``expires_at`` is
        unparsable, returns ``True`` (the record is treated as
        expired rather than silently retained — a malformed record
        has no meaningful expiry).

    Spec: ARSIA-Core.md §10.3.
    """
    parsed = _parse_ts(expires_at)
    if parsed is None:
        return True
    reference = now if now is not None else datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return reference > parsed


class IdempotencyRecord(BaseModel):
    """A persisted idempotency record.

    The record captures enough state for duplicate detection to
    short-circuit on a match and return the same response that was
    produced for the first request. The response payload itself is
    NOT stored here — ``response_fingerprint`` is opaque to the SDK
    and lets consumers pair the record with whatever caching scheme
    fits their stack.

    Spec: ARSIA-Core.md §10.3.
    """

    model_config = ConfigDict(extra="forbid")

    key: str = Field(
        min_length=IDEMPOTENCY_KEY_MIN_LENGTH,
        max_length=IDEMPOTENCY_KEY_MAX_LENGTH,
        description="The idempotency key (Core §10.2).",
    )
    from_agent: str = Field(description="Scope tuple — sender agent ID.")
    to_agent: str = Field(description="Scope tuple — recipient agent ID.")
    payload_type: str = Field(description="Scope tuple — payload.type.")
    message_id: str = Field(
        description="UUID v4 of the original request (envelope.id)."
    )
    response_fingerprint: str | None = Field(
        default=None,
        description=(
            "Caller-defined fingerprint of the response produced for the "
            "first request (e.g. SHA-256 hex of the response payload). "
            "Opaque to the SDK."
        ),
    )
    stored_at: str = Field(
        pattern=_TS_PATTERN,
        description="RFC 3339 ms timestamp when this record was stored.",
    )
    expires_at: str = Field(
        pattern=_TS_PATTERN,
        description="RFC 3339 ms timestamp after which the record may be purged.",
    )

    @field_validator("key")
    @classmethod
    def _validate_key(cls, value: str) -> str:
        errs = validate_idempotency_key(value)
        if errs:
            raise ValueError("; ".join(str(e) for e in errs))
        return value


@runtime_checkable
class IdempotencyStore(Protocol):
    """Structural interface for an idempotency store.

    The SDK does not bind to a concrete storage backend. Consumers
    implement this protocol over Redis, Postgres, DynamoDB, or any
    other store that can satisfy the operations below. The only
    ordering guarantee is that a successful :meth:`put` MUST be
    observable by a subsequent :meth:`get` with the same
    ``(scope, key)``; stronger guarantees (cross-region replication,
    ordering across keys) are implementation choices.

    v0.2.0 adds :meth:`mark_pending` / :meth:`mark_complete` /
    :meth:`check_status` for §10.3 lifecycle transitions and
    :meth:`store_response` / :meth:`get_response` for §10.3 byte-exact
    response replay. Implementations MUST implement these methods to
    be spec-conformant; the legacy :meth:`put` / :meth:`get` pair is
    retained for back-compat with pre-v0.2 consumers but does NOT
    satisfy the §10.3 replay requirement on its own.

    Spec: ARSIA-Core.md §10.3.
    """

    def get(self, scope: IdempotencyScope, key: str) -> IdempotencyRecord | None:
        """Return the completed record for ``(scope, key)`` or ``None``.

        Returns ``None`` for ``"new"`` keys, ``"pending"`` keys (the
        response has not been stored yet), and expired records.
        Implementations MAY surface expired records but SHOULD treat
        them as absent.
        """
        ...

    def put(self, record: IdempotencyRecord) -> None:
        """Persist ``record`` as a completed entry.

        Implementations MUST treat a second :meth:`put` with the same
        ``(from_agent, to_agent, payload_type, key)`` as an error:
        the first write wins and duplicates MUST NOT overwrite
        response fingerprints. Raise :class:`DuplicateIdempotencyKey`
        to surface the collision. A ``"pending"`` entry for the same
        scope+key is transitioned to ``"completed"`` by this call and
        does NOT raise.
        """
        ...

    def mark_pending(self, scope: IdempotencyScope, key: str) -> bool:
        """Atomically reserve ``(scope, key)`` for an in-flight request.

        Returns ``True`` when the caller was the first to arrive and
        the entry transitioned from ``"new"`` to ``"pending"``.
        Returns ``False`` when the entry is already ``"pending"`` or
        ``"completed"`` — the transport layer SHOULD respond with
        HTTP 409 + ``Retry-After`` per Core §10.3(4).

        Spec: ARSIA-Core.md §10.3(4).
        """
        raise NotImplementedError(
            "IdempotencyStore.mark_pending must be implemented — "
            "added in v0.2.0 for Core §10.3(4) in-progress detection"
        )

    def mark_complete(self, record: IdempotencyRecord) -> None:
        """Transition a pending entry to ``"completed"`` with ``record``.

        If the ``(scope, key)`` entry is ``"pending"``, it is replaced
        with the stored response. If no entry exists (the caller did
        not call :meth:`mark_pending` first), implementations MUST
        store the record as completed — this preserves back-compat
        with :meth:`put`. If the entry is already ``"completed"``,
        implementations MUST raise :class:`DuplicateIdempotencyKey`.

        Spec: ARSIA-Core.md §10.3.
        """
        raise NotImplementedError(
            "IdempotencyStore.mark_complete must be implemented — "
            "added in v0.2.0 for Core §10.3 lifecycle transitions"
        )

    def check_status(self, scope: IdempotencyScope, key: str) -> IdempotencyStatus:
        """Return the current lifecycle state for ``(scope, key)``.

        See :data:`IdempotencyStatus` for the state definitions.
        Expired completed entries SHOULD be reported as ``"new"`` so
        that callers can re-submit without observing stale state.

        Spec: ARSIA-Core.md §10.3.
        """
        raise NotImplementedError(
            "IdempotencyStore.check_status must be implemented — "
            "added in v0.2.0 for Core §10.3 lifecycle introspection"
        )

    def store_response(
        self, scope: IdempotencyScope, key: str, response_bytes: bytes
    ) -> None:
        """Persist the serialized response envelope for ``(scope, key)``.

        Per Core §10.2(1), the server MUST store the association
        between the idempotency key (scoped to ``from``/``to``/
        ``payload.type``) and the **complete response envelope** so
        that subsequent duplicates can be replayed byte-for-byte
        (§10.3 Rule 3). The bytes are opaque to the SDK — typically
        the canonicalized signed response envelope as it would be sent
        on the wire.

        Implementations MUST persist ``response_bytes`` durably for
        the retention window (§10.2(3): "The storage MUST survive
        server restarts within the retention window for production
        deployments"). A subsequent :meth:`get_response` for the same
        ``(scope, key)`` MUST return the same bytes until the entry
        expires.

        Spec: ARSIA-Core.md §10.2(1), §10.3.
        """
        raise NotImplementedError(
            "IdempotencyStore.store_response must be implemented — "
            "added in v0.2.0 for Core §10.3 response replay"
        )

    def get_response(self, scope: IdempotencyScope, key: str) -> bytes | None:
        """Return the stored response bytes for ``(scope, key)``.

        Returns ``None`` when no completed response is stored for the
        scope+key, or when the entry has expired. Callers use this in
        the §10.3 replay path: a hit means "return these bytes
        verbatim with the original status code"; a miss means the
        request must be processed normally.

        Spec: ARSIA-Core.md §10.3.
        """
        raise NotImplementedError(
            "IdempotencyStore.get_response must be implemented — "
            "added in v0.2.0 for Core §10.3 response replay"
        )


class DuplicateIdempotencyKey(Exception):
    """Raised by :meth:`IdempotencyStore.put` on a scoped-key collision.

    The exception carries the offending scope and key so that the
    caller can fetch the prior record via
    :meth:`IdempotencyStore.get` and short-circuit to the original
    response.

    Spec: ARSIA-Core.md §10.3.
    """

    def __init__(self, scope: IdempotencyScope, key: str) -> None:
        self.scope = scope
        self.key = key
        super().__init__(
            f"duplicate idempotency key {key!r} for scope "
            f"({scope.from_agent}, {scope.to_agent}, {scope.payload_type})"
        )


class DuplicateRequestInProgress(Exception):
    """Raised when a duplicate arrives while the original is in-flight.

    Per Core §10.3(4), the transport layer SHOULD map this to HTTP 409
    (Conflict) with error code ``conflict`` and a ``Retry-After``
    header. The SDK surfaces the building block; the HTTP mapping is
    the binding's responsibility.

    The exception carries the offending scope and key so the caller
    can include them in observability signals.

    Spec: ARSIA-Core.md §10.3(4).
    """

    def __init__(self, scope: IdempotencyScope, key: str) -> None:
        self.scope = scope
        self.key = key
        super().__init__(
            f"idempotency key {key!r} is already in-progress for scope "
            f"({scope.from_agent}, {scope.to_agent}, {scope.payload_type})"
        )


def extract_envelope_idempotency(
    envelope: Mapping[str, Any],
) -> ArsiaIdempotency | None:
    """Return the parsed ``idempotency`` sub-object or ``None``.

    The helper instantiates :class:`ArsiaIdempotency` when the field
    is present, letting callers work with a typed object rather than
    a raw dict. Returns ``None`` when the envelope does not carry
    idempotency metadata.

    Args:
        envelope: The ARSIA message envelope.

    Returns:
        The :class:`ArsiaIdempotency` model, or ``None`` when absent.

    Raises:
        ValueError: on a malformed ``idempotency`` sub-object.

    Spec: ARSIA-Core.md §4.3.2.
    """
    value = envelope.get("idempotency")
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("envelope['idempotency'] must be an object when present")
    return ArsiaIdempotency(**dict(value))


__all__ = [
    # Constants
    "IDEMPOTENCY_KEY_MIN_LENGTH",
    "IDEMPOTENCY_KEY_MAX_LENGTH",
    "HEADER_ONLY_RETENTION_HOURS",
    # Type aliases
    "IdempotencyKeySource",
    "IdempotencyStatus",
    # Validation
    "validate_idempotency_key",
    "is_valid_idempotency_key",
    # Scope and resolution
    "IdempotencyScope",
    "scope_tuple",
    "resolve_idempotency_key",
    "resolve_idempotency_source",
    "compute_idempotency_expiry",
    "extract_envelope_idempotency",
    "is_idempotency_record_expired",
    # Records
    "IdempotencyRecord",
    # Store
    "IdempotencyStore",
    "DuplicateIdempotencyKey",
    "DuplicateRequestInProgress",
]
