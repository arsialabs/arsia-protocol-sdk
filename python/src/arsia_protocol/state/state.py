# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""State primitive — validation, key grammar, and operation helpers.

This module is Layer 4 (Primitives) in the SDK dependency graph. It
depends only on :mod:`arsia_protocol.types` (Layer 1),
:mod:`arsia_protocol.validation` (Layer 3),
:mod:`arsia_protocol.compliance` (Layer 2), and
:mod:`arsia_protocol.hazmat.canonicalization` (Layer 0) — never on
``message``, ``actions``, or ``identity``.

It covers the offline, SDK-level portions of ARSIA-State.md:

- **§1 Scope Taxonomy** — the four scopes (``session``/``agent``/
  ``shared``/``global``).
- **§2.1 StateEntry** — structural validation via the Pydantic model
  in ``types/state.py`` plus the programmatic constraints that JSON
  Schema cannot express: the 1 MiB ``value`` limit (§2.1.2) and the
  immutability of ``owner_agent_id``, ``scope``, and ``key`` after
  creation (§2.1.3–§2.1.4).
- **§2.1.1 Key grammar** — ``{agent-id}/{scope}/{local-key}``, maximum
  512 characters, reserved prefix ``arsiaprotocol.`` (§2.2).
- **§3 Operations** — argument builders for the eight state operations
  (GET, SET, DELETE, QUERY, SNAPSHOT, PURGE, GRANT, REVOKE). These
  return the ``args`` dict the transport layer places inside a request
  payload; they never produce a full envelope (that lives in
  :func:`arsia_protocol.message.create_request`, which this module
  deliberately does not depend on).
- **§4.1.1 Effective retention** — ``max(profile, entry)`` via
  :func:`compute_effective_retention`, which delegates to
  :func:`arsia_protocol.compliance.get_effective_retention` for the
  profile lookup.
- **§4.2 Data residency** — entry vs. envelope consistency check.
- **§5.3 PURGE argument shape** — subject agent + reason, no
  ``value``. The actual purge procedure (six storage steps) is the
  store's job.
- **§8.2 Capability matrix** — the four ``arsiaprotocol.state.*``
  capabilities and the explicit rule that ``arsiaprotocol.state.*``
  does **not** cover :data:`STATE_CAPABILITY_PURGE` or
  :data:`STATE_CAPABILITY_SNAPSHOT`.

What this module does NOT cover (deferred to the storage/transport
layer in Slice 8):

- CRUD persistence, version counters, optimistic-concurrency conflict
  detection at rest.
- QUERY filtering, SNAPSHOT pagination, GC of expired entries.
- The six-step PURGE storage procedure (§5.3) beyond argument
  validation.
- GRANT/REVOKE persistence into reserved keys.
- HTTP endpoints and the STATE-09/10/11/13/14 conformance cases
  (kept offline-skipped until Slice 8).

Spec: ARSIA-State.md §1, §2, §3, §4.1–§4.2, §5.3, §8.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Final, Mapping

from arsia_protocol.core.compliance import (
    ART_6_LEGAL_BASES,
    ART_9_LEGAL_BASES,
    get_effective_retention as _compliance_get_effective_retention,
)
from arsia_protocol.types.errors import ValidationError
from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.types.state import (
    AccessLevel,
    PiiClassification,
    StateEntry,
    StateScope,
)

# ---------------------------------------------------------------------------
# §1 — Scopes
# ---------------------------------------------------------------------------

STATE_SCOPES: Final[frozenset[StateScope]] = frozenset(
    {"session", "agent", "shared", "global"}
)
"""The four state scopes defined in ARSIA-State.md §1."""

# ---------------------------------------------------------------------------
# §3 — Operations
# ---------------------------------------------------------------------------

STATE_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"GET", "SET", "DELETE", "QUERY", "SNAPSHOT", "PURGE", "GRANT", "REVOKE"}
)
"""The eight state operations defined in ARSIA-State.md §3."""

PAYLOAD_TYPE_PREFIX: Final[str] = "arsiaprotocol.state/"
"""Prefix for every state operation's ``payload.type`` (State §8.1)."""

PAYLOAD_TYPE_GET: Final[str] = "arsiaprotocol.state/get"
PAYLOAD_TYPE_SET: Final[str] = "arsiaprotocol.state/set"
PAYLOAD_TYPE_DELETE: Final[str] = "arsiaprotocol.state/delete"
PAYLOAD_TYPE_QUERY: Final[str] = "arsiaprotocol.state/query"
PAYLOAD_TYPE_SNAPSHOT: Final[str] = "arsiaprotocol.state/snapshot"
PAYLOAD_TYPE_PURGE: Final[str] = "arsiaprotocol.state/purge"
PAYLOAD_TYPE_GRANT: Final[str] = "arsiaprotocol.state/grant"
PAYLOAD_TYPE_REVOKE: Final[str] = "arsiaprotocol.state/revoke"

_OPERATION_TO_PAYLOAD_TYPE: Final[Mapping[str, str]] = {
    "GET": PAYLOAD_TYPE_GET,
    "SET": PAYLOAD_TYPE_SET,
    "DELETE": PAYLOAD_TYPE_DELETE,
    "QUERY": PAYLOAD_TYPE_QUERY,
    "SNAPSHOT": PAYLOAD_TYPE_SNAPSHOT,
    "PURGE": PAYLOAD_TYPE_PURGE,
    "GRANT": PAYLOAD_TYPE_GRANT,
    "REVOKE": PAYLOAD_TYPE_REVOKE,
}

# ---------------------------------------------------------------------------
# §8.2 — Capabilities
# ---------------------------------------------------------------------------

STATE_CAPABILITY_READ: Final[str] = "arsiaprotocol.state.read"
STATE_CAPABILITY_WRITE: Final[str] = "arsiaprotocol.state.write"
STATE_CAPABILITY_PURGE: Final[str] = "arsiaprotocol.state.purge"
STATE_CAPABILITY_SNAPSHOT: Final[str] = "arsiaprotocol.state.snapshot"

OPERATION_TO_CAPABILITY: Final[Mapping[str, str]] = {
    "GET": STATE_CAPABILITY_READ,
    "QUERY": STATE_CAPABILITY_READ,
    "SET": STATE_CAPABILITY_WRITE,
    "DELETE": STATE_CAPABILITY_WRITE,
    "GRANT": STATE_CAPABILITY_WRITE,
    "REVOKE": STATE_CAPABILITY_WRITE,
    "PURGE": STATE_CAPABILITY_PURGE,
    "SNAPSHOT": STATE_CAPABILITY_SNAPSHOT,
}
"""Capability required by each operation (State §8.2).

Per §8.2 the wildcard ``arsiaprotocol.state.*`` covers ``.read`` and
``.write`` only — it does NOT cover ``.purge`` or ``.snapshot``, which
must be granted explicitly.
"""

STATE_WILDCARD_EXCLUDES: Final[frozenset[str]] = frozenset(
    {STATE_CAPABILITY_PURGE, STATE_CAPABILITY_SNAPSHOT}
)
"""Capabilities NOT covered by the ``arsiaprotocol.state.*`` wildcard.

Spec: ARSIA-State.md §8.2.
"""

# ---------------------------------------------------------------------------
# §2.1.1 / §2.2 — Key grammar
# ---------------------------------------------------------------------------

STATE_KEY_MAX_LENGTH: Final[int] = 512
"""Maximum length of a state key in characters (ARSIA-State.md §2.1.1)."""

STATE_VALUE_MAX_BYTES: Final[int] = 1_048_576
"""Maximum serialized size of a state value in bytes, 1 MiB (§2.1.2)."""

STATE_RESERVED_KEY_PREFIX: Final[str] = "arsiaprotocol."
"""Reserved prefix for protocol-managed keys (ARSIA-State.md §2.2)."""

_STATE_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9:._/\-]+$")
"""Character class allowed in a state key, per the StateEntry schema."""

_SCOPE_SEGMENT_RE = re.compile(r"^(session|agent|shared|global)$")


def parse_state_key(key: str) -> tuple[str, StateScope, str]:
    """Return ``(agent_id, scope, local_key)`` from a state key.

    ARSIA-State.md §2.1.1 defines the key shape as
    ``{agent-id}/{scope}/{local-key}`` where the agent-id itself
    contains a colon (``agent:org.name``) and the local-key MAY
    contain slashes. This parser therefore splits on the **first two**
    slashes and returns the remainder as the local-key.

    Args:
        key: The namespaced state key.

    Returns:
        A tuple ``(agent_id, scope, local_key)``.

    Raises:
        ValueError: if ``key`` does not have the expected three-part
            shape, if the scope segment is unknown, or if the
            agent-id segment is not a syntactically valid agent
            identifier.

    Spec: ARSIA-State.md §2.1.1.
    """
    if not isinstance(key, str) or not key:
        raise ValueError("key: must be a non-empty string")
    parts = key.split("/", 2)
    if len(parts) < 3:
        raise ValueError(
            f"state key {key!r} must have shape "
            "'{agent-id}/{scope}/{local-key}' (State §2.1.1)"
        )
    agent_id, scope_part, local_key = parts
    if not _SCOPE_SEGMENT_RE.fullmatch(scope_part):
        raise ValueError(
            f"state key {key!r}: scope segment {scope_part!r} is not one "
            f"of {sorted(STATE_SCOPES)} (State §2.1.1)"
        )
    if not local_key:
        raise ValueError(f"state key {key!r}: local-key segment is empty")
    return agent_id, scope_part, local_key  # type: ignore[return-value]


def is_reserved_key(key: str) -> bool:
    """Return ``True`` if ``key``'s local segment starts with the reserved prefix.

    The reserved prefix ``arsiaprotocol.`` protects protocol-managed
    namespaces (e.g. ``arsiaprotocol.grants.*``) from being written
    directly by agents through SET. GRANT / REVOKE MAY write into
    these keys; ordinary SET MUST NOT.

    Args:
        key: The full namespaced key, or the local-key segment alone.

    Returns:
        ``True`` when the local-key segment begins with
        :data:`STATE_RESERVED_KEY_PREFIX`.

    Spec: ARSIA-State.md §2.2.
    """
    try:
        _agent_id, _scope, local_key = parse_state_key(key)
    except ValueError:
        return key.startswith(STATE_RESERVED_KEY_PREFIX)
    return local_key.startswith(STATE_RESERVED_KEY_PREFIX)


def validate_state_key(
    key: str,
    *,
    expected_owner: str | None = None,
    expected_scope: StateScope | None = None,
    allow_reserved: bool = False,
) -> list[ValidationError]:
    """Return the list of §2.1.1 / §2.2 errors for ``key``.

    An empty list means the key is valid.

    Args:
        key: The namespaced state key to validate.
        expected_owner: When provided, the first segment of ``key``
            MUST equal this agent-id. Used on the SET path so the
            receiver can reject writes targeting someone else's
            namespace.
        expected_scope: When provided, the scope segment of ``key``
            MUST equal this value. Used when the caller already knows
            which scope the entry belongs to (e.g. the entry's
            ``scope`` field).
        allow_reserved: When ``True``, keys under the reserved
            ``arsiaprotocol.`` prefix are permitted (GRANT / REVOKE
            call paths). Defaults to ``False`` (ordinary SET path).

    Returns:
        A list of :class:`ValidationError`; empty when valid.

    Spec: ARSIA-State.md §2.1.1, §2.2.
    """
    errors: list[ValidationError] = []
    if not isinstance(key, str):
        return [
            ValidationError(
                code="invalid_type",
                message=f"state key must be a string, got {type(key).__name__}",
                details={"got_type": type(key).__name__},
                spec_ref="State §2.1.1",
            )
        ]
    if not key:
        return [
            ValidationError(
                code="empty_key",
                message="state key is empty",
                details={},
                spec_ref="State §2.1.1",
            )
        ]
    if len(key) > STATE_KEY_MAX_LENGTH:
        errors.append(
            ValidationError(
                code="key_too_long",
                message=f"state key length {len(key)} exceeds {STATE_KEY_MAX_LENGTH}",
                details={"length": len(key), "max_length": STATE_KEY_MAX_LENGTH},
                spec_ref="State §2.1.1",
            )
        )
    if not _STATE_KEY_PATTERN.fullmatch(key):
        errors.append(
            ValidationError(
                code="invalid_key_characters",
                message=(
                    f"state key {key!r} contains characters outside the allowed "
                    "set [a-zA-Z0-9:._/-]"
                ),
                details={"key": key},
                spec_ref="State §2.1.1",
            )
        )
        return errors

    try:
        agent_id, scope, local_key = parse_state_key(key)
    except ValueError as exc:
        errors.append(
            ValidationError(
                code="invalid_key_format",
                message=str(exc),
                details={"key": key},
                spec_ref="State §2.1.1",
            )
        )
        return errors

    if expected_owner is not None and agent_id != expected_owner:
        errors.append(
            ValidationError(
                code="key_owner_mismatch",
                message=(
                    f"state key {key!r}: agent-id segment {agent_id!r} must match "
                    f"owner {expected_owner!r}"
                ),
                details={
                    "key": key,
                    "agent_id": agent_id,
                    "expected_owner": expected_owner,
                },
                spec_ref="State §2.1.1",
            )
        )
    if expected_scope is not None and scope != expected_scope:
        errors.append(
            ValidationError(
                code="key_scope_mismatch",
                message=(
                    f"state key {key!r}: scope segment {scope!r} must match entry "
                    f"scope {expected_scope!r}"
                ),
                details={"key": key, "scope": scope, "expected_scope": expected_scope},
                spec_ref="State §2.1.4",
            )
        )
    if not allow_reserved and local_key.startswith(STATE_RESERVED_KEY_PREFIX):
        errors.append(
            ValidationError(
                code="reserved_key_prefix",
                message=(
                    f"state key {key!r}: local-key starts with reserved prefix "
                    f"{STATE_RESERVED_KEY_PREFIX!r}"
                ),
                details={"key": key, "prefix": STATE_RESERVED_KEY_PREFIX},
                spec_ref="State §2.2",
            )
        )
    return errors


# ---------------------------------------------------------------------------
# §2.1.2 — Value size limit (1 MiB via RFC 8785 canonicalization)
# ---------------------------------------------------------------------------


def compute_value_size(value: Any) -> int:
    """Return the serialized size of ``value`` in bytes.

    The measurement uses RFC 8785 (JCS) canonicalization — the same
    serialization the SDK uses for signing — so every participant
    agrees on the size of a given JSON value regardless of local
    whitespace or key-ordering differences.

    Scalars (strings, numbers, booleans, ``None``) are wrapped in a
    single-element array before canonicalization, since ``rfc8785``
    expects a dict or list at the top level. The wrapper adds two
    bytes (``[`` and ``]``) to the reported size, which is consistent
    across callers and does not affect the comparison to
    :data:`STATE_VALUE_MAX_BYTES` in any practical way (a 1 MiB value
    remains 1 MiB regardless of two trailing bracket bytes).

    Args:
        value: Any JSON-serializable value.

    Returns:
        The byte count.

    Spec: ARSIA-State.md §2.1.2.
    """
    if isinstance(value, (dict, list)):
        canonical = canonicalize(value)
    else:
        canonical = canonicalize([value])
    return len(canonical)


def enforce_value_size_limit(value: Any) -> int:
    """Raise when ``value`` exceeds :data:`STATE_VALUE_MAX_BYTES`.

    Args:
        value: Any JSON-serializable value.

    Returns:
        The measured byte count (when within the limit).

    Raises:
        ValueError: when the canonical serialization exceeds 1 MiB.
            The error message is phrased so callers can map it to a
            ``payload_too_large`` error per State §8.4.

    Spec: ARSIA-State.md §2.1.2, §8.4.
    """
    size = compute_value_size(value)
    if size > STATE_VALUE_MAX_BYTES:
        raise ValueError(
            f"state value size {size} bytes exceeds "
            f"{STATE_VALUE_MAX_BYTES} (State §2.1.2; map to "
            "payload_too_large per §8.4)"
        )
    return size


# ---------------------------------------------------------------------------
# §2.1 — StateEntry validation (shape + programmatic constraints)
# ---------------------------------------------------------------------------

_IMMUTABLE_FIELDS: Final[tuple[str, ...]] = (
    "owner_agent_id",
    "scope",
    "key",
    "created_at",
    "pii_classification",
)
"""Fields that MUST NOT change between versions of the same entry.

``created_at``, ``owner_agent_id``, ``scope``, and ``key`` are
explicitly immutable per §2.1.3–§2.1.6. ``pii_classification`` is
immutable within a single version per §2.1.10 — changing
classification requires PURGE + re-create.
"""


def validate_state_entry(
    entry: StateEntry,
    *,
    sender_agent_id: str | None = None,
    envelope_compliance: Mapping[str, Any] | None = None,
) -> list[ValidationError]:
    """Return State §2.1 / §4.2 errors for ``entry`` relative to its envelope.

    This layer runs on top of the Pydantic schema validation already
    performed when ``entry`` was constructed. It surfaces constraints
    JSON Schema cannot express:

    - **§2.1.1** — ``entry.key`` is well-formed, not reserved, and its
      agent-id / scope segments match ``owner_agent_id`` and
      ``scope``.
    - **§2.1.3** — when ``sender_agent_id`` is provided, it MUST equal
      ``entry.owner_agent_id`` (a sender cannot create entries owned
      by someone else).
    - **§2.1.2** — the ``value`` size does not exceed 1 MiB.
    - **§2.1.10** — ``pii_classification='personal'`` requires the
      envelope's ``compliance.legal_basis`` and
      ``compliance.data_residency``.
    - **§4.2** — when both ``entry.data_residency`` and
      ``envelope.compliance.data_residency`` are set, they MUST
      match.

    Args:
        entry: The :class:`StateEntry` to validate.
        sender_agent_id: The ``from`` field of the enclosing envelope
            (used for the ownership check). ``None`` skips the
            ownership check.
        envelope_compliance: The ``compliance`` sub-object of the
            enclosing envelope, as a plain dict. ``None`` means the
            envelope carries no compliance — in which case the
            PII-personal and residency-matching checks that depend on
            compliance fields are skipped, and the caller is
            responsible for having already validated compliance
            presence at the envelope layer.

    Returns:
        A list of :class:`ValidationError`; empty when valid.

    Spec: ARSIA-State.md §2.1, §4.2.
    """
    errors: list[ValidationError] = []

    errors.extend(
        validate_state_key(
            entry.key,
            expected_owner=entry.owner_agent_id,
            expected_scope=entry.scope,
        )
    )

    if sender_agent_id is not None and entry.owner_agent_id != sender_agent_id:
        errors.append(
            ValidationError(
                code="owner_sender_mismatch",
                message=(
                    f"state entry owner {entry.owner_agent_id!r} must match "
                    f"envelope sender {sender_agent_id!r}"
                ),
                details={"owner": entry.owner_agent_id, "sender": sender_agent_id},
                spec_ref="State §2.1.3",
            )
        )

    try:
        enforce_value_size_limit(entry.value)
    except ValueError as exc:
        errors.append(
            ValidationError(
                code="payload_too_large",
                message=str(exc),
                details={"key": entry.key},
                spec_ref="State §2.1.2",
            )
        )

    errors.extend(_validate_json_value(entry.value))
    errors.extend(_validate_session_timeout(entry))
    errors.extend(
        _validate_pii_compliance(entry.pii_classification, envelope_compliance)
    )
    errors.extend(_validate_data_residency(entry.data_residency, envelope_compliance))

    return errors


_SESSION_TIMEOUT_HOURS: Final[int] = 24
"""Maximum session timeout in hours (State §1.1)."""


def _validate_session_timeout(entry: StateEntry) -> list[ValidationError]:
    """Per §1.1: session-scoped expires_at MUST NOT exceed created_at + 24h."""
    if entry.scope != "session" or entry.expires_at is None:
        return []
    created = _parse_rfc3339_ms(entry.created_at)
    expires = _parse_rfc3339_ms(entry.expires_at)
    max_expiry = created + timedelta(hours=_SESSION_TIMEOUT_HOURS)
    if expires > max_expiry:
        return [
            ValidationError(
                code="session_timeout_exceeded",
                message=(
                    f"session-scoped entry expires_at {entry.expires_at} exceeds "
                    f"created_at + 24h ({_format_ms_timestamp(max_expiry)})"
                ),
                details={
                    "expires_at": entry.expires_at,
                    "max_expiry": _format_ms_timestamp(max_expiry),
                },
                spec_ref="State §1.1",
            )
        ]
    return []


_EXECUTABLE_PATTERNS: Final[tuple[str, ...]] = (
    "javascript:",
    "data:text/html",
    "<script",
    "eval(",
    "function(",
    "import(",
)


def _contains_executable_content(value: Any) -> bool:
    """Best-effort check for executable content in JSON values.

    Spec: ARSIA-State §2.3 — Values MUST NOT contain executable code.
    """
    if isinstance(value, str):
        lowered = value.lower()
        return any(pat in lowered for pat in _EXECUTABLE_PATTERNS)
    if isinstance(value, dict):
        return any(_contains_executable_content(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_executable_content(item) for item in value)
    return False


def _validate_json_value(value: Any) -> list[ValidationError]:
    """Per §2.3: value MUST be a valid JSON value and MUST NOT contain executable code."""
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return [
            ValidationError(
                code="invalid_json_value",
                message="state entry value must be a valid JSON value per RFC 8259",
                details={},
                spec_ref="State §2.3",
            )
        ]
    if _contains_executable_content(value):
        return [
            ValidationError(
                code="executable_content_detected",
                message="state entry value MUST NOT contain executable code (State §2.3)",
                details={},
                spec_ref="State §2.3",
            )
        ]
    return []


def _validate_pii_compliance(
    classification: PiiClassification,
    envelope_compliance: Mapping[str, Any] | None,
) -> list[ValidationError]:
    """Per §2.1.10: ``personal``/``sensitive`` entries require legal_basis + data_residency.

    For ``sensitive`` entries, legal_basis must be an Art. 9(2) ground.
    """
    if classification not in ("personal", "sensitive"):
        return []
    if envelope_compliance is None:
        return [
            ValidationError(
                code="missing_compliance",
                message=(
                    f"pii_classification={classification!r} requires the envelope to carry a "
                    "compliance object with legal_basis and data_residency"
                ),
                details={"pii_classification": classification},
                spec_ref="State §2.1.10",
            )
        ]
    errors: list[ValidationError] = []
    legal_basis = envelope_compliance.get("legal_basis")
    if legal_basis is None:
        errors.append(
            ValidationError(
                code="missing_legal_basis",
                message=(
                    f"pii_classification={classification!r} requires "
                    "envelope.compliance.legal_basis"
                ),
                details={"pii_classification": classification},
                spec_ref="State §2.1.10",
            )
        )
    if envelope_compliance.get("data_residency") is None:
        errors.append(
            ValidationError(
                code="missing_data_residency",
                message=(
                    f"pii_classification={classification!r} requires "
                    "envelope.compliance.data_residency"
                ),
                details={"pii_classification": classification},
                spec_ref="State §2.1.10",
            )
        )
    if classification == "sensitive":
        if legal_basis is not None and legal_basis in ART_6_LEGAL_BASES:
            errors.append(
                ValidationError(
                    code="sensitive_requires_art9_basis",
                    message=(
                        f"pii_classification='sensitive' requires an Art. 9(2) legal basis, "
                        f"got Art. 6(1) basis {legal_basis!r}"
                    ),
                    details={"legal_basis": legal_basis},
                    spec_ref="State §2.1.10",
                )
            )
        elif legal_basis is not None and legal_basis not in ART_9_LEGAL_BASES:
            errors.append(
                ValidationError(
                    code="sensitive_requires_art9_basis",
                    message=(
                        f"pii_classification='sensitive' requires an Art. 9(2) legal basis, "
                        f"got unknown basis {legal_basis!r}"
                    ),
                    details={"legal_basis": legal_basis},
                    spec_ref="State §2.1.10",
                )
            )
    return errors


def resolve_entry_data_residency(
    args_data_residency: str | None,
    envelope_compliance: Mapping[str, Any] | None,
) -> str | None:
    """Resolve effective data_residency for a state entry.

    Spec: ARSIA-State §8.3 — payload.args.data_residency takes
    precedence (§8.3-03); falls back to compliance.data_residency
    from envelope (§8.3-02).

    Returns the effective data_residency or None if neither source sets it.
    """
    if args_data_residency is not None:
        return args_data_residency
    if envelope_compliance is not None:
        return envelope_compliance.get("data_residency")
    return None


def _validate_data_residency(
    entry_residency: str | None,
    envelope_compliance: Mapping[str, Any] | None,
) -> list[ValidationError]:
    """Per §4.2: entry and envelope residency must match when both set."""
    if entry_residency is None or envelope_compliance is None:
        return []
    envelope_residency = envelope_compliance.get("data_residency")
    if envelope_residency is None:
        return []
    if entry_residency != envelope_residency:
        return [
            ValidationError(
                code="residency_mismatch",
                message=(
                    f"state entry data_residency {entry_residency!r} does not match "
                    f"envelope compliance.data_residency {envelope_residency!r}"
                ),
                details={
                    "entry_residency": entry_residency,
                    "envelope_residency": envelope_residency,
                },
                spec_ref="State §4.2",
            )
        ]
    return []


def detect_immutable_field_changes(
    existing: StateEntry,
    incoming: StateEntry,
) -> list[ValidationError]:
    """Return every immutable-field mismatch between two versions of an entry.

    Used by storage layers on SET-update: when a SET arrives for an
    existing ``key``, :data:`_IMMUTABLE_FIELDS` MUST be identical in
    both versions. Any mismatch MUST be rejected with
    ``invalid_request`` per State §8.4.

    Args:
        existing: The currently stored :class:`StateEntry`.
        incoming: The incoming :class:`StateEntry` from the SET
            request.

    Returns:
        A list of :class:`ValidationError` (one per mismatched field);
        empty when all immutable fields are identical.

    Spec: ARSIA-State.md §2.1.3–§2.1.6, §2.1.10.
    """
    errors: list[ValidationError] = []
    for field in _IMMUTABLE_FIELDS:
        before = getattr(existing, field)
        after = getattr(incoming, field)
        if before != after:
            errors.append(
                ValidationError(
                    code="immutable_field_changed",
                    message=(
                        f"state entry field {field!r} is immutable: "
                        f"{before!r} -> {after!r}"
                    ),
                    details={"field": field, "before": before, "after": after},
                    spec_ref="State §2.1",
                )
            )
    return errors


# ---------------------------------------------------------------------------
# §4.1.1 — Effective retention
# ---------------------------------------------------------------------------


def compute_effective_retention(
    profile_name: str | None,
    entry_retention_days: int | None,
) -> int | None:
    """Return ``max(profile_retention, entry_retention_days)``.

    ARSIA-State.md §4.1.1 defines the effective retention of a state
    entry as the maximum of the profile's retention floor and the
    entry's per-entry override. Setting the entry value can
    **extend** the retention beyond the profile minimum but MUST NOT
    **reduce** it below.

    Args:
        profile_name: The compliance profile name whose default
            retention applies (``"GDPR-STANDARD"`` /
            ``"EU-AI-ACT-HIGH-RISK"`` / ``"MIFID-II"`` /
            ``"PAC-AGRICULTURE"``). ``None`` skips the profile
            lookup.
        entry_retention_days: The per-entry override from
            :attr:`StateEntry.retention_days`. ``None`` means the
            entry has no override.

    Returns:
        The effective retention in days, or ``None`` when neither
        input contributes a value.

    Spec: ARSIA-State.md §4.1.1.
    """
    profile_retention: int | None = None
    if profile_name is not None:
        envelope_stub = {"compliance": {"profile": profile_name}}
        profile_retention = _compliance_get_effective_retention(envelope_stub)

    if profile_retention is None and entry_retention_days is None:
        return None
    if profile_retention is None:
        return entry_retention_days
    if entry_retention_days is None:
        return profile_retention
    return max(profile_retention, entry_retention_days)


def resolve_entry_retention(
    args_retention_days: int | None,
    envelope_compliance: Mapping[str, Any] | None,
    profile_name: str | None = None,
) -> int | None:
    """Resolve effective retention_days for a state entry.

    Spec: ARSIA-State §8.3 — payload.args.retention_days takes
    precedence; falls back to compliance.retention_days from
    envelope (§8.3-04). The result is then floored by the profile
    minimum via :func:`compute_effective_retention`.

    Returns the effective retention_days or None.
    """
    entry_retention = args_retention_days
    if entry_retention is None and envelope_compliance is not None:
        raw = envelope_compliance.get("retention_days")
        if isinstance(raw, int):
            entry_retention = raw
    if profile_name is not None:
        return compute_effective_retention(profile_name, entry_retention)
    return entry_retention


def apply_compliance_defaults_for_state(
    envelope_compliance: Mapping[str, Any] | None,
    profile_name: str | None,
) -> dict[str, Any]:
    """Apply profile defaults to compliance fields for state operations.

    Spec: ARSIA-State §8.3 — Profile defaults MUST be applied for
    compliance fields not explicitly set in the message.

    Delegates to :func:`arsia_protocol.core.compliance.apply_profile`.
    """
    from arsia_protocol.core.compliance import apply_profile

    compliance_dict: dict[str, Any] = (
        dict(envelope_compliance) if envelope_compliance else {}
    )
    if profile_name and "profile" not in compliance_dict:
        compliance_dict["profile"] = profile_name
    if not compliance_dict:
        return {}
    envelope_stub = {"compliance": compliance_dict}
    resolved = apply_profile(envelope_stub)
    result = resolved.get("compliance")
    if isinstance(result, dict):
        return result
    return compliance_dict


def _parse_rfc3339_ms(value: str) -> datetime:
    """Parse an RFC 3339 ms UTC timestamp into a timezone-aware datetime."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _format_ms_timestamp(moment: datetime) -> str:
    """Format ``moment`` as an RFC 3339 ms UTC string."""
    moment = moment.astimezone(timezone.utc)
    millis = moment.microsecond // 1000
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{millis:03d}Z"


def is_entry_expired(
    entry: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` when ``entry['expires_at']`` has passed.

    Per ARSIA-State.md §2.1.7 an entry expires at its ``expires_at``
    timestamp. Entries without ``expires_at`` never expire on their
    own (retention is handled separately by
    :func:`is_within_retention`).

    Args:
        entry: A state-entry dict (as produced by
            :meth:`StateEntry.model_dump`). Only ``expires_at`` is
            read; other fields are ignored.
        now: Reference instant for the comparison. Defaults to
            :func:`datetime.now(timezone.utc)`. Inject a fixed value
            for deterministic tests.

    Returns:
        ``True`` when ``entry['expires_at']`` is set and strictly less
        than ``now``; ``False`` when ``expires_at`` is missing, ``None``,
        or still in the future.

    Spec: ARSIA-State.md §2.1.7.
    """
    expires_at = entry.get("expires_at")
    if not expires_at:
        return False
    expires = _parse_rfc3339_ms(expires_at)
    if now is None:
        now = datetime.now(timezone.utc)
    return now > expires


def is_within_retention(
    entry: Mapping[str, Any],
    profile: Mapping[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` when ``entry`` is still within its retention period.

    Per ARSIA-State.md §2.1.8 / §4.1.1 an entry is "within retention"
    when ``now < created_at + (effective_retention * 86400 seconds)``.
    Effective retention is the max of the entry's own override and
    the compliance profile's floor.

    Args:
        entry: A state-entry dict with at least ``created_at`` and
            optionally ``retention_days``.
        profile: The compliance profile dict (``{"name": ...}``) whose
            retention floor applies. ``None`` means no profile floor.
        now: Reference instant for the comparison. Defaults to
            :func:`datetime.now(timezone.utc)`.

    Returns:
        ``True`` when the entry is still within retention; ``False``
        when either no retention applies (returns ``False`` — nothing
        to protect) or the retention window has elapsed.

    Spec: ARSIA-State.md §4.1.1.
    """
    profile_name: str | None = None
    if profile is not None:
        candidate = profile.get("name")
        if isinstance(candidate, str):
            profile_name = candidate

    retention = compute_effective_retention(
        profile_name,
        entry.get("retention_days"),
    )
    if retention is None or retention <= 0:
        return False

    created_at_raw = entry.get("created_at")
    if not isinstance(created_at_raw, str):
        return False
    created = _parse_rfc3339_ms(created_at_raw)
    if now is None:
        now = datetime.now(timezone.utc)
    return now < created + timedelta(days=retention)


# ---------------------------------------------------------------------------
# §8.2 — Capability gating
# ---------------------------------------------------------------------------


def required_capability_for(operation: str) -> str:
    """Return the capability required to perform ``operation``.

    Args:
        operation: One of :data:`STATE_OPERATIONS`.

    Returns:
        The capability string (one of :data:`STATE_CAPABILITY_READ`
        / :data:`STATE_CAPABILITY_WRITE` / :data:`STATE_CAPABILITY_PURGE`
        / :data:`STATE_CAPABILITY_SNAPSHOT`).

    Raises:
        ValueError: when ``operation`` is not a known state operation.

    Spec: ARSIA-State.md §8.2.
    """
    try:
        return OPERATION_TO_CAPABILITY[operation]
    except KeyError:
        raise ValueError(
            f"operation: unknown state operation {operation!r}. "
            f"Expected one of {sorted(STATE_OPERATIONS)}."
        ) from None


def payload_type_for(operation: str) -> str:
    """Return the ``payload.type`` for a state operation.

    Args:
        operation: One of :data:`STATE_OPERATIONS`.

    Returns:
        The payload-type string (``arsiaprotocol.state/<op>``).

    Raises:
        ValueError: when ``operation`` is not a known state operation.

    Spec: ARSIA-State.md §8.1.
    """
    try:
        return _OPERATION_TO_PAYLOAD_TYPE[operation]
    except KeyError:
        raise ValueError(
            f"operation: unknown state operation {operation!r}. "
            f"Expected one of {sorted(STATE_OPERATIONS)}."
        ) from None


_STANDARD_STATE_PAYLOAD_TYPES: Final[frozenset[str]] = frozenset(
    {
        PAYLOAD_TYPE_GET,
        PAYLOAD_TYPE_SET,
        PAYLOAD_TYPE_DELETE,
        PAYLOAD_TYPE_QUERY,
        PAYLOAD_TYPE_SNAPSHOT,
        PAYLOAD_TYPE_PURGE,
        PAYLOAD_TYPE_GRANT,
        PAYLOAD_TYPE_REVOKE,
    }
)


def validate_custom_state_payload_type(
    payload_type: str,
) -> list[ValidationError]:
    """Validate that a custom state payload_type doesn't use the reserved prefix.

    Spec: ARSIA-State §8.1 — Custom state operations MUST NOT use
    the ``arsiaprotocol.state/`` prefix.

    Returns list of :class:`ValidationError` (empty if valid).
    """
    if (
        payload_type.startswith(PAYLOAD_TYPE_PREFIX)
        and payload_type not in _STANDARD_STATE_PAYLOAD_TYPES
    ):
        return [
            ValidationError(
                code="reserved_payload_type_prefix",
                message=(
                    f"Custom state operations must not use the "
                    f"{PAYLOAD_TYPE_PREFIX} prefix (State §8.1)."
                ),
                details={"payload_type": payload_type},
                spec_ref="State §8.1",
            )
        ]
    return []


def wildcard_covers_state_capability(wildcard: str, capability: str) -> bool:
    """Return whether ``wildcard`` covers ``capability`` under §8.2 rules.

    The ``arsiaprotocol.state.*`` wildcard explicitly excludes
    :data:`STATE_CAPABILITY_PURGE` and :data:`STATE_CAPABILITY_SNAPSHOT`
    per State §8.2. This helper implements that exclusion without
    depending on :mod:`arsia_protocol.actions` (keeping state.py
    within its allow-list).

    Args:
        wildcard: A capability string, possibly containing a ``*``
            wildcard segment.
        capability: The concrete capability being checked.

    Returns:
        ``True`` when ``wildcard`` grants ``capability``.

    Spec: ARSIA-State.md §8.2.
    """
    if wildcard == capability:
        return True
    if wildcard == "arsiaprotocol.state.*":
        return capability not in STATE_WILDCARD_EXCLUDES and capability in (
            STATE_CAPABILITY_READ,
            STATE_CAPABILITY_WRITE,
        )
    if wildcard.endswith(".*"):
        prefix = wildcard[:-2]
        return capability == prefix or capability.startswith(prefix + ".")
    return False


# ---------------------------------------------------------------------------
# §3 — Operation argument builders
# ---------------------------------------------------------------------------


def build_set_args(
    entry: StateEntry,
    *,
    expected_version: int | None = None,
) -> dict[str, Any]:
    """Return the ``args`` object for a SET request.

    Per ARSIA-State.md §3.1.2 the SET ``payload.args`` is a flat
    dict carrying the agent-supplied fields of the entry only.
    Server-managed fields (``owner_agent_id``, ``created_at``,
    ``updated_at``, ``version``, ``deleted``) are NOT part of the
    request — the receiving store assigns them when it persists
    the entry.

    The transport layer wraps the returned dict inside a request
    envelope via :func:`arsia_protocol.message.create_request` with
    ``payload_type=PAYLOAD_TYPE_SET``. State.py deliberately does
    not produce full envelopes (see the module docstring).

    Args:
        entry: The :class:`StateEntry` whose user-facing fields
            populate the SET args.
        expected_version: Optional optimistic-concurrency token — the
            store MUST reject with ``conflict`` when the current
            stored version differs. ``None`` skips concurrency
            control.

    Returns:
        A plain dict suitable for ``payload.args`` with shape::

            {
                "key": str,                # REQUIRED
                "value": Any,              # REQUIRED
                "scope": "session"|"agent"|"shared",  # REQUIRED
                "pii_classification": "none"|"pseudonymised"|"personal",
                "expires_at": str,         # OPTIONAL
                "retention_days": int,     # OPTIONAL
                "data_residency": str,     # OPTIONAL
                "expected_version": int,   # OPTIONAL
            }

    Raises:
        ValueError: when ``entry.scope`` is ``"global"``. Per
            §3.1.2 agents cannot create global-scoped entries via
            SET — such requests MUST be rejected with error code
            ``"forbidden"``. The sender-side builder raises early so
            a malformed request never reaches the wire.

    Spec: ARSIA-State.md §3.1.2.
    """
    if entry.scope == "global":
        raise ValueError(
            "SET with scope='global' is forbidden — agents cannot "
            "create global-scoped entries via SET (State §3.1.2; "
            "map to error code 'forbidden')"
        )
    args: dict[str, Any] = {
        "key": entry.key,
        "value": entry.value,
        "scope": entry.scope,
        "pii_classification": entry.pii_classification,
    }
    if entry.pii_special_categories is not None:
        args["pii_special_categories"] = entry.pii_special_categories
    if entry.expires_at is not None:
        args["expires_at"] = entry.expires_at
    if entry.retention_days is not None:
        args["retention_days"] = entry.retention_days
    if entry.data_residency is not None:
        args["data_residency"] = entry.data_residency
    if expected_version is not None:
        args["expected_version"] = expected_version
    return args


def build_get_args(key: str) -> dict[str, Any]:
    """Return the ``args`` object for a GET request (State §3.1)."""
    return {"key": key}


def build_delete_args(
    key: str,
    *,
    expected_version: int | None = None,
) -> dict[str, Any]:
    """Return the ``args`` object for a DELETE request (State §3.3)."""
    args: dict[str, Any] = {"key": key}
    if expected_version is not None:
        args["expected_version"] = expected_version
    return args


_QUERY_LIMIT_MAX: Final[int] = 1000
"""Maximum QUERY ``limit`` per ARSIA-State.md §3.1.4 (clamped, not rejected)."""


def build_query_args(
    scope: StateScope | None = None,
    *,
    key_prefix: str | None = None,
    owner_agent_id: str | None = None,
    pii_classification: PiiClassification | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """Return the ``args`` object for a QUERY request (State §3.1.4).

    All filter fields are OPTIONAL and combined with AND logic. A call
    with no arguments returns ``{}`` — matching every entry the
    requesting agent is authorised to see.

    ``limit`` is clamped to 1000 (not rejected) per §3.1.4:
    "Requests with ``limit`` exceeding 1000 MUST be clamped to 1000 —
    not rejected."
    """
    if scope is not None and scope not in STATE_SCOPES:
        raise ValueError(
            f"scope: unknown state scope {scope!r}. "
            f"Expected one of {sorted(STATE_SCOPES)}."
        )
    if limit is not None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError("limit: must be a non-negative integer (State §3.1.4)")
        if limit > _QUERY_LIMIT_MAX:
            limit = _QUERY_LIMIT_MAX
    if offset is not None and (
        not isinstance(offset, int) or isinstance(offset, bool) or offset < 0
    ):
        raise ValueError("offset: must be a non-negative integer (State §3.1.4)")
    args: dict[str, Any] = {}
    if scope is not None:
        args["scope"] = scope
    if owner_agent_id is not None:
        args["owner_agent_id"] = owner_agent_id
    if key_prefix is not None:
        args["key_prefix"] = key_prefix
    if pii_classification is not None:
        args["pii_classification"] = pii_classification
    if created_after is not None:
        args["created_after"] = created_after
    if created_before is not None:
        args["created_before"] = created_before
    if limit is not None:
        args["limit"] = limit
    if offset is not None:
        args["offset"] = offset
    return args


_AS_OF_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


def build_snapshot_args(
    as_of: str,
    *,
    filter: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the ``args`` object for a SNAPSHOT request (State §3.2.1).

    ``as_of`` is REQUIRED and MUST be an RFC 3339 UTC timestamp with
    exactly three fractional digits (e.g. ``2026-03-24T14:00:00.000Z``).
    ``filter`` is OPTIONAL and accepts the same fields as QUERY
    (§3.1.4).
    """
    if not isinstance(as_of, str) or not _AS_OF_PATTERN.fullmatch(as_of):
        raise ValueError(
            "as_of: must be an RFC 3339 UTC timestamp with 3 fractional "
            "digits (e.g. '2026-03-24T14:00:00.000Z'). (State §3.2.1)"
        )
    as_of_dt = _parse_rfc3339_ms(as_of)
    now = datetime.now(timezone.utc)
    if as_of_dt > now + timedelta(seconds=300):
        raise ValueError(
            f"as_of {as_of} is in the future beyond the ±300s clock skew "
            "tolerance — SNAPSHOT requests with a future as_of MUST be "
            "rejected with error code 'invalid_request' (State §3.2.1)"
        )
    args: dict[str, Any] = {"as_of": as_of}
    if filter is not None:
        args["filter"] = dict(filter)
    return args


def build_purge_args(
    key: str,
    reason: str,
) -> dict[str, Any]:
    """Return the ``args`` object for a PURGE request (State §3.2.2).

    PURGE deletes exactly ONE entry (identified by ``key``) along with
    all of its historical versions. Subject-wide erasure is a
    higher-level workflow (query matching entries → PURGE each one); the
    SDK intentionally does not conflate the two.

    Per §3.2.2, the request payload carries only ``key`` and a ``reason``
    string — never the value being erased. The PURGE audit event
    preserves the key, metadata, and reason but MUST NOT contain the
    purged value (§3.2.2, §5.3).

    Args:
        key: The state-entry key to purge (``{agent}/{scope}/{local}``).
        reason: Free-text legal basis for the erasure (forwarded into
            the audit event, e.g. ``"gdpr_erasure"``,
            ``"data_subject_request"``).

    Returns:
        A plain dict suitable for ``payload.args``.
    """
    if not isinstance(key, str) or not key.strip():
        raise ValueError("key: must be a non-empty string (State §3.2.2)")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason: must be a non-empty string (State §3.2.2)")
    return {"key": key, "reason": reason}


def build_purge_result(
    key: str,
    purged_at: str,
) -> dict[str, Any]:
    """Return the ``payload.result`` object for a PURGE response (§3.2.2).

    Per §3.2.2 a successful PURGE response carries::

        { "purged": true, "key": "...", "purged_at": "RFC 3339 ms UTC" }

    ``purged_at`` MUST be an RFC 3339 UTC timestamp with exactly three
    fractional digits (e.g. ``2026-03-24T15:00:00.000Z``).
    """
    if not isinstance(key, str) or not key.strip():
        raise ValueError("key: must be a non-empty string (State §3.2.2)")
    if not isinstance(purged_at, str) or not _AS_OF_PATTERN.fullmatch(purged_at):
        raise ValueError(
            "purged_at: must be an RFC 3339 UTC timestamp with 3 fractional "
            "digits (e.g. '2026-03-24T15:00:00.000Z'). (State §3.2.2)"
        )
    return {"purged": True, "key": key, "purged_at": purged_at}


_GRANT_ACCESS_LEVELS: Final[frozenset[str]] = frozenset({"read", "read_write"})


def build_grant_args(
    key_pattern: str,
    grantee_agent_id: str,
    access_level: AccessLevel,
    *,
    sender_agent_id: str | None = None,
    valid_until: str | None = None,
) -> dict[str, Any]:
    """Return the ``args`` object for a GRANT request (State §3.3.1).

    The GRANT operation creates an access grant that allows another
    agent to read or read-write specific state entries owned by the
    granting agent. The returned dict matches the spec shape::

        {
            "key_pattern": str,        # REQUIRED
            "grantee_agent_id": str,   # REQUIRED
            "access_level": "read" | "read_write",  # REQUIRED
            "valid_until": str,        # OPTIONAL (RFC 3339 ms)
        }

    ``key_pattern`` supports exact match or prefix match (trailing
    ``*``). When ``sender_agent_id`` is provided, the pattern MUST
    start with the granting agent's agent-id prefix per §3.3.1 —
    an agent MUST NOT grant access to keys it does not own.
    """
    if not isinstance(key_pattern, str) or not key_pattern.strip():
        raise ValueError("key_pattern: must be a non-empty string (State §3.3.1)")
    if not isinstance(grantee_agent_id, str) or not grantee_agent_id.strip():
        raise ValueError("grantee_agent_id: must be a non-empty string (State §3.3.1)")
    if sender_agent_id is not None:
        expected_prefix = sender_agent_id + "/"
        if not key_pattern.startswith(expected_prefix):
            raise ValueError(
                f"key_pattern {key_pattern!r} must start with the granting "
                f"agent's prefix {expected_prefix!r} — an agent MUST NOT "
                "grant access to keys it does not own (State §3.3.1)"
            )
    if access_level not in _GRANT_ACCESS_LEVELS:
        raise ValueError(
            f"access_level must be one of {sorted(_GRANT_ACCESS_LEVELS)} "
            f"(State §3.3.1); got {access_level!r}"
        )
    if valid_until is not None and (
        not isinstance(valid_until, str) or not _AS_OF_PATTERN.fullmatch(valid_until)
    ):
        raise ValueError(
            "valid_until: must be an RFC 3339 UTC timestamp with 3 "
            "fractional digits (e.g. '2026-06-24T00:00:00.000Z'). "
            "(State §3.3.1)"
        )
    args: dict[str, Any] = {
        "key_pattern": key_pattern,
        "grantee_agent_id": grantee_agent_id,
        "access_level": access_level,
    }
    if valid_until is not None:
        args["valid_until"] = valid_until
    return args


def build_grant_result(
    key_pattern: str,
    grantee_agent_id: str,
    access_level: AccessLevel,
    created_at: str,
    *,
    valid_until: str | None = None,
    grant_id: str | None = None,
) -> dict[str, Any]:
    """Return the ``payload.result`` object for a GRANT response (§3.3.1).

    Generates a fresh UUID v4 ``grant_id`` when one is not supplied.
    The result echoes the request fields plus the server-assigned
    handle::

        {
            "grant_id": str,           # UUID v4 — handle for REVOKE
            "key_pattern": str,
            "grantee_agent_id": str,
            "access_level": "read" | "read_write",
            "valid_until": str | None,
            "created_at": str,         # RFC 3339 ms UTC
        }
    """
    if not isinstance(created_at, str) or not _AS_OF_PATTERN.fullmatch(created_at):
        raise ValueError(
            "created_at: must be an RFC 3339 UTC timestamp with 3 "
            "fractional digits (e.g. '2026-03-24T15:00:00.000Z'). "
            "(State §3.3.1)"
        )
    # Reuse the request-shape validation for the echoed fields.
    echoed = build_grant_args(
        key_pattern,
        grantee_agent_id,
        access_level,
        valid_until=valid_until,
    )
    if grant_id is None:
        import uuid

        grant_id = str(uuid.uuid4())
    result: dict[str, Any] = {
        "grant_id": grant_id,
        "key_pattern": echoed["key_pattern"],
        "grantee_agent_id": echoed["grantee_agent_id"],
        "access_level": echoed["access_level"],
        "valid_until": echoed.get("valid_until"),
        "created_at": created_at,
    }
    return result


def build_revoke_args(grant_id: str) -> dict[str, Any]:
    """Return the ``args`` object for a REVOKE request (State §3.3.2).

    Revocation targets a single grant by the UUID v4 handle returned
    from :func:`build_grant_result`. The returned shape is::

        { "grant_id": str }
    """
    if not isinstance(grant_id, str) or not grant_id.strip():
        raise ValueError("grant_id: must be a non-empty string (State §3.3.2)")
    return {"grant_id": grant_id}


def build_revoke_result(
    grant_id: str,
    revoked_at: str,
) -> dict[str, Any]:
    """Return the ``payload.result`` object for a REVOKE response (§3.3.2).

    Per §3.3.2 a successful REVOKE response carries::

        {
            "revoked": true,
            "grant_id": str,
            "revoked_at": str,         # RFC 3339 ms UTC
        }

    Revocation is idempotent: revoking a non-existent or
    already-revoked grant MUST still return a successful response
    (the SDK does not re-check existence here — that is the store's
    job).
    """
    if not isinstance(grant_id, str) or not grant_id.strip():
        raise ValueError("grant_id: must be a non-empty string (State §3.3.2)")
    if not isinstance(revoked_at, str) or not _AS_OF_PATTERN.fullmatch(revoked_at):
        raise ValueError(
            "revoked_at: must be an RFC 3339 UTC timestamp with 3 "
            "fractional digits (e.g. '2026-03-24T16:00:00.000Z'). "
            "(State §3.3.2)"
        )
    return {"revoked": True, "grant_id": grant_id, "revoked_at": revoked_at}


def validate_eu_ai_act_response(
    envelope: Mapping[str, Any],
) -> list[ValidationError]:
    """Validate EU-AI-ACT-HIGH-RISK response payload and explanation (State §6.2).

    Under the EU-AI-ACT-HIGH-RISK profile, every response MUST include
    a payload with an ``explanation`` subobject containing at least
    ``reasoning`` (non-empty str), ``confidence`` (number 0.0–1.0),
    and ``inputs_used`` (non-empty list).
    """
    compliance = envelope.get("compliance")
    if not isinstance(compliance, dict):
        return []
    profile = compliance.get("profile")
    if profile != "EU-AI-ACT-HIGH-RISK":
        return []
    intent = envelope.get("intent")
    if intent != "response":
        return []
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or not payload:
        return [
            ValidationError(
                code="missing_payload",
                message="EU-AI-ACT-HIGH-RISK responses MUST include a payload",
                details={},
                spec_ref="State §6.2",
            )
        ]
    errors: list[ValidationError] = []
    explanation = payload.get("explanation")
    if not isinstance(explanation, dict):
        errors.append(
            ValidationError(
                code="missing_explanation",
                message=(
                    "EU-AI-ACT-HIGH-RISK responses MUST include a payload.explanation "
                    "subobject"
                ),
                details={},
                spec_ref="State §6.2",
            )
        )
        return errors
    if (
        not isinstance(explanation.get("reasoning"), str)
        or not explanation["reasoning"]
    ):
        errors.append(
            ValidationError(
                code="missing_reasoning",
                message=(
                    "EU-AI-ACT-HIGH-RISK explanation.reasoning MUST be a non-empty "
                    "string"
                ),
                details={},
                spec_ref="State §6.2",
            )
        )
    confidence = explanation.get("confidence")
    if not isinstance(confidence, (int, float)) or confidence < 0.0 or confidence > 1.0:
        errors.append(
            ValidationError(
                code="invalid_confidence",
                message=(
                    "EU-AI-ACT-HIGH-RISK explanation.confidence MUST be a number "
                    "between 0.0 and 1.0"
                ),
                details={"confidence": confidence},
                spec_ref="State §6.2",
            )
        )
    inputs_used = explanation.get("inputs_used")
    if not isinstance(inputs_used, list) or not inputs_used:
        errors.append(
            ValidationError(
                code="missing_inputs_used",
                message=(
                    "EU-AI-ACT-HIGH-RISK explanation.inputs_used MUST be a non-empty "
                    "list"
                ),
                details={},
                spec_ref="State §6.2",
            )
        )
    return errors


def build_conflict_error(
    current_version: int,
    expected_version: int,
    *,
    updated_at: str | None = None,
    updated_by: str | None = None,
) -> dict[str, Any]:
    """Return the error details for a SET optimistic-concurrency conflict.

    Per State §8.4, the error response MUST include
    ``current_version``, ``expected_version``, and when available,
    ``updated_at`` and ``updated_by`` so the requesting agent can
    understand who last modified the entry and when.
    """
    result: dict[str, Any] = {
        "error_code": "conflict",
        "current_version": current_version,
        "expected_version": expected_version,
    }
    if updated_at is not None:
        result["updated_at"] = updated_at
    if updated_by is not None:
        result["updated_by"] = updated_by
    return result


__all__ = [
    # §1 scopes
    "STATE_SCOPES",
    # §3 operations
    "STATE_OPERATIONS",
    "PAYLOAD_TYPE_PREFIX",
    "PAYLOAD_TYPE_GET",
    "PAYLOAD_TYPE_SET",
    "PAYLOAD_TYPE_DELETE",
    "PAYLOAD_TYPE_QUERY",
    "PAYLOAD_TYPE_SNAPSHOT",
    "PAYLOAD_TYPE_PURGE",
    "PAYLOAD_TYPE_GRANT",
    "PAYLOAD_TYPE_REVOKE",
    "payload_type_for",
    # §2.1.1 keys
    "STATE_KEY_MAX_LENGTH",
    "STATE_VALUE_MAX_BYTES",
    "STATE_RESERVED_KEY_PREFIX",
    "parse_state_key",
    "is_reserved_key",
    "validate_state_key",
    # §2.1.2 value size
    "compute_value_size",
    "enforce_value_size_limit",
    # §2.1 entry validation
    "validate_state_entry",
    "detect_immutable_field_changes",
    # §8.3 inheritance
    "resolve_entry_data_residency",
    "resolve_entry_retention",
    "apply_compliance_defaults_for_state",
    # §4.1.1 retention / §2.1.7 expiry
    "compute_effective_retention",
    "is_entry_expired",
    "is_within_retention",
    # §8.1 custom payload_type validation
    "validate_custom_state_payload_type",
    # §8.2 capabilities
    "STATE_CAPABILITY_READ",
    "STATE_CAPABILITY_WRITE",
    "STATE_CAPABILITY_PURGE",
    "STATE_CAPABILITY_SNAPSHOT",
    "STATE_WILDCARD_EXCLUDES",
    "OPERATION_TO_CAPABILITY",
    "required_capability_for",
    "wildcard_covers_state_capability",
    # §3 argument builders
    "build_set_args",
    "build_get_args",
    "build_delete_args",
    "build_query_args",
    "build_snapshot_args",
    "build_purge_args",
    "build_purge_result",
    "build_grant_args",
    "build_grant_result",
    "build_revoke_args",
    "build_revoke_result",
    # §6.2 EU-AI-ACT validation
    "validate_eu_ai_act_response",
    # §8.4 error shapes
    "build_conflict_error",
]
