# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Audit-record builders and payload-hash helpers.

This module is Layer 5 (Cross-cutting) in the SDK dependency graph. It
depends only on :mod:`arsia_protocol.types` (for the
:class:`ArsiaAuditRecord` model and event-type alias),
:mod:`arsia_protocol.hazmat.canonicalization` (for the RFC 8785
serialization used to compute ``payload_hash``), and
:mod:`arsia_protocol.validation` (for the :func:`validate_schema`
helper that :func:`validate_audit_record` delegates to for L1
schema checks).

The SDK's responsibility is to **build** and **validate** audit
records. Persistence, append-only guarantees, the audit query endpoint
at ``/.well-known/arsia/audit`` (State §7.4), and retention/archival
lifecycle all live in the deployment's storage layer — not in this
library.

What this module provides
-------------------------

- :func:`compute_payload_hash` — SHA-256 hex of the JCS-canonicalized
  ``payload`` sub-object of a message. This is the authoritative way
  to derive the ``payload_hash`` field of an :class:`ArsiaAuditRecord`.
  Never hash ``json.dumps(payload)``: the canonicalization layer of
  the SDK is RFC 8785 across the board, and audit integrity
  verification depends on every participant producing the same bytes.
- :func:`derive_event_type_from_intent` — maps the six envelope
  intents from Core §4.1.6 (``request``, ``response``, ``event``,
  ``error``, ``pending_approval``, ``approval_decision``) to their
  :data:`AuditEventType` counterpart. The eleven primitive-specific
  event types (``state_set``, ``state_delete``, ``state_grant``,
  ``state_revoke``, ``state_purge``, ``asset_transfer``,
  ``broker_relay``, ``key_rotation``, ``approval_expired``,
  ``dora_incident``, ``rollback``) are **not** derivable from the
  envelope intent alone and MUST be passed explicitly to
  :func:`build_audit_record`.
- :func:`build_audit_record` — assembles an :class:`ArsiaAuditRecord`
  from a signed (or unsigned) envelope dict plus the contextual fields
  the transport layer carries (``operator_id`` resolved from the
  owning agent's :class:`IdentityRecord`, effective retention resolved
  from the compliance profile, and the human-oversight outcome when
  one applies). The returned record is a validated Pydantic object —
  callers can serialize it with ``model_dump(mode='json')`` and hand
  it to their audit store.

Spec: ARSIA-State.md §7.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Final, Mapping

from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.types.errors import ValidationError
from arsia_protocol.types.state import (
    AccessLevel,
    ArsiaAuditRecord,
    AuditEventType,
    LegalBasis,
    OversightStatus,
)
from arsia_protocol.core.validation import validate_schema

_PAYLOAD_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")
"""Lowercase hex SHA-256 pattern for the audit-record ``payload_hash``.

Matches the schema constraint in ``arsia-audit-record.schema.json``.
"""

AUDIT_EVENT_TYPES: Final[frozenset[AuditEventType]] = frozenset(
    {
        "approval_decision",
        "approval_expired",
        "asset_transfer",
        "broker_relay",
        "dora_incident",
        "error",
        "event",
        "key_rotation",
        "pending_approval",
        "request",
        "response",
        "rollback",
        "state_delete",
        "state_grant",
        "state_purge",
        "state_revoke",
        "state_set",
    }
)
"""The 17 audit event types defined in ARSIA-State.md §7.1."""

_INTENT_TO_EVENT: Final[Mapping[str, AuditEventType]] = {
    "request": "request",
    "response": "response",
    "event": "event",
    "error": "error",
    "pending_approval": "pending_approval",
    "approval_decision": "approval_decision",
}
"""One-to-one mapping between the six envelope intents and their audit events.

The remaining eleven event types (``state_set``, ``state_delete``,
``state_grant``, ``state_revoke``, ``state_purge``, ``asset_transfer``,
``broker_relay``, ``key_rotation``, ``approval_expired``,
``dora_incident``, ``rollback``) are primitive-specific and MUST be
selected by the caller — the intent alone does not disambiguate them
from a generic ``request``/``event``.
"""


def compute_payload_hash(payload: dict[str, Any] | str) -> str:
    """Return the SHA-256 hex of the ``payload``.

    When ``payload`` is a dict (normal envelope), the digest is
    computed over the RFC 8785 (JCS) canonical byte sequence.

    When ``payload`` is a str (JWE Compact Serialization for encrypted
    envelopes where ``security.encrypted=true``), the digest is
    computed over the raw UTF-8 bytes of the JWE string — no
    canonicalization is applied because the ciphertext is opaque.

    The output is lowercase hex — matching the schema pattern
    ``^[a-f0-9]{64}$``.

    Args:
        payload: Either the ``payload`` sub-object of an ARSIA
            envelope (dict) or a JWE Compact Serialization string
            when the envelope is encrypted.

    Returns:
        The 64-character lowercase hex digest.

    Spec: ARSIA-Core.md §5.3.1, ARSIA-State.md §7.1.
    """
    if isinstance(payload, str):
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical = canonicalize(payload)
    return hashlib.sha256(canonical).hexdigest()


def derive_event_type_from_intent(intent: str) -> AuditEventType:
    """Return the audit event type for a Core §4.1.6 envelope intent.

    Args:
        intent: One of the six envelope intents (``request``,
            ``response``, ``event``, ``error``, ``pending_approval``,
            ``approval_decision``).

    Returns:
        The matching :data:`AuditEventType`.

    Raises:
        ValueError: when ``intent`` is not one of the six envelope
            intents. Primitive-specific event types (``state_set``,
            ``state_delete``, ``state_purge``, ``asset_transfer``,
            ``broker_relay``, ``key_rotation``, etc.) cannot be derived
            from the intent alone
            and MUST be selected by the caller — this function never
            returns them.
    """
    try:
        return _INTENT_TO_EVENT[intent]
    except KeyError:
        raise ValueError(
            f"cannot derive audit event_type from intent {intent!r}; "
            f"expected one of {sorted(_INTENT_TO_EVENT)} "
            "(primitive-specific event types must be passed explicitly)"
        ) from None


def _format_ms_timestamp(moment: datetime) -> str:
    """Format ``moment`` as an RFC 3339 ms UTC string (State §7.1 pattern)."""
    moment = moment.astimezone(timezone.utc)
    millis = moment.microsecond // 1000
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{millis:03d}Z"


def build_audit_record(
    envelope: Mapping[str, Any],
    *,
    event_type: AuditEventType,
    operator_id: str,
    effective_retention_days: int,
    oversight_status: OversightStatus | None = None,
    approver_id: str | None = None,
    data_residency: str | None = None,
    processed_at: datetime | None = None,
    record_id: str | None = None,
    actor_agent_id: str | None = None,
    entry_key: str | None = None,
    owner_agent_id: str | None = None,
    entry_version: int | None = None,
    correlation_id: str | None = None,
    approval_deadline: str | None = None,
    grant_id: str | None = None,
    key_pattern: str | None = None,
    grantor_agent_id: str | None = None,
    grantee_agent_id: str | None = None,
    access_level: AccessLevel | None = None,
    valid_until: str | None = None,
    plaintext_hash: str | None = None,
    hash_chain: str | None = None,
    legal_basis: LegalBasis | None = None,
    sender_owner_id: str | None = None,
    receiver_owner_id: str | None = None,
    deployer_id: str | None = None,
) -> ArsiaAuditRecord:
    """Assemble an :class:`ArsiaAuditRecord` for ``envelope``.

    The builder does not persist anything; it produces a validated
    Pydantic model that the caller serializes into its audit store.
    All immutability, append-only, and retention-lifecycle rules from
    §7.2 and §7.3 are storage-layer concerns.

    Field derivation:

    - ``record_id`` — UUID v4. Generated when the caller does not
      supply one (the caller MAY pass a precomputed UUID v4 so that the
      value is known before the record is committed, e.g. for
      idempotency).
    - ``message_id`` — read from ``envelope['id']``.
    - ``from_agent`` / ``to_agent`` — read from ``envelope['from']``
      and ``envelope['to']``.
    - ``intent`` — read from ``envelope['intent']``.
    - ``payload_type`` — read from ``envelope['payload']['type']``.
    - ``payload_hash`` — :func:`compute_payload_hash` of the
      envelope's ``payload`` sub-object.
    - ``compliance_profile`` — read from
      ``envelope['compliance']['profile']`` when present; falls back
      to the literal string ``"none"`` when the envelope has no
      ``compliance`` field (matching §7.1's wording).
    - ``human_oversight_status`` / ``approver_id`` —
      caller-supplied. The builder enforces §7.1's conditional:
      ``approver_id`` is required when ``oversight_status`` is
      ``"approved"`` or ``"denied"``.
    - ``processed_at`` — defaults to ``datetime.now(timezone.utc)``;
      callers MAY pass a deterministic moment (testing, replay).
    - ``retained_until`` — ``processed_at + effective_retention_days``.
      The caller resolves the retention value through
      :func:`arsia_protocol.compliance.get_effective_retention`; this
      builder does not re-apply the profile floor.
    - ``data_residency`` — caller-supplied. When ``None``, the builder
      falls back to ``envelope['compliance']['data_residency']`` when
      present. §7.1 requires that, when set, it matches the
      originating message's ``compliance.data_residency``.
    - ``operator_id`` — caller-supplied, resolved from the owning
      agent's :class:`IdentityRecord.owner_id`.

    Args:
        envelope: The originating ARSIA message as a dict.
        event_type: One of the 17 :data:`AuditEventType` values.
        operator_id: Legal-entity ID from the audit owner's
            :class:`IdentityRecord.owner_id`.
        effective_retention_days: The retention period already
            resolved against the compliance profile (see
            :func:`arsia_protocol.compliance.get_effective_retention`).
            MUST be >= 1.
        oversight_status: Human-oversight outcome for this event, or
            ``None`` when oversight is out of scope for the caller.
        approver_id: Agent ID of the approver. Required when
            ``oversight_status`` is ``"approved"`` or ``"denied"``.
        data_residency: Explicit override. When ``None``, inherited
            from ``envelope['compliance']['data_residency']`` when
            present.
        processed_at: Reference instant. Defaults to current UTC.
        record_id: Caller-supplied UUID v4. Defaults to a fresh one.

    Returns:
        A validated :class:`ArsiaAuditRecord`.

    Raises:
        ValueError: on missing required envelope fields, invalid
            ``event_type``, invalid ``effective_retention_days``, or
            a missing ``approver_id`` when required.

    Spec: ARSIA-State.md §7.1.
    """
    if event_type not in AUDIT_EVENT_TYPES:
        raise ValueError(
            f"event_type: {event_type!r} is not one of the 17 audit "
            f"event types defined in State §7.1. "
            f"Expected one of {sorted(AUDIT_EVENT_TYPES)}."
        )
    if effective_retention_days < 1:
        raise ValueError(
            f"effective_retention_days must be >= 1, got "
            f"{effective_retention_days} (State §7.1)"
        )
    if oversight_status in ("approved", "denied") and approver_id is None:
        raise ValueError(
            "approver_id is required when oversight_status is "
            "'approved' or 'denied' (State §7.1)"
        )

    message_id = envelope.get("id")
    if not isinstance(message_id, str):
        raise ValueError("envelope['id'] must be a string UUID v4")
    from_agent = envelope.get("from")
    if not isinstance(from_agent, str):
        raise ValueError("envelope['from'] must be a string agent-id")
    to_agent = envelope.get("to")
    if not isinstance(to_agent, str):
        raise ValueError("envelope['to'] must be a string agent-id")
    intent = envelope.get("intent")
    if not isinstance(intent, str):
        raise ValueError("envelope['intent'] must be a string")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("envelope['payload'] must be an object")
    payload_type = payload.get("type")
    if not isinstance(payload_type, str):
        raise ValueError("envelope['payload']['type'] must be a string")

    compliance = envelope.get("compliance")
    if isinstance(compliance, dict):
        declared_profile = compliance.get("profile")
        compliance_profile = (
            declared_profile if isinstance(declared_profile, str) else "none"
        )
        residency_from_envelope = compliance.get("data_residency")
    else:
        compliance_profile = "none"
        residency_from_envelope = None

    resolved_residency = data_residency
    if resolved_residency is None and isinstance(residency_from_envelope, str):
        resolved_residency = residency_from_envelope

    if processed_at is None:
        processed_at = datetime.now(timezone.utc)
    retained_until = processed_at + timedelta(days=effective_retention_days)

    return ArsiaAuditRecord(
        record_id=record_id if record_id is not None else str(uuid.uuid4()),
        message_id=message_id,
        event_type=event_type,
        from_agent=from_agent,
        to_agent=to_agent,
        intent=intent,
        payload_type=payload_type,
        payload_hash=compute_payload_hash(payload),
        compliance_profile=compliance_profile,
        human_oversight_status=oversight_status,
        approver_id=approver_id,
        processed_at=_format_ms_timestamp(processed_at),
        retained_until=_format_ms_timestamp(retained_until),
        data_residency=resolved_residency,
        actor_agent_id=actor_agent_id,
        entry_key=entry_key,
        owner_agent_id=owner_agent_id,
        version=entry_version,
        correlation_id=correlation_id,
        approval_deadline=approval_deadline,
        grant_id=grant_id,
        key_pattern=key_pattern,
        grantor_agent_id=grantor_agent_id,
        grantee_agent_id=grantee_agent_id,
        access_level=access_level,
        valid_until=valid_until,
        plaintext_hash=plaintext_hash,
        hash_chain=hash_chain,
        legal_basis=legal_basis,
        operator_id=operator_id,
        sender_owner_id=sender_owner_id,
        receiver_owner_id=receiver_owner_id,
        deployer_id=deployer_id,
    )


def validate_audit_record(
    record: Mapping[str, Any],
    *,
    strict: bool = False,
) -> list[ValidationError]:
    """Return the list of errors for an audit-record dict.

    Runs L1 (JSON Schema) validation against
    ``arsia-audit-record.schema.json`` followed by the L2 semantic
    rules from ARSIA-State.md §7.1 that JSON Schema cannot fully
    express:

    - ``payload_hash`` matches ``^[a-f0-9]{64}$`` (lowercase hex
      SHA-256).
    - ``event_type`` is one of :data:`AUDIT_EVENT_TYPES`.
    - ``approver_id`` is present when ``human_oversight_status`` is
      ``"approved"`` or ``"denied"``.

    Args:
        record: The audit-record dict to validate.
        strict: When ``True``, L2 checks are skipped if L1 reports
            any error (a structurally broken record cannot be
            meaningfully checked for semantic rules). When ``False``,
            both layers always run.

    Returns:
        A list of :class:`ValidationError`; empty when valid.

    Spec: ARSIA-State.md §7.1.
    """
    # --- Input normalization (Pydantic model + None stripping) ---
    # Spec: ARSIA-State §7.1 — optional fields are expressed via
    # absence, not null. Strip None so schema validation passes.
    if hasattr(record, "model_dump"):
        data: dict[str, Any] = {
            k: v for k, v in record.model_dump().items() if v is not None
        }
    elif isinstance(record, Mapping):
        data = {k: v for k, v in record.items() if v is not None}
    else:
        return [
            ValidationError(
                code="invalid_record_type",
                message=(
                    f"record must be a Mapping or have .model_dump(), "
                    f"got {type(record).__name__}"
                ),
                spec_ref="State §7.1",
            )
        ]

    errors = validate_schema(data, "arsia-audit-record.schema.json")
    if errors and strict:
        return errors

    payload_hash = data.get("payload_hash")
    if isinstance(payload_hash, str) and not _PAYLOAD_HASH_RE.fullmatch(payload_hash):
        errors.append(
            ValidationError(
                code="invalid_payload_hash",
                message=(
                    f"payload_hash must match ^[a-f0-9]{{64}}$; got {payload_hash!r}"
                ),
                details={"field": "payload_hash"},
                spec_ref="State §7.1",
            )
        )

    event_type = data.get("event_type")
    if isinstance(event_type, str) and event_type not in AUDIT_EVENT_TYPES:
        errors.append(
            ValidationError(
                code="invalid_event_type",
                message=(
                    f"event_type {event_type!r} is not one of the 17 audit event types"
                ),
                details={"field": "event_type", "value": event_type},
                spec_ref="State §7.1",
            )
        )

    status = data.get("human_oversight_status")
    if status in ("approved", "denied") and not data.get("approver_id"):
        errors.append(
            ValidationError(
                code="missing_approver_id",
                message=(
                    f"approver_id is required when human_oversight_status={status!r}"
                ),
                details={
                    "field": "approver_id",
                    "human_oversight_status": status,
                },
                spec_ref="State §7.1",
            )
        )

    return errors


__all__ = [
    "AUDIT_EVENT_TYPES",
    "build_audit_record",
    "compute_payload_hash",
    "derive_event_type_from_intent",
    "validate_audit_record",
]
