# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic models for the State primitive (state entries + audit records).

Business logic (state operations, GDPR erasure, audit immutability)
lives in ``arsia_protocol.state`` and ``arsia_protocol.audit`` starting
in Slice 5. This module provides the structural models only, mirroring:

- ``shared/schemas/arsia-state-entry.schema.json`` (State §2.1)
- ``shared/schemas/arsia-audit-record.schema.json`` (State §7.1)
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arsia_protocol.identity.agent_id import is_valid_agent_id

StateScope = Literal["session", "agent", "shared", "global"]
"""State scope taxonomy per ARSIA-State.md §1."""

PiiClassification = Literal["none", "pseudonymised", "personal", "sensitive"]
"""GDPR PII classification per ARSIA-State.md §2.1.10.

Note: the schema uses the British spelling ``pseudonymised``.
``sensitive`` denotes GDPR Art. 9(1) special category data.
"""

PiiSpecialCategory = Literal[
    "health",
    "biometric",
    "genetic",
    "racial_ethnic",
    "political",
    "religious",
    "trade_union",
    "sexual_orientation",
]
"""GDPR Art. 9(1) special category types per ARSIA-State.md §2.1.11."""

AccessLevel = Literal["read", "read_write"]
"""Grant access level per ARSIA-State.md §3.3.1."""

LegalBasis = Literal[
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests",
    "explicit_consent",
    "employment_social_security",
    "vital_interests_incapacity",
    "legitimate_activities",
    "manifestly_public",
    "legal_claims",
    "substantial_public_interest",
    "health_medicine",
    "public_health",
    "archiving_research",
]
"""GDPR legal basis per ARSIA-State.md §8.3 Rule 3.

Art. 6(1) grounds for 'personal' entries, Art. 9(2) grounds for
'sensitive' entries.
"""

AuditEventType = Literal[
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
]
"""The 17 audit event types per ARSIA-State.md §7.1."""

OversightStatus = Literal[
    "not_required",
    "pending",
    "approved",
    "denied",
    "expired",
]
"""Human oversight status per ARSIA-State.md §7.1."""

_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
_UUID_V4_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _check_agent_id(value: str) -> str:
    if not is_valid_agent_id(value):
        raise ValueError(f"'{value}' is not a valid ARSIA agent identifier (Core §3.3)")
    return value


class StateEntry(BaseModel):
    """Fundamental unit of state in the ARSIA Protocol.

    Spec: ARSIA-State.md §2.1 and
    ``shared/schemas/arsia-state-entry.schema.json``.
    """

    model_config = ConfigDict(extra="forbid")

    key: str = Field(
        max_length=512,
        pattern=r"^[a-zA-Z0-9:._/\-]+$",
        description="Namespaced key in the form {agent-id}/{scope}/{local-key}.",
    )
    value: Any = Field(
        description="Opaque stored JSON value. Max 1 MiB (enforced programmatically).",
    )
    owner_agent_id: str = Field(
        description="Agent that created this entry (immutable)."
    )
    scope: StateScope = Field(description="Lifecycle and visibility scope.")
    created_at: str = Field(
        pattern=_TS_PATTERN, description="RFC 3339 ms timestamp of creation."
    )
    updated_at: str = Field(
        pattern=_TS_PATTERN, description="RFC 3339 ms timestamp of last modification."
    )
    expires_at: str | None = Field(
        default=None,
        pattern=_TS_PATTERN,
        description="Optional explicit expiry (RFC 3339 ms).",
    )
    retention_days: int | None = Field(
        default=None,
        ge=1,
        description="Per-entry retention override (may extend, never shorten).",
    )
    data_residency: str | None = Field(
        default=None,
        pattern=r"^[A-Z]{2}$",
        description="ISO 3166-1 alpha-2 or supranational code.",
    )
    pii_classification: PiiClassification = Field(
        description="GDPR classification of the stored value.",
    )
    pii_special_categories: list[PiiSpecialCategory] | None = Field(
        default=None,
        description=(
            "GDPR Art. 9(1) special category types. "
            "REQUIRED when pii_classification is 'sensitive'. "
            "MUST NOT be present otherwise."
        ),
    )
    version: int = Field(
        ge=1, description="Monotonically increasing version, starts at 1."
    )
    deleted: bool | None = Field(
        default=None,
        description="Set by the implementation when logically deleted.",
    )

    @field_validator("owner_agent_id")
    @classmethod
    def _validate_owner_agent_id(cls, value: str) -> str:
        return _check_agent_id(value)

    @model_validator(mode="after")
    def _validate_pii_special_categories(self) -> "StateEntry":
        if self.pii_classification == "sensitive":
            if not self.pii_special_categories:
                raise ValueError(
                    "pii_special_categories is required and must be non-empty "
                    "when pii_classification is 'sensitive' (State §2.1.11)"
                )
            if len(self.pii_special_categories) != len(
                set(self.pii_special_categories)
            ):
                raise ValueError(
                    "pii_special_categories must not contain duplicates (State §2.1.11)"
                )
        else:
            if self.pii_special_categories is not None:
                raise ValueError(
                    "pii_special_categories MUST NOT be present when "
                    f"pii_classification is '{self.pii_classification}' "
                    "(State §2.1.11)"
                )
        return self


class ArsiaAuditRecord(BaseModel):
    """Immutable, append-only audit record for a compliance-relevant event.

    The record stores a SHA-256 hash of the canonicalized payload rather
    than the raw payload, so audit records do not contain personal data
    and are exempt from GDPR Art. 17 erasure.

    Spec: ARSIA-State.md §7.1 and
    ``shared/schemas/arsia-audit-record.schema.json``.
    """

    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(
        pattern=_UUID_V4_PATTERN, description="UUID v4 for this audit record."
    )
    message_id: str = Field(
        pattern=_UUID_V4_PATTERN,
        description="UUID v4 of the originating message.",
    )
    event_type: AuditEventType = Field(description="Type of audited event.")
    from_agent: str = Field(description="agent-id of the sender.")
    to_agent: str = Field(description="agent-id of the recipient.")
    intent: str = Field(description="The intent field from the originating message.")
    payload_type: str = Field(
        description="The payload.type from the originating message."
    )
    payload_hash: str = Field(
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 hex of the JCS-canonicalized payload object.",
    )
    compliance_profile: str = Field(
        description="Profile name or 'none' if the message had no compliance field.",
    )
    human_oversight_status: OversightStatus | None = Field(
        default=None, description="Human oversight status for this event."
    )
    approver_id: str | None = Field(
        default=None,
        description="agent-id of the approver; required when status is approved/denied.",
    )
    processed_at: str = Field(
        pattern=_TS_PATTERN, description="RFC 3339 ms when the record was created."
    )
    retained_until: str = Field(
        pattern=_TS_PATTERN,
        description="RFC 3339 ms retention deadline (processed_at + retention_days).",
    )
    data_residency: str | None = Field(
        default=None,
        pattern=r"^[A-Z]{2}$",
        description="ISO 3166-1 alpha-2 or supranational zone.",
    )
    actor_agent_id: str | None = Field(
        default=None,
        description=(
            "Agent-id of the agent that performed the operation. "
            "May differ from from_agent when operating via a grant."
        ),
    )
    entry_key: str | None = Field(
        default=None,
        description="State entry key for state operation audit events.",
    )
    owner_agent_id: str | None = Field(
        default=None,
        description="Owner agent-id for state operation audit events.",
    )
    version: int | None = Field(
        default=None,
        ge=1,
        description="Entry version number for state operation audit events.",
    )
    correlation_id: str | None = Field(
        default=None,
        pattern=_UUID_V4_PATTERN,
        description="UUID v4 linking oversight audit records to the originating request.",
    )
    approval_deadline: str | None = Field(
        default=None,
        pattern=_TS_PATTERN,
        description="Approval deadline timestamp from the pending_approval message.",
    )
    grant_id: str | None = Field(
        default=None,
        pattern=_UUID_V4_PATTERN,
        description="UUID of the access grant. Present in state_grant/state_revoke events.",
    )
    key_pattern: str | None = Field(
        default=None,
        description="Key or key prefix pattern for the grant. Present in state_grant events.",
    )
    grantor_agent_id: str | None = Field(
        default=None,
        description="Agent granting access. Present in state_grant/state_revoke events.",
    )
    grantee_agent_id: str | None = Field(
        default=None,
        description="Agent receiving access. Present in state_grant/state_revoke events.",
    )
    access_level: AccessLevel | None = Field(
        default=None,
        description="Grant access level. Present in state_grant events.",
    )
    valid_until: str | None = Field(
        default=None,
        pattern=_TS_PATTERN,
        description="Grant expiry timestamp or None for no expiry. Present in state_grant events.",
    )
    plaintext_hash: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 of plaintext payload. Present ONLY when security.encrypted=true.",
    )
    hash_chain: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 of previous record_id + payload_hash. Tamper detection.",
    )
    legal_basis: LegalBasis | None = Field(
        default=None,
        description="GDPR legal basis. Present in state_set events for PII entries.",
    )
    operator_id: str = Field(
        description="Legal entity ID from the IdentityRecord of the audit owner.",
    )
    sender_owner_id: str | None = Field(
        default=None,
        description="Owner ID from the sender's IdentityRecord (Identity §4.1).",
    )
    receiver_owner_id: str | None = Field(
        default=None,
        description="Owner ID from the receiver's IdentityRecord (Identity §4.1).",
    )
    deployer_id: str | None = Field(
        default=None,
        description="Deployer ID for split-responsibility agents (Identity §4.4).",
    )

    @field_validator("from_agent", "to_agent")
    @classmethod
    def _validate_agent_ids(cls, value: str) -> str:
        return _check_agent_id(value)

    @field_validator(
        "approver_id", "actor_agent_id", "grantor_agent_id", "grantee_agent_id"
    )
    @classmethod
    def _validate_optional_agent_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_agent_id(value)

    @model_validator(mode="after")
    def _require_approver_when_decided(self) -> "ArsiaAuditRecord":
        if (
            self.human_oversight_status in ("approved", "denied")
            and self.approver_id is None
        ):
            raise ValueError(
                "approver_id is required when human_oversight_status is "
                "'approved' or 'denied' (State §7.1)"
            )
        return self


__all__ = [
    "StateScope",
    "PiiClassification",
    "PiiSpecialCategory",
    "AccessLevel",
    "LegalBasis",
    "AuditEventType",
    "OversightStatus",
    "StateEntry",
    "ArsiaAuditRecord",
]
