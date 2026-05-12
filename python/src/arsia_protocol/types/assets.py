# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic models for the Assets primitive (transfers + escrow).

Business logic (MiFID II traceability, precision enforcement, reversal
windows) lives in ``arsia_protocol.assets`` starting in Slice 6. This
module provides the structural models only, mirroring:

- ``shared/schemas/arsia-asset-transfer-request.schema.json`` (Assets §3.1.1)
- ``shared/schemas/arsia-asset-transfer-receipt.schema.json`` (Assets §3.2.1)
- ``shared/schemas/arsia-asset-transfer-reversal.schema.json`` (Assets §3.3.1)
- ``shared/schemas/arsia-escrow-conditions.schema.json`` (Assets §4.1)
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arsia_protocol.identity.agent_id import is_valid_agent_id

AssetType = Literal["currency", "token", "entitlement", "service_unit"]
"""Asset types per ARSIA-Assets.md §2."""

TransferStatus = Literal["pending", "completed", "failed", "escrowed"]
"""Asset transfer terminal state per ARSIA-Assets.md §3.2.1."""

_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
_UUID_V4_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_PAYLOAD_TYPE_PATTERN = (
    r"^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*"
    r"(/[a-zA-Z][a-zA-Z0-9_-]*)*$"
)


def _check_agent_id(value: str) -> str:
    if not is_valid_agent_id(value):
        raise ValueError(f"'{value}' is not a valid ARSIA agent identifier (Core §3.3)")
    return value


class EscrowConditions(BaseModel):
    """Escrow terms embedded in an ``AssetTransferRequest``.

    ARSIA does not hold funds — the actual escrow is managed by the
    payment provider; ARSIA defines only the signaling.

    Spec: ARSIA-Assets.md §4.1.
    """

    model_config = ConfigDict(extra="forbid")

    release_condition: str = Field(
        max_length=512,
        description="Human-readable release condition (Assets §4.1).",
    )
    release_trigger: str = Field(
        max_length=128,
        pattern=_PAYLOAD_TYPE_PATTERN,
        description="Payload type that triggers release (Assets §4.1).",
    )
    release_agent: str = Field(
        description="Agent authorised to send the release trigger (Assets §4.1).",
    )
    timeout_at: str = Field(
        pattern=_TS_PATTERN,
        description="Absolute escrow deadline (Assets §4.1).",
    )
    arbitration_agent: str | None = Field(
        default=None,
        description="Agent invoked in dispute resolution (Assets §4.1).",
    )

    @field_validator("release_agent")
    @classmethod
    def _validate_release_agent(cls, value: str) -> str:
        return _check_agent_id(value)

    @field_validator("arbitration_agent")
    @classmethod
    def _validate_arbitration_agent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_agent_id(value)


class AssetTransferRequestArgs(BaseModel):
    """``payload.args`` of an ``AssetTransferRequest`` message.

    Spec: ARSIA-Assets.md §3.1.1.
    """

    model_config = ConfigDict(extra="forbid")

    amount: float = Field(gt=0, description="Positive transfer amount (Assets §3.1.1).")
    currency_or_unit: str = Field(
        max_length=32, description="ISO 4217 or application-defined unit."
    )
    asset_type: AssetType = Field(description="Asset type (Assets §2).")
    from_agent: str = Field(description="Payer agent-id.")
    to_agent: str = Field(description="Payee agent-id.")
    payment_reference: str = Field(
        max_length=128,
        description="Unique reference (MiFID II traceability).",
    )
    description: str = Field(
        max_length=256, description="Human-readable business purpose."
    )
    provider: str | None = Field(
        default=None,
        description="Optional licensed payment provider agent-id.",
    )
    escrow_conditions: EscrowConditions | None = Field(
        default=None,
        description="When set, the transfer is held in escrow.",
    )
    idempotency_key: str = Field(
        max_length=128,
        description="Mandatory idempotency key for asset transfers.",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Opaque application-specific metadata.",
    )

    @field_validator("from_agent", "to_agent")
    @classmethod
    def _validate_parties(cls, value: str) -> str:
        return _check_agent_id(value)

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_agent_id(value)


class AssetTransferReceiptResult(BaseModel):
    """``payload.result`` of an ``AssetTransferReceipt`` message.

    Spec: ARSIA-Assets.md §3.2.1.
    """

    model_config = ConfigDict(extra="forbid")

    status: TransferStatus = Field(description="Terminal state of the transfer.")
    payment_reference: str = Field(
        max_length=128, description="Echoed from the request; MUST match byte-for-byte."
    )
    provider_reference: str | None = Field(
        default=None,
        max_length=256,
        description="Provider's transaction identifier.",
    )
    amount: float = Field(gt=0, description="Actual amount processed by the provider.")
    currency_or_unit: str = Field(
        max_length=32, description="Echoed from the request; MUST match exactly."
    )
    initiated_at: str = Field(
        pattern=_TS_PATTERN,
        description="When the provider began processing (RFC 3339 ms).",
    )
    settled_at: str | None = Field(
        default=None,
        pattern=_TS_PATTERN,
        description="When the transfer was settled; required when status='completed'.",
    )
    failure_reason: str | None = Field(
        default=None,
        max_length=512,
        description="Why the transfer failed; required when status='failed'.",
    )
    audit_id: str = Field(
        pattern=_UUID_V4_PATTERN,
        description="UUID v4 of the audit record for this transfer.",
    )

    @model_validator(mode="after")
    def _enforce_status_invariants(self) -> "AssetTransferReceiptResult":
        if self.status == "failed":
            if self.failure_reason is None:
                raise ValueError(
                    "failure_reason is required when status='failed' (Assets §3.2.1)"
                )
            if self.settled_at is not None:
                raise ValueError(
                    "settled_at MUST be absent when status='failed' (Assets §3.2.1)"
                )
        elif self.status == "completed":
            if self.settled_at is None:
                raise ValueError(
                    "settled_at is required when status='completed' (Assets §3.2.1)"
                )
            if self.failure_reason is not None:
                raise ValueError(
                    "failure_reason MUST be absent when status='completed' "
                    "(Assets §3.2.1)"
                )
        else:  # pending or escrowed
            if self.settled_at is not None or self.failure_reason is not None:
                raise ValueError(
                    "settled_at and failure_reason MUST be absent when status is "
                    "'pending' or 'escrowed' (Assets §3.2.1)"
                )
        return self


class AssetTransferReversalArgs(BaseModel):
    """``payload.args`` of an ``AssetTransferReversal`` message.

    Spec: ARSIA-Assets.md §3.3.1.
    """

    model_config = ConfigDict(extra="forbid")

    original_payment_reference: str = Field(
        max_length=128,
        description="payment_reference of the original transfer to reverse.",
    )
    reversal_reason: str = Field(
        max_length=512, description="Business justification for the reversal."
    )
    requested_by: str = Field(description="agent-id of the requesting entity.")
    reversal_amount: float | None = Field(
        default=None,
        gt=0,
        description="Partial reversal amount; defaults to full when absent.",
    )

    @field_validator("requested_by")
    @classmethod
    def _validate_requested_by(cls, value: str) -> str:
        return _check_agent_id(value)


__all__ = [
    "AssetType",
    "TransferStatus",
    "EscrowConditions",
    "AssetTransferRequestArgs",
    "AssetTransferReceiptResult",
    "AssetTransferReversalArgs",
]
