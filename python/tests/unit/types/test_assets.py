# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.assets``.

Spec: ARSIA-Assets.md §3 and §4.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arsia_protocol.types.assets import (
    AssetTransferReceiptResult,
    AssetTransferRequestArgs,
    AssetTransferReversalArgs,
    EscrowConditions,
)


def test_transfer_request_args_minimal_valid() -> None:
    """A minimal AssetTransferRequestArgs constructs successfully.

    Spec: ARSIA-Assets.md §3.1.1.
    """
    args = AssetTransferRequestArgs(
        amount=100.0,
        currency_or_unit="EUR",
        asset_type="currency",
        from_agent="agent:acme.billing",
        to_agent="agent:acme.payments",
        payment_reference="INV-2026-001",
        description="Monthly service fee",
        idempotency_key="idem-key-001",
    )
    assert args.amount == 100.0
    assert args.asset_type == "currency"


def test_transfer_request_rejects_negative_amount() -> None:
    """amount must be positive.

    Spec: ARSIA-Assets.md §3.1.1.
    """
    with pytest.raises(ValidationError):
        AssetTransferRequestArgs(
            amount=-1.0,
            currency_or_unit="EUR",
            asset_type="currency",
            from_agent="agent:acme.billing",
            to_agent="agent:acme.payments",
            payment_reference="INV-1",
            description="x",
            idempotency_key="k",
        )


def test_transfer_request_rejects_invalid_agent_id() -> None:
    """from_agent and to_agent must be valid agent identifiers.

    Spec: ARSIA-Core.md §3.3.
    """
    with pytest.raises(ValidationError):
        AssetTransferRequestArgs(
            amount=1.0,
            currency_or_unit="EUR",
            asset_type="currency",
            from_agent="not-an-agent-id",
            to_agent="agent:acme.payments",
            payment_reference="INV-1",
            description="x",
            idempotency_key="k",
        )


def test_transfer_receipt_completed_requires_settled_at() -> None:
    """status='completed' requires settled_at and forbids failure_reason.

    Spec: ARSIA-Assets.md §3.2.1.
    """
    with pytest.raises(ValidationError, match="settled_at is required"):
        AssetTransferReceiptResult(
            status="completed",
            payment_reference="INV-1",
            amount=1.0,
            currency_or_unit="EUR",
            initiated_at="2026-03-24T10:15:30.000Z",
            audit_id="550e8400-e29b-41d4-a716-446655440000",
        )


def test_transfer_receipt_failed_requires_failure_reason() -> None:
    """status='failed' requires failure_reason and forbids settled_at.

    Spec: ARSIA-Assets.md §3.2.1.
    """
    with pytest.raises(ValidationError, match="failure_reason is required"):
        AssetTransferReceiptResult(
            status="failed",
            payment_reference="INV-1",
            amount=1.0,
            currency_or_unit="EUR",
            initiated_at="2026-03-24T10:15:30.000Z",
            audit_id="550e8400-e29b-41d4-a716-446655440000",
        )


def test_transfer_receipt_completed_valid() -> None:
    """A completed transfer with settled_at constructs successfully.

    Spec: ARSIA-Assets.md §3.2.1.
    """
    rec = AssetTransferReceiptResult(
        status="completed",
        payment_reference="INV-1",
        amount=1.0,
        currency_or_unit="EUR",
        initiated_at="2026-03-24T10:15:30.000Z",
        settled_at="2026-03-24T10:15:31.000Z",
        audit_id="550e8400-e29b-41d4-a716-446655440000",
    )
    assert rec.status == "completed"


def test_transfer_receipt_pending_forbids_settlement_fields() -> None:
    """status='pending' forbids both settled_at and failure_reason.

    Spec: ARSIA-Assets.md §3.2.1.
    """
    with pytest.raises(ValidationError, match="MUST be absent"):
        AssetTransferReceiptResult(
            status="pending",
            payment_reference="INV-1",
            amount=1.0,
            currency_or_unit="EUR",
            initiated_at="2026-03-24T10:15:30.000Z",
            settled_at="2026-03-24T10:15:31.000Z",
            audit_id="550e8400-e29b-41d4-a716-446655440000",
        )


def test_escrow_conditions_valid() -> None:
    """An EscrowConditions with required fields constructs successfully.

    Spec: ARSIA-Assets.md §4.1.
    """
    esc = EscrowConditions(
        release_condition="Delivery confirmed by shipper.",
        release_trigger="com.acme.shipping/delivered",
        release_agent="agent:acme.shipping",
        timeout_at="2026-04-24T10:15:30.000Z",
    )
    assert esc.release_agent == "agent:acme.shipping"


def test_reversal_args_valid() -> None:
    """An AssetTransferReversalArgs constructs successfully.

    Spec: ARSIA-Assets.md §3.3.1.
    """
    rev = AssetTransferReversalArgs(
        original_payment_reference="INV-1",
        reversal_reason="Customer requested refund within 14-day window.",
        requested_by="agent:acme.billing",
    )
    assert rev.requested_by == "agent:acme.billing"
