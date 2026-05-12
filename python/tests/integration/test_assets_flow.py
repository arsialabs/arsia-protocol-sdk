# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""End-to-end integration for the Assets primitive (Slice 6).

These scenarios compose :mod:`arsia_protocol.assets` with the message
factory, signing, envelope validation, and the audit builder to cover
realistic asset lifecycles:

1. **Currency transfer → MiFID audit.** Build and sign a currency
   ``AssetTransferRequest``, validate it at the envelope + Layer-4
   level, and project a MiFID II audit record using
   :func:`build_mifid_audit_fields` with a ``payload_hash`` computed by
   :func:`compute_payload_hash`.
2. **Reversal precondition flow.** Sign an ``AssetTransferReversal``
   request, confirm envelope validation passes, and drive
   :func:`validate_reversal_precondition` both through the positive
   ``completed`` case and the cumulative-bound rejection.
3. **Escrow lifecycle.** Sign a transfer carrying a full
   ``escrow_conditions`` object, validate, and walk the §4.2 state
   machine through ESCROWED → DISPUTED → RETURNED.
4. **DORA incident event.** Build a ``payload.data`` dict via
   :func:`build_dora_incident_event`, wrap it via
   :func:`create_event`, sign, and validate the envelope.

These tests do not touch any transport or storage; the SDK's job ends
at producing conformant envelopes and deriving audit records from them.

Spec: ARSIA-Assets.md §3, §4, §5, §6.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from arsia_protocol.assets.assets import (
    PAYLOAD_TYPE_DORA_INCIDENT,
    PAYLOAD_TYPE_TRANSFER_REQUEST,
    PAYLOAD_TYPE_TRANSFER_REVERSAL,
    build_dora_incident_event,
    build_mifid_audit_fields,
    is_terminal_escrow_state,
    is_valid_escrow_transition,
    validate_escrow_conditions,
    validate_reversal_precondition,
    validate_transfer_request,
    validate_transfer_reversal,
    validate_two_party_auth,
)
from arsia_protocol.state.audit import compute_payload_hash
from arsia_protocol.core.message import (
    create_event,
    create_request,
    sign_message,
    verify_message,
)
from arsia_protocol.core.validation import validate_envelope


# ---------------------------------------------------------------------------
# Scenario 1 — Currency transfer + MiFID audit
# ---------------------------------------------------------------------------


def test_currency_transfer_signs_validates_and_produces_mifid_record(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.risk-assessor"
    recipient = "agent:arsialabs.demo.compliance-checker"

    args: dict[str, Any] = {
        "amount": 1250.00,
        "currency_or_unit": "EUR",
        "asset_type": "currency",
        "from_agent": sender,
        "to_agent": recipient,
        "payment_reference": "pay-ref-mifid-001",
        "description": "MiFID transfer scenario",
        "idempotency_key": "idem-mifid-001",
    }

    assert validate_transfer_request(args) == []

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type=PAYLOAD_TYPE_TRANSFER_REQUEST,
        capabilities=["arsiaprotocol.assets.transfer.initiate"],
        args=args,
        compliance={
            "profile": "MIFID-II",
            "data_residency": "EU",
            "retention_days": 1827,
        },
    )
    signed = sign_message(
        envelope,
        keypair_risk_assessor["private_key"],
        keypair_risk_assessor["kid"],
    )
    assert verify_message(signed, keypair_risk_assessor["public_key"]) is True
    assert validate_envelope(signed, strict=False) == []

    payload_hash = compute_payload_hash(signed["payload"])
    record = build_mifid_audit_fields(
        audit_id="11111111-1111-4111-8111-111111111111",
        request_envelope=signed,
        payload_hash=payload_hash,
        created_at="2026-04-13T12:00:00.000Z",
    )

    assert record["asset_type"] == "currency"
    assert record["amount"] == 1250.00
    assert record["compliance_profile"] == "MIFID-II"
    assert record["data_residency"] == "EU"
    assert record["payment_reference"] == "pay-ref-mifid-001"
    assert record["payload_hash"] == payload_hash
    assert record["human_oversight_status"] == "not_required"


# ---------------------------------------------------------------------------
# Scenario 2 — Reversal precondition flow
# ---------------------------------------------------------------------------


def test_reversal_envelope_validates_and_precondition_bounds_apply(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.risk-assessor"
    recipient = "agent:arsialabs.demo.compliance-checker"

    reversal_args: dict[str, Any] = {
        "original_payment_reference": "pay-ref-mifid-001",
        "reversal_reason": "Duplicate charge flagged by post-audit",
        "requested_by": sender,
    }
    assert validate_transfer_reversal(reversal_args) == []

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type=PAYLOAD_TYPE_TRANSFER_REVERSAL,
        capabilities=["arsiaprotocol.assets.transfer.reverse"],
        args=reversal_args,
        compliance={
            "profile": "MIFID-II",
            "data_residency": "EU",
            "retention_days": 1827,
        },
    )
    envelope["idempotency"] = {
        "key": "reversal-pay-ref-mifid-001",
        "expires_at": "2099-12-31T23:59:59.000Z",
    }
    signed = sign_message(
        envelope,
        keypair_risk_assessor["private_key"],
        keypair_risk_assessor["kid"],
    )
    assert verify_message(signed, keypair_risk_assessor["public_key"]) is True
    assert validate_envelope(signed, strict=False) == []

    # Full reversal against a completed transfer within window → ok.
    now = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
    ok = validate_reversal_precondition(
        reversal_args,
        original_status="completed",
        original_amount=1250.00,
        original_settled_at="2026-04-13T11:00:00.000Z",
        now=now,
    )
    assert ok == []

    # Partial reversal that pushes cumulative > original_amount → rejected.
    partial_args = dict(reversal_args, reversal_amount=600.00)
    exceeded = validate_reversal_precondition(
        partial_args,
        original_status="completed",
        original_amount=1000.00,
        already_reversed_total=500.00,
    )
    assert exceeded
    assert any(e.code == "cumulative_reversal_exceeded" for e in exceeded)

    # Window-expired reversal against completed transfer → rejected.
    late = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)
    expired = validate_reversal_precondition(
        reversal_args,
        original_status="completed",
        original_settled_at="2026-04-13T11:00:00.000Z",
        now=late,
    )
    assert expired
    assert any(e.code == "reversal_window_expired" for e in expired)


# ---------------------------------------------------------------------------
# Scenario 3 — Escrow lifecycle
# ---------------------------------------------------------------------------


def test_escrow_transfer_signs_validates_and_walks_state_machine(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.risk-assessor"
    recipient = "agent:arsialabs.demo.compliance-checker"
    escrow: dict[str, Any] = {
        "release_agent": "agent:arsialabs.demo.release-agent",
        "release_condition": "Signed delivery confirmation from recipient",
        "release_trigger": "arsiaprotocol.assets/escrow-release",
        "arbitration_agent": "agent:arsialabs.demo.arbitration",
        "timeout_at": "2026-05-13T12:00:00.000Z",
    }
    assert validate_escrow_conditions(
        escrow, envelope_ts="2026-04-13T12:00:00.000Z"
    ) == []

    args: dict[str, Any] = {
        "amount": 5000.00,
        "currency_or_unit": "EUR",
        "asset_type": "currency",
        "from_agent": sender,
        "to_agent": recipient,
        "payment_reference": "pay-ref-escrow-001",
        "description": "Escrowed transfer with arbitration fallback",
        "idempotency_key": "idem-escrow-001",
        "escrow_conditions": escrow,
    }
    assert validate_transfer_request(args) == []

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type=PAYLOAD_TYPE_TRANSFER_REQUEST,
        capabilities=[
            "arsiaprotocol.assets.transfer.initiate",
            "arsiaprotocol.assets.escrow.create",
        ],
        args=args,
        compliance={
            "profile": "MIFID-II",
            "data_residency": "EU",
            "retention_days": 1827,
        },
    )
    signed = sign_message(
        envelope,
        keypair_risk_assessor["private_key"],
        keypair_risk_assessor["kid"],
    )
    assert verify_message(signed, keypair_risk_assessor["public_key"]) is True
    assert validate_envelope(signed, strict=False) == []

    assert is_valid_escrow_transition("ESCROWED", "DISPUTED") is True
    assert is_valid_escrow_transition("DISPUTED", "RETURNED") is True
    assert is_valid_escrow_transition("RETURNED", "RELEASED") is False
    assert is_terminal_escrow_state("RETURNED") is True
    assert is_terminal_escrow_state("DISPUTED") is False


# ---------------------------------------------------------------------------
# Scenario 4 — Two-party auth composition
# ---------------------------------------------------------------------------


def test_two_party_auth_accepts_distinct_approver_with_both_capabilities() -> None:
    errors = validate_two_party_auth(
        initiator_agent_id="agent:acme.initiator",
        approver_agent_id="agent:acme.approver",
        approver_capabilities=[
            "arsiaprotocol.assets.transfer.approve",
            "arsiaprotocol.oversight.approve",
        ],
    )
    assert errors == []

    rejected = validate_two_party_auth(
        initiator_agent_id="agent:acme.same",
        approver_agent_id="agent:acme.same",
        approver_capabilities=[
            "arsiaprotocol.assets.transfer.approve",
            "arsiaprotocol.oversight.approve",
        ],
    )
    assert rejected
    assert any(e.code == "same_initiator_approver" for e in rejected)


# ---------------------------------------------------------------------------
# Scenario 5 — DORA incident event
# ---------------------------------------------------------------------------


def test_dora_incident_event_signs_and_validates(
    keypair_compliance_checker: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.compliance-checker"
    recipient = "agent:arsialabs.demo.risk-assessor"

    data = build_dora_incident_event(
        incident_type="provider_unavailable",
        affected_service="agent:arsialabs.demo.payment-provider",
        started_at="2026-04-13T11:45:00.000Z",
        estimated_impact="3 transfers delayed; 1 failed",
        severity="high",
        original_payment_reference="pay-ref-mifid-001",
        resolved_at=None,
    )
    assert data["incident_type"] == "provider_unavailable"
    assert data["severity"] == "high"

    envelope = create_event(
        from_agent=sender,
        to_agent=recipient,
        payload_type=PAYLOAD_TYPE_DORA_INCIDENT,
        data=data,
        compliance={
            "profile": "MIFID-II",
            "data_residency": "EU",
            "retention_days": 1827,
        },
    )
    signed = sign_message(
        envelope,
        keypair_compliance_checker["private_key"],
        keypair_compliance_checker["kid"],
    )
    assert verify_message(signed, keypair_compliance_checker["public_key"]) is True
    assert validate_envelope(signed, strict=False) == []

    # The audit builder over an event envelope is the caller's concern;
    # we only assert that the round-trip produces a valid payload_hash
    # for the event data without mutating its fields.
    ph = compute_payload_hash(signed["payload"])
    assert len(ph) == 64  # SHA-256 hex

    # Sanity: resolved_at == None must remain null, not be dropped.
    assert signed["payload"]["data"]["resolved_at"] is None
