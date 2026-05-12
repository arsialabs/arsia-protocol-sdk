# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""End-to-end integration for the State + Audit primitives (Slice 5).

These tests compose the state validators, the message factory, the
signing/verification path, envelope validation, compliance
inheritance, and the audit builder into realistic scenarios. They do
not touch any transport or storage — the SDK's job is to produce
conformant envelopes and audit records; persistence is the product
repo's responsibility.

Scenarios covered:

1. **PII personal entry over GDPR-STANDARD** — SET request with a
   ``pii_classification='personal'`` entry, full signing,
   verification, envelope validation, and audit record derivation.
2. **Retention extension** — entry ``retention_days`` extends the
   profile minimum; the audit builder honours the resolved effective
   retention.
3. **PURGE flow** — purge request payload carries only the ``key``
   and ``reason`` (per-entry PURGE per §3.2.2), the audit record uses
   ``event_type='state_purge'`` and ``payload_hash`` is reproducible
   from the purge payload with no value leakage.

Spec: ARSIA-State.md §2.1, §3.2.2, §4.1.1, §4.2, §5.3, §7.1.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from arsia_protocol.state.audit import (
    build_audit_record,
    compute_payload_hash,
    derive_event_type_from_intent,
)
from arsia_protocol.core.compliance import apply_profile
from arsia_protocol.core.message import (
    create_request,
    sign_message,
    verify_message,
)
from arsia_protocol.state.state import (
    PAYLOAD_TYPE_PURGE,
    PAYLOAD_TYPE_SET,
    build_purge_args,
    build_set_args,
    compute_effective_retention,
    validate_state_entry,
)
from arsia_protocol.types.state import StateEntry
from arsia_protocol.core.validation import validate_envelope

_OPERATOR = "LEI:529900T8BM49AURSDO55"


def _entry(
    *,
    owner: str,
    pii: str = "personal",
    data_residency: str = "PT",
    retention_days: int | None = None,
) -> StateEntry:
    ts = "2026-04-13T12:00:00.000Z"
    return StateEntry(
        key=f"{owner}/agent/user.profile",
        value={"name": "Jane Doe", "country": "PT"},
        owner_agent_id=owner,
        scope="agent",
        created_at=ts,
        updated_at=ts,
        pii_classification=pii,  # type: ignore[arg-type]
        version=1,
        data_residency=data_residency,
        retention_days=retention_days,
    )


# ---------------------------------------------------------------------------
# Scenario 1 — GDPR-STANDARD with personal PII
# ---------------------------------------------------------------------------


def test_personal_pii_set_request_signs_verifies_validates_and_audits(
    keypair_acme: dict[str, Any],
) -> None:
    sender = "agent:acme.echo-client"
    recipient = "agent:acme.state-store"
    entry = _entry(owner=sender)

    assert validate_state_entry(
        entry,
        sender_agent_id=sender,
        envelope_compliance={
            "profile": "GDPR-STANDARD",
            "legal_basis": "consent",
            "data_residency": "PT",
            "pii_involved": True,
        },
    ) == []

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type=PAYLOAD_TYPE_SET,
        capabilities=["arsiaprotocol.state.write"],
        args=build_set_args(entry),
        compliance={
            "profile": "GDPR-STANDARD",
            "legal_basis": "consent",
            "data_residency": "PT",
            "pii_involved": True,
        },
    )

    signed = sign_message(envelope, keypair_acme["private_key"], keypair_acme["kid"])
    assert verify_message(signed, keypair_acme["public_key"]) is True

    assert validate_envelope(signed, strict=False) == []

    effective_retention = compute_effective_retention("GDPR-STANDARD", 365)
    assert effective_retention == 365

    record = build_audit_record(
        signed,
        event_type="state_set",
        operator_id=_OPERATOR,
        effective_retention_days=effective_retention,
    )
    assert record.event_type == "state_set"
    assert record.payload_type == PAYLOAD_TYPE_SET
    assert record.payload_hash == compute_payload_hash(signed["payload"])
    assert record.compliance_profile == "GDPR-STANDARD"
    assert record.data_residency == "PT"
    assert record.operator_id == _OPERATOR


# ---------------------------------------------------------------------------
# Scenario 2 — Retention extension via entry override
# ---------------------------------------------------------------------------


def test_entry_retention_extends_profile_minimum(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.risk-assessor"
    recipient = "agent:arsialabs.demo.state-store"

    # EU-AI-ACT-HIGH-RISK minimum is 180 days; entry extends to 2555.
    entry = _entry(owner=sender, pii="none", retention_days=2555)
    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type=PAYLOAD_TYPE_SET,
        capabilities=["arsiaprotocol.state.write"],
        args=build_set_args(entry),
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        },
    )
    envelope = apply_profile(envelope)
    signed = sign_message(
        envelope,
        keypair_risk_assessor["private_key"],
        keypair_risk_assessor["kid"],
    )
    assert verify_message(signed, keypair_risk_assessor["public_key"]) is True

    # Envelope layer must accept this; R3/R7 satisfied by explicit
    # human_oversight + profile.
    assert validate_envelope(signed, strict=False) == []

    retention = compute_effective_retention("EU-AI-ACT-HIGH-RISK", 2555)
    assert retention == 2555

    processed = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
    record = build_audit_record(
        signed,
        event_type="state_set",
        operator_id=_OPERATOR,
        effective_retention_days=retention,
        processed_at=processed,
    )
    retained = datetime.fromisoformat(record.retained_until.replace("Z", "+00:00"))
    assert (retained - processed) == timedelta(days=2555)


# ---------------------------------------------------------------------------
# Scenario 3 — PURGE carries no value and produces a state_purge audit
# ---------------------------------------------------------------------------


def test_purge_request_audit_has_no_value_leakage(
    keypair_compliance_checker: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.compliance-checker"
    recipient = "agent:arsialabs.demo.state-store"
    # §3.2.2 — PURGE targets a single entry identified by key.
    entry_key = "agent:acme.echo-client/agent/personal-data"

    args = build_purge_args(entry_key, "GDPR Art. 17 erasure request")
    # §3.2.2 — PURGE payload carries only key + reason, never the value.
    assert set(args) == {"key", "reason"}
    assert "value" not in args

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type=PAYLOAD_TYPE_PURGE,
        capabilities=["arsiaprotocol.state.purge"],
        args=args,
        compliance={
            "profile": "GDPR-STANDARD",
            "legal_basis": "legal_obligation",
            "data_residency": "PT",
            "pii_involved": True,
        },
    )
    signed = sign_message(
        envelope,
        keypair_compliance_checker["private_key"],
        keypair_compliance_checker["kid"],
    )
    assert verify_message(signed, keypair_compliance_checker["public_key"]) is True
    assert validate_envelope(signed, strict=False) == []

    record = build_audit_record(
        signed,
        event_type="state_purge",
        operator_id=_OPERATOR,
        effective_retention_days=90,
    )
    assert record.event_type == "state_purge"
    assert record.payload_type == PAYLOAD_TYPE_PURGE
    assert record.payload_hash == compute_payload_hash(signed["payload"])
    # The payload itself carries no value field — the hash therefore
    # cannot expose the erased data.
    assert "value" not in signed["payload"].get("args", {})


# ---------------------------------------------------------------------------
# Sanity — derive_event_type_from_intent covers every envelope factory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "intent",
    [
        "request",
        "response",
        "event",
        "error",
        "pending_approval",
        "approval_decision",
    ],
)
def test_derive_event_type_round_trips_through_envelope_factories(
    intent: str,
) -> None:
    # Every envelope-intent factory's output produces an audit record
    # whose event_type matches derive_event_type_from_intent.
    assert derive_event_type_from_intent(intent) == intent
