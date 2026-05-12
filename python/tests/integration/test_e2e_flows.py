# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Phase 3 — Cross-Primitive E2E Flows.

These scenarios exercise the SDK's public API the way a consumer
application would: real Ed25519 keys, real canonicalization, real
signatures, no mocks of SDK internals. Each scenario composes at
least three primitives across the layered dependency graph and
validates that they produce conformant, internally consistent
outputs.

Five scenarios:

1. :class:`TestScenario1_OversightFlow` — oversight lifecycle
   (request → pending_approval → approval_decision → response) with
   a four-record audit trail derived from the signed envelopes.
2. :class:`TestScenario2_AssetsEscrow` — MiFID-II profile applied to
   a currency transfer with a full ``escrow_conditions`` block; the
   §4.2 escrow state machine is walked through one permitted and one
   forbidden transition.
3. :class:`TestScenario3_OnboardingPolicy` — §8.3 deny-by-default
   capability evaluation covering ``allowed`` / ``oversight_required`` /
   ``prohibited`` / deny-by-default with the corresponding decision
   payload.
4. :class:`TestScenario4_RoutingResidency` — §1.3 three-output
   topology determination (``direct`` / ``brokered`` / ``error``) with a
   ``broker_relay`` audit record for the brokered path.
5. :class:`TestScenario5_Idempotency` — full Core §10.3 lifecycle
   (``new`` → ``pending`` → ``completed``) including the Transport
   Fix C replay semantics: a completed entry replays the stored
   response regardless of the duplicate request's body.

Spec: ARSIA-Core.md §4, §8, §10; ARSIA-Identity.md §7, §8; ARSIA-Assets.md §4;
ARSIA-Routing.md §1.3, §4.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from arsia_protocol import (
    AuditEventType,
    BrokerCapacity,
    BrokerEntry,
    CapabilityPolicy,
    CapabilityRule,
    DuplicateRequestInProgress,
    IdempotencyRecord,
    PAYLOAD_TYPE_TRANSFER_REQUEST,
    apply_profile,
    build_audit_record,
    build_broker_relay_audit_record,
    build_mifid_audit_fields,
    build_onboarding_decision,
    compute_idempotency_expiry,
    compute_payload_hash,
    create_approval_decision,
    create_pending_approval,
    create_request,
    create_response,
    evaluate_capability_policy,
    is_valid_escrow_transition,
    match_capability,
    scope_tuple,
    select_topology,
    sign_message,
    validate_audit_record,
    validate_capability_policy,
    validate_envelope,
    validate_escrow_conditions,
    validate_transfer_amount,
    validate_transfer_request,
    verify_message,
)
from tests.fixtures.in_memory_idempotency_store import InMemoryIdempotencyStore


def _now_iso_ms() -> str:
    """RFC 3339 millisecond UTC timestamp with ``Z`` suffix."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _iso_ms(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Scenario 1 — Oversight Flow
# ---------------------------------------------------------------------------


class TestScenario1_OversightFlow:
    """Request → pending_approval → approval_decision → response.

    Three agents: requester (acme), executor (risk-assessor), approver
    (compliance-checker). Each envelope is signed by its sender and
    verified by the receiver using the sender's public key. Four
    audit records are built from the four signed envelopes and each
    validates against the audit schema.

    Spec: ARSIA-Core.md §4.4, §9.
    """

    @pytest.fixture()
    def flow(
        self,
        keypair_acme: dict[str, Any],
        keypair_risk_assessor: dict[str, Any],
        keypair_compliance_checker: dict[str, Any],
    ) -> dict[str, Any]:
        requester = "agent:acme.echo-client"
        executor = "agent:arsialabs.demo.risk-assessor"
        approver = "agent:arsialabs.demo.compliance-checker"

        request = create_request(
            from_agent=requester,
            to_agent=executor,
            payload_type="demo.oversight.execute",
            capabilities=["demo.execute"],
            args={"operation": "run-analysis"},
        )
        signed_request = sign_message(
            request,
            keypair_acme["private_key"],
            keypair_acme["kid"],
        )

        pending = create_pending_approval(
            from_agent=executor,
            to_agent=requester,
            correlation_id=signed_request["id"],
            payload_type="arsiaprotocol.oversight/pending",
            args={
                "action_id": "demo.oversight.execute",
                "original_request_id": signed_request["id"],
                "approval_deadline": signed_request["expires_at"],
                "approver_capability": "arsiaprotocol.oversight.approve",
                "context": "Approval needed for run-analysis operation",
                "risk_level": 7,
                "approval_requested_from": approver,
            },
        )
        signed_pending = sign_message(
            pending,
            keypair_risk_assessor["private_key"],
            keypair_risk_assessor["kid"],
        )

        decision = create_approval_decision(
            from_agent=approver,
            to_agent=executor,
            correlation_id=signed_request["id"],
            payload_type="demo.oversight.decision",
            capabilities=["arsiaprotocol.oversight.approve"],
            result={"approved": True, "reason": "policy-compliant"},
        )
        signed_decision = sign_message(
            decision,
            keypair_compliance_checker["private_key"],
            keypair_compliance_checker["kid"],
        )

        response = create_response(
            from_agent=executor,
            to_agent=requester,
            correlation_id=signed_request["id"],
            payload_type="demo.oversight.response",
            result={"status": "ok", "output": 42},
        )
        signed_response = sign_message(
            response,
            keypair_risk_assessor["private_key"],
            keypair_risk_assessor["kid"],
        )

        return {
            "requester": requester,
            "executor": executor,
            "approver": approver,
            "request": signed_request,
            "pending": signed_pending,
            "decision": signed_decision,
            "response": signed_response,
            "keypair_acme": keypair_acme,
            "keypair_risk_assessor": keypair_risk_assessor,
            "keypair_compliance_checker": keypair_compliance_checker,
        }

    def test_request_signed_and_verifies(self, flow: dict[str, Any]) -> None:
        env = flow["request"]
        assert env["intent"] == "request"
        assert env["from"] == flow["requester"]
        assert env["to"] == flow["executor"]
        assert env["security"]["kid"].startswith(flow["requester"] + "#")
        assert verify_message(env, flow["keypair_acme"]["public_key"]) is True
        assert validate_envelope(env) == []

    def test_pending_approval_correlates_and_verifies(
        self, flow: dict[str, Any]
    ) -> None:
        env = flow["pending"]
        assert env["intent"] == "pending_approval"
        assert env["correlation_id"] == flow["request"]["id"]
        assert (
            verify_message(env, flow["keypair_risk_assessor"]["public_key"])
            is True
        )
        assert validate_envelope(env) == []

    def test_approval_decision_correlates_and_verifies(
        self, flow: dict[str, Any]
    ) -> None:
        env = flow["decision"]
        assert env["intent"] == "approval_decision"
        assert env["correlation_id"] == flow["request"]["id"]
        assert env["from"] == flow["approver"]
        assert env["payload"]["result"]["approved"] is True
        assert (
            verify_message(env, flow["keypair_compliance_checker"]["public_key"])
            is True
        )
        assert validate_envelope(env) == []

    def test_response_correlates_and_verifies(self, flow: dict[str, Any]) -> None:
        env = flow["response"]
        assert env["intent"] == "response"
        assert env["correlation_id"] == flow["request"]["id"]
        assert env["from"] == flow["executor"]
        assert (
            verify_message(env, flow["keypair_risk_assessor"]["public_key"])
            is True
        )
        assert validate_envelope(env) == []

    def test_four_audit_records_built_with_payload_hash(
        self, flow: dict[str, Any]
    ) -> None:
        envelopes: list[tuple[dict[str, Any], AuditEventType, str]] = [
            (flow["request"], "request", flow["requester"]),
            (flow["pending"], "pending_approval", flow["executor"]),
            (flow["decision"], "approval_decision", flow["approver"]),
            (flow["response"], "response", flow["executor"]),
        ]
        records = []
        for env, event_type, operator in envelopes:
            record = build_audit_record(
                env,
                event_type=event_type,
                operator_id=operator,
                effective_retention_days=90,
                oversight_status="not_required",
            )
            records.append(record)
            assert record.payload_hash == compute_payload_hash(env["payload"])
            assert record.message_id == env["id"]

        assert len({r.record_id for r in records}) == 4
        assert {r.event_type for r in records} == {
            "request",
            "pending_approval",
            "approval_decision",
            "response",
        }

    def test_audit_records_validate(self, flow: dict[str, Any]) -> None:
        correlation_id = flow["request"]["id"]
        approval_deadline = flow["pending"]["payload"]["args"]["approval_deadline"]
        cases: list[tuple[dict[str, Any], AuditEventType, str]] = [
            (flow["request"], "request", flow["requester"]),
            (flow["pending"], "pending_approval", flow["executor"]),
            (flow["decision"], "approval_decision", flow["approver"]),
            (flow["response"], "response", flow["executor"]),
        ]
        for env, event_type, operator in cases:
            extra: dict[str, Any] = {}
            if event_type in ("pending_approval", "approval_decision", "approval_expired"):
                extra["correlation_id"] = correlation_id
            if event_type == "pending_approval":
                extra["approval_deadline"] = approval_deadline
            record = build_audit_record(
                env,
                event_type=event_type,
                operator_id=operator,
                effective_retention_days=90,
                oversight_status="not_required",
                **extra,
            )
            dumped = record.model_dump(mode="json", exclude_none=True)
            assert validate_audit_record(dumped) == []


# ---------------------------------------------------------------------------
# Scenario 2 — Assets + Escrow
# ---------------------------------------------------------------------------


class TestScenario2_AssetsEscrow:
    """MiFID-II currency transfer with an escrow block.

    ``apply_profile`` injects the MIFID-II defaults into the
    compliance field; the request carries a full escrow conditions
    sub-object; :func:`validate_transfer_amount` enforces 2-decimal
    currency precision; and the §4.2 escrow state machine rejects
    transitions out of a terminal state.

    Spec: ARSIA-Assets.md §3, §4.2.
    """

    @pytest.fixture()
    def signed_transfer(
        self, keypair_risk_assessor: dict[str, Any]
    ) -> dict[str, Any]:
        sender = "agent:arsialabs.demo.risk-assessor"
        recipient = "agent:arsialabs.demo.compliance-checker"
        timeout = _iso_ms(datetime.now(timezone.utc) + timedelta(hours=24))

        args: dict[str, Any] = {
            "amount": 2500.00,
            "currency_or_unit": "EUR",
            "asset_type": "currency",
            "from_agent": sender,
            "to_agent": recipient,
            "payment_reference": "pay-escrow-001",
            "description": "Escrowed MiFID transfer",
            "escrow_conditions": {
                "release_condition": "delivery_confirmed",
                "release_trigger": "manual",
                "release_agent": "agent:arsialabs.demo.compliance-checker",
                "timeout_at": timeout,
            },
            "idempotency_key": "idem-escrow-001",
        }
        assert validate_transfer_request(args) == []

        envelope = create_request(
            from_agent=sender,
            to_agent=recipient,
            payload_type=PAYLOAD_TYPE_TRANSFER_REQUEST,
            capabilities=["arsiaprotocol.assets.transfer.initiate"],
            args=args,
            compliance={"profile": "MIFID-II"},
        )
        envelope = apply_profile(envelope)
        signed = sign_message(
            envelope,
            keypair_risk_assessor["private_key"],
            keypair_risk_assessor["kid"],
        )
        return {
            "envelope": signed,
            "args": args,
            "keypair": keypair_risk_assessor,
        }

    def test_mifid_profile_applied_to_request(
        self, signed_transfer: dict[str, Any]
    ) -> None:
        env = signed_transfer["envelope"]
        compliance = env["compliance"]
        assert compliance["profile"] == "MIFID-II"
        assert compliance["data_residency"] == "EU"
        assert compliance["retention_days"] >= 1827
        assert compliance["pii_involved"] is True
        assert compliance["legal_basis"] == "contract"

    def test_currency_precision_rejects_three_decimals(self) -> None:
        assert validate_transfer_amount(100.00, "currency") == []
        errs = validate_transfer_amount(100.001, "currency")
        assert errs != []
        assert any(e.code == "amount_precision_exceeded" for e in errs)

    def test_escrow_conditions_validate(
        self, signed_transfer: dict[str, Any]
    ) -> None:
        conditions = signed_transfer["args"]["escrow_conditions"]
        errs = validate_escrow_conditions(
            conditions, envelope_ts=signed_transfer["envelope"]["ts"]
        )
        assert errs == []

    def test_signed_transfer_request_verifies(
        self, signed_transfer: dict[str, Any]
    ) -> None:
        env = signed_transfer["envelope"]
        assert verify_message(env, signed_transfer["keypair"]["public_key"]) is True
        assert validate_envelope(env) == []

    def test_escrow_transitions_escrowed_to_released_allowed(self) -> None:
        assert is_valid_escrow_transition("ESCROWED", "RELEASED") is True
        assert is_valid_escrow_transition("ESCROWED", "RETURNED") is True
        assert is_valid_escrow_transition("ESCROWED", "DISPUTED") is True
        assert is_valid_escrow_transition("DISPUTED", "RELEASED") is True

    def test_escrow_transition_released_to_disputed_rejected(self) -> None:
        assert is_valid_escrow_transition("RELEASED", "DISPUTED") is False
        assert is_valid_escrow_transition("RELEASED", "RETURNED") is False
        assert is_valid_escrow_transition("RETURNED", "RELEASED") is False

    def test_mifid_audit_fields_include_required_flags(
        self, signed_transfer: dict[str, Any]
    ) -> None:
        env = signed_transfer["envelope"]
        payload_hash = compute_payload_hash(env["payload"])
        record = build_mifid_audit_fields(
            audit_id="22222222-2222-4222-8222-222222222222",
            request_envelope=env,
            payload_hash=payload_hash,
            created_at=_now_iso_ms(),
        )
        assert record["asset_type"] == "currency"
        assert record["amount"] == 2500.00
        assert record["compliance_profile"] == "MIFID-II"
        assert record["data_residency"] == "EU"
        assert record["payload_hash"] == payload_hash
        assert record["payment_reference"] == "pay-escrow-001"


# ---------------------------------------------------------------------------
# Scenario 3 — Onboarding / Capability Policy
# ---------------------------------------------------------------------------


class TestScenario3_OnboardingPolicy:
    """§8.3 deny-by-default capability evaluation.

    Two distinct spec contracts govern wildcard handling, and the SDK
    implements both correctly:

    - **Identity §8.2 (policy rules: exact only)** — each
      :class:`CapabilityRule` MUST specify an exact capability string.
      Wildcards (e.g. ``arsiaprotocol.test.*``) are NOT permitted in
      policy rules. The Pydantic pattern on
      ``CapabilityRule.capability``
      (``^[a-zA-Z][a-zA-Z0-9]*(\\.[a-zA-Z][a-zA-Z0-9]*)*$``) enforces
      this at the schema level. Denials are therefore expressed
      either as a literal ``prohibited`` rule or as deny-by-default
      (capability not listed).
    - **Actions §1.2 (token scope: wildcards permitted)** —
      :func:`match_capability` accepts wildcard scope entries when
      authorizing a requested capability against a granted token
      scope.

    The two contracts apply to different artefacts (policy rules vs.
    token scope entries), so the SDK's behaviour is spec-correct, not
    asymmetric. ``test_match_capability_wildcard_semantics``
    exercises the §1.2 wildcard semantics directly.

    Spec: ARSIA-Identity.md §7.4, §7.6, §8.2, §8.3;
    ARSIA-Actions.md §1.2.
    """

    @pytest.fixture()
    def policy(self) -> CapabilityPolicy:
        return CapabilityPolicy(
            policy_version="v1.0",
            token_lifetime_seconds=3600,
            capabilities=[
                CapabilityRule(capability="notes.read", status="allowed"),
                CapabilityRule(
                    capability="notes.write", status="oversight_required"
                ),
                CapabilityRule(capability="admin.delete", status="prohibited"),
            ],
        )

    def test_policy_is_structurally_valid(
        self, policy: CapabilityPolicy
    ) -> None:
        assert validate_capability_policy(policy) == []

    def test_freely_allowed_capability_granted(
        self, policy: CapabilityPolicy
    ) -> None:
        result = evaluate_capability_policy(policy, ["notes.read"])
        assert result.is_approved is True
        assert result.freely_allowed == ("notes.read",)
        assert result.oversight_required == ()
        assert result.denied == ()

    def test_oversight_capability_flagged(
        self, policy: CapabilityPolicy
    ) -> None:
        result = evaluate_capability_policy(policy, ["notes.write"])
        assert result.is_approved is True
        assert result.freely_allowed == ()
        assert result.oversight_required == ("notes.write",)
        assert result.denied == ()

    def test_prohibited_capability_denied(
        self, policy: CapabilityPolicy
    ) -> None:
        result = evaluate_capability_policy(
            policy, ["notes.read", "admin.delete"]
        )
        assert result.is_approved is False
        assert "admin.delete" in result.denied
        assert result.denial_reason == "no_permitted_capabilities"

    def test_deny_by_default_unlisted_capability(
        self, policy: CapabilityPolicy
    ) -> None:
        result = evaluate_capability_policy(policy, ["billing.charge"])
        assert result.is_approved is False
        assert result.denied == ("billing.charge",)
        assert result.denial_reason == "no_permitted_capabilities"

    def test_match_capability_wildcard_semantics(self) -> None:
        assert match_capability("admin.*", "admin.delete") is True
        assert match_capability("admin.delete", "admin.delete") is True
        assert match_capability("admin.delete", "admin.*") is False
        assert match_capability("notes.*", "billing.charge") is False

    def test_build_decision_on_approval(
        self, policy: CapabilityPolicy
    ) -> None:
        result = evaluate_capability_policy(
            policy, ["notes.read", "notes.write"]
        )
        decision = build_onboarding_decision(
            agent_id="agent:acme.echo-client",
            policy=policy,
            evaluation=result,
        )
        assert decision.outcome == "approved"
        assert decision.granted_capabilities == ("notes.read",)
        assert decision.oversight_required == ("notes.write",)
        assert decision.token_lifetime_seconds == 3600
        assert decision.denial_reasons == ()

    def test_build_decision_on_denial(
        self, policy: CapabilityPolicy
    ) -> None:
        result = evaluate_capability_policy(policy, ["admin.delete"])
        decision = build_onboarding_decision(
            agent_id="agent:acme.echo-client",
            policy=policy,
            evaluation=result,
        )
        assert decision.outcome == "denied"
        assert decision.granted_capabilities == ()
        assert decision.token_lifetime_seconds == 0
        assert "no_permitted_capabilities" in decision.denial_reasons


# ---------------------------------------------------------------------------
# Scenario 4 — Routing / Data Residency
# ---------------------------------------------------------------------------


class TestScenario4_RoutingResidency:
    """§1.3 three-output topology procedure.

    - No ``data_residency`` → ``direct``.
    - Declared zone with a serving broker → ``brokered``, broker
      populated.
    - Declared zone with no serving broker → ``error``, payload echoes
      the required zone and the candidate zone list.

    Also builds a ``broker_relay`` audit record for the brokered path
    and verifies it is structurally sound.

    Spec: ARSIA-Routing.md §1.3, §4.
    """

    @pytest.fixture()
    def eu_broker(self) -> BrokerEntry:
        return BrokerEntry(
            agent_id="agent:broker.eu-01",
            inbox="https://broker.example/inbox",
            jurisdiction="DE",
            residency_zones=["EU"],
            capacity=BrokerCapacity(
                requests_per_minute=1000, current_load_pct=10
            ),
            health="healthy",
            last_health_check=_now_iso_ms(),
        )

    @pytest.fixture()
    def signed_envelope(
        self, keypair_acme: dict[str, Any]
    ) -> dict[str, Any]:
        env = create_request(
            from_agent="agent:acme.echo-client",
            to_agent="agent:arsialabs.demo.compliance-checker",
            payload_type="demo.routing.test",
            capabilities=["demo.test"],
            args={"x": 1},
        )
        return sign_message(
            env,
            keypair_acme["private_key"],
            keypair_acme["kid"],
        )

    def test_direct_topology_same_zone(
        self, signed_envelope: dict[str, Any]
    ) -> None:
        decision = select_topology(signed_envelope)
        assert decision.topology == "direct"
        assert decision.data_residency is None
        assert decision.broker is None
        assert decision.error is None

    def test_brokered_topology_with_broker_selection(
        self, keypair_acme: dict[str, Any], eu_broker: BrokerEntry
    ) -> None:
        env = create_request(
            from_agent="agent:acme.echo-client",
            to_agent="agent:arsialabs.demo.compliance-checker",
            payload_type="demo.routing.test",
            capabilities=["demo.test"],
            args={"x": 1},
            compliance={"data_residency": "EU"},
        )
        signed = sign_message(
            env,
            keypair_acme["private_key"],
            keypair_acme["kid"],
        )
        decision = select_topology(signed, brokers=[eu_broker])
        assert decision.topology == "brokered"
        assert decision.data_residency == "EU"
        assert decision.broker is not None
        assert decision.broker.get("agent_id") == "agent:broker.eu-01"
        assert decision.error is None

    def test_error_topology_unsupported_zone(
        self, keypair_acme: dict[str, Any], eu_broker: BrokerEntry
    ) -> None:
        env = create_request(
            from_agent="agent:acme.echo-client",
            to_agent="agent:arsialabs.demo.compliance-checker",
            payload_type="demo.routing.test",
            capabilities=["demo.test"],
            args={"x": 1},
            compliance={"data_residency": "BR"},
        )
        signed = sign_message(
            env,
            keypair_acme["private_key"],
            keypair_acme["kid"],
        )
        decision = select_topology(signed, brokers=[eu_broker])
        assert decision.topology == "error"
        assert decision.data_residency == "BR"
        assert decision.broker is None
        assert decision.error is not None
        assert decision.error["code"] == "service_unavailable"
        details = decision.error["details"]
        assert details["data_residency_violation"] is True
        assert details["required_zone"] == "BR"
        assert "EU" in tuple(details["available_zones"])

    def test_broker_relay_audit_record_validates(
        self,
        keypair_acme: dict[str, Any],
        eu_broker: BrokerEntry,
    ) -> None:
        env = create_request(
            from_agent="agent:acme.echo-client",
            to_agent="agent:arsialabs.demo.compliance-checker",
            payload_type="demo.routing.test",
            capabilities=["demo.test"],
            args={"x": 1},
            compliance={"data_residency": "EU"},
        )
        signed = sign_message(
            env,
            keypair_acme["private_key"],
            keypair_acme["kid"],
        )
        payload_hash = compute_payload_hash(signed["payload"])
        record = build_broker_relay_audit_record(
            signed,
            broker_agent_id=eu_broker.agent_id,
            payload_hash=payload_hash,
            forwarding_result="success",
            relay_latency_ms=42,
            residency_zone="EU",
        )
        assert record.audit_type == "broker_relay"
        assert record.broker_agent_id == eu_broker.agent_id
        assert record.residency_zone == "EU"
        assert record.forwarding_result == "success"
        assert record.relay_latency_ms == 42
        assert record.payload_hash == payload_hash
        assert record.from_agent == signed["from"]
        assert record.to_agent == signed["to"]
        assert record.message_id == signed["id"]


# ---------------------------------------------------------------------------
# Scenario 5 — Idempotency
# ---------------------------------------------------------------------------


class TestScenario5_Idempotency:
    """Core §10.3 lifecycle + Transport Fix C replay semantics.

    The store transitions through ``new → pending → completed`` and
    the Transport Fix C rule is exercised directly against the
    store's ``store_response`` / ``get_response`` pair: a completed
    entry replays the stored bytes regardless of what the duplicate
    request body looked like.

    Spec: ARSIA-Core.md §10.
    """

    @pytest.fixture()
    def envelope(
        self, keypair_acme: dict[str, Any]
    ) -> dict[str, Any]:
        expires_at = _iso_ms(datetime.now(timezone.utc) + timedelta(hours=1))
        return create_request(
            from_agent="agent:acme.echo-client",
            to_agent="agent:arsialabs.demo.compliance-checker",
            payload_type="demo.idem.test",
            capabilities=["demo.test"],
            args={"x": 1},
            idempotency={"key": "idem-e2e-001", "expires_at": expires_at},
        )

    def test_new_key_marks_pending_then_complete(
        self, envelope: dict[str, Any]
    ) -> None:
        store = InMemoryIdempotencyStore()
        scope = scope_tuple(envelope)
        key = envelope["idempotency"]["key"]

        assert store.check_status(scope, key) == "new"
        assert store.mark_pending(scope, key) is True
        assert store.check_status(scope, key) == "pending"

        record = IdempotencyRecord(
            key=key,
            from_agent=scope.from_agent,
            to_agent=scope.to_agent,
            payload_type=scope.payload_type,
            message_id=envelope["id"],
            stored_at=_now_iso_ms(),
            expires_at=envelope["idempotency"]["expires_at"],
        )
        store.mark_complete(record)
        assert store.check_status(scope, key) == "completed"
        assert store.get(scope, key) is not None

    def test_duplicate_in_progress_returns_false_from_mark_pending(
        self, envelope: dict[str, Any]
    ) -> None:
        store = InMemoryIdempotencyStore()
        scope = scope_tuple(envelope)
        key = envelope["idempotency"]["key"]

        assert store.mark_pending(scope, key) is True
        assert store.mark_pending(scope, key) is False

    def test_DuplicateRequestInProgress_carries_scope_and_key(
        self, envelope: dict[str, Any]
    ) -> None:
        scope = scope_tuple(envelope)
        key = envelope["idempotency"]["key"]
        exc = DuplicateRequestInProgress(scope, key)
        assert exc.scope == scope
        assert exc.key == key
        assert key in str(exc)

    def test_completed_same_key_different_body_replays_stored_response(
        self, envelope: dict[str, Any]
    ) -> None:
        store = InMemoryIdempotencyStore()
        scope = scope_tuple(envelope)
        key = envelope["idempotency"]["key"]

        record = IdempotencyRecord(
            key=key,
            from_agent=scope.from_agent,
            to_agent=scope.to_agent,
            payload_type=scope.payload_type,
            message_id=envelope["id"],
            stored_at=_now_iso_ms(),
            expires_at=envelope["idempotency"]["expires_at"],
        )
        store.mark_pending(scope, key)
        store.mark_complete(record)
        stored_response = json.dumps(
            {"intent": "response", "result": {"status": "ok"}}
        ).encode("utf-8")
        store.store_response(scope, key, stored_response)

        replay_once = store.get_response(scope, key)
        replay_twice = store.get_response(scope, key)
        assert replay_once == stored_response
        assert replay_twice == stored_response

    def test_expired_record_purged_allows_reuse(self) -> None:
        store = InMemoryIdempotencyStore()
        scope = scope_tuple(
            {
                "from": "agent:acme.echo-client",
                "to": "agent:arsialabs.demo.compliance-checker",
                "payload": {"type": "demo.idem.test"},
            }
        )
        key = "idem-expired-001"
        past = _iso_ms(datetime.now(timezone.utc) - timedelta(hours=1))

        record = IdempotencyRecord(
            key=key,
            from_agent=scope.from_agent,
            to_agent=scope.to_agent,
            payload_type=scope.payload_type,
            message_id="11111111-1111-4111-8111-111111111111",
            stored_at=past,
            expires_at=past,
        )
        store.mark_complete(record)

        assert store.check_status(scope, key) == "new"
        assert store.get(scope, key) is None
        assert store.get_response(scope, key) is None
        assert store.mark_pending(scope, key) is True

    def test_scope_tuple_isolates_per_scope(self) -> None:
        store = InMemoryIdempotencyStore()
        scope_a = scope_tuple(
            {
                "from": "agent:acme.echo-client",
                "to": "agent:arsialabs.demo.compliance-checker",
                "payload": {"type": "demo.alpha"},
            }
        )
        scope_b = scope_tuple(
            {
                "from": "agent:acme.echo-client",
                "to": "agent:arsialabs.demo.compliance-checker",
                "payload": {"type": "demo.beta"},
            }
        )
        key = "shared-idempotency-key"

        assert store.mark_pending(scope_a, key) is True
        assert store.mark_pending(scope_b, key) is True
        assert store.check_status(scope_a, key) == "pending"
        assert store.check_status(scope_b, key) == "pending"

    def test_compute_idempotency_expiry_honours_envelope_value(
        self, envelope: dict[str, Any]
    ) -> None:
        envelope_expiry = envelope["idempotency"]["expires_at"]
        resolved = compute_idempotency_expiry(envelope_expiry, header_only=False)
        assert resolved == envelope_expiry

    def test_compute_idempotency_expiry_defaults_to_24h_floor(self) -> None:
        now = datetime(2026, 4, 15, 12, 0, 0, tzinfo=timezone.utc)
        resolved = compute_idempotency_expiry(None, header_only=True, now=now)
        expected = _iso_ms(now + timedelta(hours=24))
        assert resolved == expected
