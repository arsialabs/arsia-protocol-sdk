# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Integration tests for action flows — cross-module compositions.

These tests exercise actions.py in combination with message, audit,
validation, and compliance modules. Each test class covers a distinct
action flow that is NOT covered by test_e2e_flows.py (which covers
the oversight lifecycle: request → pending_approval → approval_decision
→ response with audit records).

Flows covered here:

1. :class:`TestRollbackFlow` — request → response → rollback request
   with validation guards, audit records, and partial rollback.
2. :class:`TestCapabilityDowngradeFlow` — capability matching,
   downgrade, and effective_capabilities attachment on a signed
   response envelope.
3. :class:`TestRiskClassificationEscalation` — descriptor validation
   cross-checked with risk classification and compliance profile.
4. :class:`TestTimeoutFlow` — executing action timeout detection,
   timeout error envelope, and partial execution audit.
5. :class:`TestExplanationEnforcement` — explanation required by
   descriptor and/or compliance, validated in response context with
   timestamp invariant.
6. :class:`TestVersionNegotiation` — version resolution, major bump
   detection, and not-supported error envelope.

Spec: ARSIA-Actions.md §1–§5; ARSIA-Core.md §4, §11; ARSIA-State.md §7.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from arsia_protocol import (
    build_audit_record,
    compute_payload_hash,
    create_request,
    create_response,
    sign_message,
    validate_audit_record,
    validate_envelope,
    verify_message,
)
from arsia_protocol.actions.actions import (
    attach_effective_capabilities,
    build_partial_execution_audit,
    build_partial_rollback_response,
    build_rollback_audit_record,
    build_timeout_error,
    is_explanation_required,
    create_rollback_request,
    build_version_not_supported_error,
    downgrade_capabilities,
    find_unsatisfied_capabilities,
    get_risk_classification,
    is_major_version_bump,
    is_terminal_state,
    is_valid_transition,
    match_capabilities,
    resolve_action_version,
    validate_action_descriptor,
    validate_explanation,
    validate_explanation_timestamp,
    validate_response_explanation,
    validate_rollback,
    validate_timeout_cancellation,
)


def _iso_ms(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _minimal_descriptor(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "action_id": "com.example.notes/write",
        "category": "data",
        "description": "Write notes owned by the requesting agent.",
        "risk_level": 2,
        "reversible": True,
        "idempotent": False,
        "required_capabilities": ["notes.write"],
        "human_oversight_required": False,
        "audit_required": False,
        "explainability_required": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Flow 1 — Rollback
# ---------------------------------------------------------------------------


class TestRollbackFlow:
    """Request → response → rollback request with audit trail.

    Exercises create_rollback_request composing with message.create_request,
    validate_rollback guards, build_rollback_audit_record, and
    build_partial_rollback_response.

    Spec: ARSIA-Actions.md §4.1, §4.2.
    """

    @pytest.fixture()
    def completed_action(
        self,
        keypair_acme: dict[str, Any],
        keypair_risk_assessor: dict[str, Any],
    ) -> dict[str, Any]:
        requester = "agent:acme.echo-client"
        executor = "agent:arsialabs.demo.risk-assessor"

        request = create_request(
            from_agent=requester,
            to_agent=executor,
            payload_type="com.example.notes/write",
            capabilities=["notes.write"],
            args={"content": "hello world"},
        )
        signed_request = sign_message(
            request,
            keypair_acme["private_key"],
            keypair_acme["kid"],
        )

        response = create_response(
            from_agent=executor,
            to_agent=requester,
            correlation_id=signed_request["id"],
            payload_type="com.example.notes/write",
            result={"status": "ok", "note_id": "note-42"},
        )
        signed_response = sign_message(
            response,
            keypair_risk_assessor["private_key"],
            keypair_risk_assessor["kid"],
        )

        completed_at = datetime.now(timezone.utc)

        return {
            "requester": requester,
            "executor": executor,
            "request": signed_request,
            "response": signed_response,
            "completed_at": completed_at,
            "keypair_acme": keypair_acme,
            "keypair_risk_assessor": keypair_risk_assessor,
            "descriptor": _minimal_descriptor(),
        }

    def test_rollback_request_correlates_with_original(
        self, completed_action: dict[str, Any]
    ) -> None:
        original_request = completed_action["request"]
        rollback = create_rollback_request(
            from_agent=completed_action["requester"],
            to_agent=completed_action["executor"],
            original_action_id="com.example.notes/write",
            original_message_id=original_request["id"],
            capabilities=["notes.write"],
        )
        signed_rollback = sign_message(
            rollback,
            completed_action["keypair_acme"]["private_key"],
            completed_action["keypair_acme"]["kid"],
        )
        assert signed_rollback["intent"] == "request"
        assert signed_rollback["payload"]["type"] == "com.example.notes/write/rollback"
        assert signed_rollback["payload"]["args"]["original_message_id"] == original_request["id"]
        assert validate_envelope(signed_rollback) == []

    def test_rollback_request_signs_and_verifies(
        self, completed_action: dict[str, Any]
    ) -> None:
        rollback = create_rollback_request(
            from_agent=completed_action["requester"],
            to_agent=completed_action["executor"],
            original_action_id="com.example.notes/write",
            original_message_id=completed_action["request"]["id"],
            capabilities=["notes.write"],
        )
        signed = sign_message(
            rollback,
            completed_action["keypair_acme"]["private_key"],
            completed_action["keypair_acme"]["kid"],
        )
        assert verify_message(signed, completed_action["keypair_acme"]["public_key"]) is True
        assert validate_envelope(signed) == []

    def test_validate_rollback_allows_within_window(
        self, completed_action: dict[str, Any]
    ) -> None:
        now = completed_action["completed_at"] + timedelta(seconds=60)
        result = validate_rollback(
            descriptor=completed_action["descriptor"],
            current_state="completed",
            rollback_window_seconds=300,
            completed_at=completed_action["completed_at"],
            now=now,
        )
        assert result is None

    def test_validate_rollback_rejects_expired_window(
        self, completed_action: dict[str, Any]
    ) -> None:
        now = completed_action["completed_at"] + timedelta(seconds=600)
        result = validate_rollback(
            descriptor=completed_action["descriptor"],
            current_state="completed",
            rollback_window_seconds=300,
            completed_at=completed_action["completed_at"],
            now=now,
        )
        assert result is not None
        assert result["code"] == "conflict"
        assert result["details"]["rollback_window_exceeded"] is True

    def test_validate_rollback_rejects_non_reversible(self) -> None:
        descriptor = _minimal_descriptor(reversible=False)
        result = validate_rollback(
            descriptor=descriptor,
            current_state="completed",
        )
        assert result is not None
        assert result["code"] == "not_implemented"

    def test_state_transitions_through_rollback_path(self) -> None:
        assert is_valid_transition("requested", "executing") is True
        assert is_valid_transition("executing", "completed") is True
        assert is_valid_transition("completed", "rolled_back") is True
        assert is_terminal_state("rolled_back") is True
        assert is_valid_transition("rolled_back", "completed") is False

    def test_rollback_audit_record_chain(
        self, completed_action: dict[str, Any]
    ) -> None:
        original_request = completed_action["request"]
        rollback = create_rollback_request(
            from_agent=completed_action["requester"],
            to_agent=completed_action["executor"],
            original_action_id="com.example.notes/write",
            original_message_id=original_request["id"],
            capabilities=["notes.write"],
        )
        signed_rollback = sign_message(
            rollback,
            completed_action["keypair_acme"]["private_key"],
            completed_action["keypair_acme"]["kid"],
        )

        request_audit = build_audit_record(
            original_request,
            event_type="request",
            operator_id=completed_action["requester"],
            effective_retention_days=90,
            oversight_status="not_required",
        )
        rollback_audit = build_audit_record(
            signed_rollback,
            event_type="request",
            operator_id=completed_action["requester"],
            effective_retention_days=90,
            oversight_status="not_required",
        )

        assert request_audit.record_id != rollback_audit.record_id
        assert request_audit.message_id == original_request["id"]
        assert rollback_audit.message_id == signed_rollback["id"]
        assert rollback_audit.payload_type == "com.example.notes/write/rollback"

        for rec in [request_audit, rollback_audit]:
            dumped = rec.model_dump(mode="json", exclude_none=True)
            assert validate_audit_record(dumped) == []

        rollback_action_record = build_rollback_audit_record(
            original_message_id=original_request["id"],
            original_action_id="com.example.notes/write",
            rollback_message_id=signed_rollback["id"],
            timestamp=_iso_ms(datetime.now(timezone.utc)),
            full_rollback=True,
        )
        assert rollback_action_record["event_type"] == "rollback"
        assert rollback_action_record["original_message_id"] == original_request["id"]
        assert rollback_action_record["full_rollback"] is True

    def test_partial_rollback_response_shape(self) -> None:
        partial = build_partial_rollback_response(
            rolled_back=["note-42 content reverted"],
            not_rolled_back=["notification-sent event already delivered"],
        )
        assert partial["partial_rollback"] is True
        assert len(partial["rolled_back"]) == 1
        assert len(partial["not_rolled_back"]) == 1

    def test_partial_rollback_audit_record_marks_not_full(
        self, completed_action: dict[str, Any]
    ) -> None:
        record = build_rollback_audit_record(
            original_message_id=completed_action["request"]["id"],
            original_action_id="com.example.notes/write",
            rollback_message_id="22222222-2222-4222-8222-222222222222",
            timestamp=_iso_ms(datetime.now(timezone.utc)),
            full_rollback=False,
        )
        assert record["full_rollback"] is False


# ---------------------------------------------------------------------------
# Flow 2 — Capability Downgrade
# ---------------------------------------------------------------------------


class TestCapabilityDowngradeFlow:
    """Capability evaluation → downgrade → attach to signed response.

    Exercises match_capabilities, find_unsatisfied_capabilities,
    downgrade_capabilities, and attach_effective_capabilities composing
    with message.create_response + sign_message.

    Spec: ARSIA-Actions.md §1.2, §1.3.
    """

    def test_full_scope_match_no_downgrade_needed(self) -> None:
        scope = ["notes.read", "notes.write", "notes.delete"]
        requested = ["notes.read", "notes.write"]
        assert match_capabilities(scope, requested) is True
        assert find_unsatisfied_capabilities(scope, requested) == []

    def test_partial_scope_triggers_downgrade(self) -> None:
        scope = ["notes.read", "notes.write"]
        requested = ["notes.read", "notes.write", "notes.delete"]
        assert match_capabilities(scope, requested) is False
        unsatisfied = find_unsatisfied_capabilities(scope, requested)
        assert unsatisfied == ["notes.delete"]

        effective = downgrade_capabilities(requested, scope)
        assert effective == ["notes.read", "notes.write"]

    def test_downgraded_response_envelope_with_effective_capabilities(
        self,
        keypair_risk_assessor: dict[str, Any],
    ) -> None:
        scope = ["notes.read"]
        requested = ["notes.read", "notes.write"]
        effective = downgrade_capabilities(requested, scope)
        assert effective == ["notes.read"]

        response = create_response(
            from_agent="agent:arsialabs.demo.risk-assessor",
            to_agent="agent:acme.echo-client",
            correlation_id="11111111-1111-4111-8111-111111111111",
            payload_type="com.example.notes/read",
            result={"note": "hello world"},
        )
        response_with_caps = attach_effective_capabilities(response, effective)
        assert response_with_caps["payload"]["result"]["effective_capabilities"] == [
            "notes.read"
        ]
        assert "effective_capabilities" not in response["payload"].get("result", {})

        signed = sign_message(
            response_with_caps,
            keypair_risk_assessor["private_key"],
            keypair_risk_assessor["kid"],
        )
        assert verify_message(signed, keypair_risk_assessor["public_key"]) is True
        assert validate_envelope(signed) == []
        assert signed["payload"]["result"]["effective_capabilities"] == ["notes.read"]

    def test_wildcard_scope_covers_all_requested(self) -> None:
        scope = ["notes.*"]
        requested = ["notes.read", "notes.write", "notes.admin.reset"]
        assert match_capabilities(scope, requested) is True
        effective = downgrade_capabilities(requested, scope)
        assert effective == requested

    def test_zero_overlap_downgrade_raises_for_forbidden_error(self) -> None:
        scope = ["payments.charge"]
        requested = ["notes.read", "notes.write"]
        with pytest.raises(ValueError, match="§1.3 rule 3"):
            downgrade_capabilities(requested, scope)
        unsatisfied = find_unsatisfied_capabilities(scope, requested)
        assert unsatisfied == ["notes.read", "notes.write"]


# ---------------------------------------------------------------------------
# Flow 3 — Risk Classification Escalation
# ---------------------------------------------------------------------------


class TestRiskClassificationEscalation:
    """Descriptor risk level → classification → flag enforcement.

    Exercises get_risk_classification + validate_action_descriptor
    cross-field rules, verifying that high/critical descriptors
    require the correct boolean flags.

    Spec: ARSIA-Actions.md §2.2.
    """

    def test_minimal_risk_descriptor_valid(self) -> None:
        descriptor = _minimal_descriptor(risk_level=1)
        assert validate_action_descriptor(descriptor) == []
        assert get_risk_classification(1) == "minimal-risk"

    def test_elevated_risk_requires_audit(self) -> None:
        descriptor = _minimal_descriptor(risk_level=5, audit_required=False)
        errors = validate_action_descriptor(descriptor)
        assert any("audit_required" in e.message for e in errors)
        assert get_risk_classification(5) == "elevated-risk"

    def test_high_risk_requires_audit_and_explainability(self) -> None:
        descriptor = _minimal_descriptor(
            risk_level=7,
            audit_required=False,
            explainability_required=False,
        )
        errors = validate_action_descriptor(descriptor)
        audit_errors = [e for e in errors if "audit_required" in e.message]
        explain_errors = [e for e in errors if "explainability_required" in e.message]
        assert len(audit_errors) == 1
        assert len(explain_errors) == 1
        assert get_risk_classification(7) == "high-risk"

    def test_critical_risk_requires_all_three_flags(self) -> None:
        descriptor = _minimal_descriptor(
            risk_level=9,
            audit_required=True,
            explainability_required=True,
            human_oversight_required=False,
        )
        errors = validate_action_descriptor(descriptor)
        assert any("human_oversight_required" in e.message for e in errors)
        assert get_risk_classification(9) == "critical-risk"

    def test_critical_risk_descriptor_with_all_flags_passes(self) -> None:
        descriptor = _minimal_descriptor(
            risk_level=10,
            audit_required=True,
            explainability_required=True,
            human_oversight_required=True,
        )
        assert validate_action_descriptor(descriptor) == []
        assert get_risk_classification(10) == "critical-risk"

    def test_classification_covers_full_range(self) -> None:
        expected = {
            0: "minimal-risk",
            1: "minimal-risk",
            2: "minimal-risk",
            3: "limited-risk",
            4: "limited-risk",
            5: "elevated-risk",
            6: "elevated-risk",
            7: "high-risk",
            8: "high-risk",
            9: "critical-risk",
            10: "critical-risk",
        }
        for level, classification in expected.items():
            assert get_risk_classification(level) == classification


# ---------------------------------------------------------------------------
# Flow 4 — Timeout
# ---------------------------------------------------------------------------


class TestTimeoutFlow:
    """Executing action → timeout detected → error + partial audit.

    Exercises validate_timeout_cancellation, build_timeout_error, and
    build_partial_execution_audit composing with signed envelopes and
    audit validation.

    Spec: ARSIA-Actions.md §4.3.
    """

    @pytest.fixture()
    def executing_action(
        self,
        keypair_acme: dict[str, Any],
    ) -> dict[str, Any]:
        requester = "agent:acme.echo-client"
        executor = "agent:arsialabs.demo.risk-assessor"
        started_at = datetime(2026, 4, 15, 12, 0, 0, tzinfo=timezone.utc)

        request = create_request(
            from_agent=requester,
            to_agent=executor,
            payload_type="com.example.analysis/run",
            capabilities=["analysis.run"],
            args={"dataset": "quarterly-report"},
        )
        signed_request = sign_message(
            request,
            keypair_acme["private_key"],
            keypair_acme["kid"],
        )
        return {
            "requester": requester,
            "executor": executor,
            "request": signed_request,
            "started_at": started_at,
            "max_execution_ms": 30000,
        }

    def test_timeout_not_exceeded(self, executing_action: dict[str, Any]) -> None:
        now = executing_action["started_at"] + timedelta(milliseconds=15000)
        assert validate_timeout_cancellation(
            current_state="executing",
            max_execution_ms=executing_action["max_execution_ms"],
            started_at=executing_action["started_at"],
            now=now,
        ) is False

    def test_timeout_exceeded(self, executing_action: dict[str, Any]) -> None:
        now = executing_action["started_at"] + timedelta(milliseconds=31000)
        assert validate_timeout_cancellation(
            current_state="executing",
            max_execution_ms=executing_action["max_execution_ms"],
            started_at=executing_action["started_at"],
            now=now,
        ) is True

    def test_timeout_error_envelope_validates(
        self, executing_action: dict[str, Any]
    ) -> None:
        error_env = build_timeout_error(
            from_agent=executing_action["executor"],
            to_agent=executing_action["requester"],
            correlation_id=executing_action["request"]["id"],
            action_id="com.example.analysis/run",
            timeout_ms=executing_action["max_execution_ms"],
        )
        assert error_env["intent"] == "error"
        assert error_env["correlation_id"] == executing_action["request"]["id"]
        assert error_env["payload"]["error"]["code"] == "service_unavailable"
        assert error_env["payload"]["error"]["description"] == "Action execution timeout"
        assert error_env["payload"]["error"]["details"]["timeout_ms"] == 30000
        assert validate_envelope(error_env) == []

    def test_timeout_error_audit_record_validates(
        self, executing_action: dict[str, Any]
    ) -> None:
        error_env = build_timeout_error(
            from_agent=executing_action["executor"],
            to_agent=executing_action["requester"],
            correlation_id=executing_action["request"]["id"],
            action_id="com.example.analysis/run",
            timeout_ms=executing_action["max_execution_ms"],
        )
        audit = build_audit_record(
            error_env,
            event_type="error",
            operator_id=executing_action["executor"],
            effective_retention_days=90,
        )
        dumped = audit.model_dump(mode="json", exclude_none=True)
        assert validate_audit_record(dumped) == []
        assert audit.event_type == "error"
        assert audit.payload_hash == compute_payload_hash(error_env["payload"])

    def test_partial_execution_audit_after_timeout(
        self, executing_action: dict[str, Any]
    ) -> None:
        now = _iso_ms(datetime.now(timezone.utc))
        record = build_partial_execution_audit(
            message_id=executing_action["request"]["id"],
            action_id="com.example.analysis/run",
            timestamp=now,
            partial_results={"rows_processed": 500, "total_rows": 10000},
            reason="timeout",
        )
        assert record["event_type"] == "partial_execution"
        assert record["message_id"] == executing_action["request"]["id"]
        assert record["action_id"] == "com.example.analysis/run"
        assert record["reason"] == "timeout"
        assert record["partial_results"]["rows_processed"] == 500

    def test_timeout_only_applies_to_executing_state(
        self, executing_action: dict[str, Any]
    ) -> None:
        now = executing_action["started_at"] + timedelta(milliseconds=60000)
        for state in ["requested", "pending_approval", "completed", "failed", "rolled_back"]:
            assert validate_timeout_cancellation(
                current_state=state,
                max_execution_ms=executing_action["max_execution_ms"],
                started_at=executing_action["started_at"],
                now=now,
            ) is False


# ---------------------------------------------------------------------------
# Flow 5 — Explanation Enforcement
# ---------------------------------------------------------------------------


class TestExplanationEnforcement:
    """Response must include explanation when descriptor or compliance requires it.

    Exercises is_explanation_required, validate_explanation,
    validate_explanation_timestamp, and validate_response_explanation
    in envelope context.

    Spec: ARSIA-Actions.md §5.1, §5.2.
    """

    def test_explanation_required_by_descriptor_present(self) -> None:
        descriptor = _minimal_descriptor(
            risk_level=8,
            audit_required=True,
            explainability_required=True,
        )
        assert validate_action_descriptor(descriptor) == []
        assert is_explanation_required(descriptor=descriptor) is True

        explanation = {
            "reasoning": "Analysis shows low counterparty risk.",
            "confidence": 0.87,
            "inputs_used": ["state:risk/model-v3"],
            "decision_timestamp": "2026-04-15T12:00:00.000Z",
        }
        assert validate_explanation(explanation) == []

        errors = validate_response_explanation(
            response_payload={"explanation": explanation},
            descriptor=descriptor,
        )
        assert errors == []

    def test_explanation_required_by_compliance_override(self) -> None:
        descriptor = _minimal_descriptor(explainability_required=False)
        compliance = {"explainability_required": True}
        assert is_explanation_required(
            descriptor=descriptor, compliance=compliance
        ) is True

        errors = validate_response_explanation(
            response_payload={},
            descriptor=descriptor,
            compliance=compliance,
        )
        assert len(errors) == 1
        assert errors[0].code == "missing_explanation"

    def test_explanation_not_required_no_error(self) -> None:
        descriptor = _minimal_descriptor(explainability_required=False)
        assert is_explanation_required(descriptor=descriptor) is False
        errors = validate_response_explanation(
            response_payload={},
            descriptor=descriptor,
        )
        assert errors == []

    def test_explanation_timestamp_must_precede_envelope_ts(self) -> None:
        envelope_ts = "2026-04-15T12:00:00.000Z"
        explanation = {
            "reasoning": "Decision was made before envelope creation.",
            "confidence": 0.95,
            "inputs_used": ["state:context/a"],
            "decision_timestamp": "2026-04-15T11:59:59.000Z",
        }
        assert validate_explanation(explanation) == []
        assert validate_explanation_timestamp(explanation, envelope_ts) == []

    def test_explanation_timestamp_after_envelope_ts_rejected(self) -> None:
        envelope_ts = "2026-04-15T12:00:00.000Z"
        explanation = {
            "reasoning": "Paradoxically timestamped in the future.",
            "confidence": 0.50,
            "inputs_used": [],
            "decision_timestamp": "2026-04-15T12:00:01.000Z",
        }
        errors = validate_explanation_timestamp(explanation, envelope_ts)
        assert len(errors) == 1
        assert errors[0].code == "decision_timestamp_after_envelope"

    def test_explanation_in_signed_response_envelope(
        self,
        keypair_risk_assessor: dict[str, Any],
    ) -> None:
        descriptor = _minimal_descriptor(
            risk_level=7,
            audit_required=True,
            explainability_required=True,
        )
        assert is_explanation_required(descriptor=descriptor) is True

        explanation = {
            "reasoning": "Model v3 assessed counterparty risk as low.",
            "confidence": 0.91,
            "inputs_used": ["state:risk/model-v3", "state:counterparty/profile"],
        }
        response = create_response(
            from_agent="agent:arsialabs.demo.risk-assessor",
            to_agent="agent:acme.echo-client",
            correlation_id="11111111-1111-4111-8111-111111111111",
            payload_type="com.example.risk/assess",
            result={"risk_score": 0.12},
            explanation=explanation,
        )

        signed = sign_message(
            response,
            keypair_risk_assessor["private_key"],
            keypair_risk_assessor["kid"],
        )
        assert verify_message(signed, keypair_risk_assessor["public_key"]) is True
        assert validate_envelope(signed) == []
        assert signed["payload"]["explanation"] == explanation

        errors = validate_response_explanation(
            response_payload=signed["payload"],
            descriptor=descriptor,
        )
        assert errors == []

        audit = build_audit_record(
            signed,
            event_type="response",
            operator_id="agent:arsialabs.demo.risk-assessor",
            effective_retention_days=365,
        )
        dumped = audit.model_dump(mode="json", exclude_none=True)
        assert validate_audit_record(dumped) == []


# ---------------------------------------------------------------------------
# Flow 6 — Version Negotiation
# ---------------------------------------------------------------------------


class TestVersionNegotiation:
    """Version resolution, major bump detection, and not-supported error.

    Exercises resolve_action_version, is_major_version_bump, and
    build_version_not_supported_error composing with envelope
    validation.

    Spec: ARSIA-Actions.md §2.4.
    """

    def test_resolve_absent_version_uses_latest(self) -> None:
        payload: dict[str, Any] = {"type": "com.example.notes/read", "args": {}}
        supported = ["1.0", "1.1", "2.0"]
        resolved = resolve_action_version(payload, supported)
        assert resolved == "2.0"

    def test_resolve_present_version_passthrough(self) -> None:
        payload: dict[str, Any] = {
            "type": "com.example.notes/read",
            "version": "1.1",
        }
        resolved = resolve_action_version(payload, ["1.0", "1.1", "2.0"])
        assert resolved == "1.1"

    def test_major_version_bump_triggers_new_action_treatment(self) -> None:
        assert is_major_version_bump("1.0", "2.0") is True
        assert is_major_version_bump("1.0", "1.1") is False
        assert is_major_version_bump("2.3", "3.0") is True

    def test_unsupported_version_error_envelope_validates(self) -> None:
        error = build_version_not_supported_error(
            from_agent="agent:arsialabs.demo.risk-assessor",
            to_agent="agent:acme.echo-client",
            correlation_id="11111111-1111-4111-8111-111111111111",
            requested_version="3.0",
            supported_versions=["1.0", "2.0"],
        )
        assert error["intent"] == "error"
        assert error["payload"]["error"]["code"] == "not_implemented"
        assert error["payload"]["error"]["details"]["requested_version"] == "3.0"
        assert error["payload"]["error"]["details"]["supported_versions"] == {
            "min": "1.0",
            "max": "2.0",
        }
        assert validate_envelope(error) == []

    def test_version_negotiation_full_flow(
        self,
        keypair_risk_assessor: dict[str, Any],
    ) -> None:
        supported = ["1.0", "2.0"]
        payload: dict[str, Any] = {
            "type": "com.example.notes/read",
            "version": "3.0",
        }
        resolved = resolve_action_version(payload, supported)
        assert resolved == "3.0"
        assert resolved not in supported

        error = build_version_not_supported_error(
            from_agent="agent:arsialabs.demo.risk-assessor",
            to_agent="agent:acme.echo-client",
            correlation_id="11111111-1111-4111-8111-111111111111",
            requested_version=resolved,
            supported_versions=supported,
        )
        signed = sign_message(
            error,
            keypair_risk_assessor["private_key"],
            keypair_risk_assessor["kid"],
        )
        assert verify_message(signed, keypair_risk_assessor["public_key"]) is True
        assert validate_envelope(signed) == []

        audit = build_audit_record(
            signed,
            event_type="error",
            operator_id="agent:arsialabs.demo.risk-assessor",
            effective_retention_days=90,
        )
        dumped = audit.model_dump(mode="json", exclude_none=True)
        assert validate_audit_record(dumped) == []
        assert audit.payload_type == "org.arsiaprotocol.error"
