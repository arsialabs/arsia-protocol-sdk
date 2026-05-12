# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""End-to-end lifecycle tests for the ARSIA Protocol SDK.

Covers 8 categories:
  E2E-01  Message lifecycle (sign/verify/validate all intents)
  E2E-02  Compliance pipeline (profiles, retention, classification)
  E2E-03  Action approval workflow (capabilities, transitions, policy)
  E2E-04  State management (entries, keys, audit, expiry, retention)
  E2E-05  Asset transfer & escrow (transfer, escrow, dispute, cancel, reversal)
  E2E-06  Encrypted message / JWE (encrypt→sign→verify→decrypt)
  E2E-07  Routing (topology, brokers, relay preconditions)
  E2E-08  Idempotency (store lifecycle, expiry, purge)
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FROM_AGENT = "agent:testorg.sender"
TO_AGENT = "agent:testorg.receiver"
KID = f"{FROM_AGENT}#sign-1"
KID_RECEIVER = f"{TO_AGENT}#sign-1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ms() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _future_ms(seconds: int = 600) -> str:
    t = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _past_ms(seconds: int = 600) -> str:
    t = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ed25519_keypair():
    from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
    return generate_keypair()


@pytest.fixture(scope="module")
def ec_keypair():
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )
    priv = generate_private_key(SECP256R1())
    return priv, priv.public_key()


@pytest.fixture(scope="module")
def receiver_jwks(ec_keypair):
    from arsia_protocol.identity.discovery import build_ec_jwk
    _, pub = ec_keypair
    jwk = build_ec_jwk(pub, f"{TO_AGENT}#enc-1", use="enc")
    return {"keys": [jwk]}


# ═══════════════════════════════════════════════════════════════════════════
# E2E-01 — Message lifecycle
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E01MessageLifecycle:

    def test_sign_verify_validate_request(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_request, sign_message, verify_message,
        )
        from arsia_protocol.core.validation import validate_envelope

        priv, pub = ed25519_keypair
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            args={"key": "value"},
        )
        assert env["intent"] == "request"
        signed = sign_message(env, priv, KID)
        assert signed["security"]["alg"] == "EdDSA"
        assert signed["security"]["kid"] == KID
        assert verify_message(signed, pub) is True
        assert validate_envelope(signed) == []

    def test_sign_verify_validate_response(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_response, sign_message, verify_message,
        )
        from arsia_protocol.core.validation import validate_envelope

        priv, pub = ed25519_keypair
        env = create_response(
            FROM_AGENT, TO_AGENT, str(uuid.uuid4()), "org.test/action",
            result={"ok": True},
        )
        assert env["intent"] == "response"
        signed = sign_message(env, priv, KID)
        assert verify_message(signed, pub) is True
        assert validate_envelope(signed) == []

    def test_sign_verify_validate_pending_approval(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_pending_approval, sign_message, verify_message,
        )
        from arsia_protocol.core.validation import validate_envelope

        priv, pub = ed25519_keypair
        env = create_pending_approval(
            FROM_AGENT, TO_AGENT, str(uuid.uuid4()),
            "arsiaprotocol.oversight/pending",
            args={
                "action_id": "org.test.oversight.execute",
                "original_request_id": str(uuid.uuid4()),
                "approval_deadline": _future_ms(3600),
                "approver_capability": "arsiaprotocol.oversight.approve",
                "context": "Approval needed for test operation",
                "risk_level": 7,
            },
        )
        assert env["intent"] == "pending_approval"
        signed = sign_message(env, priv, KID)
        assert verify_message(signed, pub) is True
        assert validate_envelope(signed) == []

    def test_sign_verify_validate_approval_decision(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_approval_decision, sign_message, verify_message,
        )
        from arsia_protocol.core.validation import validate_envelope

        priv, pub = ed25519_keypair
        env = create_approval_decision(
            FROM_AGENT, TO_AGENT, str(uuid.uuid4()), "org.test/action",
            ["test.read"], result={"approved": True},
        )
        assert env["intent"] == "approval_decision"
        signed = sign_message(env, priv, KID)
        assert verify_message(signed, pub) is True
        assert validate_envelope(signed) == []

    def test_sign_verify_validate_event(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_event, sign_message, verify_message,
        )
        from arsia_protocol.core.validation import validate_envelope

        priv, pub = ed25519_keypair
        env = create_event(
            FROM_AGENT, TO_AGENT, "org.test/notification",
            data={"msg": "hello"},
        )
        assert env["intent"] == "event"
        signed = sign_message(env, priv, KID)
        assert verify_message(signed, pub) is True
        assert validate_envelope(signed) == []

    def test_sign_verify_validate_error(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_error, sign_message, verify_message,
        )
        from arsia_protocol.core.validation import validate_envelope

        priv, pub = ed25519_keypair
        env = create_error(
            FROM_AGENT, TO_AGENT, str(uuid.uuid4()),
            "invalid_request", "Bad input",
        )
        assert env["intent"] == "error"
        signed = sign_message(env, priv, KID)
        assert verify_message(signed, pub) is True
        assert validate_envelope(signed) == []

    def test_tamper_payload_rejects_verify(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_request, sign_message, verify_message,
        )

        priv, pub = ed25519_keypair
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        signed = sign_message(env, priv, KID)
        tampered = copy.deepcopy(signed)
        tampered["payload"]["type"] = "org.test/TAMPERED"
        assert verify_message(tampered, pub) is False

    def test_tamper_kid_caught_by_validation(self, ed25519_keypair):
        from arsia_protocol.core.message import (
            create_request, sign_message, verify_message,
        )
        from arsia_protocol.core.validation import validate_envelope

        priv, pub = ed25519_keypair
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        signed = sign_message(env, priv, KID)
        tampered = copy.deepcopy(signed)
        tampered["security"]["kid"] = "agent:evil.attacker#key-1"
        assert verify_message(tampered, pub) is True
        errors = validate_envelope(tampered)
        kid_errors = [e for e in errors if "kid" in str(e).lower()]
        assert len(kid_errors) > 0

    def test_wrong_key_rejects_verify(self):
        from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
        from arsia_protocol.core.message import (
            create_request, sign_message, verify_message,
        )

        priv, pub = generate_keypair()
        priv2, pub2 = generate_keypair()
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        signed = sign_message(env, priv, KID)
        assert verify_message(signed, pub2) is False


# ═══════════════════════════════════════════════════════════════════════════
# E2E-02 — Compliance pipeline
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E02CompliancePipeline:

    def test_load_profiles(self):
        from arsia_protocol.core.compliance import load_profiles
        profiles = load_profiles()
        assert isinstance(profiles, dict)
        assert len(profiles) >= 7

    def test_get_profile_names(self):
        from arsia_protocol.core.compliance import get_profile_names
        names = get_profile_names()
        expected = [
            "DORA", "DSA-VLOP", "EU-AI-ACT-HIGH-RISK",
            "EU-AI-ACT-LIMITED-RISK", "GDPR-STANDARD", "MIFID-II",
            "PAC-AGRICULTURE",
        ]
        assert names == expected

    def test_get_each_profile(self):
        from arsia_protocol.core.compliance import get_profile, get_profile_names
        for name in get_profile_names():
            prof = get_profile(name)
            assert prof["name"] == name
            assert prof["status"] == "active"

    def test_get_profile_invalid_raises(self):
        from arsia_protocol.core.compliance import get_profile
        with pytest.raises(ValueError):
            get_profile("NONEXISTENT-PROFILE")

    def test_compliance_request_build_validate_apply(self):
        from arsia_protocol.core.compliance import (
            apply_profile, validate_compliance,
        )
        from arsia_protocol.core.message import create_request

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            compliance={
                "profile": "GDPR-STANDARD",
                "data_residency": "DE",
                "pii_involved": True,
                "audit_required": True,
                "pii_classification": "personal",
                "retention_days": 365,
                "legal_basis": "consent",
            },
        )
        assert validate_compliance(env) == []
        applied = apply_profile(env)
        assert applied["compliance"]["profile"] == "GDPR-STANDARD"

    def test_retention_floor_enforcement(self):
        from arsia_protocol.core.compliance import (
            apply_profile, get_effective_retention,
        )
        from arsia_protocol.core.message import create_request

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            compliance={"profile": "MIFID-II", "retention_days": 90},
        )
        applied = apply_profile(env)
        retention = get_effective_retention(applied)
        assert retention is not None
        assert retention >= 1827

    def test_profile_requirement_high_risk_no_profile(self):
        from arsia_protocol.identity.onboarding import validate_profile_requirement
        errors = validate_profile_requirement(
            identity_classification="high-risk",
            declared_profile=None,
        )
        assert len(errors) > 0

    def test_profile_requirement_high_risk_with_profile(self):
        from arsia_protocol.identity.onboarding import validate_profile_requirement
        errors = validate_profile_requirement(
            identity_classification="high-risk",
            declared_profile="EU-AI-ACT-HIGH-RISK",
        )
        assert len(errors) == 0

    def test_profile_requirement_unacceptable_risk(self):
        from arsia_protocol.identity.onboarding import validate_profile_requirement
        errors = validate_profile_requirement(
            identity_classification="unacceptable-risk",
            declared_profile="GDPR-STANDARD",
        )
        assert len(errors) > 0

    def test_profile_requirement_error_exempt(self):
        from arsia_protocol.identity.onboarding import validate_profile_requirement
        errors = validate_profile_requirement(
            identity_classification="high-risk",
            declared_profile=None,
            intent="error",
        )
        assert len(errors) == 0

    def test_classification_consistency_valid(self):
        from arsia_protocol.identity.onboarding import is_classification_consistent
        assert is_classification_consistent("minimal-risk", "high-risk") is True
        assert is_classification_consistent("limited-risk", "limited-risk") is True
        assert is_classification_consistent("high-risk", "high-risk") is True
        assert is_classification_consistent("minimal-risk", "minimal-risk") is True

    def test_classification_consistency_escalation(self):
        from arsia_protocol.identity.onboarding import is_classification_consistent
        assert is_classification_consistent("high-risk", "minimal-risk") is False
        assert is_classification_consistent("high-risk", "limited-risk") is False

    def test_risk_classification_0_through_10(self):
        from arsia_protocol.actions.actions import get_risk_classification
        expected_map = {
            0: "minimal-risk", 1: "minimal-risk", 2: "minimal-risk",
            3: "limited-risk", 4: "limited-risk",
            5: "elevated-risk", 6: "elevated-risk",
            7: "high-risk", 8: "high-risk",
            9: "critical-risk", 10: "critical-risk",
        }
        for level, expected in expected_map.items():
            assert get_risk_classification(level) == expected

    def test_risk_classification_out_of_range(self):
        from arsia_protocol.actions.actions import get_risk_classification
        for bad in [-1, 11, 100]:
            with pytest.raises(ValueError):
                get_risk_classification(bad)


# ═══════════════════════════════════════════════════════════════════════════
# E2E-03 — Action approval workflow
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E03ActionApproval:

    def test_validate_valid_capabilities(self):
        from arsia_protocol.actions.actions import validate_capability, is_valid_capability
        for cap in ["notes.read", "payments.charge", "admin.users.list"]:
            assert validate_capability(cap) == []
            assert is_valid_capability(cap) is True

    def test_validate_invalid_capabilities(self):
        from arsia_protocol.actions.actions import validate_capability, is_valid_capability
        for cap in ["", "x", "has space.read"]:
            assert len(validate_capability(cap)) > 0
            assert is_valid_capability(cap) is False

    def test_match_capabilities_patterns(self):
        from arsia_protocol.actions.actions import (
            match_capabilities, match_capability,
        )
        assert match_capabilities(["notes.read"], ["notes.read"]) is True
        assert match_capability("notes.*", "notes.read") is True
        assert match_capabilities(["notes.*"], ["notes.read"]) is True
        assert match_capabilities(["payments.charge"], ["notes.read"]) is False
        assert match_capability("notes.read", "notes.*") is False

    def test_find_unsatisfied_capabilities(self):
        from arsia_protocol.actions.actions import find_unsatisfied_capabilities
        unsatisfied = find_unsatisfied_capabilities(
            ["notes.read"], ["notes.read", "notes.write", "admin.delete"],
        )
        assert "notes.write" in unsatisfied
        assert "admin.delete" in unsatisfied
        assert "notes.read" not in unsatisfied

    def test_valid_execution_state_transitions(self):
        from arsia_protocol.actions.actions import is_valid_transition
        valid_pairs = [
            ("requested", "pending_approval"),
            ("requested", "executing"),
            ("requested", "failed"),
            ("pending_approval", "executing"),
            ("pending_approval", "failed"),
            ("executing", "completed"),
            ("executing", "failed"),
            ("completed", "rolled_back"),
        ]
        for from_s, to_s in valid_pairs:
            assert is_valid_transition(from_s, to_s) is True, \
                f"Expected valid: {from_s}->{to_s}"

    def test_invalid_execution_state_transitions(self):
        from arsia_protocol.actions.actions import is_valid_transition
        invalid_pairs = [
            ("completed", "executing"),
            ("failed", "executing"),
            ("rolled_back", "completed"),
            ("executing", "requested"),
            ("failed", "requested"),
        ]
        for from_s, to_s in invalid_pairs:
            assert is_valid_transition(from_s, to_s) is False, \
                f"Expected invalid: {from_s}->{to_s}"

    def test_validate_valid_action_descriptor(self):
        from arsia_protocol.actions.actions import validate_action_descriptor
        descriptor = {
            "action_id": "com.test/doStuff",
            "category": "data",
            "description": "Test action",
            "risk_level": 3,
            "reversible": True,
            "idempotent": False,
            "required_capabilities": ["test.read"],
            "human_oversight_required": False,
            "audit_required": True,
            "explainability_required": False,
        }
        assert validate_action_descriptor(descriptor) == []

    def test_validate_invalid_action_descriptor(self):
        from arsia_protocol.actions.actions import validate_action_descriptor
        assert len(validate_action_descriptor({})) > 0

    def test_validate_valid_explanation(self):
        from arsia_protocol.actions.actions import validate_explanation
        explanation = {
            "reasoning": "Based on analysis",
            "confidence": 0.95,
            "inputs_used": ["data_source_1"],
        }
        assert validate_explanation(explanation) == []

    def test_validate_invalid_explanation(self):
        from arsia_protocol.actions.actions import validate_explanation
        assert len(validate_explanation({})) > 0

    def test_evaluate_capability_policy_allowed(self):
        from arsia_protocol.identity.onboarding import evaluate_capability_policy
        from arsia_protocol.types.routing import CapabilityPolicy, CapabilityRule

        policy = CapabilityPolicy(
            policy_version="1.0",
            token_lifetime_seconds=3600,
            capabilities=[
                CapabilityRule(capability="notes.read", status="allowed"),
            ],
        )
        result = evaluate_capability_policy(policy, ["notes.read"])
        assert result.is_approved is True
        assert "notes.read" in result.freely_allowed

    def test_evaluate_capability_policy_prohibited(self):
        from arsia_protocol.identity.onboarding import evaluate_capability_policy
        from arsia_protocol.types.routing import CapabilityPolicy, CapabilityRule

        policy = CapabilityPolicy(
            policy_version="1.0",
            token_lifetime_seconds=3600,
            capabilities=[
                CapabilityRule(capability="admin.delete", status="prohibited"),
            ],
        )
        result = evaluate_capability_policy(policy, ["admin.delete"])
        assert result.is_approved is False
        assert "admin.delete" in result.denied

    def test_evaluate_capability_policy_oversight_required(self):
        from arsia_protocol.identity.onboarding import evaluate_capability_policy
        from arsia_protocol.types.routing import CapabilityPolicy, CapabilityRule

        policy = CapabilityPolicy(
            policy_version="1.0",
            token_lifetime_seconds=3600,
            capabilities=[
                CapabilityRule(capability="payments.charge", status="oversight_required"),
            ],
        )
        result = evaluate_capability_policy(policy, ["payments.charge"])
        assert result.is_approved is True
        assert "payments.charge" in result.oversight_required

    def test_full_approval_flow(self):
        from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
        from arsia_protocol.core.message import (
            create_request, create_pending_approval,
            create_approval_decision, sign_message, verify_message,
        )

        priv, pub = generate_keypair()
        request = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        signed_req = sign_message(request, priv, KID)
        assert verify_message(signed_req, pub) is True

        priv2, pub2 = generate_keypair()
        pending = create_pending_approval(
            TO_AGENT, FROM_AGENT, signed_req["id"], "org.test/action",
            args={"review_needed": True},
        )
        signed_pending = sign_message(pending, priv2, KID_RECEIVER)
        assert verify_message(signed_pending, pub2) is True

        decision = create_approval_decision(
            TO_AGENT, FROM_AGENT, signed_req["id"], "org.test/action",
            ["test.read"], result={"approved": True},
        )
        signed_decision = sign_message(decision, priv2, KID_RECEIVER)
        assert verify_message(signed_decision, pub2) is True
        assert signed_decision["intent"] == "approval_decision"


# ═══════════════════════════════════════════════════════════════════════════
# E2E-04 — State management
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E04StateManagement:

    def test_build_state_entry_all_fields(self):
        from arsia_protocol.types.state import StateEntry

        now_str = _now_ms()
        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/mykey",
            value={"data": "test"},
            owner_agent_id=FROM_AGENT,
            scope="agent",
            created_at=now_str,
            updated_at=now_str,
            version=1,
            pii_classification="none",
            expires_at=_future_ms(3600),
            retention_days=30,
            data_residency="DE",
            pii_special_categories=None,
        )
        assert entry.key == f"{FROM_AGENT}/agent/mykey"
        assert entry.scope == "agent"

    def test_build_args_all_operations(self):
        from arsia_protocol.types.state import StateEntry
        from arsia_protocol.state.state import (
            build_set_args, build_get_args, build_delete_args,
            build_query_args, build_snapshot_args,
            build_grant_args, build_revoke_args, build_purge_args,
        )

        now_str = _now_ms()
        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/mykey",
            value={"hello": "world"},
            owner_agent_id=FROM_AGENT,
            scope="agent",
            created_at=now_str,
            updated_at=now_str,
            version=1,
            pii_classification="none",
        )

        set_args = build_set_args(entry)
        assert set_args["key"] == f"{FROM_AGENT}/agent/mykey"
        assert set_args["value"] == {"hello": "world"}
        assert set_args["scope"] == "agent"

        get_args = build_get_args(f"{FROM_AGENT}/agent/mykey")
        assert get_args["key"] == f"{FROM_AGENT}/agent/mykey"

        del_args = build_delete_args(f"{FROM_AGENT}/agent/mykey")
        assert del_args["key"] == f"{FROM_AGENT}/agent/mykey"

        query_args = build_query_args(key_prefix=f"{FROM_AGENT}/agent/")
        assert "key_prefix" in query_args

        snap_args = build_snapshot_args(now_str)
        assert "as_of" in snap_args

        grant_args = build_grant_args(
            f"{FROM_AGENT}/agent/*", TO_AGENT, "read",
            sender_agent_id=FROM_AGENT,
        )
        assert grant_args["access_level"] == "read"

        revoke_args = build_revoke_args(str(uuid.uuid4()))
        assert "grant_id" in revoke_args

        purge_args = build_purge_args(f"{FROM_AGENT}/agent/mykey", "GDPR erasure")
        assert "key" in purge_args

    def test_validate_state_entry_with_and_without_sender(self):
        from arsia_protocol.types.state import StateEntry
        from arsia_protocol.state.state import validate_state_entry

        now_str = _now_ms()
        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/mykey",
            value="test",
            owner_agent_id=FROM_AGENT,
            scope="agent",
            created_at=now_str,
            updated_at=now_str,
            version=1,
            pii_classification="none",
        )
        assert validate_state_entry(entry, sender_agent_id=FROM_AGENT) == []
        assert validate_state_entry(entry) == []

    def test_validate_and_parse_state_keys_all_scopes(self):
        from arsia_protocol.state.state import validate_state_key, parse_state_key

        for scope in ["session", "agent", "shared", "global"]:
            key = f"{FROM_AGENT}/{scope}/mykey"
            assert validate_state_key(key) == []
            parsed_agent, parsed_scope, parsed_local = parse_state_key(key)
            assert parsed_agent == FROM_AGENT
            assert parsed_scope == scope
            assert parsed_local == "mykey"

    def test_validate_invalid_state_key(self):
        from arsia_protocol.state.state import validate_state_key
        assert len(validate_state_key("not-a-valid-key")) > 0

    def test_build_and_validate_audit_record(self):
        from arsia_protocol.state.audit import build_audit_record, validate_audit_record
        from arsia_protocol.core.message import create_request

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        record = build_audit_record(
            env,
            event_type="request",
            operator_id="operator-1",
            effective_retention_days=365,
        )
        assert record.event_type == "request"
        assert record.from_agent == FROM_AGENT
        assert validate_audit_record(record.model_dump()) == []

    def test_validate_invalid_audit_record(self):
        from arsia_protocol.state.audit import validate_audit_record
        assert len(validate_audit_record({"record_id": "bad"})) > 0

    def test_is_entry_expired_past_future_none(self):
        from arsia_protocol.state.state import is_entry_expired

        assert is_entry_expired({"expires_at": _past_ms(60)}) is True
        assert is_entry_expired({"expires_at": _future_ms(3600)}) is False
        assert is_entry_expired({}) is False

    def test_is_within_retention_with_and_without_profile(self):
        from arsia_protocol.state.state import is_within_retention
        from arsia_protocol.core.compliance import get_profile

        assert is_within_retention({
            "created_at": _now_ms(),
            "retention_days": 30,
        }) is True

        assert is_within_retention({
            "created_at": "2020-01-01T00:00:00.000Z",
            "retention_days": 1,
        }) is False

        profile = get_profile("MIFID-II")
        assert is_within_retention({
            "created_at": _now_ms(),
            "retention_days": 1,
        }, profile) is True


# ═══════════════════════════════════════════════════════════════════════════
# E2E-05 — Asset transfer & escrow
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E05AssetTransfer:

    def test_validate_valid_transfer_request(self):
        from arsia_protocol.assets.assets import validate_transfer_request

        args = {
            "from_agent": FROM_AGENT,
            "to_agent": TO_AGENT,
            "amount": 100.50,
            "currency_or_unit": "EUR",
            "asset_type": "currency",
            "payment_reference": f"PAY-{uuid.uuid4().hex[:12]}",
            "description": "Test payment for goods",
            "idempotency_key": f"idem-{uuid.uuid4().hex[:12]}",
        }
        assert validate_transfer_request(args) == []

    def test_validate_empty_transfer_request(self):
        from arsia_protocol.assets.assets import validate_transfer_request
        assert len(validate_transfer_request({})) > 0

    def test_validate_transfer_missing_fields(self):
        from arsia_protocol.assets.assets import validate_transfer_request
        assert len(validate_transfer_request({"amount": 100})) > 0

    def test_validate_valid_escrow_conditions(self):
        from arsia_protocol.assets.assets import validate_escrow_conditions

        conditions = {
            "release_condition": "Goods delivered",
            "release_trigger": "org.example/delivery",
            "release_agent": TO_AGENT,
            "timeout_at": _future_ms(86400),
        }
        assert validate_escrow_conditions(conditions) == []

    def test_validate_invalid_escrow_conditions(self):
        from arsia_protocol.assets.assets import validate_escrow_conditions
        assert len(validate_escrow_conditions({})) > 0

    def test_dispute_outsider_rejected(self):
        from arsia_protocol.assets.assets import validate_escrow_dispute

        args = {
            "payment_reference": "PAY-123",
            "dispute_reason": "Goods not received",
            "disputed_by": "agent:outsider.attacker",
        }
        errors = validate_escrow_dispute(
            args,
            sender_agent_id="agent:outsider.attacker",
            escrow_parties=(FROM_AGENT, TO_AGENT),
        )
        assert len(errors) > 0

    def test_dispute_valid_from_agent_party(self):
        from arsia_protocol.assets.assets import validate_escrow_dispute

        args = {
            "payment_reference": "PAY-123",
            "dispute_reason": "Goods not received",
            "disputed_by": FROM_AGENT,
        }
        errors = validate_escrow_dispute(
            args,
            sender_agent_id=FROM_AGENT,
            escrow_parties=(FROM_AGENT, TO_AGENT),
        )
        assert errors == []

    def test_dispute_valid_to_agent_party(self):
        from arsia_protocol.assets.assets import validate_escrow_dispute

        args = {
            "payment_reference": "PAY-123",
            "dispute_reason": "Wrong goods",
            "disputed_by": TO_AGENT,
        }
        errors = validate_escrow_dispute(
            args,
            sender_agent_id=TO_AGENT,
            escrow_parties=(FROM_AGENT, TO_AGENT),
        )
        assert errors == []

    def test_dispute_no_sender_param(self):
        from arsia_protocol.assets.assets import validate_escrow_dispute

        args = {
            "payment_reference": "PAY-123",
            "dispute_reason": "Issue found",
            "disputed_by": FROM_AGENT,
        }
        assert validate_escrow_dispute(args) == []

    def test_cancel_wrong_sender_rejected(self):
        from arsia_protocol.assets.assets import validate_escrow_cancel

        args = {
            "payment_reference": "PAY-123",
            "cancellation_reason": "Changed mind",
        }
        errors = validate_escrow_cancel(
            args,
            sender_agent_id=TO_AGENT,
            from_agent=FROM_AGENT,
        )
        assert len(errors) > 0

    def test_cancel_correct_sender_passes(self):
        from arsia_protocol.assets.assets import validate_escrow_cancel

        args = {
            "payment_reference": "PAY-123",
            "cancellation_reason": "Changed mind",
        }
        errors = validate_escrow_cancel(
            args,
            sender_agent_id=FROM_AGENT,
            from_agent=FROM_AGENT,
        )
        assert errors == []

    def test_cancel_no_sender_param(self):
        from arsia_protocol.assets.assets import validate_escrow_cancel

        args = {
            "payment_reference": "PAY-123",
            "cancellation_reason": "Changed mind",
        }
        assert validate_escrow_cancel(args) == []

    def test_valid_escrow_transitions(self):
        from arsia_protocol.assets.assets import is_valid_escrow_transition

        valid = [
            ("ESCROWED", "RELEASED"),
            ("ESCROWED", "RETURNED"),
            ("ESCROWED", "DISPUTED"),
            ("DISPUTED", "RELEASED"),
            ("DISPUTED", "RETURNED"),
        ]
        for from_s, to_s in valid:
            assert is_valid_escrow_transition(from_s, to_s) is True, \
                f"Expected valid: {from_s}->{to_s}"

    def test_invalid_escrow_transitions(self):
        from arsia_protocol.assets.assets import is_valid_escrow_transition

        invalid = [
            ("RELEASED", "ESCROWED"),
            ("RETURNED", "ESCROWED"),
            ("RELEASED", "DISPUTED"),
            ("RETURNED", "DISPUTED"),
            ("RELEASED", "RETURNED"),
            ("RETURNED", "RELEASED"),
        ]
        for from_s, to_s in invalid:
            assert is_valid_escrow_transition(from_s, to_s) is False, \
                f"Expected invalid: {from_s}->{to_s}"

    def test_is_terminal_escrow_state(self):
        from arsia_protocol.assets.assets import is_terminal_escrow_state

        assert is_terminal_escrow_state("RELEASED") is True
        assert is_terminal_escrow_state("RETURNED") is True
        assert is_terminal_escrow_state("DISPUTED") is False
        assert is_terminal_escrow_state("ESCROWED") is False

    def test_reversal_precondition_valid(self):
        from arsia_protocol.assets.assets import validate_reversal_precondition

        reversal_args = {
            "payment_reference": "PAY-123",
            "reversal_reason": "Customer returned goods",
        }
        errors = validate_reversal_precondition(
            reversal_args,
            original_status="completed",
            original_amount=Decimal("100.00"),
            original_settled_at=_past_ms(3600),
            now=datetime.now(timezone.utc),
        )
        assert errors == []

    def test_reversal_precondition_not_completed(self):
        from arsia_protocol.assets.assets import validate_reversal_precondition

        reversal_args = {
            "payment_reference": "PAY-123",
            "reversal_reason": "Reverse it",
        }
        errors = validate_reversal_precondition(
            reversal_args,
            original_status="pending",
        )
        assert len(errors) > 0


# ═══════════════════════════════════════════════════════════════════════════
# E2E-06 — Encrypted message (JWE)
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E06EncryptedMessage:

    def test_full_encrypt_sign_verify_decrypt_flow(
        self, ed25519_keypair, ec_keypair, receiver_jwks,
    ):
        from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
        from arsia_protocol.core.message import (
            create_request, sign_message, verify_message,
        )

        sender_priv, sender_pub = ed25519_keypair
        rec_ec_priv, _ = ec_keypair

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/encrypt", ["test.read"],
            args={"message": "hello encrypted", "count": 42},
        )
        original_payload = copy.deepcopy(env["payload"])

        encrypted = encrypt_payload(env, receiver_jwks)
        assert isinstance(encrypted["payload"], str)
        assert encrypted["security"]["encrypted"] is True

        signed = sign_message(encrypted, sender_priv, KID)
        assert verify_message(signed, sender_pub) is True

        decrypted = decrypt_and_verify(signed, sender_pub, rec_ec_priv)
        assert isinstance(decrypted["payload"], dict)
        assert decrypted["payload"] == original_payload

    def test_tamper_ciphertext_rejects(
        self, ed25519_keypair, ec_keypair, receiver_jwks,
    ):
        from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
        from arsia_protocol.core.message import create_request, sign_message

        sender_priv, sender_pub = ed25519_keypair
        rec_ec_priv, _ = ec_keypair

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/encrypt", ["test.read"],
            args={"secret": "data"},
        )
        encrypted = encrypt_payload(env, receiver_jwks)
        signed = sign_message(encrypted, sender_priv, KID)

        tampered = copy.deepcopy(signed)
        if isinstance(tampered["payload"], str):
            parts = tampered["payload"].split(".")
            if len(parts) >= 4:
                parts[3] = parts[3][::-1]
                tampered["payload"] = ".".join(parts)

        with pytest.raises(Exception):
            decrypt_and_verify(tampered, sender_pub, rec_ec_priv)

    def test_tamper_signature_on_encrypted_rejects(
        self, ed25519_keypair, ec_keypair, receiver_jwks,
    ):
        from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
        from arsia_protocol.core.message import create_request, sign_message

        sender_priv, sender_pub = ed25519_keypair
        rec_ec_priv, _ = ec_keypair

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/encrypt", ["test.read"],
            args={"data": "value"},
        )
        encrypted = encrypt_payload(env, receiver_jwks)
        signed = sign_message(encrypted, sender_priv, KID)

        tampered = copy.deepcopy(signed)
        tampered["security"]["sig"] = "AAAA" + tampered["security"]["sig"][4:]

        with pytest.raises(Exception):
            decrypt_and_verify(tampered, sender_pub, rec_ec_priv)

    def test_wrong_decryption_key_rejects(
        self, ed25519_keypair, receiver_jwks,
    ):
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            generate_private_key,
        )
        from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
        from arsia_protocol.core.message import create_request, sign_message

        sender_priv, sender_pub = ed25519_keypair

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/encrypt", ["test.read"],
            args={"data": "value"},
        )
        encrypted = encrypt_payload(env, receiver_jwks)
        signed = sign_message(encrypted, sender_priv, KID)

        wrong_ec_priv = generate_private_key(SECP256R1())
        with pytest.raises(Exception):
            decrypt_and_verify(signed, sender_pub, wrong_ec_priv)


# ═══════════════════════════════════════════════════════════════════════════
# E2E-07 — Routing
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E07Routing:

    @staticmethod
    def _make_broker(agent_id, jurisdiction, zones, health="healthy"):
        return {
            "agent_id": agent_id,
            "inbox": f"https://{agent_id.split(':')[1]}/inbox",
            "jurisdiction": jurisdiction,
            "residency_zones": zones,
            "health": health,
            "last_health_check": _now_ms(),
        }

    def test_direct_topology_no_residency(self):
        from arsia_protocol.routing.routing import select_topology
        from arsia_protocol.core.message import create_request

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        decision = select_topology(env)
        assert decision.topology == "direct"
        assert decision.broker is None

    def test_brokered_topology_eu_residency(self):
        from arsia_protocol.routing.routing import select_topology
        from arsia_protocol.core.message import create_request

        eu_broker = self._make_broker("agent:brokers.eubroker", "DE", ["EU"])
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            compliance={"data_residency": "EU"},
        )
        decision = select_topology(env, brokers=[eu_broker])
        assert decision.topology == "brokered"
        assert decision.broker is not None

    def test_broker_wrong_zone_error_topology(self):
        from arsia_protocol.routing.routing import select_topology
        from arsia_protocol.core.message import create_request

        us_broker = self._make_broker("agent:brokers.usbroker", "US", ["US"])
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            compliance={"data_residency": "EU"},
        )
        decision = select_topology(env, brokers=[us_broker])
        assert decision.topology == "error"
        assert decision.error is not None

    def test_no_brokers_error_topology(self):
        from arsia_protocol.routing.routing import select_topology
        from arsia_protocol.core.message import create_request

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            compliance={"data_residency": "EU"},
        )
        decision = select_topology(env, brokers=[])
        assert decision.topology == "error"

    def test_validate_valid_broker_entry(self):
        from arsia_protocol.routing.routing import validate_broker_entry

        eu_broker = self._make_broker("agent:brokers.eubroker", "DE", ["EU"])
        assert validate_broker_entry(eu_broker) == []

    def test_validate_invalid_broker_entry(self):
        from arsia_protocol.routing.routing import validate_broker_entry
        assert len(validate_broker_entry({"agent_id": "bad"})) > 0

    def test_relay_preconditions_valid(self):
        from arsia_protocol.routing.routing import validate_relay_preconditions
        from arsia_protocol.core.message import create_request

        eu_broker = self._make_broker("agent:brokers.eubroker", "DE", ["EU"])
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            compliance={"data_residency": "EU"},
        )
        assert validate_relay_preconditions(env, eu_broker) == []

    def test_relay_preconditions_wrong_zone(self):
        from arsia_protocol.routing.routing import validate_relay_preconditions
        from arsia_protocol.core.message import create_request

        us_broker = self._make_broker("agent:brokers.usbroker", "US", ["US"])
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            compliance={"data_residency": "EU"},
        )
        assert len(validate_relay_preconditions(env, us_broker)) > 0

    def test_degraded_broker_selection(self):
        from arsia_protocol.routing.routing import select_broker_by_priority

        degraded = self._make_broker(
            "agent:brokers.degraded", "FR", ["EU"], health="degraded",
        )
        assert select_broker_by_priority([degraded], zone="EU") is not None

    def test_unhealthy_broker_excluded(self):
        from arsia_protocol.routing.routing import select_broker_by_priority

        unhealthy = self._make_broker(
            "agent:brokers.down", "DE", ["EU"], health="unhealthy",
        )
        assert select_broker_by_priority([unhealthy], zone="EU") is None

    def test_broker_serves_zone(self):
        from arsia_protocol.routing.routing import broker_serves_zone

        eu_broker = self._make_broker("agent:brokers.eubroker", "DE", ["EU"])
        us_broker = self._make_broker("agent:brokers.usbroker", "US", ["US"])
        assert broker_serves_zone(eu_broker, "EU") is True
        assert broker_serves_zone(eu_broker, "US") is False
        assert broker_serves_zone(us_broker, "US") is True


# ═══════════════════════════════════════════════════════════════════════════
# E2E-08 — Idempotency
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E08Idempotency:

    def test_build_request_with_idempotency(self):
        from arsia_protocol.core.message import create_request

        idem_key = f"idem-{uuid.uuid4().hex[:8]}"
        expires_at = _future_ms(3600)
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            idempotency={"key": idem_key, "expires_at": expires_at},
        )
        assert env["idempotency"]["key"] == idem_key
        assert env["idempotency"]["expires_at"] == expires_at

    def test_resolve_idempotency_key(self):
        from arsia_protocol.core.idempotency import resolve_idempotency_key
        from arsia_protocol.core.message import create_request

        idem_key = f"idem-{uuid.uuid4().hex[:8]}"
        expires_at = _future_ms(3600)
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            idempotency={"key": idem_key, "expires_at": expires_at},
        )
        assert resolve_idempotency_key(env) == idem_key

        env_no_idem = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        assert resolve_idempotency_key(env_no_idem) is None

    def test_resolve_idempotency_source(self):
        from arsia_protocol.core.idempotency import resolve_idempotency_source
        from arsia_protocol.core.message import create_request

        idem_key = f"idem-{uuid.uuid4().hex[:8]}"
        expires_at = _future_ms(3600)
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            idempotency={"key": idem_key, "expires_at": expires_at},
        )
        key, source = resolve_idempotency_source(env)
        assert key == idem_key
        assert source == "envelope"

        key2, source2 = resolve_idempotency_source(env, header_key="header-key")
        assert key2 == "header-key"
        assert source2 == "envelope"

        env_no_idem = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        )
        key3, source3 = resolve_idempotency_source(env_no_idem, header_key="hdr")
        assert key3 == "hdr"
        assert source3 == "header"

        key4, source4 = resolve_idempotency_source(env_no_idem)
        assert key4 is None
        assert source4 is None

    def test_full_store_lifecycle(self):
        from arsia_protocol.core.idempotency import (
            IdempotencyRecord, IdempotencyScope,
        )
        from tests.fixtures.in_memory_idempotency_store import InMemoryIdempotencyStore

        store = InMemoryIdempotencyStore()
        scope = IdempotencyScope(
            from_agent=FROM_AGENT,
            to_agent=TO_AGENT,
            payload_type="org.test/action",
        )
        test_key = f"lifecycle-{uuid.uuid4().hex[:8]}"

        assert store.check_status(scope, test_key) == "new"

        assert store.mark_pending(scope, test_key) is True
        assert store.check_status(scope, test_key) == "pending"

        record = IdempotencyRecord(
            key=test_key,
            from_agent=FROM_AGENT,
            to_agent=TO_AGENT,
            payload_type="org.test/action",
            message_id=str(uuid.uuid4()),
            stored_at=_now_ms(),
            expires_at=_future_ms(3600),
        )
        store.mark_complete(record)
        assert store.check_status(scope, test_key) == "completed"

        response_bytes = b'{"result": "ok"}'
        store.store_response(scope, test_key, response_bytes)
        assert store.get_response(scope, test_key) == response_bytes

    def test_expired_record_detection(self):
        from arsia_protocol.core.idempotency import is_idempotency_record_expired
        assert is_idempotency_record_expired(_past_ms(60)) is True

    def test_non_expired_record_detection(self):
        from arsia_protocol.core.idempotency import is_idempotency_record_expired
        assert is_idempotency_record_expired(_future_ms(3600)) is False

    def test_expired_record_purged_from_store(self):
        from arsia_protocol.core.idempotency import (
            IdempotencyRecord, IdempotencyScope,
        )
        from tests.fixtures.in_memory_idempotency_store import InMemoryIdempotencyStore

        store = InMemoryIdempotencyStore()
        scope = IdempotencyScope(
            from_agent=FROM_AGENT,
            to_agent=TO_AGENT,
            payload_type="org.test/action",
        )
        expired_key = f"expired-{uuid.uuid4().hex[:8]}"

        record = IdempotencyRecord(
            key=expired_key,
            from_agent=FROM_AGENT,
            to_agent=TO_AGENT,
            payload_type="org.test/action",
            message_id=str(uuid.uuid4()),
            stored_at=_past_ms(7200),
            expires_at=_past_ms(3600),
        )
        store.put(record)

        status = store.check_status(scope, expired_key)
        assert status == "new"
