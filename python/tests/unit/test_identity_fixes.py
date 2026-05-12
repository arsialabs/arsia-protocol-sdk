# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for BL-07/17/18/19/20/21/25/26 Identity fixes.

Covers:
- BL-07: Decision payload field names (§7.6)
- BL-17: Identity layer inconsistency detection (§1.1)
- BL-18: Dual owner_id in audit records (§4.1)
- BL-19: deployer_id in audit records (§4.4)
- BL-20: max_risk_level 0–10 range (§8.2)
- BL-21: keyCertSign rejection on leaf certs (§6.2)
- BL-25: ONBOARDING_EVALUATE_CAPABILITY constant (§7.1.1)
- BL-26: approval_decision event type (§7.6)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from arsia_protocol.state.audit import build_audit_record
from arsia_protocol.identity.certificates import verify_certificate_chain
from arsia_protocol.identity.onboarding import (
    ONBOARDING_AUDIT_EVENTS,
    ONBOARDING_EVALUATE_CAPABILITY,
    build_decision_payload,
    build_onboarding_decision,
    evaluate_capability_policy,
)
from arsia_protocol.types.routing import CapabilityPolicy, CapabilityRule
from arsia_protocol.core.validation import (
    IdentityConsistencyResult,
    check_identity_consistency,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _policy() -> CapabilityPolicy:
    return CapabilityPolicy(
        policy_version="test-v1",
        token_lifetime_seconds=3600,
        capabilities=[
            CapabilityRule(capability="notes.read", status="allowed"),
            CapabilityRule(capability="notes.write", status="oversight_required"),
        ],
    )


def _envelope() -> dict[str, Any]:
    return {
        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "v": "1.0",
        "ts": "2024-01-01T00:00:00.000Z",
        "from": "agent:acme.sender",
        "to": "agent:acme.receiver",
        "intent": "request",
        "payload": {"type": "arsiaprotocol/test", "data": "hello"},
    }


# ==================================================================
# BL-07: Decision payload field names
# ==================================================================


class TestBL07DecisionPayloadFields:
    """Spec: ARSIA-Identity.md §7.6."""

    def test_decision_not_outcome(self) -> None:
        """Payload uses 'decision' not 'outcome'."""
        policy = _policy()
        evaluation = evaluate_capability_policy(policy, ["notes.read"])
        decision = build_onboarding_decision(
            agent_id="agent:acme.client",
            policy=policy,
            evaluation=evaluation,
            token="h.p.s",
            token_expires_at="2025-01-01T00:00:00.000Z",
        )
        payload = build_decision_payload(decision)
        assert "decision" in payload
        assert "outcome" not in payload
        assert payload["decision"] == "approved"

    def test_freely_allowed_not_granted_capabilities(self) -> None:
        """Payload uses 'freely_allowed' not 'granted_capabilities'."""
        policy = _policy()
        evaluation = evaluate_capability_policy(policy, ["notes.read"])
        decision = build_onboarding_decision(
            agent_id="agent:acme.client",
            policy=policy,
            evaluation=evaluation,
            token="h.p.s",
            token_expires_at="2025-01-01T00:00:00.000Z",
        )
        payload = build_decision_payload(decision)
        assert "freely_allowed" in payload
        assert "granted_capabilities" not in payload
        assert payload["freely_allowed"] == ["notes.read"]

    def test_effective_capabilities_present(self) -> None:
        """Payload contains 'effective_capabilities'."""
        policy = _policy()
        evaluation = evaluate_capability_policy(
            policy, ["notes.read", "notes.write"]
        )
        decision = build_onboarding_decision(
            agent_id="agent:acme.client",
            policy=policy,
            evaluation=evaluation,
            token="h.p.s",
            token_expires_at="2025-01-01T00:00:00.000Z",
        )
        payload = build_decision_payload(decision)
        assert "effective_capabilities" in payload

    def test_effective_capabilities_is_union(self) -> None:
        """effective_capabilities = freely_allowed ∪ oversight_required."""
        policy = _policy()
        evaluation = evaluate_capability_policy(
            policy, ["notes.read", "notes.write"]
        )
        decision = build_onboarding_decision(
            agent_id="agent:acme.client",
            policy=policy,
            evaluation=evaluation,
            token="h.p.s",
            token_expires_at="2025-01-01T00:00:00.000Z",
        )
        payload = build_decision_payload(decision)
        assert set(payload["effective_capabilities"]) == {
            "notes.read",
            "notes.write",
        }
        assert set(payload["effective_capabilities"]) == (
            set(payload["freely_allowed"]) | set(payload["oversight_required"])
        )

    def test_denial_reason_singular(self) -> None:
        """Denial uses 'denial_reason' (singular string) not 'denial_reasons'."""
        policy = _policy()
        evaluation = evaluate_capability_policy(policy, ["payments.charge"])
        decision = build_onboarding_decision(
            agent_id="agent:acme.client",
            policy=policy,
            evaluation=evaluation,
        )
        payload = build_decision_payload(decision)
        assert "denial_reason" in payload
        assert "denial_reasons" not in payload
        assert isinstance(payload["denial_reason"], str)

    def test_approval_no_denial_reason(self) -> None:
        """Approved payloads do not contain denial_reason."""
        policy = _policy()
        evaluation = evaluate_capability_policy(policy, ["notes.read"])
        decision = build_onboarding_decision(
            agent_id="agent:acme.client",
            policy=policy,
            evaluation=evaluation,
            token="h.p.s",
            token_expires_at="2025-01-01T00:00:00.000Z",
        )
        payload = build_decision_payload(decision)
        assert payload["decision"] == "approved"
        assert "denial_reason" not in payload


# ==================================================================
# BL-20: max_risk_level range 0–10
# ==================================================================


class TestBL20MaxRiskLevel:
    """Spec: ARSIA-Identity.md §8.2."""

    def test_max_risk_level_zero_accepted(self) -> None:
        """max_risk_level=0 is valid per schema."""
        rule = CapabilityRule(
            capability="notes.read", status="allowed", max_risk_level=0
        )
        assert rule.max_risk_level == 0

    def test_max_risk_level_ten_accepted(self) -> None:
        """max_risk_level=10 is valid per schema."""
        rule = CapabilityRule(
            capability="notes.read", status="allowed", max_risk_level=10
        )
        assert rule.max_risk_level == 10

    def test_max_risk_level_eleven_rejected(self) -> None:
        """max_risk_level=11 exceeds maximum 10."""
        with pytest.raises(ValidationError):
            CapabilityRule(
                capability="notes.read", status="allowed", max_risk_level=11
            )

    def test_max_risk_level_negative_rejected(self) -> None:
        """max_risk_level=-1 below minimum 0."""
        with pytest.raises(ValidationError):
            CapabilityRule(
                capability="notes.read", status="allowed", max_risk_level=-1
            )


# ==================================================================
# BL-21: keyCertSign rejection on leaf certs
# ==================================================================


class TestBL21KeyCertSign:
    """Spec: ARSIA-Identity.md §6.2."""

    def _build_leaf_cert(
        self, *, key_cert_sign: bool = False
    ) -> tuple[list[str], bytes]:
        """Build a self-signed Ed25519 leaf cert with specified Key Usage."""
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "test-agent"),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=key_cert_sign,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier("agent:acme.test"),
                ]),
                critical=False,
            )
        )
        cert = builder.sign(private_key, algorithm=None)
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        raw_pub = public_key.public_bytes_raw()
        return [pem], raw_pub

    def test_leaf_with_key_cert_sign_rejected(self) -> None:
        """Leaf cert with keyCertSign bit set must be rejected."""
        chain, pub_bytes = self._build_leaf_cert(key_cert_sign=True)
        result = verify_certificate_chain(
            chain, "agent:acme.test", pub_bytes
        )
        assert not result.is_valid
        assert any("keyCertSign" in str(e) for e in result.errors)

    def test_leaf_without_key_cert_sign_accepted(self) -> None:
        """Leaf cert without keyCertSign bit passes Key Usage check."""
        chain, pub_bytes = self._build_leaf_cert(key_cert_sign=False)
        result = verify_certificate_chain(
            chain, "agent:acme.test", pub_bytes
        )
        assert result.is_valid
        assert result.trust_level == "L2"

    def test_leaf_digital_signature_only_accepted(self) -> None:
        """Leaf cert with only digitalSignature passes."""
        chain, pub_bytes = self._build_leaf_cert(key_cert_sign=False)
        result = verify_certificate_chain(
            chain, "agent:acme.test", pub_bytes
        )
        assert result.is_valid
        assert not any("keyCertSign" in e for e in result.errors)


# ==================================================================
# BL-25: ONBOARDING_EVALUATE_CAPABILITY constant
# ==================================================================


class TestBL25OnboardingCapability:
    """Spec: ARSIA-Identity.md §7.1.1."""

    def test_constant_value(self) -> None:
        """Constant has the correct value."""
        assert ONBOARDING_EVALUATE_CAPABILITY == "arsiaprotocol.onboarding.evaluate"

    def test_constant_importable(self) -> None:
        """Constant is importable from arsia_protocol.onboarding."""
        from arsia_protocol.identity.onboarding import ONBOARDING_EVALUATE_CAPABILITY as cap
        assert cap == "arsiaprotocol.onboarding.evaluate"


# ==================================================================
# BL-26: approval_decision event type
# ==================================================================


class TestBL26ApprovalDecisionEvent:
    """Spec: ARSIA-Identity.md §7.6."""

    def test_approval_decision_in_audit_event_type(self) -> None:
        """'approval_decision' is a valid AuditEventType."""
        from arsia_protocol.types.state import AuditEventType
        from typing import get_args

        assert "approval_decision" in get_args(AuditEventType)

    def test_approval_decision_in_onboarding_events(self) -> None:
        """'approval_decision' is in ONBOARDING_AUDIT_EVENTS."""
        assert "approval_decision" in ONBOARDING_AUDIT_EVENTS

    def test_approval_decision_payload_type_namespaced(self) -> None:
        """The payload type follows the onboarding namespace."""
        pt = ONBOARDING_AUDIT_EVENTS["approval_decision"]
        assert pt.startswith("arsiaprotocol/audit.onboarding.")


# ==================================================================
# BL-18: Dual owner_id in audit records
# ==================================================================


class TestBL18DualOwnerId:
    """Spec: ARSIA-Identity.md §4.1."""

    def test_build_audit_record_with_owner_ids(self) -> None:
        """sender_owner_id and receiver_owner_id included in record."""
        record = build_audit_record(
            _envelope(),
            event_type="request",
            operator_id="CORP-001",
            effective_retention_days=90,
            sender_owner_id="SENDER-ORG-123",
            receiver_owner_id="RECEIVER-ORG-456",
            processed_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        assert record.sender_owner_id == "SENDER-ORG-123"
        assert record.receiver_owner_id == "RECEIVER-ORG-456"

    def test_build_audit_record_backward_compat(self) -> None:
        """Without new params, fields are None."""
        record = build_audit_record(
            _envelope(),
            event_type="request",
            operator_id="CORP-001",
            effective_retention_days=90,
            processed_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        assert record.sender_owner_id is None
        assert record.receiver_owner_id is None


# ==================================================================
# BL-19: deployer_id in audit records
# ==================================================================


class TestBL19DeployerId:
    """Spec: ARSIA-Identity.md §4.4."""

    def test_build_audit_record_with_deployer_id(self) -> None:
        """deployer_id included in record when provided."""
        record = build_audit_record(
            _envelope(),
            event_type="request",
            operator_id="CORP-001",
            effective_retention_days=90,
            deployer_id="DEPLOYER-789",
            processed_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        assert record.deployer_id == "DEPLOYER-789"

    def test_build_audit_record_without_deployer_id(self) -> None:
        """Without deployer_id, field is None."""
        record = build_audit_record(
            _envelope(),
            event_type="request",
            operator_id="CORP-001",
            effective_retention_days=90,
            processed_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        assert record.deployer_id is None


# ==================================================================
# BL-17: Identity layer inconsistency detection
# ==================================================================


class TestBL17IdentityConsistency:
    """Spec: ARSIA-Identity.md §1.1."""

    def test_all_layers_match(self) -> None:
        """Matching from, kid prefix, and identity_agent_id → consistent."""
        result = check_identity_consistency(
            from_agent="agent:acme.sender",
            kid="agent:acme.sender#key-1",
            identity_agent_id="agent:acme.sender",
        )
        assert result.is_consistent
        assert result.warnings == ()

    def test_kid_prefix_mismatch(self) -> None:
        """kid prefix does not match from → warning."""
        result = check_identity_consistency(
            from_agent="agent:acme.sender",
            kid="agent:acme.other#key-1",
        )
        assert not result.is_consistent
        assert any("kid prefix" in w for w in result.warnings)

    def test_from_mismatch_with_identity(self) -> None:
        """from field does not match identity_agent_id → warning."""
        result = check_identity_consistency(
            from_agent="agent:acme.sender",
            kid="agent:acme.sender#key-1",
            identity_agent_id="agent:acme.different",
        )
        assert not result.is_consistent
        assert any("IdentityRecord agent_id" in w for w in result.warnings)

    def test_without_identity_record(self) -> None:
        """Without identity_agent_id, only from/kid checked."""
        result = check_identity_consistency(
            from_agent="agent:acme.sender",
            kid="agent:acme.sender#key-1",
        )
        assert result.is_consistent
        assert result.warnings == ()

    def test_result_type(self) -> None:
        """Returns an IdentityConsistencyResult."""
        result = check_identity_consistency(
            from_agent="agent:acme.sender",
            kid="agent:acme.sender#key-1",
        )
        assert isinstance(result, IdentityConsistencyResult)
