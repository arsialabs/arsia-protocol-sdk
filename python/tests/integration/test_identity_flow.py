# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Cross-module integration tests for the Identity primitive.

These tests exercise end-to-end flows that span multiple SDK modules.
Unit tests prove each function works alone; these tests prove the
modules compose correctly — discovery, authorization, certificates,
onboarding, compliance, actions, and message all interacting.

All tests use real Ed25519 keypairs from ``conftest.py`` fixtures.

Spec: ARSIA-Identity.md §1–§10.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from arsia_protocol.actions.actions import is_valid_capability
from arsia_protocol.core.authorization import (
    build_dpop_proof,
    build_jwt,
    check_scope_coverage,
    compute_jwk_thumbprint,
    decode_jwt,
    validate_dpop_proof,
    validate_token_claims,
    verify_dpop_binding,
)
from arsia_protocol.identity.certificates import compute_trust_level
from arsia_protocol.core.compliance import validate_compliance
from arsia_protocol.identity.discovery import (
    build_capability_listing,
    build_discovery_document,
    build_jwk,
    build_jwks,
)
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_decode,
    public_key_from_bytes,
    public_key_to_jwk_dict,
)
from arsia_protocol.core.message import (
    create_request,
    format_timestamp,
    sign_message,
    verify_message,
)
from arsia_protocol.identity.onboarding import (
    build_decision_payload,
    build_onboarding_decision,
    validate_profile_requirement,
    evaluate_capability_policy,
    validate_capability_policy,
    verify_provenance,
)
from arsia_protocol.types.routing import CapabilityPolicy


# Fixed timestamp for deterministic tests.
_FIXED_NOW = datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
_FIXED_NOW_UNIX = int(_FIXED_NOW.timestamp())


# ------------------------------------------------------------------
# Discovery → JWK → verify roundtrip
# ------------------------------------------------------------------


def test_discovery_to_jwk_to_verify_roundtrip(
    keypair_acme: dict[str, Any],
) -> None:
    """Build discovery doc, extract JWK, recover public key, verify message.

    Spec: ARSIA-Core.md §7.1, §5.2.
    """
    sk: Ed25519PrivateKey = keypair_acme["private_key"]
    pk: Ed25519PublicKey = keypair_acme["public_key"]
    kid: str = keypair_acme["kid"]

    # Build discovery + JWKS
    jwk = build_jwk(pk, kid)
    jwks = build_jwks([jwk])
    doc = build_discovery_document(
        agent_id="agent:acme.echo-client",
        name="Acme Echo Client",
        version="1.0.0",
        inbox="https://acme.example/.well-known/arsia/inbox",
        jwks="https://acme.example/.well-known/arsia/jwks",
    )

    # Verify discovery doc has required fields
    assert doc["agent_id"] == "agent:acme.echo-client"
    assert doc["jwks"] == "https://acme.example/.well-known/arsia/jwks"

    # Recover public key from JWK x field
    x_b64 = jwks["keys"][0]["x"]
    pk_bytes = base64url_decode(x_b64)
    recovered_pk = public_key_from_bytes(pk_bytes)

    # Build and sign a message
    envelope = create_request(
        from_agent="agent:acme.echo-client",
        to_agent="agent:acme.echo-server",
        payload_type="com.acme.echo/ping",
        capabilities=["echo.ping"],
    )
    signed = sign_message(envelope, sk, kid)

    # Verify with the recovered key
    assert verify_message(signed, recovered_pk) is True


# ------------------------------------------------------------------
# Build JWT → validate token claims
# ------------------------------------------------------------------


def test_build_jwt_then_validate(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Build a JWT, then validate its claims using the same keypair.

    Spec: ARSIA-Identity.md §3.2.
    """
    sk: Ed25519PrivateKey = keypair_risk_assessor["private_key"]
    pk: Ed25519PublicKey = keypair_risk_assessor["public_key"]

    token = build_jwt(
        {
            "iss": "https://gateway.arsialabs.ai",
            "sub": "agent:arsialabs.demo.risk-assessor",
            "aud": "https://api.arsialabs.ai",
            "exp": _FIXED_NOW_UNIX + 3600,
            "iat": _FIXED_NOW_UNIX,
            "jti": "jwt-integration-test-01",
            "scope": "compliance.check risk.assess",
        },
        sk,
    )

    result = validate_token_claims(
        token,
        pk,
        expected_sub="agent:arsialabs.demo.risk-assessor",
        expected_aud="https://api.arsialabs.ai",
        required_capabilities=["compliance.check"],
        now=_FIXED_NOW,
    )

    assert result.is_valid, f"token validation failed: {result.errors}"
    assert result.errors == ()


# ------------------------------------------------------------------
# DPoP end-to-end
# ------------------------------------------------------------------


def test_dpop_end_to_end(
    keypair_acme: dict[str, Any],
) -> None:
    """Build access token + DPoP proof, validate both, verify binding.

    Spec: ARSIA-Identity.md §3.3.
    """
    sk: Ed25519PrivateKey = keypair_acme["private_key"]
    pk: Ed25519PublicKey = keypair_acme["public_key"]
    kid: str = keypair_acme["kid"]

    # Build JWK dict for thumbprint computation
    jwk_dict = public_key_to_jwk_dict(pk, kid)

    # Compute JWK thumbprint for cnf.jkt — needs the minimal
    # {kty, crv, x} dict per RFC 7638
    thumbprint = compute_jwk_thumbprint({
        "kty": jwk_dict["kty"],
        "crv": jwk_dict["crv"],
        "x": jwk_dict["x"],
    })

    # Build access token with cnf.jkt binding
    access_token = build_jwt(
        {
            "iss": "https://gateway.example",
            "sub": "agent:acme.echo-client",
            "aud": "https://api.example",
            "exp": _FIXED_NOW_UNIX + 3600,
            "iat": _FIXED_NOW_UNIX,
            "jti": "jwt-dpop-test-01",
            "scope": "echo.ping",
            "cnf": {"jkt": thumbprint},
        },
        sk,
    )

    # Build DPoP proof
    dpop_proof = build_dpop_proof(
        private_key=sk,
        public_key=pk,
        access_token=access_token,
        htm="POST",
        htu="https://api.example/v1/messages",
    )

    # Validate DPoP proof
    dpop_result = validate_dpop_proof(
        dpop_proof,
        access_token,
        expected_htm="POST",
        expected_htu="https://api.example/v1/messages",
    )
    assert dpop_result.is_valid, f"DPoP validation failed: {dpop_result.errors}"

    # Verify binding: decode token claims + DPoP header, then compare
    token_header, token_claims, _ = decode_jwt(access_token)
    dpop_header, _, _ = decode_jwt(dpop_proof)
    assert verify_dpop_binding(token_claims, dpop_header) is True


# ------------------------------------------------------------------
# Certificate trust level → token
# ------------------------------------------------------------------


def test_certificate_trust_then_token(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Compute trust level (L1 — no chain), build token, validate claims.

    Spec: ARSIA-Identity.md §6.1, §3.2.
    """
    sk: Ed25519PrivateKey = keypair_risk_assessor["private_key"]
    pk: Ed25519PublicKey = keypair_risk_assessor["public_key"]

    # No certificate chain → trust level L1
    identity_record: dict[str, object] = {
        "agent_id": "agent:arsialabs.demo.risk-assessor",
    }
    trust_level = compute_trust_level(identity_record)
    assert trust_level == "L1"

    # Build a token as if issued by a gateway at this trust level
    token = build_jwt(
        {
            "iss": "https://gateway.arsialabs.ai",
            "sub": "agent:arsialabs.demo.risk-assessor",
            "aud": "https://api.arsialabs.ai",
            "exp": _FIXED_NOW_UNIX + 3600,
            "iat": _FIXED_NOW_UNIX,
            "jti": "jwt-cert-trust-test-01",
            "scope": "compliance.check",
            "trust_level": trust_level,
        },
        sk,
    )

    result = validate_token_claims(
        token,
        pk,
        expected_sub="agent:arsialabs.demo.risk-assessor",
        expected_aud="https://api.arsialabs.ai",
        now=_FIXED_NOW,
    )
    assert result.is_valid, f"token validation failed: {result.errors}"


# ------------------------------------------------------------------
# Capability policy → token scope
# ------------------------------------------------------------------


def _make_policy(rules: list[dict[str, str]]) -> CapabilityPolicy:
    """Build a CapabilityPolicy with required fields + given rules."""
    return CapabilityPolicy.model_validate({
        "policy_version": "test-v1",
        "token_lifetime_seconds": 3600,
        "capabilities": rules,
    })


def test_capability_policy_to_token_scope(
    keypair_acme: dict[str, Any],
) -> None:
    """Evaluate policy, build JWT with effective capabilities as scope, verify.

    Spec: ARSIA-Identity.md §8.3, §3.2, Core §6.4.
    """
    sk: Ed25519PrivateKey = keypair_acme["private_key"]
    pk: Ed25519PublicKey = keypair_acme["public_key"]

    policy = _make_policy([
        {"capability": "echo.ping", "status": "allowed"},
        {"capability": "echo.stats", "status": "oversight_required"},
        {"capability": "admin.delete", "status": "prohibited"},
    ])

    evaluation = evaluate_capability_policy(
        policy,
        requested_capabilities=["echo.ping", "echo.stats"],
    )
    assert evaluation.is_approved
    assert "echo.ping" in evaluation.freely_allowed
    assert "echo.stats" in evaluation.oversight_required

    # Build token with effective capabilities as scope
    effective = list(evaluation.freely_allowed) + list(evaluation.oversight_required)
    scope_str = " ".join(effective)

    token = build_jwt(
        {
            "iss": "https://gateway.example",
            "sub": "agent:acme.echo-client",
            "aud": "https://api.example",
            "exp": _FIXED_NOW_UNIX + 3600,
            "iat": _FIXED_NOW_UNIX,
            "jti": "jwt-policy-scope-test-01",
            "scope": scope_str,
        },
        sk,
    )

    # Validate that the token covers the effective capabilities
    result = validate_token_claims(
        token,
        pk,
        expected_sub="agent:acme.echo-client",
        expected_aud="https://api.example",
        required_capabilities=["echo.ping"],
        now=_FIXED_NOW,
    )
    assert result.is_valid

    # Scope coverage check: echo.ping covered, admin.delete not
    scope_set = set(scope_str.split())
    covered, missing = check_scope_coverage(scope_set, ["echo.ping"])
    assert covered is True
    assert missing == []
    covered_admin, missing_admin = check_scope_coverage(
        scope_set, ["admin.delete"]
    )
    assert covered_admin is False
    assert missing_admin == ["admin.delete"]


# ------------------------------------------------------------------
# Onboarding decision payload
# ------------------------------------------------------------------


def test_onboarding_decision_payload() -> None:
    """Build evaluation, decision, verify payload structure matches §7.6.

    Spec: ARSIA-Identity.md §7.6, §8.3.
    """
    policy = _make_policy([
        {"capability": "code.review", "status": "allowed"},
        {"capability": "code.refactor", "status": "oversight_required"},
    ])

    evaluation = evaluate_capability_policy(
        policy,
        requested_capabilities=["code.review", "code.refactor"],
    )
    assert evaluation.is_approved

    decision = build_onboarding_decision(
        agent_id="agent:external.code-reviewer",
        policy=policy,
        evaluation=evaluation,
    )
    assert decision.outcome == "approved"
    assert "code.review" in decision.granted_capabilities

    payload = build_decision_payload(decision)
    # §7.6 contract keys
    assert "decision" in payload
    assert "agent_id" in payload
    assert "freely_allowed" in payload
    assert "effective_capabilities" in payload
    assert "oversight_required" in payload
    assert "token_lifetime_seconds" in payload
    assert "phase" in payload
    # Forbidden keys (transport concerns)
    assert "access_token" not in payload
    assert "jwt" not in payload
    assert "bearer" not in payload


# ------------------------------------------------------------------
# Classification consistency R6 end-to-end
# ------------------------------------------------------------------


def test_classification_consistency_r6_end_to_end() -> None:
    """Build envelope with high-risk, validate_compliance with identity=minimal.

    Spec: ARSIA-Core.md §4.3.8 R6; ARSIA-Identity.md §4.2.
    """
    envelope: dict[str, Any] = {
        "v": "1.0",
        "id": "12345678-0000-4000-8000-000000000001",
        "ts": "2026-04-12T12:00:00.000Z",
        "from": "agent:test.sender",
        "to": "agent:test.receiver",
        "intent": "request",
        "expires_at": "2026-04-12T12:00:30.000Z",
        "capabilities": ["test.action"],
        "payload": {"type": "com.test/action", "args": {}},
        "compliance": {
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
            "profile": "EU-AI-ACT-HIGH-RISK",
        },
    }

    # With identity_classification="minimal-risk", R6 fires
    errors = validate_compliance(
        envelope,
        identity_classification="minimal-risk",
    )
    assert any(e.code == "classification_escalation" for e in errors), f"R6 should fire: {errors}"


# ------------------------------------------------------------------
# Provenance with real timestamps
# ------------------------------------------------------------------


def test_provenance_with_real_timestamps() -> None:
    """verify_provenance with format_timestamp-produced timestamps.

    Spec: ARSIA-Identity.md §7.5.
    """
    now = _FIXED_NOW
    identity_created = format_timestamp(now)
    audit_after = format_timestamp(
        datetime(2026, 4, 12, 12, 5, 0, tzinfo=timezone.utc)
    )

    result = verify_provenance(
        identity_created_at=identity_created,
        earliest_audit_record=audit_after,
    )
    assert result.provenance_verified is True
    assert result.notes == ()


def test_provenance_audit_predates_identity() -> None:
    """Audit record timestamp before identity creation -> warning.

    Spec: ARSIA-Identity.md §7.5.
    """
    identity_created = format_timestamp(
        datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
    )
    audit_before = format_timestamp(
        datetime(2026, 4, 12, 11, 0, 0, tzinfo=timezone.utc)
    )

    result = verify_provenance(
        identity_created_at=identity_created,
        earliest_audit_record=audit_before,
    )
    assert result.provenance_verified is False
    assert any("predates" in note.lower() for note in result.notes)


# ------------------------------------------------------------------
# Reserved capability in policy
# ------------------------------------------------------------------


def test_reserved_capability_in_policy() -> None:
    """validate_capability_policy catches reserved prefix misuse.

    Spec: ARSIA-Actions.md §1.1 rule 5; ARSIA-Identity.md §8.1.
    """
    policy = _make_policy([
        {"capability": "echo.ping", "status": "allowed"},
        {
            "capability": "arsiaprotocol.custom.evil",
            "status": "allowed",
        },
    ])

    errors = validate_capability_policy(policy)
    assert errors, "should catch reserved prefix misuse"
    assert any("reserved" in str(e).lower() for e in errors)


# ------------------------------------------------------------------
# Build JWKS with multiple keys → verify different messages
# ------------------------------------------------------------------


def test_build_jwks_multiple_keys_verify(
    keypair_acme: dict[str, Any],
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Build JWKS with 2 keys, sign with each, verify with corresponding key.

    Spec: ARSIA-Core.md §7.1; ARSIA-Identity.md §2.3.
    """
    pk_a: Ed25519PublicKey = keypair_acme["public_key"]
    sk_a: Ed25519PrivateKey = keypair_acme["private_key"]
    kid_a: str = keypair_acme["kid"]

    pk_b: Ed25519PublicKey = keypair_risk_assessor["public_key"]
    sk_b: Ed25519PrivateKey = keypair_risk_assessor["private_key"]
    kid_b: str = keypair_risk_assessor["kid"]

    jwk_a = build_jwk(pk_a, kid_a)
    jwk_b = build_jwk(pk_b, kid_b)
    jwks = build_jwks([jwk_a, jwk_b])

    assert len(jwks["keys"]) == 2

    # Sign two different messages
    env_a = create_request(
        from_agent="agent:acme.echo-client",
        to_agent="agent:acme.echo-server",
        payload_type="com.acme.echo/ping",
        capabilities=["echo.ping"],
    )
    signed_a = sign_message(env_a, sk_a, kid_a)

    env_b = create_request(
        from_agent="agent:arsialabs.demo.risk-assessor",
        to_agent="agent:arsialabs.demo.compliance-checker",
        payload_type="org.arsiaprotocol.compliance/check",
        capabilities=["compliance.check"],
    )
    signed_b = sign_message(env_b, sk_b, kid_b)

    # Verify each with its own key
    assert verify_message(signed_a, pk_a) is True
    assert verify_message(signed_b, pk_b) is True

    # Cross-verify fails
    assert verify_message(signed_a, pk_b) is False
    assert verify_message(signed_b, pk_a) is False


# ------------------------------------------------------------------
# Profile requirement end-to-end (onboarding + compliance)
# ------------------------------------------------------------------


def test_profile_requirement_onboarding_and_envelope() -> None:
    """Both enforcement points agree: high-risk without profile is rejected.

    Spec: ARSIA-Identity.md §4.2; ARSIA-Core.md §4.3.8 R7.
    """
    # Onboarding-level check (agent-level)
    onb_errors = validate_profile_requirement(
        identity_classification="high-risk",
        declared_profile=None,
        intent="request",
    )
    assert onb_errors, "onboarding should reject high-risk without profile"

    # Envelope-level check (per-message)
    envelope: dict[str, Any] = {
        "v": "1.0",
        "id": "12345678-0000-4000-8000-000000000002",
        "ts": "2026-04-12T12:00:00.000Z",
        "from": "agent:test.sender",
        "to": "agent:test.receiver",
        "intent": "request",
        "expires_at": "2026-04-12T12:00:30.000Z",
        "capabilities": ["test.action"],
        "payload": {"type": "com.test/action", "args": {}},
        "compliance": {
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        },
    }
    comp_errors = validate_compliance(envelope)
    assert any(e.code == "missing_profile" for e in comp_errors), f"R7 should fire: {comp_errors}"

    # Both pass when profile is declared
    onb_ok = validate_profile_requirement(
        identity_classification="high-risk",
        declared_profile="EU-AI-ACT-HIGH-RISK",
        intent="request",
    )
    assert onb_ok == []

    envelope["compliance"]["profile"] = "EU-AI-ACT-HIGH-RISK"
    comp_ok = validate_compliance(envelope)
    assert not any(e.code == "missing_profile" for e in comp_ok)


# ------------------------------------------------------------------
# Capability listing pagination
# ------------------------------------------------------------------


def test_capability_listing_integration() -> None:
    """build_capability_listing works with capabilities checked by actions module.

    Spec: ARSIA-Core.md §7.2; ARSIA-Actions.md §1.1.
    """
    caps = ["echo.ping", "echo.stats", "compliance.check"]
    for cap in caps:
        assert is_valid_capability(cap), f"{cap} should be valid"

    listing = build_capability_listing(
        actions=caps,
        total=len(caps),
        limit=2,
        offset=0,
    )
    assert listing["total"] == 3
    assert listing["limit"] == 2
    assert listing["offset"] == 0
    assert len(listing["actions"]) == 3
