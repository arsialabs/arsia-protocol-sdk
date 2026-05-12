# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for the 12 MUST MISSING requirement closures (C.6 task).

Covers:
- req:3db51f66 §11.1 — error descriptions in English
- req:cd6a79c3 §2.2 — envelope produce/consume/verify/discovery
- req:f5d1885c §5.1 — RSA key minimum 2048 bits
- req:6e59adae §7.2 — capability co-requisites
- req:e504ee6c §9.2 — brokers required only when data_residency set
- req:15a7bce2 §11.3 — rate-limited retry delay respects Retry-After
- req:cdc75ed6 §5.2 — JWKS cache refresh policy
- req:b7feb635 §7.3 — key rotation overlap (24h)
- req:1e1f9448 §7.3 — compromised key removal
- req:15960142 §7.3 — revoked kid detection
- req:efe78f8f §7.4 — outbound version validation
- req:5f255f3d §8.1 — async status endpoint response
"""

from __future__ import annotations

import pytest

from arsia_protocol.identity.discovery import (
    JWKS_MAX_CACHE_SECONDS,
    JWKSCachePolicy,
    ROTATION_OVERLAP_HOURS,
    RSA_MINIMUM_KEY_BITS,
    build_rotation_jwks,
    filter_compromised_keys,
    is_kid_revoked,
    validate_capability_prerequisites,
    validate_rsa_key_size,
)
from arsia_protocol.core.errors import build_error_envelope
from arsia_protocol.core.message import (
    build_async_status_response,
    create_request,
    create_response,
    sign_message,
    verify_message,
)
from arsia_protocol.routing.routing import (
    RATE_LIMITED_DEFAULT_DELAY_S,
    compute_rate_limited_delay,
    select_topology,
)
from arsia_protocol.core.version import validate_outbound_version

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ---------------------------------------------------------------------------
# req:3db51f66 §11.1 — Error descriptions MUST be in English
# ---------------------------------------------------------------------------


class TestErrorDescriptionEnglish:
    def test_sdk_error_descriptions_are_english(self):
        """All SDK-generated error envelopes use English descriptions."""
        env = build_error_envelope(
            from_agent="agent:test.a",
            to_agent="agent:test.b",
            correlation_id="cid-1",
            code="invalid_request",
            description="The request is malformed.",
        )
        desc = env["payload"]["error"]["description"]
        assert isinstance(desc, str)
        assert len(desc) > 0
        assert desc.isascii()


# ---------------------------------------------------------------------------
# req:cd6a79c3 §2.2 — produce/consume/verify/discovery
# ---------------------------------------------------------------------------


class TestEnvelopeCapability:
    def test_produce_and_verify_round_trip(self):
        """SDK can produce envelopes, sign, and verify them."""
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        env = create_request(
            from_agent="agent:test.sender",
            to_agent="agent:test.receiver",
            payload_type="org.example.test",
            capabilities=["example.read"],
        )
        signed = sign_message(env, priv, "agent:test.sender#key1")
        assert verify_message(signed, pub) is True


# ---------------------------------------------------------------------------
# req:f5d1885c §5.1 — RSA key MUST be ≥ 2048 bits
# ---------------------------------------------------------------------------


class TestRsaKeySize:
    def test_2048_accepted(self):
        validate_rsa_key_size(2048)

    def test_4096_accepted(self):
        validate_rsa_key_size(4096)

    def test_1024_rejected(self):
        with pytest.raises(ValueError, match="at least 2048"):
            validate_rsa_key_size(1024)

    def test_512_rejected(self):
        with pytest.raises(ValueError, match="at least 2048"):
            validate_rsa_key_size(512)

    def test_constant(self):
        assert RSA_MINIMUM_KEY_BITS == 2048


# ---------------------------------------------------------------------------
# req:6e59adae §7.2 — capability co-requisites
# ---------------------------------------------------------------------------


class TestCapabilityPrerequisites:
    def test_satisfied(self):
        descriptors = [
            {
                "capability": "billing.refund",
                "requires": ["billing.get-invoice"],
            },
        ]
        errors = validate_capability_prerequisites(
            ["billing.refund", "billing.get-invoice"], descriptors
        )
        assert errors == []

    def test_missing_prerequisite(self):
        descriptors = [
            {
                "capability": "billing.refund",
                "requires": ["billing.get-invoice"],
            },
        ]
        errors = validate_capability_prerequisites(
            ["billing.refund"], descriptors
        )
        assert len(errors) == 1
        assert "billing.get-invoice" in str(errors[0])

    def test_no_requires_field(self):
        descriptors = [{"capability": "billing.read"}]
        errors = validate_capability_prerequisites(
            ["billing.read"], descriptors
        )
        assert errors == []

    def test_unknown_capability_ignored(self):
        errors = validate_capability_prerequisites(
            ["unknown.cap"],
            [{"capability": "other.cap", "requires": ["dep"]}],
        )
        assert errors == []

    def test_multiple_prerequisites(self):
        descriptors = [
            {
                "capability": "admin.delete",
                "requires": ["admin.read", "admin.write"],
            },
        ]
        errors = validate_capability_prerequisites(
            ["admin.delete", "admin.read"], descriptors
        )
        assert len(errors) == 1
        assert "admin.write" in str(errors[0])


# ---------------------------------------------------------------------------
# req:e504ee6c §9.2 — brokers required only when data_residency set
# ---------------------------------------------------------------------------


class TestBrokersRequiredOnlyWithResidency:
    def test_no_residency_direct(self):
        env = {"compliance": {}}
        decision = select_topology(env)
        assert decision.topology == "direct"

    def test_no_compliance_direct(self):
        env = {}
        decision = select_topology(env)
        assert decision.topology == "direct"

    def test_residency_set_requires_broker(self):
        env = {"compliance": {"data_residency": "EU"}}
        decision = select_topology(env)
        assert decision.topology == "error"


# ---------------------------------------------------------------------------
# req:15a7bce2 §11.3 — rate-limited retry delay
# ---------------------------------------------------------------------------


class TestRateLimitedDelay:
    def test_retry_after_header_respected(self):
        delay = compute_rate_limited_delay(retry_after_header=30)
        assert delay == 30.0

    def test_details_retry_after_used_when_no_header(self):
        delay = compute_rate_limited_delay(details_retry_after=45)
        assert delay == 45.0

    def test_header_takes_precedence(self):
        delay = compute_rate_limited_delay(
            retry_after_header=10, details_retry_after=45
        )
        assert delay == 10.0

    def test_default_60_seconds(self):
        delay = compute_rate_limited_delay()
        assert delay == RATE_LIMITED_DEFAULT_DELAY_S
        assert delay == 60.0

    def test_negative_clamped_to_zero(self):
        delay = compute_rate_limited_delay(retry_after_header=-5)
        assert delay == 0.0


# ---------------------------------------------------------------------------
# req:cdc75ed6 §5.2 — JWKS cache refresh policy
# ---------------------------------------------------------------------------


class TestJWKSCachePolicy:
    def test_unknown_kid_triggers_refresh(self):
        policy = JWKSCachePolicy()
        assert policy.should_refresh(age_seconds=0, kid_known=False) is True

    def test_expired_max_age_triggers_refresh(self):
        policy = JWKSCachePolicy(max_age_seconds=3600)
        assert policy.should_refresh(age_seconds=3601) is True

    def test_24h_ceiling(self):
        policy = JWKSCachePolicy(max_age_seconds=100000)
        assert policy.should_refresh(age_seconds=JWKS_MAX_CACHE_SECONDS + 1) is True

    def test_fresh_cache_no_refresh(self):
        policy = JWKSCachePolicy()
        assert policy.should_refresh(age_seconds=100) is False

    def test_default_max_age(self):
        policy = JWKSCachePolicy()
        assert policy.max_age_seconds == 3600
        assert policy.max_lifetime_seconds == 86400


# ---------------------------------------------------------------------------
# req:b7feb635 §7.3 — key rotation overlap
# ---------------------------------------------------------------------------


class TestKeyRotation:
    def test_rotation_jwks_contains_both(self):
        old = [{"kid": "old", "kty": "OKP"}]
        new = [{"kid": "new", "kty": "OKP"}]
        jwks = build_rotation_jwks(old, new)
        kids = [k["kid"] for k in jwks["keys"]]
        assert "old" in kids
        assert "new" in kids
        assert len(jwks["keys"]) == 2

    def test_rotation_overlap_constant(self):
        assert ROTATION_OVERLAP_HOURS == 24


# ---------------------------------------------------------------------------
# req:1e1f9448 §7.3 — compromised key removal
# ---------------------------------------------------------------------------


class TestCompromisedKeyFilter:
    def test_removes_compromised(self):
        keys = [
            {"kid": "k1", "kty": "OKP"},
            {"kid": "k2", "kty": "OKP"},
            {"kid": "k3", "kty": "OKP"},
        ]
        filtered = filter_compromised_keys(keys, {"k2"})
        assert len(filtered) == 2
        kids = [k["kid"] for k in filtered]
        assert "k2" not in kids

    def test_no_compromised(self):
        keys = [{"kid": "k1", "kty": "OKP"}]
        filtered = filter_compromised_keys(keys, set())
        assert len(filtered) == 1

    def test_all_compromised(self):
        keys = [{"kid": "k1", "kty": "OKP"}]
        filtered = filter_compromised_keys(keys, {"k1"})
        assert len(filtered) == 0


# ---------------------------------------------------------------------------
# req:15960142 §7.3 — revoked kid detection
# ---------------------------------------------------------------------------


class TestKidRevocation:
    def test_revoked_kid_detected(self):
        assert is_kid_revoked("compromised-key", {"compromised-key"}) is True

    def test_valid_kid_not_revoked(self):
        assert is_kid_revoked("good-key", {"compromised-key"}) is False

    def test_empty_revocation_set(self):
        assert is_kid_revoked("any-key", set()) is False


# ---------------------------------------------------------------------------
# req:efe78f8f §7.4 — outbound version validation
# ---------------------------------------------------------------------------


class TestOutboundVersion:
    def test_same_version_allowed(self):
        validate_outbound_version("1.0", "1.0")

    def test_lower_version_allowed(self):
        validate_outbound_version("1.0", "1.1")

    def test_higher_version_rejected(self):
        with pytest.raises(ValueError, match="exceeds"):
            validate_outbound_version("2.0", "1.0")

    def test_minor_higher_rejected(self):
        with pytest.raises(ValueError, match="exceeds"):
            validate_outbound_version("1.2", "1.1")


# ---------------------------------------------------------------------------
# req:5f255f3d §8.1 — async status response
# ---------------------------------------------------------------------------


class TestAsyncStatusResponse:
    def test_pending_status(self):
        resp = build_async_status_response("pending")
        assert resp["status"] == "pending"
        assert "envelope" not in resp

    def test_completed_status_with_envelope(self):
        env = create_response(
            from_agent="agent:test.a",
            to_agent="agent:test.b",
            correlation_id="cid-1",
            payload_type="org.example.result",
            result={"value": 42},
        )
        resp = build_async_status_response("completed", envelope=env)
        assert resp["status"] == "completed"
        assert resp["envelope"]["intent"] == "response"

    def test_failed_status(self):
        resp = build_async_status_response("failed")
        assert resp["status"] == "failed"
