# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA Protocol SDK — Security Tests

Adversarial tests that attempt to BREAK the SDK's security guarantees.
Every test documents: property, spec reference, attack vector, expected result.

Run: cd python && pytest tests/security/ -v
"""

from __future__ import annotations

import copy
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key as ec_generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey as CryptoEd25519PrivateKey,
)

from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
from arsia_protocol.core.message import (
    check_envelope_size,
    create_request,
    is_expired,
    sign_message,
    verify_message,
)
from arsia_protocol.core.validation import validate_envelope
from arsia_protocol.identity.agent_id import is_valid_agent_id, validate_agent_id
from arsia_protocol.actions.actions import (
    EXPLICIT_GRANT_ONLY,
    is_reserved_capability,
    is_reserved_prefix_misuse,
    is_valid_capability,
    match_capability,
    validate_capability,
)
from arsia_protocol.core.compliance import apply_profile, validate_compliance
from arsia_protocol.identity.onboarding import is_classification_consistent
from arsia_protocol.state.audit import compute_payload_hash
from arsia_protocol.identity.discovery import build_ec_jwk, build_jwk
from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload

FROM_AGENT = "agent:testorg.sender"
TO_AGENT = "agent:testorg.receiver"
KID = f"{FROM_AGENT}#sign-1"


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
def ed_keys_a():
    priv, pub = generate_keypair()
    return priv, pub


@pytest.fixture(scope="module")
def ed_keys_b():
    priv, pub = generate_keypair()
    return priv, pub


@pytest.fixture(scope="module")
def ec_keys():
    priv = ec_generate_private_key(SECP256R1())
    pub = priv.public_key()
    return priv, pub


@pytest.fixture()
def signed_request(ed_keys_a):
    priv, pub = ed_keys_a
    env = create_request(
        FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        args={"key": "value"},
    )
    return sign_message(env, priv, KID)


# ===========================================================================
# Category 1 — Cryptographic integrity (SEC-01 through SEC-09)
# ===========================================================================


class TestCryptoIntegrity:
    """Signature tampering and integrity tests — Core §5.1, §5.2."""

    def test_sec_01_tampered_payload(self, signed_request, ed_keys_a):
        """SEC-01: Tampered payload rejected after signing.
        Property: Signature covers entire envelope minus security object
        Spec: ARSIA-Core §5.1, §5.2
        Attack: Attacker modifies payload.args after sender signs
        Expected: verify_message returns False
        """
        _, pub = ed_keys_a
        tampered = copy.deepcopy(signed_request)
        tampered["payload"]["args"]["key"] = "TAMPERED"
        assert verify_message(tampered, pub) is False

    def test_sec_02_tampered_from(self, signed_request, ed_keys_a):
        """SEC-02: Tampered from field rejected.
        Property: Signature covers from — attacker cannot impersonate
        Spec: ARSIA-Core §5.1
        Attack: Change from to a different agent after signing
        """
        _, pub = ed_keys_a
        tampered = copy.deepcopy(signed_request)
        tampered["from"] = "agent:evil.attacker"
        assert verify_message(tampered, pub) is False

    def test_sec_03_tampered_to(self, signed_request, ed_keys_a):
        """SEC-03: Tampered to field rejected.
        Property: Signature covers to — attacker cannot redirect
        Spec: ARSIA-Core §5.1
        Attack: Change to to redirect the message
        """
        _, pub = ed_keys_a
        tampered = copy.deepcopy(signed_request)
        tampered["to"] = "agent:evil.redirect"
        assert verify_message(tampered, pub) is False

    def test_sec_04_tampered_capabilities(self, signed_request, ed_keys_a):
        """SEC-04: Tampered capabilities rejected.
        Property: Signature covers capabilities — attacker cannot escalate
        Spec: ARSIA-Core §5.1, §13.2.3
        Attack: Add extra capability after signing
        """
        _, pub = ed_keys_a
        tampered = copy.deepcopy(signed_request)
        tampered["capabilities"].append("admin.delete")
        assert verify_message(tampered, pub) is False

    def test_sec_05_tampered_expires_at(self, signed_request, ed_keys_a):
        """SEC-05: Tampered expires_at rejected.
        Property: Signature covers expires_at — attacker cannot extend replay window
        Spec: ARSIA-Core §5.1, §13.2.2
        Attack: Extend expires_at by 1 hour
        """
        _, pub = ed_keys_a
        tampered = copy.deepcopy(signed_request)
        tampered["expires_at"] = _future_ms(7200)
        assert verify_message(tampered, pub) is False

    def test_sec_06_wrong_key(self, signed_request, ed_keys_b):
        """SEC-06: Wrong key rejected.
        Property: Signature bound to specific keypair
        Spec: ARSIA-Core §5.2
        Attack: Verify with a different key
        """
        _, pub_b = ed_keys_b
        assert verify_message(signed_request, pub_b) is False

    def test_sec_07_empty_signature(self, signed_request, ed_keys_a):
        """SEC-07: Empty signature rejected.
        Property: Envelope without valid signature must not verify
        Spec: ARSIA-Core §5.2
        Attack: Submit message with empty signature
        """
        _, pub = ed_keys_a
        tampered = copy.deepcopy(signed_request)
        tampered["security"]["sig"] = ""
        try:
            result = verify_message(tampered, pub)
            assert result is False
        except Exception:
            pass  # raising is also acceptable

    def test_sec_08_cross_message_signature(self, ed_keys_a):
        """SEC-08: Signature from different message rejected.
        Property: Signature bound to specific message content
        Spec: ARSIA-Core §5.1, §5.2
        Attack: Copy signature from message A to message B
        """
        priv, pub = ed_keys_a
        env_a = create_request(FROM_AGENT, TO_AGENT, "org.test/a", ["a.read"])
        env_b = create_request(FROM_AGENT, TO_AGENT, "org.test/b", ["b.write"])
        signed_a = sign_message(env_a, priv, KID)
        signed_b = sign_message(env_b, priv, KID)
        signed_b["security"]["sig"] = signed_a["security"]["sig"]
        assert verify_message(signed_b, pub) is False

    def test_sec_09_re_signing(self, ed_keys_a, ed_keys_b):
        """SEC-09: Re-signing replaces signature correctly.
        Property: After re-signing with key B, key A must fail
        Spec: ARSIA-Core §5.1
        Attack: Verifier trusts old key after rotation
        """
        priv_a, pub_a = ed_keys_a
        priv_b, pub_b = ed_keys_b
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/re", ["test.read"])
        signed = sign_message(env, priv_a, KID)
        assert verify_message(signed, pub_a) is True

        re_signed = sign_message(signed, priv_b, f"{FROM_AGENT}#sign-2")
        assert verify_message(re_signed, pub_b) is True
        assert verify_message(re_signed, pub_a) is False


# ===========================================================================
# Category 2 — Key confusion and leakage (SEC-10 through SEC-14)
# ===========================================================================


class TestKeyConfusion:
    """Key type misuse and private key leakage — Core §5.3, §7.3."""

    def test_sec_10_ed25519_for_encryption(self, ed_keys_a):
        """SEC-10: Ed25519 key cannot be used for encryption.
        Property: Ed25519 is signing-only; encryption requires P-256
        Spec: ARSIA-Core §5.3, §7.3
        Attack: Provide Ed25519 key where P-256 expected
        """
        _, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/enc", ["test.read"])
        bad_jwk = build_jwk(pub, f"{TO_AGENT}#enc-bad", use="enc")
        with pytest.raises(Exception):
            encrypt_payload(env, {"keys": [bad_jwk]})

    def test_sec_11_ec_for_signing(self, ec_keys):
        """SEC-11: EC key cannot be used for signing.
        Property: P-256 is encryption-only; signing requires Ed25519
        Spec: ARSIA-Core §5.1
        Attack: Provide P-256 key where Ed25519 expected
        """
        ec_priv, _ = ec_keys
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/sig", ["test.read"])
        with pytest.raises(Exception):
            sign_message(env, ec_priv, KID)  # type: ignore[arg-type]

    def test_sec_12_jwk_no_private_key(self, ed_keys_a, ec_keys):
        """SEC-12: JWK output excludes private key material (d parameter).
        Property: Public JWK MUST NOT contain d
        Spec: ARSIA-Identity §6.8, ARSIA-Core §7.3
        Attack: Leaking d exposes private key
        """
        _, ed_pub = ed_keys_a
        _, ec_pub = ec_keys
        assert "d" not in build_jwk(ed_pub, f"{FROM_AGENT}#sig-1")
        assert "d" not in build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1")

    def test_sec_13_private_key_rejected_by_jwk(self, ed_keys_a):
        """SEC-13: Private key rejected by build_jwk.
        Property: build_jwk accepts only public keys
        Spec: ARSIA-Identity §6.8
        Attack: Developer accidentally passes private key
        """
        priv, _ = ed_keys_a
        with pytest.raises(Exception):
            build_jwk(priv, f"{FROM_AGENT}#sig-priv")  # type: ignore[arg-type]

    def test_sec_14_wrong_recipient_decrypt(self, ed_keys_a, ec_keys):
        """SEC-14: Wrong recipient key fails on decrypt.
        Property: Only intended recipient can decrypt
        Spec: ARSIA-Core §5.3
        Attack: Attacker intercepts and decrypts with own key
        """
        priv, pub = ed_keys_a
        _, ec_pub = ec_keys
        rec_jwks = {"keys": [build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1", use="enc")]}

        env = create_request(FROM_AGENT, TO_AGENT, "org.test/enc", ["test.read"],
                             args={"secret": "classified"})
        encrypted = encrypt_payload(env, rec_jwks)
        signed = sign_message(encrypted, priv, KID)

        wrong_ec = ec_generate_private_key(SECP256R1())
        with pytest.raises(Exception):
            decrypt_and_verify(signed, pub, wrong_ec)


# ===========================================================================
# Category 3 — Capability and authorization bypass (SEC-15 through SEC-21)
# ===========================================================================


class TestCapabilityBypass:
    """Wildcard, reserved prefix, injection — Actions §1.1, §1.2, §1.4."""

    def test_sec_15_wildcard_direction(self):
        """SEC-15: Specific scope never satisfies wildcard request.
        Spec: ARSIA-Actions §1.2
        Attack: Scope notes.read requests notes.* (escalation)
        """
        assert match_capability("notes.read", "notes.*") is False

    def test_sec_16_empty_capability(self):
        """SEC-16: Empty capability rejected.
        Spec: ARSIA-Actions §1.1
        """
        assert is_valid_capability("") is False
        assert len(validate_capability("")) > 0

    def test_sec_17_dots_only_capability(self):
        """SEC-17: Dots-only capability rejected.
        Spec: ARSIA-Actions §1.1
        """
        assert is_valid_capability("...") is False

    def test_sec_18_reserved_prefix(self):
        """SEC-18: Reserved capability prefix detected.
        Spec: ARSIA-Actions §1.4
        """
        assert is_reserved_capability("arsiaprotocol.state.read") is True
        assert is_reserved_prefix_misuse("arsiaprotocol.internal.custom") is True
        assert is_reserved_prefix_misuse("myapp.normal") is False

    def test_sec_19_wildcard_on_reserved(self):
        """SEC-19: Wildcard scope matches non-explicit-grant reserved capabilities.
        Spec: ARSIA-Actions §1.2, §1.4
        """
        assert match_capability("arsiaprotocol.state.*", "arsiaprotocol.state.read") is True
        assert match_capability("arsiaprotocol.state.*", "arsiaprotocol.state.write") is True

    def test_sec_20_explicit_grant_only(self):
        """SEC-20: EXPLICIT_GRANT_ONLY caps immune to wildcards.
        Spec: ARSIA-Actions §1.4
        Attack: Wildcard scope attempts purge/snapshot/oversight
        """
        for cap in EXPLICIT_GRANT_ONLY:
            prefix = ".".join(cap.split(".")[:-1]) + ".*"
            assert match_capability(prefix, cap) is False, \
                f"Wildcard {prefix} must NOT satisfy {cap}"

    def test_sec_21_special_char_injection(self):
        """SEC-21: Special character injection in capabilities.
        Spec: ARSIA-Actions §1.1
        Attack: Newlines, null bytes, path traversal in capabilities
        """
        vectors = [
            "notes.read\nnotes.admin",
            "notes.read\x00admin",
            "notes/../../etc/passwd",
            "notes.read; DROP TABLE",
            "notes.read\tnotes.admin",
        ]
        for v in vectors:
            assert len(validate_capability(v)) > 0, f"Must reject: {v!r}"


# ===========================================================================
# Category 4 — Input validation and fuzzing (SEC-22 through SEC-28)
# ===========================================================================


class TestInputValidation:
    """Agent-ID, envelope, timestamp, canonicalization — Core §3.3, §4."""

    def test_sec_22_oversized_agent_id(self):
        """SEC-22: Agent-ID exceeding 256 characters rejected.
        Spec: ARSIA-Core §3.3
        """
        long_id = f"agent:testorg.{'a' * 250}"
        assert len(long_id) > 256
        assert is_valid_agent_id(long_id) is False
        assert len(validate_agent_id(long_id)) > 0

    def test_sec_23_special_chars_agent_id(self):
        """SEC-23: Special characters in agent-ID rejected.
        Spec: ARSIA-Core §3.3
        """
        bad_ids = [
            "agent:test org.sender",
            "agent:test\norg.sender",
            "agent:test\x00org.sender",
            "agent:test/../../../etc",
            "agent:test%00org.sender",
        ]
        for bad_id in bad_ids:
            assert is_valid_agent_id(bad_id) is False, f"Must reject: {bad_id!r}"

    def test_sec_24_non_dict_validate_envelope(self):
        """SEC-24: Non-dict input to validate_envelope.
        Spec: ARSIA-Core §4
        """
        for bad_input in [None, "string", [1, 2, 3], 42, True]:
            try:
                errors = validate_envelope(bad_input)  # type: ignore[arg-type]
                assert len(errors) > 0
            except (TypeError, AttributeError):
                pass

    def test_sec_25_extra_fields(self):
        """SEC-25: Extra unknown fields in envelope handled.
        Spec: ARSIA-Core §4
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"])
        env["__injected_field"] = "evil"
        env["admin_override"] = True
        validate_envelope(env)  # must not crash

    def test_sec_26_oversized_payload(self):
        """SEC-26: Oversized payload detected.
        Spec: ARSIA-Core §4.5
        Attack: >1MB payload for DoS
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
            args={"data": "x" * (1024 * 1024)},
        )
        within_limit, actual_size = check_envelope_size(env)
        assert within_limit is False
        assert actual_size > 1048576

    def test_sec_27_malformed_timestamps(self):
        """SEC-27: Malformed timestamps rejected.
        Spec: ARSIA-Core §4.1.3
        """
        for bad_ts in [1700000000, "2026-01-01T00:00:00+05:00", "",
                       "'; DROP TABLE messages; --"]:
            env = create_request(FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"])
            env["ts"] = bad_ts
            assert len(validate_envelope(env)) > 0, f"Must reject ts={bad_ts!r}"

    def test_sec_28_canonical_hash_determinism(self):
        """SEC-28: Canonical hash determinism under adversarial input.
        Spec: ARSIA-Core §5.3.1
        """
        assert compute_payload_hash({"key": "value", "num": 42}) == \
               compute_payload_hash({"num": 42, "key": "value"})

        deep = {"a": "b"}
        for _ in range(50):
            deep = {"nested": deep}
        assert len(compute_payload_hash(deep)) == 64

        long_val = {"value": "x" * 100000}
        assert compute_payload_hash(long_val) == compute_payload_hash(long_val)


# ===========================================================================
# Category 5 — PII and GDPR enforcement (SEC-29 through SEC-33)
# ===========================================================================


class TestPiiGdpr:
    """PII rules, Art. 9, classification escalation — Core §4.3.8, State §2.1."""

    def test_sec_29_pii_forces_audit_required(self):
        """SEC-29: pii_involved=true forces audit_required=true.
        Spec: ARSIA-Core §4.3.8 Rule 7
        Attack: Send PII without audit trail
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/pii", ["test.read"],
            compliance={
                "profile": "GDPR-STANDARD",
                "pii_involved": True,
                "audit_required": False,
                "legal_basis": "consent",
            },
        )
        applied = apply_profile(env)
        comp = applied.get("compliance", {})
        if comp.get("audit_required") is not True:
            errors = validate_compliance(applied)
            assert any(
                "pii" in str(getattr(e, "message", "")).lower()
                or "audit" in str(getattr(e, "message", "")).lower()
                for e in errors
            ), "PII must force audit_required"

    def test_sec_30_sensitive_pii_without_art9(self):
        """SEC-30: Sensitive PII without Art. 9 legal basis rejected.
        Spec: ARSIA-State §2.1.10, GDPR Art. 9
        Attack: Classify data as sensitive but use Art. 6 basis
        """
        from arsia_protocol.state.state import validate_state_entry
        from arsia_protocol.types.state import StateEntry

        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/test.sensitive",
            value="sensitive-health-data",
            owner_agent_id=FROM_AGENT, scope="agent",
            created_at=_now_ms(), updated_at=_now_ms(),
            pii_classification="sensitive",
            pii_special_categories=["health"], version=1,
        )
        errors = validate_state_entry(
            entry, sender_agent_id=FROM_AGENT,
            envelope_compliance={"legal_basis": "consent", "data_residency": "DE"},
        )
        assert any(
            any(kw in str(getattr(e, "message", "")).lower()
                for kw in ("legal_basis", "art", "sensitive", "special", "explicit"))
            for e in errors
        ), f"Sensitive PII with Art. 6 basis must be rejected. Errors: {errors}"

    def test_sec_31_sensitive_pii_with_art9(self):
        """SEC-31: Sensitive PII with valid Art. 9 basis accepted.
        Spec: ARSIA-State §2.1.10, GDPR Art. 9(2)(a)
        """
        from arsia_protocol.state.state import validate_state_entry
        from arsia_protocol.types.state import StateEntry

        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/test.sensitive.ok",
            value="sensitive-health-data",
            owner_agent_id=FROM_AGENT, scope="agent",
            created_at=_now_ms(), updated_at=_now_ms(),
            pii_classification="sensitive",
            pii_special_categories=["health"], version=1,
        )
        errors = validate_state_entry(
            entry, sender_agent_id=FROM_AGENT,
            envelope_compliance={"legal_basis": "explicit_consent", "data_residency": "DE"},
        )
        pii_errors = [
            e for e in errors
            if any(kw in str(getattr(e, "message", "")).lower()
                   for kw in ("legal_basis", "special"))
        ]
        assert len(pii_errors) == 0, f"Art. 9 explicit_consent must pass. Errors: {pii_errors}"

    def test_sec_32_classification_escalation(self):
        """SEC-32: Classification escalation blocked.
        Spec: ARSIA-Core §4.3.8 Rule 6
        Attack: minimal-risk agent sends high-risk per-message classification
        """
        assert is_classification_consistent("high-risk", "minimal-risk") is False
        assert is_classification_consistent("minimal-risk", "high-risk") is True
        assert is_classification_consistent("high-risk", "high-risk") is True

    def test_sec_33_error_no_pii_leak(self):
        """SEC-33: Error messages do not leak PII data.
        Spec: ARSIA-Core §13.3
        Attack: Trigger validation error to extract PII from error output
        """
        from arsia_protocol.state.state import validate_state_entry
        from arsia_protocol.types.state import StateEntry

        pii_value = "SUPER_SECRET_SSN_123-45-6789"
        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/test.pii.leak",
            value=pii_value, owner_agent_id=FROM_AGENT,
            scope="agent", created_at=_now_ms(), updated_at=_now_ms(),
            pii_classification="personal", version=1,
        )
        errors = validate_state_entry(
            entry, sender_agent_id="agent:evil.attacker",
            envelope_compliance={"legal_basis": "consent", "data_residency": "DE"},
        )
        assert len(errors) > 0
        for e in errors:
            assert pii_value not in str(e)
            if hasattr(e, "details"):
                assert pii_value not in str(e.details)


# ===========================================================================
# Category 6 — Timestamp and expiration (SEC-34 through SEC-38)
# ===========================================================================


class TestTimestampExpiration:
    """Clock skew, expiration, future timestamps — Core §4.2.2, §8.3."""

    def test_sec_34_expired_message(self):
        """SEC-34: Expired message detected.
        Spec: ARSIA-Core §4.2.2, §8.3
        Attack: Replay expired message
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/exp", ["test.read"],
                             expires_in_seconds=1)
        past = datetime.now(timezone.utc) - timedelta(seconds=600)
        env["ts"] = past.strftime("%Y-%m-%dT%H:%M:%S.") + f"{past.microsecond // 1000:03d}Z"
        env["expires_at"] = (past + timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.") + f"{past.microsecond // 1000:03d}Z"
        assert is_expired(env, clock_skew_seconds=0) is True

    def test_sec_35_clock_skew_boundary(self):
        """SEC-35: Clock skew boundary — strict >.
        Spec: ARSIA-Core §8.3
        Attack: Replay at exact boundary of tolerance
        """
        now = datetime(2026, 5, 7, 12, 0, 0, 0, tzinfo=timezone.utc)
        boundary = now - timedelta(seconds=300)
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/boundary", ["test.read"])
        env["expires_at"] = boundary.strftime(
            "%Y-%m-%dT%H:%M:%S.") + f"{boundary.microsecond // 1000:03d}Z"

        assert is_expired(env, clock_skew_seconds=300, now=now) is False
        assert is_expired(env, clock_skew_seconds=300,
                          now=now + timedelta(seconds=1)) is True

    def test_sec_36_beyond_clock_skew(self):
        """SEC-36: Beyond clock skew is expired.
        Spec: ARSIA-Core §8.3
        """
        now = datetime.now(timezone.utc)
        expired = now - timedelta(seconds=301)
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/beyond", ["test.read"])
        env["expires_at"] = expired.strftime(
            "%Y-%m-%dT%H:%M:%S.") + f"{expired.microsecond // 1000:03d}Z"
        assert is_expired(env, clock_skew_seconds=300, now=now) is True

    def test_sec_37_future_within_skew(self):
        """SEC-37: Future timestamp within clock skew accepted.
        Spec: ARSIA-Core §8.3
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/future", ["test.read"])
        future = datetime.now(timezone.utc) + timedelta(seconds=299)
        env["ts"] = future.strftime("%Y-%m-%dT%H:%M:%S.") + \
                    f"{future.microsecond // 1000:03d}Z"
        ts_errors = [
            e for e in validate_envelope(env)
            if any(kw in str(getattr(e, "field", "")).lower()
                   for kw in ("ts", "future", "clock"))
        ]
        assert len(ts_errors) == 0

    def test_sec_38_far_future(self):
        """SEC-38: Far-future timestamp handled gracefully.
        Spec: ARSIA-Core §8.3
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/farfuture", ["test.read"])
        far = datetime.now(timezone.utc) + timedelta(seconds=600)
        env["ts"] = far.strftime("%Y-%m-%dT%H:%M:%S.") + \
                    f"{far.microsecond // 1000:03d}Z"
        validate_envelope(env)  # must not crash


# ===========================================================================
# Category 7 — JWE encryption integrity (SEC-39 through SEC-42)
# ===========================================================================


class TestJweIntegrity:
    """Ciphertext/header tampering, encrypt-then-sign — Core §5.3."""

    @pytest.fixture()
    def encrypted_signed(self, ed_keys_a, ec_keys):
        priv, pub = ed_keys_a
        ec_priv, ec_pub = ec_keys
        rec_jwks = {"keys": [build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1", use="enc")]}
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/jwe", ["test.read"],
                             args={"secret": "classified"})
        encrypted = encrypt_payload(env, rec_jwks)
        signed = sign_message(encrypted, priv, KID)
        return signed, pub, ec_priv, rec_jwks

    def test_sec_39_tampered_ciphertext(self, encrypted_signed):
        """SEC-39: Tampered JWE ciphertext rejected.
        Spec: ARSIA-Core §5.3
        """
        signed, pub, ec_priv, _ = encrypted_signed
        tampered = copy.deepcopy(signed)
        if isinstance(tampered["payload"], str):
            parts = tampered["payload"].split(".")
            if len(parts) >= 4 and len(parts[3]) > 10:
                ct = list(parts[3])
                ct[5] = "A" if ct[5] != "A" else "B"
                parts[3] = "".join(ct)
                tampered["payload"] = ".".join(parts)
        with pytest.raises(Exception):
            decrypt_and_verify(tampered, pub, ec_priv)

    def test_sec_40_tampered_header(self, encrypted_signed):
        """SEC-40: Tampered JWE header rejected.
        Spec: ARSIA-Core §5.3
        """
        signed, pub, ec_priv, _ = encrypted_signed
        tampered = copy.deepcopy(signed)
        if isinstance(tampered["payload"], str):
            parts = tampered["payload"].split(".")
            if len(parts) >= 5:
                try:
                    hdr_b64 = parts[0]
                    pad = 4 - len(hdr_b64) % 4
                    hdr_bytes = base64.urlsafe_b64decode(
                        hdr_b64 + "=" * (pad if pad != 4 else 0))
                    hdr = json.loads(hdr_bytes)
                    hdr["tampered"] = True
                    parts[0] = base64.urlsafe_b64encode(
                        json.dumps(hdr).encode()).rstrip(b"=").decode()
                except Exception:
                    parts[0] = parts[0] + "XX"
                tampered["payload"] = ".".join(parts)
        with pytest.raises(Exception):
            decrypt_and_verify(tampered, pub, ec_priv)

    def test_sec_41_valid_sig_wrong_enc_key(self, encrypted_signed):
        """SEC-41: Valid signature but wrong decryption key.
        Spec: ARSIA-Core §5.2, §5.3
        """
        signed, pub, _, _ = encrypted_signed
        assert verify_message(signed, pub) is True
        wrong_ec = ec_generate_private_key(SECP256R1())
        with pytest.raises(Exception):
            decrypt_and_verify(signed, pub, wrong_ec)

    def test_sec_42_sign_then_encrypt_order(self, ed_keys_a, ec_keys):
        """SEC-42: Sign-then-encrypt produces invalid result.
        Spec: ARSIA-Core §5.3 point 4
        Attack: Sign before encrypting — signature covers plaintext, not JWE
        """
        priv, pub = ed_keys_a
        _, ec_pub = ec_keys
        rec_jwks = {"keys": [build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1", use="enc")]}

        env = create_request(FROM_AGENT, TO_AGENT, "org.test/order", ["test.read"],
                             args={"data": "test"})
        signed_first = sign_message(env, priv, KID)
        encrypted_after = encrypt_payload(signed_first, rec_jwks)

        ec_priv = ec_keys[0]
        with pytest.raises(Exception):
            decrypt_and_verify(encrypted_after, pub, ec_priv)


# ===========================================================================
# Category 8 — Replay and idempotency (SEC-43 through SEC-44)
# ===========================================================================


class TestReplayIdempotency:
    """Duplicate detection and pending reservation — Core §10, §13.2.2."""

    def test_sec_43_duplicate_idem_key(self):
        """SEC-43: Duplicate idempotency key rejected.
        Spec: ARSIA-Core §10, §13.2.2
        Attack: Replay signed message with same idempotency key
        """
        from arsia_protocol.core.idempotency import (
            DuplicateIdempotencyKey,
            IdempotencyRecord,
        )
        from tests.fixtures.in_memory_idempotency_store import InMemoryIdempotencyStore
        store = InMemoryIdempotencyStore()
        record = IdempotencyRecord(
            key="replay-key-001", from_agent=FROM_AGENT,
            to_agent=TO_AGENT, payload_type="org.test/replay",
            message_id="msg-001", stored_at=_now_ms(),
            expires_at=_future_ms(3600),
        )
        store.put(record)

        record2 = IdempotencyRecord(
            key="replay-key-001", from_agent=FROM_AGENT,
            to_agent=TO_AGENT, payload_type="org.test/replay",
            message_id="msg-002", stored_at=_now_ms(),
            expires_at=_future_ms(3600),
        )
        with pytest.raises(DuplicateIdempotencyKey):
            store.put(record2)

    def test_sec_44_pending_blocks_concurrent(self):
        """SEC-44: Pending reservation blocks second request.
        Spec: ARSIA-Core §10.3 Rule 4
        Attack: Two identical requests concurrently
        """
        from arsia_protocol.core.idempotency import IdempotencyScope
        from tests.fixtures.in_memory_idempotency_store import InMemoryIdempotencyStore
        store = InMemoryIdempotencyStore()
        scope = IdempotencyScope(
            from_agent=FROM_AGENT, to_agent=TO_AGENT,
            payload_type="org.test/concurrent",
        )
        assert store.mark_pending(scope, "concurrent-001") is True
        assert store.mark_pending(scope, "concurrent-001") is False


# ===========================================================================
# Category 9 — kid substitution and relaxed mode (SEC-45 through SEC-46)
# ===========================================================================


class TestKidRelaxed:
    """kid-swap detection and relaxed mode — Core §5.1, §5.2, Identity §3.1."""

    def test_sec_45_kid_substitution(self, ed_keys_a):
        """SEC-45: kid substitution detected by validate_envelope.
        Spec: ARSIA-Core §5.1 Step 6
        Attack: Swap kid to point to a different agent's key
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/kid", ["test.read"])
        signed = sign_message(env, priv, KID)

        tampered = copy.deepcopy(signed)
        tampered["security"]["kid"] = "agent:evil.attacker#stolen-key"

        # verify_message passes (kid not in signed bytes — by design)
        assert verify_message(tampered, pub) is True

        # validate_envelope catches kid_prefix_mismatch
        errors = validate_envelope(tampered)
        assert any(
            any(kw in str(getattr(e, "code", "")).lower() + str(getattr(e, "message", "")).lower()
                for kw in ("kid", "prefix"))
            for e in errors
        ), f"Must detect kid_prefix_mismatch. Errors: {errors}"

    def test_sec_46_relaxed_mode(self, ed_keys_a):
        """SEC-46: relaxed=True bypasses verification.
        Spec: ARSIA-Identity §3.1
        Attack: Production code left with relaxed=True
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/relaxed", ["test.read"])
        signed = sign_message(env, priv, KID)

        tampered = copy.deepcopy(signed)
        tampered["payload"]["args"] = {"tampered": True}

        assert verify_message(tampered, pub) is False
        assert verify_message(tampered, pub, relaxed=True) is True


# ===========================================================================
# Category 10 — DPoP and JWT (SEC-47 through SEC-49)
# ===========================================================================


class TestDpopJwt:
    """Token expiry, wrong-key JWT, DPoP replay — Core §6.4, Identity §3.3."""

    @pytest.fixture(scope="class")
    def as_keys(self):
        return generate_keypair()

    @pytest.fixture(scope="class")
    def agent_keys(self):
        return generate_keypair()

    def test_sec_47_expired_jwt(self, as_keys):
        """SEC-47: Expired JWT token rejected.
        Spec: ARSIA-Core §6.4 step 4
        Attack: Reuse captured token after exp
        """
        from arsia_protocol.core.authorization import (
            build_jwt, validate_token_claims, verify_jwt_signature,
        )
        priv, pub = as_keys
        now_epoch = int(time.time())

        token = build_jwt({
            "iss": "https://as.example.com", "sub": FROM_AGENT,
            "aud": TO_AGENT, "iat": now_epoch - 7200,
            "exp": now_epoch - 3600, "scope": "test.read",
        }, priv)

        assert verify_jwt_signature(token, pub) is True
        result = validate_token_claims(token, pub, expected_sub=FROM_AGENT,
                                       clock_skew_seconds=300)
        assert result.is_valid is False
        assert any("exp" in str(e).lower() or "expir" in str(e).lower()
                    for e in result.errors)

    def test_sec_48_jwt_wrong_key(self, as_keys):
        """SEC-48: JWT signed by wrong key rejected.
        Spec: ARSIA-Core §6.4 step 2
        Attack: Attacker mints token with own key
        """
        from arsia_protocol.core.authorization import build_jwt, verify_jwt_signature
        _, pub = as_keys
        other_priv, _ = generate_keypair()
        now_epoch = int(time.time())

        forged = build_jwt({
            "iss": "https://as.example.com", "sub": FROM_AGENT,
            "iat": now_epoch, "exp": now_epoch + 3600, "scope": "test.read",
        }, other_priv)
        assert verify_jwt_signature(forged, pub) is False

    def test_sec_49_dpop_replay(self, as_keys, agent_keys):
        """SEC-49: DPoP proof replay detected.
        Spec: ARSIA-Identity §3.3 step 8
        Attack: Replay captured DPoP proof
        """
        from arsia_protocol.core.authorization import (
            build_dpop_proof, build_jwt, validate_dpop_proof,
        )
        as_priv, _ = as_keys
        ag_priv, ag_pub = agent_keys
        now_epoch = int(time.time())
        htu = "https://agent.example.com/arsia/inbox"

        access_token = build_jwt({
            "sub": FROM_AGENT, "iat": now_epoch,
            "exp": now_epoch + 300, "scope": "test.read",
        }, as_priv)

        proof = build_dpop_proof(
            ag_priv, ag_pub, htu=htu, access_token=access_token,
            jti="unique-jti-001", iat=now_epoch,
        )

        seen_jti: set[str] = set()
        r1 = validate_dpop_proof(proof, access_token, expected_htu=htu,
                                 seen_jti=seen_jti)
        if r1.is_valid:
            seen_jti.add("unique-jti-001")

        r2 = validate_dpop_proof(proof, access_token, expected_htu=htu,
                                 seen_jti=seen_jti)
        assert r2.is_valid is False
        assert any("jti" in str(e).lower() or "replay" in str(e).lower()
                    for e in r2.errors)


# ===========================================================================
# Category 11 — Canonicalization edge cases (SEC-50)
# ===========================================================================


class TestCanonicalization:
    """RFC 8785 numeric, unicode, ordering — Core §5.1 Step 3."""

    def test_sec_50_edge_cases(self):
        """SEC-50: RFC 8785 edge cases.
        Spec: ARSIA-Core §5.1 Step 3, RFC 8785
        Attack: Craft payloads with unusual representations
        """
        from arsia_protocol.hazmat.canonicalization import canonicalize

        assert len(compute_payload_hash({"amount": 1})) == 64
        assert len(compute_payload_hash({"amount": 1.0})) == 64

        assert compute_payload_hash({"z": 1, "a": 2}) == \
               compute_payload_hash({"a": 2, "z": 1})

        # NFC vs NFD — JCS preserves unicode as-is
        assert canonicalize({"name": "é"}) != \
               canonicalize({"name": "é"})

        p = {"key": "", "null": None, "arr": [], "obj": {}}
        h = compute_payload_hash(p)
        assert len(h) == 64
        assert compute_payload_hash(p) == h


# ===========================================================================
# Category 12 — Escrow, state ownership, reserved keys (SEC-51 through SEC-53)
# ===========================================================================


class TestEscrowStateOwnership:
    """Party verification, ownership, reserved keys — Assets §4.2, State §2.1."""

    def test_sec_51_non_party_escrow_dispute(self):
        """SEC-51: Non-party cannot dispute escrow.
        Spec: ARSIA-Assets §4.2.3
        Attack: Third-party disputes escrow they are not party to
        """
        from arsia_protocol.assets.assets import validate_escrow_dispute

        errors = validate_escrow_dispute(
            {"payment_reference": "PAY-001",
             "dispute_reason": "Goods not delivered",
             "disputed_by": "agent:evil.attacker"},
            sender_agent_id="agent:evil.attacker",
            escrow_parties=(FROM_AGENT, TO_AGENT),
        )
        assert any(
            any(kw in str(getattr(e, "message", "")).lower()
                for kw in ("party", "sender", "authorized", "not a party"))
            for e in errors
        ), f"Non-party dispute must be rejected. Errors: {errors}"

    def test_sec_52_cross_agent_state_write(self):
        """SEC-52: Agent A cannot write state for Agent B.
        Spec: ARSIA-State §2.1.3
        Attack: Create entry with different owner_agent_id
        """
        from arsia_protocol.state.state import validate_state_entry
        from arsia_protocol.types.state import StateEntry

        entry = StateEntry(
            key=f"{TO_AGENT}/agent/stolen.data",
            value="injected", owner_agent_id=TO_AGENT,
            scope="agent", created_at=_now_ms(), updated_at=_now_ms(),
            pii_classification="none", version=1,
        )
        errors = validate_state_entry(entry, sender_agent_id=FROM_AGENT)
        assert any(
            any(kw in str(getattr(e, "message", "")).lower()
                for kw in ("owner", "sender"))
            for e in errors
        ), f"Cross-agent write must be rejected. Errors: {errors}"

    def test_sec_53_reserved_key_prefix(self):
        """SEC-53: Reserved key prefix blocked for SET.
        Spec: ARSIA-State §2.2
        Attack: Write to arsiaprotocol.* via SET
        """
        from arsia_protocol.state.state import is_reserved_key, validate_state_key

        for key in [f"{FROM_AGENT}/agent/arsiaprotocol.grants.test",
                    f"{FROM_AGENT}/shared/arsiaprotocol.internal.config"]:
            assert is_reserved_key(key) is True
            errors = validate_state_key(key, allow_reserved=False)
            assert any("reserved" in str(getattr(e, "message", "")).lower()
                        for e in errors), \
                f"Reserved key must be rejected. Key: {key}, Errors: {errors}"

        assert is_reserved_key(f"{FROM_AGENT}/agent/myapp.config") is False


# ===========================================================================
# Category 13 — Certificate chain and version (SEC-54 through SEC-55)
# ===========================================================================


class TestCertVersion:
    """Expired cert, version negotiation — Identity §6.4.1, Core §7.4."""

    def test_sec_54_expired_certificate(self):
        """SEC-54: Expired certificate in chain rejected.
        Spec: ARSIA-Identity §6.4.1 step 4c
        Attack: Use expired certificate to claim trust
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.serialization import Encoding
        from arsia_protocol.identity.certificates import verify_certificate_chain

        priv_key = CryptoEd25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        now = datetime.now(timezone.utc)

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=365))
            .not_valid_after(now - timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(FROM_AGENT)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False),
                critical=True)
            .sign(priv_key, None)
        )
        pem = cert.public_bytes(encoding=Encoding.PEM).decode()
        result = verify_certificate_chain(
            [pem], FROM_AGENT, pub_key.public_bytes_raw(), now=now)
        assert result.is_valid is False
        assert any("expir" in str(e).lower() or "valid" in str(e).lower()
                    for e in result.errors)

    def test_sec_55_version_negotiation(self):
        """SEC-55: Outbound version exceeding server_max rejected.
        Spec: ARSIA-Core §7.4
        Attack: Send v=2.0 to recipient that only supports v=1.0
        """
        from arsia_protocol.core.version import validate_outbound_version

        with pytest.raises(ValueError):
            validate_outbound_version("2.0", "1.0")

        validate_outbound_version("1.0", "2.0")
        validate_outbound_version("1.0", "1.0")
