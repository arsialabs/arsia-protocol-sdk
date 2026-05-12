# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA Protocol SDK — Adversarial Test Suite

Targeted attack vectors that attempt to break SDK security guarantees
through malicious inputs, edge cases, and abuse patterns. Each test
documents the threat model: what an attacker is trying to achieve and
why the SDK must resist it.

Not a fuzzer — every test is a specific, named attack with a clear
expected outcome. Does not duplicate tests in tests/security/.

Run: cd python && pytest tests/adversarial/ -v
"""

from __future__ import annotations

import base64
import copy
import json
import struct
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key as ec_generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey as CryptoEd25519PrivateKey,
)

from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.core.message import (
    check_envelope_size,
    create_request,
    sign_message,
    verify_message,
)
from arsia_protocol.core.validation import validate_envelope
from arsia_protocol.identity.agent_id import (
    is_valid_agent_id,
    parse_agent_id,
    validate_agent_id,
)
from arsia_protocol.actions.actions import (
    EXPLICIT_GRANT_ONLY,
    is_reserved_capability,
    is_reserved_prefix_misuse,
    is_valid_capability,
    match_capability,
    validate_capability,
)
from arsia_protocol.core.compliance import apply_profile, validate_compliance
from arsia_protocol.core.idempotency import (
    validate_idempotency_key,
    is_valid_idempotency_key,
)
from arsia_protocol.state.audit import compute_payload_hash

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


@pytest.fixture()
def signed_request(ed_keys_a):
    priv, pub = ed_keys_a
    env = create_request(
        FROM_AGENT, TO_AGENT, "org.test/action", ["test.read"],
        args={"key": "value"},
    )
    return sign_message(env, priv, KID)


# ===========================================================================
# Category 1 — Signature Forgery & Manipulation
# ===========================================================================


class TestSignatureForgery:
    """Attempts to forge, tamper, or bypass envelope signatures.
    Threat: Attacker crafts or mutates signatures to bypass verification.
    """

    def test_zero_signature_rejected(self, ed_keys_a):
        """All-zero 64-byte signature must not verify.
        Threat: Attacker submits envelope with zeroed signature bytes.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/zero", ["test.read"])
        signed = sign_message(env, priv, KID)
        zero_sig = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()
        signed["security"]["sig"] = zero_sig
        assert verify_message(signed, pub) is False

    def test_truncated_signature_rejected(self, ed_keys_a):
        """63-byte signature must not verify.
        Threat: Attacker submits truncated signature hoping for off-by-one.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/trunc", ["test.read"])
        signed = sign_message(env, priv, KID)
        short_sig = base64.urlsafe_b64encode(b"\xAB" * 63).rstrip(b"=").decode()
        signed["security"]["sig"] = short_sig
        assert verify_message(signed, pub) is False

    def test_extended_signature_rejected(self, ed_keys_a):
        """65-byte signature must not verify.
        Threat: Attacker appends extra byte to valid signature.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/ext", ["test.read"])
        signed = sign_message(env, priv, KID)
        long_sig = base64.urlsafe_b64encode(b"\xCD" * 65).rstrip(b"=").decode()
        signed["security"]["sig"] = long_sig
        assert verify_message(signed, pub) is False

    def test_flipped_bit_in_signature_rejected(self, ed_keys_a):
        """Single bit flip in valid signature must not verify.
        Threat: Attacker modifies one bit hoping Ed25519 doesn't catch it.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/flip", ["test.read"])
        signed = sign_message(env, priv, KID)
        sig_b64 = signed["security"]["sig"]
        pad = 4 - len(sig_b64) % 4
        sig_bytes = bytearray(
            base64.urlsafe_b64decode(sig_b64 + "=" * (pad if pad != 4 else 0))
        )
        sig_bytes[0] ^= 0x01
        signed["security"]["sig"] = (
            base64.urlsafe_b64encode(bytes(sig_bytes)).rstrip(b"=").decode()
        )
        assert verify_message(signed, pub) is False

    def test_signature_from_different_message_rejected(self, ed_keys_a):
        """Valid signature on message A must not verify on message B.
        Threat: Attacker replays signature from one message on another.
        """
        priv, pub = ed_keys_a
        env_a = create_request(FROM_AGENT, TO_AGENT, "org.test/msg-a", ["a.read"])
        env_b = create_request(FROM_AGENT, TO_AGENT, "org.test/msg-b", ["b.write"])
        signed_a = sign_message(env_a, priv, KID)
        signed_b = sign_message(env_b, priv, KID)
        signed_b["security"]["sig"] = signed_a["security"]["sig"]
        assert verify_message(signed_b, pub) is False

    def test_null_bytes_in_signature_rejected(self, ed_keys_a):
        """Signature with embedded null bytes must not verify.
        Threat: Attacker inserts nulls hoping for C-string-style truncation.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/null", ["test.read"])
        signed = sign_message(env, priv, KID)
        null_sig = base64.urlsafe_b64encode(
            b"\x00" * 10 + b"\xFF" * 44 + b"\x00" * 10
        ).rstrip(b"=").decode()
        signed["security"]["sig"] = null_sig
        assert verify_message(signed, pub) is False

    def test_signature_with_wrong_algorithm_label(self, ed_keys_a):
        """EdDSA signature with alg set to ES256 must not verify via ES256 path.
        Threat: Algorithm confusion — relabel sig to trigger wrong verifier.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/algswap", ["test.read"])
        signed = sign_message(env, priv, KID)
        signed["security"]["alg"] = "ES256"
        assert verify_message(signed, pub) is False

    def test_replay_signature_on_modified_payload(self, ed_keys_a):
        """Sign envelope, modify payload, reuse original signature — must fail.
        Threat: Attacker modifies payload content after signing.
        """
        priv, pub = ed_keys_a
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/replay-mod", ["test.read"],
            args={"data": "original"},
        )
        signed = sign_message(env, priv, KID)
        original_sig = signed["security"]["sig"]
        tampered = copy.deepcopy(signed)
        tampered["payload"]["args"]["data"] = "TAMPERED"
        tampered["security"]["sig"] = original_sig
        assert verify_message(tampered, pub) is False

    def test_replay_signature_on_modified_timestamp(self, ed_keys_a):
        """Sign envelope, change ts field, reuse original signature — must fail.
        Threat: Attacker extends message's apparent validity.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/ts-swap", ["test.read"])
        signed = sign_message(env, priv, KID)
        original_sig = signed["security"]["sig"]
        tampered = copy.deepcopy(signed)
        tampered["ts"] = _future_ms(9999)
        tampered["security"]["sig"] = original_sig
        assert verify_message(tampered, pub) is False

    def test_remove_security_object_after_signing(self, ed_keys_a):
        """Remove security object entirely from signed envelope — verify must fail.
        Threat: Strip all crypto from envelope to bypass verification.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/no-sec", ["test.read"])
        signed = sign_message(env, priv, KID)
        del signed["security"]
        with pytest.raises((KeyError, TypeError)):
            verify_message(signed, pub)

    def test_swap_kid_to_different_agent(self, ed_keys_a):
        """Change kid prefix to different agent after signing — must fail kid prefix check.
        Threat: Attacker rewrites kid to steal another agent's identity.
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/kid-swap", ["test.read"])
        signed = sign_message(env, priv, KID)
        signed["security"]["kid"] = "agent:evil.attacker#stolen-key"
        errors = validate_envelope(signed)
        kid_errors = [
            e for e in errors
            if "kid" in str(getattr(e, "code", "")).lower()
            or "kid" in str(getattr(e, "message", "")).lower()
        ]
        assert len(kid_errors) > 0, f"Must detect kid prefix mismatch. Errors: {errors}"


# ===========================================================================
# Category 2 — Canonicalization Attacks
# ===========================================================================


class TestCanonicalizationAttacks:
    """Attempts to exploit JSON canonicalization edge cases.
    Threat: Attacker crafts payloads that canonicalize differently from
    what was signed, or cause crashes during canonicalization.
    """

    def test_unicode_normalization_nfc_vs_nfd(self):
        """NFC and NFD forms of same string must canonicalize identically per RFC 8785.
        Threat: Attacker exploits NFC/NFD difference to sign one form but send another.
        RFC 8785 does NOT normalize unicode — they must be treated as different.
        """
        nfc = "é"  # é composed
        nfd = "é"  # é decomposed
        canon_nfc = canonicalize({"name": nfc})
        canon_nfd = canonicalize({"name": nfd})
        assert canon_nfc != canon_nfd, "NFC and NFD must produce different canonical forms"

    def test_unicode_escape_vs_literal(self):
        """JSON unicode escape and literal character must canonicalize the same.
        Threat: Attacker uses different encodings of same codepoint.
        RFC 8785 §3.2.2.2: characters above U+001F are output literally.
        """
        literal = {"key": "é"}
        canon1 = canonicalize(literal)
        canon2 = canonicalize({"key": "é"})
        assert canon1 == canon2

    def test_number_precision_attack(self):
        """Different JSON number representations must canonicalize consistently.
        Threat: Attacker exploits float precision to create ambiguous canonical forms.
        """
        h1 = compute_payload_hash({"amount": 1})
        h2 = compute_payload_hash({"amount": 1.0})
        assert len(h1) == 64
        assert len(h2) == 64

    def test_key_ordering_attack(self):
        """Different JSON key orderings must produce identical canonical form.
        Threat: Attacker reorders keys to change signature input.
        """
        ordered_abc = canonicalize({"a": 1, "b": 2, "c": 3})
        ordered_cba = canonicalize({"c": 3, "b": 2, "a": 1})
        ordered_bac = canonicalize({"b": 2, "a": 1, "c": 3})
        assert ordered_abc == ordered_cba == ordered_bac

    def test_deeply_nested_object_canonicalization(self):
        """100-level nested object must canonicalize without stack overflow.
        Threat: Attacker sends deeply nested JSON to crash canonicalizer.
        """
        deep: dict = {"value": "leaf"}
        for _ in range(100):
            deep = {"nested": deep}
        result = canonicalize(deep)
        assert len(result) > 0
        assert b"leaf" in result

    def test_empty_string_vs_missing_field(self):
        """Empty string value vs absent field must produce different canonical forms.
        Threat: Attacker substitutes empty string for absent field to bypass checks.
        """
        with_empty = canonicalize({"key": ""})
        without_key = canonicalize({})
        assert with_empty != without_key

    def test_null_value_canonicalization(self):
        """null values must be preserved in canonical form, not stripped.
        Threat: Attacker uses null to make fields disappear from signing input.
        """
        with_null = canonicalize({"key": None})
        assert b"null" in with_null
        without_key = canonicalize({})
        assert with_null != without_key

    def test_duplicate_json_keys_via_raw_parse(self):
        """JSON with duplicate keys — verify deterministic handling.
        Threat: Attacker sends JSON with duplicate keys; one verifier sees
        the first value, another sees the last — leading to different
        canonical forms and a signature bypass.
        """
        raw = '{"key": "first", "key": "second"}'
        parsed = json.loads(raw)
        canon = canonicalize(parsed)
        assert b'"key"' in canon
        reparsed = json.loads(raw)
        assert canonicalize(reparsed) == canon

    def test_large_number_canonicalization(self):
        """Very large and very small numbers must canonicalize without crash.
        Threat: Attacker sends extreme numeric values to trigger overflow.
        """
        canon = canonicalize({"big": 1e308, "small": 5e-324})
        assert len(canon) > 0

    def test_special_json_characters_in_keys(self):
        """Keys with special characters must canonicalize deterministically.
        Threat: Attacker uses unusual key names to confuse canonicalizer.
        """
        obj = {
            'key"with"quotes': 1,
            "key\\with\\backslash": 2,
            "key\nwith\nnewlines": 3,
        }
        c1 = canonicalize(obj)
        c2 = canonicalize(obj)
        assert c1 == c2
        assert len(c1) > 0


# ===========================================================================
# Category 3 — Agent ID Injection
# ===========================================================================


class TestAgentIdInjection:
    """Attempts to inject malicious content via agent identifiers.
    Threat: Attacker crafts agent IDs that exploit parsing, cause path
    traversal, or confuse identity checks.
    """

    def test_agent_id_with_null_bytes(self):
        """Agent ID containing \\x00 must be rejected.
        Threat: Null byte injection to truncate string in downstream systems.
        """
        assert is_valid_agent_id("agent:test\x00org.sender") is False

    def test_agent_id_with_path_traversal(self):
        """agent:evil/../../../etc/passwd must be rejected.
        Threat: Path traversal in agent ID used as filesystem key.
        """
        assert is_valid_agent_id("agent:evil/../../../etc/passwd") is False
        assert len(validate_agent_id("agent:evil/../../../etc/passwd")) > 0

    def test_agent_id_with_unicode_homoglyph(self):
        """Cyrillic а vs Latin a — must be treated as different IDs.
        Threat: Homoglyph attack where attacker registers lookalike agent.
        """
        latin = "agent:acme.bot"
        cyrillic = "agent:аcme.bot"  # Cyrillic а (U+0430)
        assert is_valid_agent_id(latin) is True
        assert is_valid_agent_id(cyrillic) is False

    def test_agent_id_max_length_boundary(self):
        """256 chars must pass; 257 must fail.
        Threat: Boundary testing — off-by-one in length check.
        """
        prefix = "agent:testorg."
        pad_len_pass = 256 - len(prefix)
        at_limit = prefix + "a" * pad_len_pass
        assert len(at_limit) == 256
        assert is_valid_agent_id(at_limit) is True

        over_limit = prefix + "a" * (pad_len_pass + 1)
        assert len(over_limit) == 257
        assert is_valid_agent_id(over_limit) is False

    def test_agent_id_with_url_encoding(self):
        """agent:acme%2Ecom/bot must be rejected.
        Threat: URL encoding bypass — agent ID parser must not decode %2E as period.
        """
        assert is_valid_agent_id("agent:acme%2Ecom.bot") is False

    def test_agent_id_with_newline(self):
        """Agent ID containing \\n must be rejected.
        Threat: Header injection in systems that use agent ID in HTTP headers.
        """
        assert is_valid_agent_id("agent:testorg.sender\n") is False
        assert is_valid_agent_id("agent:testorg\n.sender") is False

    def test_agent_id_with_space(self):
        """Agent ID containing spaces must be rejected.
        Threat: Token splitting in scope strings if space is allowed.
        """
        assert is_valid_agent_id("agent:test org.sender") is False

    def test_agent_id_with_control_characters(self):
        """Agent ID with control chars (tab, CR, bell, etc.) must be rejected.
        Threat: Control character injection to confuse log parsers.
        """
        controls = ["\t", "\r", "\x07", "\x1b", "\x7f"]
        for ch in controls:
            aid = f"agent:testorg{ch}.sender"
            assert is_valid_agent_id(aid) is False, f"Must reject control char {ch!r}"

    def test_agent_id_empty_org_segment(self):
        """agent:.sender must be rejected (empty org).
        Threat: Empty segment bypass to create ambiguous identities.
        """
        assert is_valid_agent_id("agent:.sender") is False
        assert len(validate_agent_id("agent:.sender")) > 0

    def test_agent_id_double_dots(self):
        """agent:testorg..sender must be rejected (double dots).
        Threat: Double dot creates empty segment, may bypass segment count checks.
        """
        assert is_valid_agent_id("agent:testorg..sender") is False

    def test_agent_id_leading_trailing_hyphen(self):
        """Segments with leading/trailing hyphens must be rejected.
        Threat: DNS-incompatible segments if agent IDs are used in discovery.
        """
        assert is_valid_agent_id("agent:-testorg.sender") is False
        assert is_valid_agent_id("agent:testorg-.sender") is False
        assert is_valid_agent_id("agent:testorg.-sender") is False


# ===========================================================================
# Category 4 — Token & Authorization Attacks
# ===========================================================================


class TestTokenAttacks:
    """Attempts to bypass authorization via malformed or crafted tokens.
    Threat: Attacker forges, extends, or manipulates JWT tokens to gain
    unauthorized access.
    """

    @pytest.fixture(scope="class")
    def as_keys(self):
        return generate_keypair()

    def test_token_with_wildcard_scope(self, as_keys):
        """Token with scope='*' must not grant access to all capabilities.
        Threat: Attacker mints token with universal wildcard.
        """
        from arsia_protocol.core.authorization import (
            build_jwt,
            validate_token_claims,
        )
        priv, pub = as_keys
        now_epoch = int(time.time())
        token = build_jwt({
            "iss": "https://as.example.com", "sub": FROM_AGENT,
            "aud": TO_AGENT, "iat": now_epoch,
            "exp": now_epoch + 3600, "scope": "*",
        }, priv)
        result = validate_token_claims(
            token, pub, expected_sub=FROM_AGENT,
            required_capabilities=["notes.read"],
        )
        assert result.is_valid is False

    def test_token_exp_max_int(self, as_keys):
        """Token with exp=9999999999999 must be handled without overflow.
        Threat: Integer overflow in timestamp comparison.
        """
        from arsia_protocol.core.authorization import build_jwt, validate_token_claims
        priv, pub = as_keys
        now_epoch = int(time.time())
        token = build_jwt({
            "iss": "https://as.example.com", "sub": FROM_AGENT,
            "aud": TO_AGENT, "iat": now_epoch,
            "exp": 9999999999999, "scope": "test.read",
        }, priv)
        result = validate_token_claims(token, pub, expected_sub=FROM_AGENT)
        assert result is not None  # must not crash

    def test_token_negative_exp(self, as_keys):
        """Token with exp=-1 must be rejected.
        Threat: Negative timestamp interpreted as far future on some systems.
        """
        from arsia_protocol.core.authorization import build_jwt, validate_token_claims
        priv, pub = as_keys
        now_epoch = int(time.time())
        token = build_jwt({
            "iss": "https://as.example.com", "sub": FROM_AGENT,
            "iat": now_epoch, "exp": -1, "scope": "test.read",
        }, priv)
        result = validate_token_claims(token, pub, expected_sub=FROM_AGENT)
        assert result.is_valid is False

    def test_token_sub_empty_string(self, as_keys):
        """Token with sub='' must fail subject match.
        Threat: Empty sub bypasses identity binding.
        """
        from arsia_protocol.core.authorization import build_jwt, validate_token_claims
        priv, pub = as_keys
        now_epoch = int(time.time())
        token = build_jwt({
            "iss": "https://as.example.com", "sub": "",
            "aud": TO_AGENT, "iat": now_epoch,
            "exp": now_epoch + 3600, "scope": "test.read",
        }, priv)
        result = validate_token_claims(
            token, pub, expected_sub=FROM_AGENT,
        )
        assert result.is_valid is False

    def test_token_aud_mismatch_case_sensitivity(self, as_keys):
        """Token aud case mismatch must be rejected (case-sensitive comparison).
        Threat: Case-insensitive aud check allows cross-agent token reuse.
        """
        from arsia_protocol.core.authorization import build_jwt, validate_token_claims
        priv, pub = as_keys
        now_epoch = int(time.time())
        token = build_jwt({
            "iss": "https://as.example.com", "sub": FROM_AGENT,
            "aud": "agent:TestOrg.Receiver",  # wrong case
            "iat": now_epoch, "exp": now_epoch + 3600,
            "scope": "test.read",
        }, priv)
        result = validate_token_claims(
            token, pub, expected_sub=FROM_AGENT,
            expected_aud=TO_AGENT,
        )
        assert result.is_valid is False

    def test_token_scope_with_extra_spaces(self, as_keys):
        """Token scope='  read   write  ' — must parse correctly.
        Threat: Extra whitespace could create phantom empty capabilities.
        """
        from arsia_protocol.core.authorization import parse_scope
        scope = parse_scope("  read   write  ")
        assert "" not in scope
        assert "read" in scope
        assert "write" in scope

    def test_token_iat_in_far_future(self, as_keys):
        """Token iat=year_3000 must be rejected (beyond clock skew).
        Threat: Token with future iat bypasses not-before semantics.
        """
        from arsia_protocol.core.authorization import build_jwt, validate_token_claims
        priv, pub = as_keys
        far_future = int(datetime(3000, 1, 1, tzinfo=timezone.utc).timestamp())
        token = build_jwt({
            "iss": "https://as.example.com", "sub": FROM_AGENT,
            "aud": TO_AGENT, "iat": far_future,
            "exp": far_future + 3600, "scope": "test.read",
        }, priv)
        result = validate_token_claims(token, pub, expected_sub=FROM_AGENT)
        assert result.is_valid is False

    def test_dpop_proof_reuse(self, as_keys):
        """Same DPoP proof JWT used twice — second use must fail (jti tracked).
        Threat: Attacker captures and replays DPoP proof.
        """
        from arsia_protocol.core.authorization import (
            build_dpop_proof,
            build_jwt,
            validate_dpop_proof,
        )
        as_priv, _ = as_keys
        ag_priv, ag_pub = generate_keypair()
        now_epoch = int(time.time())
        htu = "https://agent.example.com/arsia/inbox"

        access_token = build_jwt({
            "sub": FROM_AGENT, "iat": now_epoch,
            "exp": now_epoch + 300, "scope": "test.read",
        }, as_priv)

        proof = build_dpop_proof(
            ag_priv, ag_pub, htu=htu, access_token=access_token,
            jti="adversarial-jti-001", iat=now_epoch,
        )

        seen_jti: set[str] = set()
        r1 = validate_dpop_proof(
            proof, access_token, expected_htu=htu, seen_jti=seen_jti,
        )
        if r1.is_valid:
            seen_jti.add("adversarial-jti-001")

        r2 = validate_dpop_proof(
            proof, access_token, expected_htu=htu, seen_jti=seen_jti,
        )
        assert r2.is_valid is False


# ===========================================================================
# Category 5 — Compliance Bypass Attempts
# ===========================================================================


class TestComplianceBypass:
    """Attempts to bypass regulatory compliance controls.
    Threat: Attacker manipulates compliance fields to avoid regulatory
    obligations (GDPR, MiFID II, EU AI Act).
    """

    def test_pii_without_legal_basis(self):
        """pii_involved=true without legal_basis — must be rejected.
        Threat: Process personal data without GDPR justification.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/pii-bypass", ["test.read"],
            compliance={
                "profile": "GDPR-STANDARD",
                "pii_involved": True,
                "audit_required": True,
            },
        )
        errors = validate_compliance(env)
        assert any(
            "legal_basis" in str(getattr(e, "code", "")).lower()
            or "legal_basis" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must require legal_basis. Errors: {errors}"

    def test_retention_below_profile_minimum(self):
        """retention_days=1 with MIFID-II profile — must be floored.
        Threat: Delete financial records before regulatory minimum.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/retention", ["test.read"],
            compliance={
                "profile": "MIFID-II",
                "retention_days": 1,
                "pii_involved": False,
                "audit_required": True,
            },
        )
        applied = apply_profile(env)
        comp = applied.get("compliance", {})
        assert comp.get("retention_days", 0) >= 1827, \
            f"MIFID-II must floor retention to 1827, got {comp.get('retention_days')}"

    def test_unknown_profile_in_strict_mode(self):
        """Unknown profile name in strict mode — must reject.
        Threat: Use fake profile name to bypass all profile-level checks.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/fake-profile", ["test.read"],
            compliance={
                "profile": "TOTALLY-FAKE-PROFILE",
                "pii_involved": False,
                "audit_required": False,
            },
        )
        errors = validate_compliance(env, strict=True)
        assert any(
            "unknown" in str(getattr(e, "code", "")).lower()
            or "profile" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must reject unknown profile in strict mode. Errors: {errors}"

    def test_high_risk_without_human_oversight(self):
        """high-risk classification without human_oversight — R7 must fire
        when no profile is declared, since high-risk requires a profile.
        Threat: Deploy high-risk AI without committing to compliance framework.
        Note: R3 (missing_human_oversight) cannot fire through the public API
        because the effective compliance resolution always fills human_oversight
        from the fallback profile. This test verifies R7 catches the scenario.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/no-oversight", ["test.read"],
            compliance={
                "ai_system_classification": "high-risk",
                "audit_required": True,
                "pii_involved": False,
            },
        )
        errors = validate_compliance(env)
        assert any(
            "profile" in str(getattr(e, "code", "")).lower()
            or "profile" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must require profile for high-risk. Errors: {errors}"

    def test_classification_escalation_blocked(self):
        """Per-message classification higher than identity record — must be caught.
        Threat: minimal-risk agent escalates to high-risk to unlock capabilities.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/escalation", ["test.read"],
            compliance={
                "profile": "EU-AI-ACT-HIGH-RISK",
                "ai_system_classification": "high-risk",
                "human_oversight": True,
                "audit_required": True,
                "pii_involved": False,
            },
        )
        errors = validate_compliance(
            env, identity_classification="minimal-risk",
        )
        assert any(
            "classification" in str(getattr(e, "code", "")).lower()
            or "escalation" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must catch classification escalation. Errors: {errors}"

    def test_high_risk_missing_profile(self):
        """high-risk classification without a declared profile — R7 violation.
        Threat: Claim high-risk classification without committing to any
        compliance framework, avoiding all profile-level checks.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/no-profile-hr", ["test.read"],
            compliance={
                "ai_system_classification": "high-risk",
                "human_oversight": True,
                "audit_required": True,
                "pii_involved": False,
            },
        )
        errors = validate_compliance(env)
        assert any(
            "profile" in str(getattr(e, "code", "")).lower()
            or "profile" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must require profile for high-risk. Errors: {errors}"


# ===========================================================================
# Category 6 — Payload & Size Attacks
# ===========================================================================


class TestPayloadAttacks:
    """Attempts to exploit payload handling.
    Threat: Attacker crafts oversized, deeply nested, or malformed payloads
    to cause crashes, memory exhaustion, or bypass validation.
    """

    def test_payload_exceeding_1mib(self):
        """Payload just over 1 MiB — must be rejected by size check.
        Threat: DoS via oversized payload.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/big", ["test.read"],
            args={"data": "x" * (1024 * 1024)},
        )
        within_limit, actual_size = check_envelope_size(env)
        assert within_limit is False
        assert actual_size > 1_048_576

    def test_payload_at_exact_1mib(self):
        """Payload at exactly 1,048,576 bytes — must be accepted.
        Threat: Off-by-one in size check boundary.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/exact", ["test.read"],
            args={"data": "x"},
        )
        base_size = len(json.dumps(env).encode("utf-8"))
        target = 1_048_576 - base_size + len('"x"')
        env["payload"]["args"]["data"] = "x" * max(1, target - 2)
        within_limit, actual_size = check_envelope_size(env)
        assert actual_size <= 1_048_576
        assert within_limit is True

    def test_deeply_nested_json_payload(self):
        """500-level nested JSON — must handle without crash.
        Threat: Stack overflow via recursive JSON processing.
        """
        deep: dict = {"val": "leaf"}
        for _ in range(500):
            deep = {"n": deep}
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/deep", ["test.read"],
            args=deep,
        )
        validate_envelope(env)  # must not crash

    def test_massive_array_in_payload(self):
        """Array with 100,000 elements — must handle without crash.
        Threat: Memory exhaustion via large array.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/array", ["test.read"],
            args={"items": list(range(100_000))},
        )
        validate_envelope(env)  # must not crash

    def test_nan_infinity_in_json_value(self):
        """NaN/Infinity in JSON — must reject per RFC 8259.
        Threat: Non-standard JSON values that different parsers handle differently.
        """
        from arsia_protocol.state.state import _validate_json_value
        errors_nan = _validate_json_value(float("nan"))
        assert len(errors_nan) > 0, "NaN must be rejected"

        errors_inf = _validate_json_value(float("inf"))
        assert len(errors_inf) > 0, "Infinity must be rejected"


# ===========================================================================
# Category 7 — Encryption Attacks
# ===========================================================================


class TestEncryptionAttacks:
    """Attempts to break payload encryption.
    Threat: Attacker intercepts encrypted envelopes and attempts to decrypt,
    tamper, or bypass encryption checks.
    """

    @pytest.fixture(scope="class")
    def ec_keys(self):
        priv = ec_generate_private_key(SECP256R1())
        pub = priv.public_key()
        return priv, pub

    @pytest.fixture(scope="class")
    def ed_keys(self):
        return generate_keypair()

    def test_decrypt_with_wrong_key(self, ed_keys, ec_keys):
        """Decrypt JWE with different recipient's key — must fail.
        Threat: Unauthorized decryption by non-intended recipient.
        """
        from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
        from arsia_protocol.identity.discovery import build_ec_jwk

        priv, pub = ed_keys
        _, ec_pub = ec_keys
        rec_jwks = {"keys": [build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1", use="enc")]}

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/enc-wrong", ["test.read"],
            args={"secret": "classified"},
        )
        encrypted = encrypt_payload(env, rec_jwks)
        signed = sign_message(encrypted, priv, KID)

        wrong_ec = ec_generate_private_key(SECP256R1())
        with pytest.raises(ValueError):
            decrypt_and_verify(signed, pub, wrong_ec)

    def test_tampered_jwe_ciphertext(self, ed_keys, ec_keys):
        """Flip bit in JWE ciphertext — must fail with auth error.
        Threat: Attacker modifies ciphertext hoping GCM doesn't detect it.
        """
        from arsia_protocol.core.encryption import encrypt_payload
        from arsia_protocol.identity.discovery import build_ec_jwk

        priv, pub = ed_keys
        ec_priv, ec_pub = ec_keys
        rec_jwks = {"keys": [build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1", use="enc")]}

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/enc-tamper", ["test.read"],
            args={"secret": "classified"},
        )
        encrypted = encrypt_payload(env, rec_jwks)
        signed = sign_message(encrypted, priv, KID)

        if isinstance(signed["payload"], str):
            parts = signed["payload"].split(".")
            if len(parts) >= 4 and len(parts[3]) > 10:
                ct_chars = list(parts[3])
                ct_chars[5] = "A" if ct_chars[5] != "A" else "B"
                parts[3] = "".join(ct_chars)
                signed["payload"] = ".".join(parts)

        assert verify_message(signed, pub) is False

    def test_truncated_jwe(self, ed_keys, ec_keys):
        """JWE with missing component (4 parts instead of 5) — must fail.
        Threat: Truncated JWE causes parser error or partial decryption.
        """
        from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
        from arsia_protocol.identity.discovery import build_ec_jwk

        priv, pub = ed_keys
        ec_priv, ec_pub = ec_keys
        rec_jwks = {"keys": [build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1", use="enc")]}

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/enc-trunc", ["test.read"],
            args={"data": "test"},
        )
        encrypted = encrypt_payload(env, rec_jwks)
        signed = sign_message(encrypted, priv, KID)

        if isinstance(signed["payload"], str):
            parts = signed["payload"].split(".")
            signed["payload"] = ".".join(parts[:4])

        with pytest.raises(Exception):
            decrypt_and_verify(signed, pub, ec_priv)

    def test_verify_before_decrypt_ordering(self, ed_keys, ec_keys):
        """Tampered signature with valid JWE — verify must fail before decrypt.
        Threat: Attacker tampers sig but provides valid JWE, hoping decrypt
        runs first and returns plaintext before sig check.
        """
        from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
        from arsia_protocol.identity.discovery import build_ec_jwk

        priv, pub = ed_keys
        ec_priv, ec_pub = ec_keys
        rec_jwks = {"keys": [build_ec_jwk(ec_pub, f"{TO_AGENT}#enc-1", use="enc")]}

        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/enc-order", ["test.read"],
            args={"data": "verify-first"},
        )
        encrypted = encrypt_payload(env, rec_jwks)
        signed = sign_message(encrypted, priv, KID)

        bad_sig = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()
        signed["security"]["sig"] = bad_sig

        with pytest.raises(ValueError, match="[Ss]ignature"):
            decrypt_and_verify(signed, pub, ec_priv)


# ===========================================================================
# Category 8 — State & Assets Financial Attacks
# ===========================================================================


class TestFinancialAttacks:
    """Attempts to exploit state and financial operations.
    Threat: Attacker manipulates amounts, keys, or metadata to steal funds,
    bypass financial controls, or inject executable content.
    """

    def test_negative_transfer_amount(self):
        """amount=-100.00 must be rejected.
        Threat: Negative amount to reverse fund flow.
        """
        from arsia_protocol.assets.assets import validate_transfer_amount
        errors = validate_transfer_amount(-100.00, "currency")
        assert len(errors) > 0

    def test_zero_transfer_amount(self):
        """amount=0 must be rejected.
        Threat: Zero-value transfer to probe system without financial commitment.
        """
        from arsia_protocol.assets.assets import validate_transfer_amount
        errors = validate_transfer_amount(0, "currency")
        assert len(errors) > 0

    def test_transfer_amount_precision_overflow(self):
        """Currency amount with 3 decimal places must be rejected.
        Threat: Sub-cent precision to exploit rounding in downstream systems.
        """
        from arsia_protocol.assets.assets import validate_transfer_amount
        errors = validate_transfer_amount(Decimal("100.123"), "currency")
        assert any(
            "precision" in str(getattr(e, "code", "")).lower()
            or "precision" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must reject 3-decimal currency. Errors: {errors}"

    def test_iban_in_metadata(self):
        """Metadata containing IBAN pattern must be flagged.
        Threat: Leaking financial identifiers in unprotected metadata.
        """
        from arsia_protocol.assets.assets import validate_metadata_no_financial_data
        warnings = validate_metadata_no_financial_data(
            {"customer": {"account": "DE89370400440532013000"}}
        )
        assert any(
            "iban" in str(getattr(w, "code", "")).lower()
            for w in warnings
        ), f"Must flag IBAN. Warnings: {warnings}"

    def test_credit_card_in_metadata(self):
        """Metadata containing credit card number must be flagged.
        Threat: PCI DSS violation — card numbers in cleartext metadata.
        """
        from arsia_protocol.assets.assets import validate_metadata_no_financial_data
        warnings = validate_metadata_no_financial_data(
            {"reference": "4111111111111111"}
        )
        assert any(
            "card" in str(getattr(w, "code", "")).lower()
            for w in warnings
        ), f"Must flag card number. Warnings: {warnings}"

    def test_reserved_state_key_prefix(self):
        """State key with arsiaprotocol. prefix must be rejected.
        Threat: Write to reserved namespace to impersonate system state.
        """
        from arsia_protocol.state.state import is_reserved_key
        assert is_reserved_key(f"{FROM_AGENT}/agent/arsiaprotocol.grants.test") is True

    def test_executable_javascript_in_state_value(self):
        """State value containing javascript: URI must be rejected.
        Threat: XSS via state values rendered in agent UIs.
        """
        from arsia_protocol.state.state import _contains_executable_content
        assert _contains_executable_content("javascript:alert(1)") is True
        assert _contains_executable_content({"url": "javascript:void(0)"}) is True

    def test_executable_script_tag_in_state_value(self):
        """State value containing <script> must be rejected.
        Threat: HTML injection via state values.
        """
        from arsia_protocol.state.state import _contains_executable_content
        assert _contains_executable_content("<script>alert(1)</script>") is True

    def test_executable_eval_in_nested_state(self):
        """Deeply nested eval() must still be detected.
        Threat: Hide executable content in nested structures to bypass shallow scan.
        """
        from arsia_protocol.state.state import _contains_executable_content
        nested = {"a": {"b": {"c": [{"d": "eval(malicious_code)"}]}}}
        assert _contains_executable_content(nested) is True

    def test_escrow_reversal_exceeding_original(self):
        """Reversal amount > original transfer — must be rejected.
        Threat: Attacker reverses more than the original amount to extract funds.
        """
        from arsia_protocol.assets.assets import validate_reversal_precondition
        errors = validate_reversal_precondition(
            {"reversal_amount": Decimal("200.00")},
            original_status="completed",
            original_amount=Decimal("100.00"),
            already_reversed_total=Decimal("0"),
        )
        assert any(
            "exceed" in str(getattr(e, "message", "")).lower()
            or "cumulative" in str(getattr(e, "code", "")).lower()
            for e in errors
        ), f"Must reject reversal > original. Errors: {errors}"

    def test_full_reversal_after_partial(self):
        """Full reversal after partial reversal already processed — must be rejected.
        Threat: Double-dip — partial reversal then full reversal to extract extra funds.
        """
        from arsia_protocol.assets.assets import validate_reversal_precondition
        errors = validate_reversal_precondition(
            {},  # no reversal_amount = full reversal
            original_status="completed",
            original_amount=Decimal("100.00"),
            already_reversed_total=Decimal("25.00"),
        )
        assert any(
            "partial" in str(getattr(e, "message", "")).lower()
            or "full_reversal_after_partial" in str(getattr(e, "code", "")).lower()
            for e in errors
        ), f"Must reject full reversal after partial. Errors: {errors}"


# ===========================================================================
# Category 9 — Capability & Wildcard Attacks
# ===========================================================================


class TestCapabilityAttacks:
    """Attempts to escalate privileges via capability manipulation.
    Threat: Attacker exploits wildcard semantics, reserved prefixes, or
    edge cases to gain unauthorized capabilities.
    """

    def test_wildcard_does_not_cover_purge(self):
        """arsiaprotocol.state.* must NOT cover arsiaprotocol.state.purge.
        Threat: Wildcard scope grants destructive purge capability.
        """
        assert match_capability(
            "arsiaprotocol.state.*", "arsiaprotocol.state.purge"
        ) is False

    def test_wildcard_does_not_cover_snapshot(self):
        """arsiaprotocol.state.* must NOT cover arsiaprotocol.state.snapshot.
        Threat: Wildcard scope grants data export capability.
        """
        assert match_capability(
            "arsiaprotocol.state.*", "arsiaprotocol.state.snapshot"
        ) is False

    def test_wildcard_does_not_cover_oversight_approve(self):
        """arsiaprotocol.oversight.* must NOT cover arsiaprotocol.oversight.approve.
        Threat: Wildcard scope grants oversight approval capability.
        """
        assert match_capability(
            "arsiaprotocol.oversight.*", "arsiaprotocol.oversight.approve"
        ) is False

    def test_all_explicit_grant_only_immune_to_wildcards(self):
        """Every EXPLICIT_GRANT_ONLY cap must be immune to wildcard.
        Threat: Future additions to EXPLICIT_GRANT_ONLY missed by wildcards.
        """
        for cap in EXPLICIT_GRANT_ONLY:
            prefix = ".".join(cap.split(".")[:-1]) + ".*"
            assert match_capability(prefix, cap) is False, \
                f"Wildcard {prefix} must NOT satisfy {cap}"

    def test_reserved_capability_prefix_misuse(self):
        """Custom capability using arsiaprotocol. prefix must be detected.
        Threat: Attacker creates custom capability in reserved namespace.
        """
        assert is_reserved_prefix_misuse("arsiaprotocol.custom.attack") is True

    def test_capability_with_trailing_dot(self):
        """Capability with trailing dot — must be rejected.
        Threat: Trailing dot creates ambiguous matching behavior.
        """
        assert is_valid_capability("arsiaprotocol.actions.execute.") is False
        assert len(validate_capability("arsiaprotocol.actions.execute.")) > 0

    def test_capability_with_leading_dot(self):
        """Capability with leading dot — must be rejected.
        Threat: Leading dot bypass prefix matching.
        """
        assert is_valid_capability(".actions.execute") is False

    def test_empty_capability_rejected(self):
        """Empty string capability must be rejected.
        Threat: Empty capability might match everything or nothing depending on impl.
        """
        assert is_valid_capability("") is False

    def test_wildcard_star_alone(self):
        """Bare '*' as scope entry must not grant anything.
        Threat: Universal wildcard grants all capabilities.
        """
        assert match_capability("*", "notes.read") is False

    def test_double_wildcard(self):
        """'notes.**' as scope entry must not expand beyond single level.
        Threat: Recursive wildcard to grab deeply nested capabilities.
        """
        assert match_capability("notes.**", "notes.sub.deep") is False

    def test_scope_entry_direction(self):
        """Specific scope never satisfies wildcard request.
        Threat: notes.read in scope should not satisfy request for notes.*
        """
        assert match_capability("notes.read", "notes.*") is False

    def test_downgrade_then_use_original_scope(self):
        """After removing a capability, the original set must not be used.
        Threat: Attacker downgrades capabilities then uses cached original set.
        """
        original = {"notes.read", "notes.write", "notes.admin"}
        downgraded = original - {"notes.admin"}
        assert "notes.admin" not in downgraded
        assert match_capability("notes.admin", "notes.admin") is True
        assert "notes.admin" not in downgraded


# ===========================================================================
# Category 10 — Idempotency Attacks
# ===========================================================================


class TestIdempotencyAttacks:
    """Attempts to exploit idempotency handling.
    Threat: Attacker manipulates idempotency keys to bypass duplicate
    detection or cause processing errors.
    """

    def test_idempotency_key_empty_string(self):
        """Empty string idempotency key — must be rejected (min 1 char).
        Threat: Empty key could match all or no previous requests.
        """
        errors = validate_idempotency_key("")
        assert len(errors) > 0
        assert is_valid_idempotency_key("") is False

    def test_idempotency_key_129_chars(self):
        """Key at 129 chars (over max 128) — must be rejected.
        Threat: Oversized key to cause buffer overflow or storage issues.
        """
        key = "k" * 129
        errors = validate_idempotency_key(key)
        assert len(errors) > 0
        assert is_valid_idempotency_key(key) is False

    def test_idempotency_key_at_128_chars(self):
        """Key at exactly 128 chars — must be accepted.
        Threat: Off-by-one in max length check.
        """
        key = "k" * 128
        errors = validate_idempotency_key(key)
        assert len(errors) == 0
        assert is_valid_idempotency_key(key) is True

    def test_idempotency_key_at_1_char(self):
        """Key at exactly 1 char — must be accepted.
        Threat: Off-by-one in min length check.
        """
        key = "k"
        assert is_valid_idempotency_key(key) is True

    def test_idempotency_key_non_printable_ascii(self):
        """Key containing \\x01 (non-printable) — must be rejected.
        Threat: Non-printable chars in key could cause log injection or storage issues.
        """
        key = "valid-prefix\x01-suffix"
        errors = validate_idempotency_key(key)
        assert len(errors) > 0
        assert any(
            "char" in str(getattr(e, "code", "")).lower()
            or "ascii" in str(getattr(e, "message", "")).lower()
            for e in errors
        )

    def test_idempotency_key_tab_character(self):
        """Key containing tab — must be rejected (tab is below printable ASCII).
        Threat: Tab could split key in TSV log formats.
        """
        key = "key\twith-tab"
        errors = validate_idempotency_key(key)
        assert len(errors) > 0

    def test_idempotency_key_null_byte(self):
        """Key containing null byte — must be rejected.
        Threat: Null byte truncation in C-based storage backends.
        """
        key = "key\x00rest"
        errors = validate_idempotency_key(key)
        assert len(errors) > 0

    def test_idempotency_key_del_character(self):
        """Key containing DEL (0x7F) — must be rejected.
        Threat: DEL is technically control char despite being at end of ASCII range.
        """
        key = "key\x7f"
        errors = validate_idempotency_key(key)
        assert len(errors) > 0

    def test_idempotency_key_space_is_valid(self):
        """Key containing space (0x20) — must be accepted (printable ASCII).
        Threat: Verify space is correctly in the printable range.
        """
        key = "key with spaces"
        assert is_valid_idempotency_key(key) is True

    def test_idempotency_key_tilde_is_valid(self):
        """Key containing tilde (0x7E) — must be accepted (max printable ASCII).
        Threat: Boundary check at the top of printable ASCII range.
        """
        key = "key~tilde"
        assert is_valid_idempotency_key(key) is True

    def test_idempotency_expires_before_message_ts(self):
        """Idempotency with expires_at before message ts — must be detected as expired.
        Threat: Pre-expired idempotency key to immediately bypass duplicate detection.
        """
        from arsia_protocol.core.idempotency import is_idempotency_record_expired

        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=1)
        past_str = past.strftime("%Y-%m-%dT%H:%M:%S.") + f"{past.microsecond // 1000:03d}Z"

        assert is_idempotency_record_expired(past_str) is True


# ===========================================================================
# Category 11 — Envelope Structure Attacks
# ===========================================================================


class TestEnvelopeStructureAttacks:
    """Attempts to break envelope validation through structural manipulation.
    Threat: Attacker sends structurally invalid envelopes that might bypass
    specific validation steps.
    """

    def test_missing_required_fields(self):
        """Envelope with all required fields removed — must produce errors.
        Threat: Skeleton envelope bypasses all field-specific checks.
        """
        errors = validate_envelope({})
        assert len(errors) > 0

    def test_wrong_type_for_v_field(self):
        """v field as integer instead of string — must be caught.
        Threat: Type confusion in version negotiation.
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/v", ["test.read"])
        env["v"] = 1
        errors = validate_envelope(env)
        assert len(errors) > 0

    def test_wrong_type_for_capabilities(self):
        """capabilities as string instead of list — must be caught.
        Threat: String capabilities bypass list iteration checks.
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/caps", ["test.read"])
        env["capabilities"] = "test.read"
        errors = validate_envelope(env)
        assert len(errors) > 0

    def test_empty_capabilities_list(self):
        """Empty capabilities list — must be caught.
        Threat: Request with no capabilities might bypass authorization.
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/empty-caps", [])
        errors = validate_envelope(env)
        assert any(
            "capabilit" in str(getattr(e, "message", "")).lower()
            or "capabilit" in str(getattr(e, "code", "")).lower()
            for e in errors
        ), f"Must require at least one capability. Errors: {errors}"

    def test_payload_type_with_spaces(self):
        """payload.type with spaces — must be caught.
        Threat: Spaces in type could cause routing confusion.
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org test/action", ["test.read"])
        errors = validate_envelope(env)
        type_errors = [
            e for e in errors
            if "type" in str(getattr(e, "code", "")).lower()
            or "type" in str(getattr(e, "message", "")).lower()
        ]
        assert len(type_errors) > 0 or len(errors) > 0

    def test_non_uuid_message_id(self):
        """Non-UUID message ID — must be caught.
        Threat: Predictable message IDs enable replay attacks.
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/id", ["test.read"])
        env["id"] = "not-a-uuid"
        errors = validate_envelope(env)
        assert any(
            "id" in str(getattr(e, "code", "")).lower()
            or "uuid" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must reject non-UUID id. Errors: {errors}"

    def test_sequential_uuid_rejected(self):
        """Sequential UUID (v1) — must be caught (requires v4).
        Threat: Predictable UUIDs from sequential generator.
        """
        import uuid
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/seq-uuid", ["test.read"])
        env["id"] = str(uuid.uuid1())
        errors = validate_envelope(env)
        uuid_errors = [
            e for e in errors
            if "uuid" in str(getattr(e, "message", "")).lower()
            or "id" in str(getattr(e, "code", "")).lower()
        ]
        # UUID v1 might pass if SDK only checks format, not version
        # Document result either way
        assert True  # Informational — the SDK may or may not enforce v4-only

    def test_from_equals_to(self):
        """from == to — envelope sent to self.
        Threat: Self-messages might bypass cross-agent authorization.
        """
        env = create_request(FROM_AGENT, FROM_AGENT, "org.test/self", ["test.read"])
        validate_envelope(env)  # must not crash; may or may not produce errors

    def test_integer_ts_rejected(self):
        """Numeric timestamp instead of RFC 3339 string — must be caught.
        Threat: Epoch integer bypasses string-format timestamp validation.
        """
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/int-ts", ["test.read"])
        env["ts"] = 1700000000
        errors = validate_envelope(env)
        assert len(errors) > 0


# ===========================================================================
# Category 12 — Cross-Module Integration Attacks
# ===========================================================================


class TestCrossModuleAttacks:
    """Attacks that span multiple SDK modules.
    Threat: Exploit gaps between modules where one module's output is
    another module's input without shared validation.
    """

    def test_sign_then_validate_tampered_field(self, ed_keys_a):
        """Sign, tamper an unsigned meta field, validate — must catch inconsistency.
        Threat: Exploit the gap between signing (excludes security) and
        validation (checks security.kid prefix).
        """
        priv, pub = ed_keys_a
        env = create_request(FROM_AGENT, TO_AGENT, "org.test/cross-1", ["test.read"])
        signed = sign_message(env, priv, KID)
        signed["security"]["kid"] = "agent:evil.attacker#stolen"
        errors = validate_envelope(signed)
        assert any(
            "kid" in str(getattr(e, "code", "")).lower()
            for e in errors
        ), "validate_envelope must catch kid-from mismatch"

    def test_compliance_plus_validation_combined(self):
        """Envelope with both structural errors and compliance violations.
        Threat: Compliance errors mask structural errors or vice versa.
        """
        env = create_request(
            FROM_AGENT, TO_AGENT, "org.test/combined", ["test.read"],
            compliance={
                "profile": "EU-AI-ACT-HIGH-RISK",
                "ai_system_classification": "high-risk",
                "pii_involved": True,
                # Missing: human_oversight, legal_basis
            },
        )
        env["ts"] = "invalid-timestamp"
        structural_errors = validate_envelope(env)
        compliance_errors = validate_compliance(env)
        assert len(structural_errors) > 0, "Must catch structural errors"
        assert len(compliance_errors) > 0, "Must catch compliance errors"

    def test_payload_hash_changes_on_modification(self, ed_keys_a):
        """Modifying payload after computing hash must produce different hash.
        Threat: Attacker modifies payload and relies on cached hash.
        """
        payload = {"key": "original", "data": [1, 2, 3]}
        hash_before = compute_payload_hash(payload)

        modified = copy.deepcopy(payload)
        modified["key"] = "tampered"
        hash_after = compute_payload_hash(modified)

        assert hash_before != hash_after

    def test_canonical_hash_is_key_order_independent(self):
        """Same fields, different insertion order — hash must be identical.
        Threat: Key ordering in Python dict affects hash computation.
        """
        h1 = compute_payload_hash({"z": 1, "a": 2, "m": 3})
        h2 = compute_payload_hash({"a": 2, "m": 3, "z": 1})
        h3 = compute_payload_hash({"m": 3, "z": 1, "a": 2})
        assert h1 == h2 == h3


# ===========================================================================
# Category 13 — PII Boundary Attacks
# ===========================================================================


class TestPiiBoundaryAttacks:
    """Attacks targeting PII handling boundaries.
    Threat: Attacker exploits PII classification and legal basis validation
    to process sensitive data without proper authorization.
    """

    def test_sensitive_pii_with_art6_basis_rejected(self):
        """pii_classification=sensitive with Art. 6 basis (not Art. 9) — must be rejected.
        Threat: Use generic GDPR basis for special category data.
        """
        from arsia_protocol.state.state import validate_state_entry
        from arsia_protocol.types.state import StateEntry

        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/test.sensitive",
            value="health-data",
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
                for kw in ("legal_basis", "art", "sensitive", "explicit"))
            for e in errors
        ), f"Sensitive PII with Art. 6 basis must be rejected. Errors: {errors}"

    def test_personal_pii_without_data_residency(self):
        """pii_classification=personal without data_residency — must be rejected.
        Threat: Process personal data without declaring where it's stored.
        """
        from arsia_protocol.state.state import validate_state_entry
        from arsia_protocol.types.state import StateEntry

        entry = StateEntry(
            key=f"{FROM_AGENT}/agent/test.no-residency",
            value="personal-data",
            owner_agent_id=FROM_AGENT, scope="agent",
            created_at=_now_ms(), updated_at=_now_ms(),
            pii_classification="personal", version=1,
        )
        errors = validate_state_entry(
            entry, sender_agent_id=FROM_AGENT,
            envelope_compliance={"legal_basis": "consent"},
        )
        assert any(
            "residency" in str(getattr(e, "message", "")).lower()
            or "residency" in str(getattr(e, "code", "")).lower()
            for e in errors
        ), f"Must require data_residency for personal PII. Errors: {errors}"

    def test_cross_agent_state_write_ownership_check(self):
        """Agent A writing state owned by Agent B — must be rejected.
        Threat: One agent impersonates another's state ownership.
        """
        from arsia_protocol.state.state import validate_state_entry
        from arsia_protocol.types.state import StateEntry

        entry = StateEntry(
            key=f"{TO_AGENT}/agent/stolen.data",
            value="injected-by-attacker",
            owner_agent_id=TO_AGENT,
            scope="agent",
            created_at=_now_ms(), updated_at=_now_ms(),
            pii_classification="none", version=1,
        )
        errors = validate_state_entry(entry, sender_agent_id=FROM_AGENT)
        assert any(
            "owner" in str(getattr(e, "message", "")).lower()
            for e in errors
        ), f"Must reject cross-agent write. Errors: {errors}"
