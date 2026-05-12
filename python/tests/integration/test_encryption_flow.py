# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Integration tests for JWE encryption composed with message, validation, and hazmat.

These tests exercise cross-module composition:
  encryption × message × validation × discovery × hazmat
Unit-level coverage for individual functions lives in tests/unit/test_encryption.py.

Spec: ARSIA-Core.md §5.3 (Payload Encryption).
"""

from __future__ import annotations


import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arsia_protocol.identity.discovery import build_ec_jwk
from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
from arsia_protocol.core.message import (
    create_event,
    create_request,
    create_response,
    sign_message,
    verify_message,
)
from arsia_protocol.core.validation import validate_envelope


# -- Fixtures ---------------------------------------------------------------


@pytest.fixture()
def sender_signing_keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture()
def recipient_ec_keypair():
    priv = generate_private_key(SECP256R1())
    return priv, priv.public_key()


@pytest.fixture()
def recipient_jwks(recipient_ec_keypair):
    _, pub = recipient_ec_keypair
    jwk = build_ec_jwk(pub, "agent:test.recipient#enc-1", use="enc")
    return {"keys": [jwk]}


@pytest.fixture()
def request_envelope():
    return create_request(
        from_agent="agent:test.sender",
        to_agent="agent:test.recipient",
        payload_type="org.example.encryptTest",
        capabilities=["example.read"],
        args={"message": "hello, encrypted world", "count": 42},
    )


@pytest.fixture()
def response_envelope():
    return create_response(
        from_agent="agent:test.recipient",
        to_agent="agent:test.sender",
        correlation_id="corr-001",
        payload_type="org.example.encryptTest",
        result={"status": "ok", "items": [1, 2, 3]},
    )


@pytest.fixture()
def event_envelope():
    return create_event(
        from_agent="agent:test.sender",
        to_agent="agent:test.recipient",
        payload_type="org.example.notification",
        data={"level": "info", "text": "something happened"},
    )


# -- Encrypt → Decrypt round-trip with real envelope payload ----------------


class TestEncryptDecryptRoundTrip:
    """JWE encrypt → decrypt with real envelope payloads."""

    def test_request_payload_roundtrips(
        self,
        request_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """Build request → encrypt → sign → decrypt_and_verify → payload matches."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        assert decrypted["payload"] == request_envelope["payload"]

    def test_response_payload_roundtrips(
        self,
        response_envelope,
        recipient_ec_keypair,
    ):
        """Response envelopes survive encrypt → sign → decrypt_and_verify."""
        rec_priv, rec_pub = recipient_ec_keypair
        jwk = build_ec_jwk(rec_pub, "agent:test.sender#enc-1", use="enc")
        jwks = {"keys": [jwk]}

        sender_priv = Ed25519PrivateKey.generate()
        sender_pub = sender_priv.public_key()

        encrypted = encrypt_payload(response_envelope, jwks)
        signed = sign_message(
            encrypted, sender_priv, "agent:test.recipient#sign-1"
        )
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        assert decrypted["payload"]["result"] == {"status": "ok", "items": [1, 2, 3]}

    def test_event_payload_roundtrips(
        self,
        event_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """Event envelopes survive encrypt → sign → decrypt_and_verify."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(event_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        assert decrypted["payload"]["data"]["text"] == "something happened"


# -- Encrypted envelope validates after decryption --------------------------


class TestEncryptedEnvelopeValidation:
    """Decrypt an encrypted envelope, then run validate_envelope on the result."""

    def test_decrypted_request_passes_validation(
        self,
        request_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """validate_envelope returns no errors on decrypted request envelope."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        errors = validate_envelope(decrypted)
        assert errors == [], f"Unexpected validation errors: {errors}"

    def test_decrypted_event_passes_validation(
        self,
        event_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """validate_envelope returns no errors on decrypted event envelope."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(event_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        errors = validate_envelope(decrypted)
        assert errors == [], f"Unexpected validation errors: {errors}"


# -- Encrypt with wrong key fails decryption --------------------------------


class TestWrongKeyDecryptionFailure:
    """Encrypt with key A, attempt decrypt with key B — must fail."""

    def test_wrong_ec_key_raises_unauthorized(
        self,
        request_envelope,
        recipient_jwks,
        sender_signing_keypair,
    ):
        """Decryption with a different EC private key raises ValueError."""
        sender_priv, sender_pub = sender_signing_keypair
        wrong_rec_priv = generate_private_key(SECP256R1())

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")

        with pytest.raises(ValueError, match="JWE decryption failed"):
            decrypt_and_verify(signed, sender_pub, wrong_rec_priv)

    def test_wrong_sender_key_raises_unauthorized(
        self,
        request_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """Verification with wrong Ed25519 public key rejects before decrypt."""
        sender_priv, _ = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair
        wrong_sender_pub = Ed25519PrivateKey.generate().public_key()

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")

        with pytest.raises(ValueError, match="Signature verification failed"):
            decrypt_and_verify(signed, wrong_sender_pub, rec_priv)


# -- Encrypted envelope preserves signature ---------------------------------


class TestSignaturePreservation:
    """Sign → encrypt → decrypt: signature remains valid on decrypted content."""

    def test_signature_valid_on_encrypted_envelope(
        self,
        request_envelope,
        recipient_jwks,
        sender_signing_keypair,
    ):
        """verify_message succeeds on the encrypted+signed envelope."""
        sender_priv, sender_pub = sender_signing_keypair

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")

        assert verify_message(signed, sender_pub) is True

    def test_decrypt_and_verify_performs_both(
        self,
        request_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """decrypt_and_verify implicitly verifies signature + decrypts payload."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")

        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)
        assert isinstance(decrypted["payload"], dict)
        assert decrypted["security"]["sig"] == signed["security"]["sig"]


# -- JWE content type round-trips correctly ---------------------------------


class TestContentTypeRoundTrip:
    """Verify that payload.type and nested structure survive encrypt→decrypt."""

    def test_payload_type_preserved(
        self,
        request_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """payload.type survives JWE encrypt → decrypt."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        assert decrypted["payload"]["type"] == "org.example.encryptTest"

    def test_nested_payload_structure_preserved(
        self,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """Deeply nested payload args survive JWE round-trip without loss."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        envelope = create_request(
            from_agent="agent:test.sender",
            to_agent="agent:test.recipient",
            payload_type="org.example.nested",
            capabilities=["example.write"],
            args={
                "level1": {
                    "level2": {"level3": [1, 2.5, True, None, "text"]},
                    "list": [{"a": 1}, {"b": 2}],
                },
                "unicode": "éèê ☃ \U0001f600",
            },
        )

        encrypted = encrypt_payload(envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        assert decrypted["payload"]["args"] == envelope["payload"]["args"]

    def test_empty_args_preserved(
        self,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """Payload with empty args dict survives JWE round-trip."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        envelope = create_request(
            from_agent="agent:test.sender",
            to_agent="agent:test.recipient",
            payload_type="org.example.empty",
            capabilities=["example.read"],
            args={},
        )

        encrypted = encrypt_payload(envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        assert decrypted["payload"]["args"] == {}


# -- Cross-agent encryption via discovery module ----------------------------


class TestCrossAgentEncryption:
    """Two distinct agents with separate EC keypairs exchange encrypted envelopes."""

    def test_agent_a_sends_to_agent_b(self):
        """Agent A encrypts with B's public key, B decrypts with own private key."""
        a_sign_priv = Ed25519PrivateKey.generate()
        a_sign_pub = a_sign_priv.public_key()

        b_enc_priv = generate_private_key(SECP256R1())
        b_enc_pub = b_enc_priv.public_key()
        b_jwks = {"keys": [build_ec_jwk(b_enc_pub, "agent:org.b#enc-1", use="enc")]}

        envelope = create_request(
            from_agent="agent:org.a",
            to_agent="agent:org.b",
            payload_type="org.example.crossAgent",
            capabilities=["example.read"],
            args={"secret": "for-b-only"},
        )

        encrypted = encrypt_payload(envelope, b_jwks)
        signed = sign_message(encrypted, a_sign_priv, "agent:org.a#sign-1")

        decrypted = decrypt_and_verify(signed, a_sign_pub, b_enc_priv)
        assert decrypted["payload"]["args"]["secret"] == "for-b-only"

    def test_bidirectional_exchange(self):
        """Both agents can encrypt and decrypt to each other."""
        a_sign_priv = Ed25519PrivateKey.generate()
        a_sign_pub = a_sign_priv.public_key()
        a_enc_priv = generate_private_key(SECP256R1())
        a_enc_pub = a_enc_priv.public_key()
        a_jwks = {"keys": [build_ec_jwk(a_enc_pub, "agent:org.a#enc-1", use="enc")]}

        b_sign_priv = Ed25519PrivateKey.generate()
        b_sign_pub = b_sign_priv.public_key()
        b_enc_priv = generate_private_key(SECP256R1())
        b_enc_pub = b_enc_priv.public_key()
        b_jwks = {"keys": [build_ec_jwk(b_enc_pub, "agent:org.b#enc-1", use="enc")]}

        req = create_request(
            from_agent="agent:org.a",
            to_agent="agent:org.b",
            payload_type="org.example.bidir",
            capabilities=["example.read"],
            args={"question": "ping"},
        )
        enc_req = encrypt_payload(req, b_jwks)
        signed_req = sign_message(enc_req, a_sign_priv, "agent:org.a#sign-1")
        dec_req = decrypt_and_verify(signed_req, a_sign_pub, b_enc_priv)
        assert dec_req["payload"]["args"]["question"] == "ping"

        resp = create_response(
            from_agent="agent:org.b",
            to_agent="agent:org.a",
            correlation_id=req["id"],
            payload_type="org.example.bidir",
            result={"answer": "pong"},
        )
        enc_resp = encrypt_payload(resp, a_jwks)
        signed_resp = sign_message(enc_resp, b_sign_priv, "agent:org.b#sign-1")
        dec_resp = decrypt_and_verify(signed_resp, b_sign_pub, a_enc_priv)
        assert dec_resp["payload"]["result"]["answer"] == "pong"


# -- Security field integrity -----------------------------------------------


class TestSecurityFieldIntegrity:
    """Verify encryption/signing security metadata across the pipeline."""

    def test_encrypt_sets_enc_fields_before_signing(
        self,
        request_envelope,
        recipient_jwks,
    ):
        """encrypt_payload sets encrypted/enc_alg/enc_method on the security block."""
        encrypted = encrypt_payload(request_envelope, recipient_jwks)

        sec = encrypted["security"]
        assert sec["encrypted"] is True
        assert sec["enc_alg"] == "ECDH-ES"
        assert sec["enc_method"] == "A256GCM"

    def test_sign_replaces_security_block(
        self,
        request_envelope,
        recipient_jwks,
        sender_signing_keypair,
    ):
        """sign_message replaces security with {alg, kid, sig} per §5.1."""
        sender_priv, _ = sender_signing_keypair

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")

        sec = signed["security"]
        assert set(sec.keys()) == {"alg", "kid", "sig"}
        assert sec["alg"] == "EdDSA"
        assert sec["kid"] == "agent:test.sender#sign-1"

    def test_decrypted_envelope_retains_sig_security(
        self,
        request_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """After decrypt_and_verify, the signing security block is preserved."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(request_envelope, recipient_jwks)
        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)

        assert "security" in decrypted
        assert decrypted["security"]["alg"] == "EdDSA"
        assert decrypted["security"]["sig"] == signed["security"]["sig"]

    def test_ecdh_es_a256kw_roundtrip(
        self,
        request_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_signing_keypair,
    ):
        """Full pipeline with ECDH-ES+A256KW algorithm."""
        sender_priv, sender_pub = sender_signing_keypair
        rec_priv, _ = recipient_ec_keypair

        encrypted = encrypt_payload(
            request_envelope, recipient_jwks, enc_alg="ECDH-ES+A256KW"
        )
        assert encrypted["security"]["enc_alg"] == "ECDH-ES+A256KW"

        signed = sign_message(encrypted, sender_priv, "agent:test.sender#sign-1")
        decrypted = decrypt_and_verify(signed, sender_pub, rec_priv)
        assert decrypted["payload"] == request_envelope["payload"]
