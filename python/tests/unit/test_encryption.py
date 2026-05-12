# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for arsia_protocol.encryption and hazmat.primitives.jwe.

Spec: ARSIA-Core.md §5.3 (Payload Encryption).
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arsia_protocol.identity.discovery import build_ec_jwk
from arsia_protocol.core.encryption import decrypt_and_verify, encrypt_payload
from arsia_protocol.hazmat.primitives.jwe import (
    jwe_decrypt,
    jwe_encrypt,
    resolve_encryption_key,
)
from arsia_protocol.core.message import create_request, sign_message


# -- Fixtures ---------------------------------------------------------------


@pytest.fixture()
def recipient_ec_keypair():
    private_key = generate_private_key(SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture()
def sender_ed25519_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture()
def recipient_jwks(recipient_ec_keypair):
    _, pub = recipient_ec_keypair
    enc_jwk = build_ec_jwk(pub, "agent:test.recipient#enc-1", use="enc")
    return {"keys": [enc_jwk]}


@pytest.fixture()
def sample_envelope():
    return create_request(
        from_agent="agent:test.sender",
        to_agent="agent:test.recipient",
        payload_type="org.example.test",
        capabilities=["example.read"],
        args={"message": "hello, encrypted world"},
    )


# -- Raw JWE tests ----------------------------------------------------------


class TestJweEncryptDecrypt:
    """Low-level JWE Compact Serialization round-trip."""

    def test_round_trip_ecdh_es(self, recipient_ec_keypair):
        """Encrypt→decrypt with ECDH-ES produces original plaintext."""
        priv, pub = recipient_ec_keypair
        plaintext = b'{"type":"test","args":{"value":42}}'
        jwe = jwe_encrypt(plaintext, pub, alg="ECDH-ES", enc="A256GCM")
        result = jwe_decrypt(jwe, priv)
        assert result == plaintext

    def test_round_trip_ecdh_es_a256kw(self, recipient_ec_keypair):
        """Encrypt→decrypt with ECDH-ES+A256KW produces original plaintext."""
        priv, pub = recipient_ec_keypair
        plaintext = b'{"type":"test"}'
        jwe = jwe_encrypt(plaintext, pub, alg="ECDH-ES+A256KW", enc="A256GCM")
        result = jwe_decrypt(jwe, priv)
        assert result == plaintext

    def test_compact_serialization_format(self, recipient_ec_keypair):
        """JWE Compact Serialization has exactly 5 dot-separated parts."""
        _, pub = recipient_ec_keypair
        jwe = jwe_encrypt(b"test", pub)
        parts = jwe.split(".")
        assert len(parts) == 5
        for part in parts:
            assert "=" not in part, "base64url must not have padding"

    def test_header_contains_alg_enc_epk(self, recipient_ec_keypair):
        """JWE protected header contains alg, enc, and epk fields."""
        _, pub = recipient_ec_keypair
        jwe = jwe_encrypt(b"test", pub, alg="ECDH-ES", enc="A256GCM")
        import base64

        header_b64 = jwe.split(".")[0]
        padding = (-len(header_b64)) % 4
        header = json.loads(
            base64.urlsafe_b64decode(header_b64 + "=" * padding)
        )
        assert header["alg"] == "ECDH-ES"
        assert header["enc"] == "A256GCM"
        assert "epk" in header
        assert header["epk"]["kty"] == "EC"
        assert header["epk"]["crv"] == "P-256"

    def test_ecdh_es_encrypted_key_is_empty(self, recipient_ec_keypair):
        """With ECDH-ES (direct), the encrypted key part is empty."""
        _, pub = recipient_ec_keypair
        jwe = jwe_encrypt(b"test", pub, alg="ECDH-ES")
        enc_key_b64 = jwe.split(".")[1]
        assert enc_key_b64 == ""

    def test_ecdh_es_a256kw_encrypted_key_is_nonempty(self, recipient_ec_keypair):
        """With ECDH-ES+A256KW, the encrypted key part is non-empty."""
        _, pub = recipient_ec_keypair
        jwe = jwe_encrypt(b"test", pub, alg="ECDH-ES+A256KW")
        enc_key_b64 = jwe.split(".")[1]
        assert len(enc_key_b64) > 0

    def test_wrong_key_fails_decrypt(self, recipient_ec_keypair):
        """Decryption with wrong private key raises."""
        _, pub = recipient_ec_keypair
        wrong_priv = generate_private_key(SECP256R1())
        jwe = jwe_encrypt(b"secret", pub)
        with pytest.raises(Exception):
            jwe_decrypt(jwe, wrong_priv)

    def test_tampered_ciphertext_fails(self, recipient_ec_keypair):
        """Tampered ciphertext is rejected by A256GCM authentication."""
        priv, pub = recipient_ec_keypair
        jwe = jwe_encrypt(b"secret", pub)
        parts = jwe.split(".")
        ct = list(parts[3])
        ct[0] = "A" if ct[0] != "A" else "B"
        parts[3] = "".join(ct)
        tampered = ".".join(parts)
        with pytest.raises(Exception):
            jwe_decrypt(tampered, priv)

    def test_invalid_part_count_rejected(self, recipient_ec_keypair):
        """JWE string with wrong number of parts raises ValueError."""
        priv, _ = recipient_ec_keypair
        with pytest.raises(ValueError, match="5 parts"):
            jwe_decrypt("a.b.c.d", priv)

    def test_unsupported_alg_rejected(self, recipient_ec_keypair):
        """Unsupported algorithm raises ValueError."""
        _, pub = recipient_ec_keypair
        with pytest.raises(ValueError, match="Unsupported alg"):
            jwe_encrypt(b"test", pub, alg="RSA-OAEP")

    def test_unsupported_enc_rejected(self, recipient_ec_keypair):
        """Unsupported enc raises ValueError."""
        _, pub = recipient_ec_keypair
        with pytest.raises(ValueError, match="Unsupported enc"):
            jwe_encrypt(b"test", pub, enc="A128GCM")

    def test_kid_in_header(self, recipient_ec_keypair):
        """Optional kid is included in the JWE protected header."""
        _, pub = recipient_ec_keypair
        jwe = jwe_encrypt(b"test", pub, kid="agent:x#enc-1")
        import base64

        header_b64 = jwe.split(".")[0]
        padding = (-len(header_b64)) % 4
        header = json.loads(
            base64.urlsafe_b64decode(header_b64 + "=" * padding)
        )
        assert header["kid"] == "agent:x#enc-1"

    def test_large_payload(self, recipient_ec_keypair):
        """Encrypt→decrypt works with a larger payload."""
        priv, pub = recipient_ec_keypair
        plaintext = json.dumps({"data": "x" * 10000}).encode()
        jwe = jwe_encrypt(plaintext, pub)
        assert jwe_decrypt(jwe, priv) == plaintext


# -- JWKS resolution --------------------------------------------------------


class TestResolveEncryptionKey:
    """Test resolve_encryption_key from hazmat.primitives.jwe."""

    def test_finds_enc_key(self):
        jwks = {
            "keys": [
                {"kty": "OKP", "use": "sig", "kid": "k1"},
                {"kty": "EC", "use": "enc", "kid": "k2"},
            ]
        }
        result = resolve_encryption_key(jwks)
        assert result is not None
        assert result["kid"] == "k2"

    def test_returns_none_when_no_enc_key(self):
        jwks = {"keys": [{"kty": "OKP", "use": "sig", "kid": "k1"}]}
        assert resolve_encryption_key(jwks) is None

    def test_accepts_bare_list(self):
        keys = [{"kty": "EC", "use": "enc", "kid": "k1"}]
        result = resolve_encryption_key(keys)
        assert result is not None
        assert result["kid"] == "k1"

    def test_empty_jwks(self):
        assert resolve_encryption_key({"keys": []}) is None


# -- Envelope-level encryption ----------------------------------------------


class TestEncryptPayload:
    """Test encrypt_payload (sender-side encryption)."""

    def test_payload_becomes_jwe_string(
        self, sample_envelope, recipient_jwks
    ):
        """§5.3: payload field MUST contain a JWE Compact Serialization string."""
        result = encrypt_payload(sample_envelope, recipient_jwks)
        assert isinstance(result["payload"], str)
        assert len(result["payload"].split(".")) == 5

    def test_security_fields_populated(
        self, sample_envelope, recipient_jwks
    ):
        """security.encrypted, enc_alg, enc_method are set."""
        result = encrypt_payload(sample_envelope, recipient_jwks)
        assert result["security"]["encrypted"] is True
        assert result["security"]["enc_alg"] == "ECDH-ES"
        assert result["security"]["enc_method"] == "A256GCM"

    def test_custom_algorithm(self, sample_envelope, recipient_jwks):
        """enc_alg and enc_method can be overridden."""
        result = encrypt_payload(
            sample_envelope,
            recipient_jwks,
            enc_alg="ECDH-ES+A256KW",
            enc_method="A256GCM",
        )
        assert result["security"]["enc_alg"] == "ECDH-ES+A256KW"

    def test_original_envelope_not_mutated(
        self, sample_envelope, recipient_jwks
    ):
        """encrypt_payload returns a new dict, original is unchanged."""
        original_payload = sample_envelope["payload"].copy()
        encrypt_payload(sample_envelope, recipient_jwks)
        assert sample_envelope["payload"] == original_payload

    def test_no_enc_key_raises(self, sample_envelope):
        """Raises ValueError when JWKS has no use=enc key."""
        jwks = {"keys": [{"kty": "OKP", "use": "sig", "kid": "k1",
                          "crv": "Ed25519", "x": "AAAA"}]}
        with pytest.raises(ValueError, match="No encryption key"):
            encrypt_payload(sample_envelope, jwks)


# -- Envelope-level decryption ----------------------------------------------


class TestDecryptAndVerify:
    """Test decrypt_and_verify (recipient-side decryption)."""

    def _make_signed_encrypted_envelope(
        self,
        sample_envelope,
        recipient_jwks,
        sender_ed25519_keypair,
        *,
        enc_alg="ECDH-ES",
    ):
        sender_priv, _ = sender_ed25519_keypair
        kid = "agent:test.sender#sign-1"
        encrypted = encrypt_payload(
            sample_envelope, recipient_jwks, enc_alg=enc_alg
        )
        signed = sign_message(encrypted, sender_priv, kid)
        return signed

    def test_full_round_trip(
        self,
        sample_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_ed25519_keypair,
    ):
        """Encrypt→sign→verify→decrypt→parse round-trip."""
        _, sender_pub = sender_ed25519_keypair
        rec_priv, _ = recipient_ec_keypair

        signed = self._make_signed_encrypted_envelope(
            sample_envelope, recipient_jwks, sender_ed25519_keypair
        )

        result = decrypt_and_verify(signed, sender_pub, rec_priv)
        assert isinstance(result["payload"], dict)
        assert result["payload"]["type"] == "org.example.test"
        assert result["payload"]["args"]["message"] == "hello, encrypted world"

    def test_round_trip_ecdh_es_a256kw(
        self,
        sample_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_ed25519_keypair,
    ):
        """Round-trip with ECDH-ES+A256KW algorithm."""
        _, sender_pub = sender_ed25519_keypair
        rec_priv, _ = recipient_ec_keypair

        signed = self._make_signed_encrypted_envelope(
            sample_envelope,
            recipient_jwks,
            sender_ed25519_keypair,
            enc_alg="ECDH-ES+A256KW",
        )

        result = decrypt_and_verify(signed, sender_pub, rec_priv)
        assert isinstance(result["payload"], dict)
        assert result["payload"]["type"] == "org.example.test"

    def test_verify_before_decrypt(
        self,
        sample_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_ed25519_keypair,
    ):
        """§5.3: MUST verify signature BEFORE decrypting."""
        rec_priv, _ = recipient_ec_keypair
        wrong_sender_priv = Ed25519PrivateKey.generate()
        wrong_sender_pub = wrong_sender_priv.public_key()

        signed = self._make_signed_encrypted_envelope(
            sample_envelope, recipient_jwks, sender_ed25519_keypair
        )

        with pytest.raises(ValueError, match="Signature verification failed"):
            decrypt_and_verify(signed, wrong_sender_pub, rec_priv)

    def test_decryption_failure_unauthorized(
        self,
        sample_envelope,
        recipient_jwks,
        sender_ed25519_keypair,
    ):
        """§5.3: if decryption fails, reject with error code unauthorized."""
        _, sender_pub = sender_ed25519_keypair
        wrong_rec_priv = generate_private_key(SECP256R1())

        signed = self._make_signed_encrypted_envelope(
            sample_envelope, recipient_jwks, sender_ed25519_keypair
        )

        with pytest.raises(ValueError, match="JWE decryption failed"):
            decrypt_and_verify(signed, sender_pub, wrong_rec_priv)

    def test_non_json_plaintext_unauthorized(
        self,
        recipient_ec_keypair,
        sender_ed25519_keypair,
    ):
        """§5.3: decrypted plaintext that isn't valid JSON → unauthorized."""
        sender_priv, sender_pub = sender_ed25519_keypair
        rec_priv, rec_pub = recipient_ec_keypair

        jwe_string = jwe_encrypt(b"not json at all", rec_pub)
        envelope = {
            "v": "1.0",
            "id": "test-id",
            "ts": "2026-01-01T00:00:00.000Z",
            "from": "agent:test.sender",
            "to": "agent:test.recipient",
            "intent": "request",
            "payload": jwe_string,
            "security": {
                "encrypted": True,
                "enc_alg": "ECDH-ES",
                "enc_method": "A256GCM",
            },
        }
        signed = sign_message(envelope, sender_priv, "agent:test.sender#sign-1")

        with pytest.raises(ValueError, match="not valid JSON"):
            decrypt_and_verify(signed, sender_pub, rec_priv)

    def test_payload_not_string_unauthorized(
        self,
        sender_ed25519_keypair,
        recipient_ec_keypair,
    ):
        """Non-string payload in supposedly encrypted envelope → unauthorized."""
        sender_priv, sender_pub = sender_ed25519_keypair
        rec_priv, _ = recipient_ec_keypair

        envelope = {
            "v": "1.0",
            "id": "test-id",
            "ts": "2026-01-01T00:00:00.000Z",
            "from": "agent:test.sender",
            "to": "agent:test.recipient",
            "intent": "request",
            "payload": {"type": "test"},
            "security": {"encrypted": True},
        }
        signed = sign_message(envelope, sender_priv, "agent:test.sender#sign-1")

        with pytest.raises(ValueError, match="JWE string.*payload"):
            decrypt_and_verify(signed, sender_pub, rec_priv)

    def test_invalid_jwe_string_unauthorized(
        self,
        sender_ed25519_keypair,
        recipient_ec_keypair,
    ):
        """Invalid JWE string in payload → unauthorized."""
        sender_priv, sender_pub = sender_ed25519_keypair
        rec_priv, _ = recipient_ec_keypair

        envelope = {
            "v": "1.0",
            "id": "test-id",
            "ts": "2026-01-01T00:00:00.000Z",
            "from": "agent:test.sender",
            "to": "agent:test.recipient",
            "intent": "request",
            "payload": "not.a.valid.jwe.string",
            "security": {"encrypted": True},
        }
        signed = sign_message(envelope, sender_priv, "agent:test.sender#sign-1")

        with pytest.raises(ValueError, match="JWE decryption failed"):
            decrypt_and_verify(signed, sender_pub, rec_priv)

    def test_signature_covers_encrypted_payload(
        self,
        sample_envelope,
        recipient_jwks,
        recipient_ec_keypair,
        sender_ed25519_keypair,
    ):
        """§5.3 point 4: signature covers the JWE string, not plaintext."""
        sender_priv, sender_pub = sender_ed25519_keypair
        rec_priv, _ = recipient_ec_keypair

        signed = self._make_signed_encrypted_envelope(
            sample_envelope, recipient_jwks, sender_ed25519_keypair
        )

        assert isinstance(signed["payload"], str)
        from arsia_protocol.core.message import verify_message

        assert verify_message(signed, sender_pub) is True
