# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for arsia_protocol.hazmat.primitives.ecdsa (ES256 P-256)."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from arsia_protocol.hazmat.primitives import ecdsa


class TestGenerateKeypair:
    def test_produces_p256_keys(self) -> None:
        priv, pub = ecdsa.generate_keypair()
        assert isinstance(priv, ec.EllipticCurvePrivateKey)
        assert isinstance(pub, ec.EllipticCurvePublicKey)
        assert isinstance(priv.curve, ec.SECP256R1)
        assert isinstance(pub.curve, ec.SECP256R1)

    def test_different_keypairs(self) -> None:
        _, pub1 = ecdsa.generate_keypair()
        _, pub2 = ecdsa.generate_keypair()
        n1 = pub1.public_numbers()
        n2 = pub2.public_numbers()
        assert (n1.x, n1.y) != (n2.x, n2.y)


class TestSignVerify:
    def test_round_trip(self) -> None:
        priv, pub = ecdsa.generate_keypair()
        data = b"hello ARSIA"
        sig = ecdsa.sign(priv, data)
        assert ecdsa.verify(pub, data, sig) is True

    def test_produces_64_byte_signature(self) -> None:
        priv, _ = ecdsa.generate_keypair()
        sig = ecdsa.sign(priv, b"test data")
        assert len(sig) == 64

    def test_verify_wrong_key_returns_false(self) -> None:
        priv1, _ = ecdsa.generate_keypair()
        _, pub2 = ecdsa.generate_keypair()
        sig = ecdsa.sign(priv1, b"some data")
        assert ecdsa.verify(pub2, b"some data", sig) is False

    def test_verify_tampered_message_returns_false(self) -> None:
        priv, pub = ecdsa.generate_keypair()
        sig = ecdsa.sign(priv, b"original")
        assert ecdsa.verify(pub, b"tampered", sig) is False

    def test_verify_wrong_length_signature_returns_false(self) -> None:
        _, pub = ecdsa.generate_keypair()
        assert ecdsa.verify(pub, b"data", b"\x00" * 63) is False
        assert ecdsa.verify(pub, b"data", b"\x00" * 65) is False
        assert ecdsa.verify(pub, b"data", b"") is False

    def test_verify_zeroed_signature_returns_false(self) -> None:
        _, pub = ecdsa.generate_keypair()
        assert ecdsa.verify(pub, b"data", b"\x00" * 64) is False

    def test_deterministic_over_same_data(self) -> None:
        """ECDSA is non-deterministic (uses random k), so two signatures
        over the same data should differ but both verify."""
        priv, pub = ecdsa.generate_keypair()
        data = b"same data"
        sig1 = ecdsa.sign(priv, data)
        sig2 = ecdsa.sign(priv, data)
        assert sig1 != sig2
        assert ecdsa.verify(pub, data, sig1) is True
        assert ecdsa.verify(pub, data, sig2) is True


class TestPublicKeyToJwkDict:
    def test_required_fields(self) -> None:
        _, pub = ecdsa.generate_keypair()
        jwk = ecdsa.public_key_to_jwk_dict(pub, "agent:acme.signer#key-1")
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["kid"] == "agent:acme.signer#key-1"
        assert jwk["use"] == "sig"
        assert "x" in jwk
        assert "y" in jwk
        assert len(jwk) == 6

    def test_use_enc(self) -> None:
        _, pub = ecdsa.generate_keypair()
        jwk = ecdsa.public_key_to_jwk_dict(pub, "agent:acme.enc#key-1", use="enc")
        assert jwk["use"] == "enc"

    def test_x_y_are_base64url_no_padding(self) -> None:
        _, pub = ecdsa.generate_keypair()
        jwk = ecdsa.public_key_to_jwk_dict(pub, "agent:acme.signer#k1")
        assert "=" not in jwk["x"]
        assert "=" not in jwk["y"]
        assert "+" not in jwk["x"]
        assert "/" not in jwk["x"]

    def test_jwk_coordinates_roundtrip(self) -> None:
        """Export to JWK, reconstruct key from coordinates, verify a signature."""
        from arsia_protocol.hazmat.primitives.ed25519 import base64url_decode

        priv, pub = ecdsa.generate_keypair()
        jwk = ecdsa.public_key_to_jwk_dict(pub, "agent:acme.signer#k1")

        x_bytes = base64url_decode(jwk["x"])
        y_bytes = base64url_decode(jwk["y"])
        assert len(x_bytes) == 32
        assert len(y_bytes) == 32

        x_int = int.from_bytes(x_bytes, "big")
        y_int = int.from_bytes(y_bytes, "big")
        numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
        reconstructed = numbers.public_key()

        data = b"roundtrip test"
        sig = ecdsa.sign(priv, data)
        assert ecdsa.verify(reconstructed, data, sig) is True
