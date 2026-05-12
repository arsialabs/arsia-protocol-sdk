# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.hazmat.primitives.ed25519``."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_decode,
    base64url_encode,
    generate_keypair,
    private_key_from_bytes,
    private_key_from_hex,
    public_key_from_bytes,
    public_key_from_hex,
    public_key_to_jwk_dict,
    sign,
    verify,
)


def test_generate_keypair_returns_correct_types() -> None:
    """``generate_keypair`` returns an ``(Ed25519PrivateKey, Ed25519PublicKey)``
    tuple.

    Spec: ARSIA-Core.md §5.1.
    """
    private_key, public_key = generate_keypair()
    assert isinstance(private_key, Ed25519PrivateKey)
    assert isinstance(public_key, Ed25519PublicKey)


def test_generate_keypair_produces_unique_pairs() -> None:
    """Two successive calls produce distinct key material.

    Spec: ARSIA-Core.md §5.1.
    """
    _, pub1 = generate_keypair()
    _, pub2 = generate_keypair()
    raw1 = pub1.public_bytes_raw()
    raw2 = pub2.public_bytes_raw()
    assert raw1 != raw2


def test_sign_returns_64_bytes() -> None:
    """Ed25519 signatures are always exactly 64 bytes.

    Spec: ARSIA-Core.md §5.1 Step 4.
    """
    private_key, _ = generate_keypair()
    signature = sign(private_key, b"arbitrary data")
    assert len(signature) == 64


def test_sign_verify_roundtrip() -> None:
    """Sign-then-verify with the matching public key returns ``True``.

    Spec: ARSIA-Core.md §5.1-5.2.
    """
    private_key, public_key = generate_keypair()
    data = b"message to sign"
    signature = sign(private_key, data)
    assert verify(public_key, data, signature) is True


def test_verify_rejects_wrong_public_key() -> None:
    """A signature is rejected when verified with a different public key.

    Spec: ARSIA-Core.md §5.2 Step 5.
    """
    private_key_a, _ = generate_keypair()
    _, public_key_b = generate_keypair()
    signature = sign(private_key_a, b"data")
    assert verify(public_key_b, b"data", signature) is False


def test_verify_rejects_tampered_data() -> None:
    """Flipping a single byte in the signed data fails verification.

    Spec: ARSIA-Core.md §5.2 Step 5.
    """
    private_key, public_key = generate_keypair()
    data = b"the original message"
    signature = sign(private_key, data)
    tampered = b"The original message"  # capitalized T
    assert verify(public_key, tampered, signature) is False


def test_verify_rejects_tampered_signature() -> None:
    """Flipping a single byte in the signature fails verification.

    Spec: ARSIA-Core.md §5.2 Step 5.
    """
    private_key, public_key = generate_keypair()
    data = b"the original message"
    signature = bytearray(sign(private_key, data))
    signature[0] ^= 0x01
    assert verify(public_key, data, bytes(signature)) is False


def test_verify_does_not_raise_on_invalid() -> None:
    """``verify`` never raises — it returns ``False`` on failure.

    Spec: ARSIA-Core.md §5.2 Step 5.
    """
    _, public_key = generate_keypair()
    # Garbage signature of the correct length.
    garbage = b"\x00" * 64
    result = verify(public_key, b"data", garbage)
    assert result is False


def test_base64url_encode_no_padding() -> None:
    """Encoded output never contains ``=`` padding characters.

    Spec: ARSIA-Core.md §5.1 Step 5.
    """
    # 1 byte → 2 base64 chars + 2 pad; 2 bytes → 3 chars + 1 pad.
    for raw in [b"\x01", b"\x01\x02", b"\x01\x02\x03", b"\x00" * 64]:
        encoded = base64url_encode(raw)
        assert "=" not in encoded


def test_base64url_encode_url_safe() -> None:
    """Encoded output uses ``-``/``_`` instead of ``+``/``/``.

    Spec: ARSIA-Core.md §5.1 Step 5.
    """
    # These bytes are known to produce ``+`` and ``/`` in standard base64.
    raw = b"\xfb\xff\xbf"
    encoded = base64url_encode(raw)
    assert "+" not in encoded
    assert "/" not in encoded


def test_base64url_decode_without_padding() -> None:
    """Decoder accepts input without trailing ``=`` padding.

    Spec: ARSIA-Core.md §5.2 Step 1.
    """
    raw = b"hello world"
    unpadded = base64url_encode(raw)
    assert "=" not in unpadded
    assert base64url_decode(unpadded) == raw


def test_base64url_decode_with_padding() -> None:
    """Decoder also accepts input that already has padding.

    Spec: ARSIA-Core.md §5.2 Step 1.
    """
    # "hi" → "aGk" without padding, "aGk=" with padding.
    assert base64url_decode("aGk") == b"hi"
    assert base64url_decode("aGk=") == b"hi"


def test_base64url_roundtrip() -> None:
    """encode → decode returns the original bytes for various lengths.

    Spec: ARSIA-Core.md §5.1 Step 5 / §5.2 Step 1.
    """
    for raw in [b"", b"\x00", b"\xff", b"\x00\x01\x02\x03\x04", b"\xde\xad\xbe\xef"]:
        assert base64url_decode(base64url_encode(raw)) == raw


def test_private_key_from_bytes_32_bytes() -> None:
    """A 32-byte blob loads as a valid Ed25519 private key.

    Spec: ARSIA-Core.md §5.1.
    """
    raw = bytes(range(32))
    private_key = private_key_from_bytes(raw)
    assert isinstance(private_key, Ed25519PrivateKey)


def test_public_key_from_bytes_32_bytes() -> None:
    """A 32-byte blob loads as a valid Ed25519 public key.

    Spec: ARSIA-Core.md §5.2.
    """
    private_key, _ = generate_keypair()
    raw = private_key.public_key().public_bytes_raw()
    public_key = public_key_from_bytes(raw)
    assert isinstance(public_key, Ed25519PublicKey)


def test_private_key_from_hex() -> None:
    """Loading from hex produces a key that can sign and verify.

    Spec: ARSIA-Core.md §5.1.
    """
    hex_str = "8f475f7ab003e3b2c944813336136484b22520dc93a7e52f68b08c3e661501ea"
    private_key = private_key_from_hex(hex_str)
    data = b"hex loader roundtrip"
    signature = sign(private_key, data)
    assert verify(private_key.public_key(), data, signature) is True


def test_public_key_from_hex() -> None:
    """Loading a public key from hex produces the expected type.

    Spec: ARSIA-Core.md §5.2.
    """
    hex_str = "db20606b77bf63488d763f423a4caa11c92c3a54cb845ef248d691dc8c7220bd"
    public_key = public_key_from_hex(hex_str)
    assert isinstance(public_key, Ed25519PublicKey)


def test_load_keypair_acme(keypair_acme: dict[str, Any]) -> None:
    """Keypair for ``agent:acme.echo-client`` signs and verifies.

    Spec: ARSIA-Core.md §5.1-5.2.
    """
    data = b"acme echo client roundtrip"
    signature = sign(keypair_acme["private_key"], data)
    assert verify(keypair_acme["public_key"], data, signature) is True


def test_load_keypair_risk_assessor(keypair_risk_assessor: dict[str, Any]) -> None:
    """Keypair for ``agent:arsialabs.demo.risk-assessor`` signs and verifies.

    Spec: ARSIA-Core.md §5.1-5.2.
    """
    data = b"risk assessor roundtrip"
    signature = sign(keypair_risk_assessor["private_key"], data)
    assert verify(keypair_risk_assessor["public_key"], data, signature) is True


def test_load_keypair_compliance_checker(
    keypair_compliance_checker: dict[str, Any],
) -> None:
    """Keypair for ``agent:arsialabs.demo.compliance-checker`` signs and verifies.

    Spec: ARSIA-Core.md §5.1-5.2.
    """
    data = b"compliance checker roundtrip"
    signature = sign(keypair_compliance_checker["private_key"], data)
    assert verify(keypair_compliance_checker["public_key"], data, signature) is True


def test_public_key_to_jwk_dict_has_required_fields() -> None:
    """JWK dict has the five fields required by ARSIA-Core.md §7.3.

    Spec: ARSIA-Core.md §7.3 (Ed25519 key format).
    """
    _, public_key = generate_keypair()
    jwk = public_key_to_jwk_dict(public_key, "agent:acme.bot#key1")
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["kid"] == "agent:acme.bot#key1"
    assert jwk["use"] == "sig"
    assert isinstance(jwk["x"], str)


def test_public_key_to_jwk_dict_x_is_base64url_no_padding() -> None:
    """The ``x`` field is base64url without padding.

    Spec: ARSIA-Core.md §7.3, §5.1 Step 5.
    """
    _, public_key = generate_keypair()
    jwk = public_key_to_jwk_dict(public_key, "kid")
    assert "=" not in jwk["x"]
    assert "+" not in jwk["x"]
    assert "/" not in jwk["x"]


def test_public_key_to_jwk_dict_roundtrip_matches_public_key_bytes() -> None:
    """Decoding ``x`` yields the same bytes as ``public_bytes_raw``.

    This is the round-trip property that lets verifiers resolve
    ``kid`` → raw public key and feed it to ``verify``.

    Spec: ARSIA-Core.md §5.2, §7.3.
    """
    _, public_key = generate_keypair()
    jwk = public_key_to_jwk_dict(public_key, "kid")
    recovered = base64url_decode(jwk["x"])
    assert recovered == public_key.public_bytes_raw()
    assert len(recovered) == 32


def test_public_key_to_jwk_dict_custom_use() -> None:
    """The ``use`` parameter overrides the default ``"sig"``.

    Spec: ARSIA-Core.md §7.3.
    """
    _, public_key = generate_keypair()
    jwk = public_key_to_jwk_dict(public_key, "kid", use="enc")
    assert jwk["use"] == "enc"
