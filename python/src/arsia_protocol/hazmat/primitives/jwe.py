# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Raw JWE Compact Serialization encrypt/decrypt primitives.

Layer 0 — no imports from other ``arsia_protocol`` modules. Implements
ECDH-ES and ECDH-ES+A256KW key agreement with A256GCM content encryption
per RFC 7516 (JWE), RFC 7518 §4.6 (ECDH-ES), and RFC 3394 (AES Key Wrap).

Spec: ARSIA-Core.md §5.3.
"""

from __future__ import annotations

import base64
import json
import os
import struct
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

_A256GCM_KEY_BITS = 256
_A256GCM_IV_BYTES = 12

_SUPPORTED_ALGS = frozenset({"ECDH-ES", "ECDH-ES+A256KW"})
_SUPPORTED_ENCS = frozenset({"A256GCM"})


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = (-len(s)) % 4
    return base64.urlsafe_b64decode((s + "=" * padding).encode("ascii"))


def _build_concat_kdf_otherinfo(
    algorithm_id: str,
    apu: bytes,
    apv: bytes,
    key_data_len_bits: int,
) -> bytes:
    """Build the otherinfo parameter for Concat KDF per RFC 7518 §4.6.2."""
    alg_bytes = algorithm_id.encode("ascii")
    return (
        struct.pack(">I", len(alg_bytes))
        + alg_bytes
        + struct.pack(">I", len(apu))
        + apu
        + struct.pack(">I", len(apv))
        + apv
        + struct.pack(">I", key_data_len_bits)
    )


def _derive_key(
    shared_secret: bytes,
    algorithm_id: str,
    key_length_bytes: int,
    apu: bytes = b"",
    apv: bytes = b"",
) -> bytes:
    """Derive a key using Concat KDF (SHA-256) per RFC 7518 §4.6.2."""
    otherinfo = _build_concat_kdf_otherinfo(
        algorithm_id, apu, apv, key_length_bytes * 8
    )
    ckdf = ConcatKDFHash(
        algorithm=SHA256(),
        length=key_length_bytes,
        otherinfo=otherinfo,
    )
    return ckdf.derive(shared_secret)


def _ec_public_key_to_jwk(key: EllipticCurvePublicKey) -> dict[str, str]:
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": _b64url_encode(numbers.y.to_bytes(32, "big")),
    }


def _jwk_to_ec_public_key(jwk: dict[str, Any]) -> EllipticCurvePublicKey:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicNumbers,
    )

    if jwk.get("crv") != "P-256":
        raise ValueError(f"Unsupported curve: {jwk.get('crv')}")
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()


def jwe_encrypt(
    plaintext: bytes,
    recipient_public_key: EllipticCurvePublicKey,
    *,
    alg: str = "ECDH-ES",
    enc: str = "A256GCM",
    kid: str | None = None,
    apu: bytes = b"",
    apv: bytes = b"",
) -> str:
    """Produce a JWE Compact Serialization string.

    Args:
        plaintext: The payload bytes to encrypt.
        recipient_public_key: Recipient's P-256 public encryption key.
        alg: Key agreement algorithm (``ECDH-ES`` or ``ECDH-ES+A256KW``).
        enc: Content encryption algorithm (``A256GCM``).
        kid: Optional recipient key identifier for the JWE header.
        apu: Agreement PartyUInfo (optional, per RFC 7518 §4.6.2).
        apv: Agreement PartyVInfo (optional, per RFC 7518 §4.6.2).

    Returns:
        JWE Compact Serialization (5 base64url dot-separated parts).
    """
    if alg not in _SUPPORTED_ALGS:
        raise ValueError(f"Unsupported alg: {alg!r}, must be one of {_SUPPORTED_ALGS}")
    if enc not in _SUPPORTED_ENCS:
        raise ValueError(f"Unsupported enc: {enc!r}, must be one of {_SUPPORTED_ENCS}")

    ephemeral_private = generate_private_key(SECP256R1())
    ephemeral_public = ephemeral_private.public_key()
    shared_secret = ephemeral_private.exchange(ECDH(), recipient_public_key)

    header: dict[str, Any] = {
        "alg": alg,
        "enc": enc,
        "epk": _ec_public_key_to_jwk(ephemeral_public),
    }
    if kid is not None:
        header["kid"] = kid
    if apu:
        header["apu"] = _b64url_encode(apu)
    if apv:
        header["apv"] = _b64url_encode(apv)

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    protected_header = _b64url_encode(header_bytes)

    iv = os.urandom(_A256GCM_IV_BYTES)

    if alg == "ECDH-ES":
        cek = _derive_key(shared_secret, enc, _A256GCM_KEY_BITS // 8, apu, apv)
        encrypted_key = b""
    else:
        kek = _derive_key(shared_secret, "A256KW", _A256GCM_KEY_BITS // 8, apu, apv)
        cek = os.urandom(_A256GCM_KEY_BITS // 8)
        encrypted_key = aes_key_wrap(kek, cek)

    aad = protected_header.encode("ascii")
    aesgcm = AESGCM(cek)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]

    return ".".join(
        [
            protected_header,
            _b64url_encode(encrypted_key),
            _b64url_encode(iv),
            _b64url_encode(ciphertext),
            _b64url_encode(tag),
        ]
    )


def jwe_decrypt(
    jwe_string: str,
    recipient_private_key: EllipticCurvePrivateKey,
) -> bytes:
    """Decrypt a JWE Compact Serialization string.

    Args:
        jwe_string: The 5-part dot-separated JWE compact serialization.
        recipient_private_key: Recipient's P-256 private key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If the JWE is malformed or uses unsupported algorithms.
        Exception: If decryption fails (e.g., wrong key, tampered data).
    """
    parts = jwe_string.split(".")
    if len(parts) != 5:
        raise ValueError(
            f"JWE Compact Serialization must have 5 parts, got {len(parts)}"
        )

    protected_b64, enc_key_b64, iv_b64, ct_b64, tag_b64 = parts

    header_bytes = _b64url_decode(protected_b64)
    header = json.loads(header_bytes)

    alg = header.get("alg", "")
    enc = header.get("enc", "")
    if alg not in _SUPPORTED_ALGS:
        raise ValueError(f"Unsupported alg: {alg!r}")
    if enc not in _SUPPORTED_ENCS:
        raise ValueError(f"Unsupported enc: {enc!r}")

    epk = header.get("epk")
    if not epk:
        raise ValueError("JWE header missing 'epk' field")
    ephemeral_public = _jwk_to_ec_public_key(epk)

    apu = _b64url_decode(header["apu"]) if "apu" in header else b""
    apv = _b64url_decode(header["apv"]) if "apv" in header else b""

    shared_secret = recipient_private_key.exchange(ECDH(), ephemeral_public)

    encrypted_key = _b64url_decode(enc_key_b64)
    iv = _b64url_decode(iv_b64)
    ciphertext = _b64url_decode(ct_b64)
    tag = _b64url_decode(tag_b64)

    if alg == "ECDH-ES":
        cek = _derive_key(shared_secret, enc, _A256GCM_KEY_BITS // 8, apu, apv)
    else:
        kek = _derive_key(shared_secret, "A256KW", _A256GCM_KEY_BITS // 8, apu, apv)
        cek = aes_key_unwrap(kek, encrypted_key)

    aad = protected_b64.encode("ascii")
    aesgcm = AESGCM(cek)
    return aesgcm.decrypt(iv, ciphertext + tag, aad)


def resolve_encryption_key(
    jwks: dict[str, Any] | list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Find the first JWK with ``use=enc`` in a JWKS.

    Args:
        jwks: A JWKS dict (``{"keys": [...]}``) or a bare list of JWK dicts.

    Returns:
        The first JWK dict with ``"use": "enc"``, or ``None`` if not found.
    """
    keys: list[Any]
    if isinstance(jwks, dict):
        keys = jwks.get("keys", [])
    else:
        keys = jwks
    for jwk in keys:
        if isinstance(jwk, dict) and jwk.get("use") == "enc":
            return jwk
    return None


__all__ = [
    "jwe_decrypt",
    "jwe_encrypt",
    "resolve_encryption_key",
]
