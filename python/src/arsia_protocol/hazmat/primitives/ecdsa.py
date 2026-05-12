# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ECDSA P-256 (ES256) signing primitives.

Low-level cryptographic operations. Consumers should use
core.message.sign_message / verify_message instead.

Spec: ARSIA-Core §4.3.5 (ES256 SHOULD), §5.1 (ES256 RECOMMENDED).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_encode,
)


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a P-256 keypair for ES256 signing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign data with ES256 (ECDSA P-256 + SHA-256).

    Returns the signature as raw r||s (64 bytes), not DER-encoded.
    The caller is responsible for canonicalizing the input per RFC 8785.

    Args:
        private_key: P-256 signing key.
        data: Raw bytes to sign (typically JCS-canonical envelope bytes).

    Returns:
        64-byte raw signature (32-byte r + 32-byte s).
    """
    der_sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(
    public_key: ec.EllipticCurvePublicKey,
    data: bytes,
    signature: bytes,
) -> bool:
    """Verify an ES256 signature without raising on failure.

    Args:
        public_key: P-256 verification key.
        data: Raw bytes that were signed.
        signature: Raw 64-byte r||s signature.

    Returns:
        ``True`` if valid, ``False`` otherwise.
    """
    if len(signature) != 64:
        return False
    try:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)
        public_key.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, OverflowError):
        return False
    return True


def public_key_to_jwk_dict(
    public_key: ec.EllipticCurvePublicKey,
    kid: str,
    *,
    use: str = "sig",
) -> dict[str, str]:
    """Encode a P-256 public key as a JWK dictionary.

    Produces a JWK per RFC 7518 §6.2.1 with:
    - ``kty``: ``"EC"``
    - ``crv``: ``"P-256"``
    - ``x``, ``y``: base64url-encoded 32-byte coordinates
    - ``kid``: key identifier
    - ``use``: defaults to ``"sig"`` (CORE-§7.3-22)

    Args:
        public_key: P-256 public key to encode.
        kid: Key identifier string.
        use: JWK ``use`` parameter. Defaults to ``"sig"``.

    Returns:
        A dict safe to serialize as JSON directly.

    Spec: ARSIA-Core.md §7.3 (P-256 signing JWK use MUST be sig).
    """
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(numbers.x.to_bytes(32, "big")),
        "y": base64url_encode(numbers.y.to_bytes(32, "big")),
        "kid": kid,
        "use": use,
    }


__all__ = [
    "generate_keypair",
    "sign",
    "verify",
    "public_key_to_jwk_dict",
]
