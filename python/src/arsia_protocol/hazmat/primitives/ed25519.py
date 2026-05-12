# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Raw Ed25519 sign/verify primitives and base64url helpers.

This module is Layer 0 in the SDK dependency graph: it has no imports
from other ``arsia_protocol`` modules. It wraps the ``cryptography``
library's Ed25519 implementation with the encoding conventions required
by the ARSIA Protocol (base64url without padding, 64-byte raw
signatures) and convenience loaders for 32-byte raw key material.

These primitives are dangerous if misused — for example, signing data
that has not been canonicalized per §5.1 will produce signatures that
other conformant implementations cannot verify. High-level APIs in
``arsia_protocol.message`` apply the envelope rules automatically and
should be preferred.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair.

    Returns:
        A ``(private_key, public_key)`` tuple.

    Spec: ARSIA-Core.md §5.1 (Ed25519 is the primary signing algorithm).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Produce a raw 64-byte Ed25519 signature over ``data``.

    The caller is responsible for canonicalizing the input per RFC 8785
    before calling this function. See
    ``arsia_protocol.hazmat.canonicalization``.

    Args:
        private_key: Signing key.
        data: Raw bytes to sign (typically JCS-canonical envelope bytes).

    Returns:
        The 64-byte Ed25519 signature.

    Spec: ARSIA-Core.md §5.1 Step 4.
    """
    return private_key.sign(data)


def verify(
    public_key: Ed25519PublicKey,
    data: bytes,
    signature: bytes,
) -> bool:
    """Verify an Ed25519 signature without raising on failure.

    Follows §5.2 Step 5: returns ``True`` if the signature is valid for
    the given public key and data, ``False`` otherwise. Never raises
    ``InvalidSignature`` — callers that need to distinguish failure
    modes must wrap this themselves.

    Args:
        public_key: Verification key.
        data: Raw bytes that were signed.
        signature: Raw 64-byte Ed25519 signature.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.

    Spec: ARSIA-Core.md §5.2 Step 5.
    """
    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


def base64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding.

    Uses the URL-safe alphabet (``-`` and ``_`` instead of ``+`` and
    ``/``) and strips trailing ``=`` padding characters, as required by
    RFC 4648 §5 and the ARSIA signature encoding rules.

    Args:
        data: Raw bytes to encode.

    Returns:
        The base64url-encoded string, with no ``=`` characters.

    Spec: ARSIA-Core.md §5.1 Step 5.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Decode a base64url string, padding if necessary.

    Accepts input either with or without the trailing ``=`` padding and
    re-pads as needed before delegating to the standard library decoder.

    Args:
        s: The base64url-encoded string.

    Returns:
        The decoded raw bytes.

    Spec: ARSIA-Core.md §5.2 Step 1.
    """
    padding_needed = (-len(s)) % 4
    padded = s + ("=" * padding_needed)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def private_key_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from 32 raw bytes.

    Args:
        raw: Exactly 32 bytes of raw Ed25519 private key material.

    Returns:
        The loaded ``Ed25519PrivateKey``.
    """
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from 32 raw bytes.

    Args:
        raw: Exactly 32 bytes of raw Ed25519 public key material.

    Returns:
        The loaded ``Ed25519PublicKey``.
    """
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_from_hex(hex_str: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a 64-character hex string.

    Args:
        hex_str: Hex-encoded 32-byte private key.

    Returns:
        The loaded ``Ed25519PrivateKey``.
    """
    return private_key_from_bytes(bytes.fromhex(hex_str))


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a 64-character hex string.

    Args:
        hex_str: Hex-encoded 32-byte public key.

    Returns:
        The loaded ``Ed25519PublicKey``.
    """
    return public_key_from_bytes(bytes.fromhex(hex_str))


def public_key_to_jwk_dict(
    public_key: Ed25519PublicKey,
    kid: str,
    *,
    use: str = "sig",
) -> dict[str, str]:
    """Encode an Ed25519 public key as a JWK dictionary.

    Produces a JWK per RFC 8037 §2 with the ARSIA ``kid`` convention
    from ARSIA-Core.md §7.3 / §2.2:

    - ``kty``: ``"OKP"`` (Octet Key Pair)
    - ``crv``: ``"Ed25519"``
    - ``x``:   base64url-encoded 32-byte public key, no padding
    - ``kid``: the key identifier (expected to follow
      ``"{agent-id}#{key-label}"``, though this function does not
      validate that grammar — callers are responsible)
    - ``use``: defaults to ``"sig"``; pass ``"enc"`` for X25519 keys
      (though the key type would then differ — this helper is
      Ed25519-specific)

    This is a pure encoding primitive: it performs no network or
    filesystem I/O and does not validate the ``kid`` format. It lives
    in ``hazmat`` because it is dual to
    :func:`base64url_encode` and is used by the discovery builders in
    :mod:`arsia_protocol.discovery` as well as higher-level consumers
    in onboarding / authorization modules.

    Args:
        public_key: Ed25519 public key to encode.
        kid: Key identifier string. See ARSIA-Identity.md §2.2 for the
            recommended ``"{agent-id}#{key-label}"`` format.
        use: JWK ``use`` parameter. Defaults to ``"sig"`` for signing
            keys.

    Returns:
        A dict with keys ``kty``, ``crv``, ``x``, ``kid``, ``use``.
        Safe to serialize as JSON directly.

    Spec: ARSIA-Core.md §7.3 (Ed25519 key format), RFC 8037 §2.
    """
    raw = public_key.public_bytes_raw()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64url_encode(raw),
        "kid": kid,
        "use": use,
    }


__all__ = [
    "generate_keypair",
    "sign",
    "verify",
    "base64url_encode",
    "base64url_decode",
    "private_key_from_bytes",
    "public_key_from_bytes",
    "private_key_from_hex",
    "public_key_from_hex",
    "public_key_to_jwk_dict",
]
