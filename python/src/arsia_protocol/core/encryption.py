# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Payload encryption and decryption for ARSIA message envelopes.

Layer 2 (Core) — integrates with the sign/verify pipeline in
:mod:`arsia_protocol.message`. Provides:

- :func:`encrypt_payload`: encrypt a payload dict, place the JWE string
  in the envelope, and populate ``security.encrypted/enc_alg/enc_method``.
- :func:`decrypt_and_verify`: verify the signature first, then decrypt
  the JWE payload, and parse the plaintext as JSON.

Spec: ARSIA-Core.md §5.3.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arsia_protocol.hazmat.primitives.jwe import (
    jwe_decrypt,
    jwe_encrypt,
    resolve_encryption_key,
)
from arsia_protocol.hazmat.primitives.jwe import (
    _jwk_to_ec_public_key as _load_ec_key,
)
from arsia_protocol.core.message import verify_message

_DEFAULT_ENC_ALG = "ECDH-ES"
_DEFAULT_ENC_METHOD = "A256GCM"


def encrypt_payload(
    envelope: dict[str, Any],
    recipient_jwks: dict[str, Any] | list[dict[str, Any]],
    *,
    enc_alg: str = _DEFAULT_ENC_ALG,
    enc_method: str = _DEFAULT_ENC_METHOD,
) -> dict[str, Any]:
    """Encrypt the envelope payload and set encryption security fields.

    The payload dict is serialized to JSON, encrypted as a JWE Compact
    Serialization string using the recipient's public encryption key
    (``use=enc``), and placed back in the ``payload`` field. The
    ``security`` fields ``encrypted``, ``enc_alg``, and ``enc_method``
    are populated.

    The caller SHOULD sign the envelope AFTER calling this function,
    so that the signature covers the JWE string (§5.3 point 4).

    Args:
        envelope: An ARSIA envelope dict with a ``payload`` dict.
        recipient_jwks: Recipient's JWKS (dict or list of JWK dicts).
        enc_alg: Key agreement algorithm. Defaults to ``ECDH-ES``.
        enc_method: Content encryption algorithm. Defaults to ``A256GCM``.

    Returns:
        A new envelope dict with encrypted payload and security fields set.

    Raises:
        ValueError: If no encryption key is found in the recipient's JWKS.

    Spec: ARSIA-Core.md §5.3 (Encryption Procedure).
    """
    enc_jwk = resolve_encryption_key(recipient_jwks)
    if enc_jwk is None:
        raise ValueError("No encryption key (use=enc) found in recipient's JWKS")

    recipient_public_key = _load_ec_key(enc_jwk)

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("envelope.payload must be a dict before encryption")

    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    jwe_string = jwe_encrypt(
        plaintext,
        recipient_public_key,
        alg=enc_alg,
        enc=enc_method,
        kid=enc_jwk.get("kid"),
    )

    result = copy.deepcopy(envelope)
    result["payload"] = jwe_string
    security = result.get("security", {})
    security["encrypted"] = True
    security["enc_alg"] = enc_alg
    security["enc_method"] = enc_method
    result["security"] = security
    return result


def decrypt_and_verify(
    envelope: dict[str, Any],
    sender_public_key: Ed25519PublicKey,
    recipient_private_key: EllipticCurvePrivateKey,
) -> dict[str, Any]:
    """Verify the signature and decrypt the payload of an encrypted envelope.

    Per §5.3, the recipient MUST:

    1. Verify the digital signature first (§5.2).
    2. Decrypt the JWE payload string.
    3. Parse the decrypted plaintext as a JSON object (§4.4).
    4. Reject with ``unauthorized`` if decryption fails.

    Args:
        envelope: A signed ARSIA envelope with an encrypted (JWE string)
            payload.
        sender_public_key: Sender's Ed25519 public key for signature
            verification.
        recipient_private_key: Recipient's P-256 private key for
            decryption.

    Returns:
        A new envelope dict with the decrypted payload dict restored.

    Raises:
        ValueError: If signature verification fails, decryption fails,
            or the plaintext is not valid JSON.

    Spec: ARSIA-Core.md §5.3 (Decryption Procedure).
    """
    if not verify_message(envelope, sender_public_key):
        raise ValueError(
            "Signature verification failed on encrypted envelope. "
            "Verify that the sender's public key matches the signing key."
        )

    jwe_string = envelope.get("payload")
    if not isinstance(jwe_string, str):
        raise ValueError(
            "Expected a JWE string in the payload field of an encrypted "
            "envelope, got a non-string value"
        )

    try:
        plaintext = jwe_decrypt(jwe_string, recipient_private_key)
    except Exception:
        raise ValueError(
            "JWE decryption failed. Verify the recipient private key "
            "matches the encryption key in the sender's JWKS."
        ) from None

    try:
        payload = json.loads(plaintext)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError(
            "Decrypted JWE plaintext is not valid JSON. "
            "The encrypted payload must be a JSON-serialized object."
        ) from None

    if not isinstance(payload, dict):
        raise ValueError(
            "Decrypted JWE plaintext is not a JSON object (got array or "
            "primitive). The encrypted payload must deserialize to a "
            "JSON object."
        )

    result = copy.deepcopy(envelope)
    result["payload"] = payload
    return result


__all__ = [
    "decrypt_and_verify",
    "encrypt_payload",
]
