# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``signing`` category.

Covers both §5.1 Steps 4-5 (signing reproducibility) and §5.2
(verification). For each case:

1. Load the private key from ``vector.crypto.private_key_hex``.
2. Canonicalize the stripped envelope via the SDK.
3. Raw-sign the canonical bytes and compare the base64url-encoded
   signature to ``vector.crypto.signature_base64url``.
4. Call the high-level ``verify_message`` against the signed envelope
   and assert it returns ``True``.
"""

from __future__ import annotations

import copy

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        from arsia_protocol.hazmat.canonicalization import canonicalize
        from arsia_protocol.hazmat.primitives.ed25519 import (
            base64url_encode,
            private_key_from_hex,
            public_key_from_hex,
            sign as raw_sign,
        )
        from arsia_protocol.core.message import verify_message
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol import failed: {exc}"

    vector_id = case.input.get("vector_id")
    if not isinstance(vector_id, str):
        return "error", "input.vector_id is required for signing cases"
    try:
        vector = context.get_vector(vector_id)
    except KeyError as exc:
        return "error", str(exc)

    envelope = vector.get("message")
    crypto = vector.get("crypto")
    if not isinstance(envelope, dict) or not isinstance(crypto, dict):
        return "error", f"{vector_id}: missing message or crypto block"

    sk_hex = crypto.get("private_key_hex")
    pk_hex = crypto.get("public_key_hex")
    expected_sig = crypto.get("signature_base64url")
    if not isinstance(sk_hex, str) or not isinstance(pk_hex, str):
        return "error", f"{vector_id}: crypto block missing private/public key hex"
    if not isinstance(expected_sig, str):
        return "error", f"{vector_id}: crypto.signature_base64url is missing"

    unsigned = copy.deepcopy(envelope)
    unsigned.pop("security", None)
    canonical_bytes = canonicalize(unsigned)
    sk = private_key_from_hex(sk_hex)
    sig_bytes = raw_sign(sk, canonical_bytes)

    if case.expected.get("signature_match_vector", False):
        if base64url_encode(sig_bytes) != expected_sig:
            return "fail", f"{vector_id}: produced signature does not match vector"

    if case.expected.get("verify", False):
        pk = public_key_from_hex(pk_hex)
        if verify_message(envelope, pk) is not True:
            return "fail", f"{vector_id}: verify_message returned False"

    return "pass", None


__all__ = ["execute"]
