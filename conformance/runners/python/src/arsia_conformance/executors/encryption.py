# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``encryption`` category.

Exercises :func:`arsia_protocol.encryption.decrypt_and_verify` and
:func:`arsia_protocol.encryption.encrypt_payload` against the §5.3
decryption procedure.

Operations:

- ``decrypt_and_verify`` — builds a signed, encrypted envelope from
  ``input.plaintext_payload`` using the named test keypair for signing
  and an ephemeral P-256 key for encryption, then runs
  ``decrypt_and_verify``. Asserts ``expected.valid`` and optional
  ``expected.payload_type`` / ``expected.error_contains``.
- ``decrypt_bad_signature`` — same as above but signs with a DIFFERENT
  Ed25519 key (``input.wrong_signer_agent_id``). The decryption step
  never executes; the signature check rejects first.
- ``decrypt_dual_fault`` — same as ``decrypt_bad_signature`` but also
  corrupts the JWE payload (truncated to one segment). Both faults are
  present; the error message reveals which check ran first.  If signature
  verification runs first (correct per §5.3), the error mentions
  "signature". If decryption runs first (wrong), the error mentions
  "JWE decryption failed".
- ``decrypt_not_json_object`` — encrypts raw bytes that are NOT a JSON
  object (e.g. a JSON array), signs the envelope, then calls
  ``decrypt_and_verify``. Asserts rejection because the plaintext is
  not a JSON object per §4.4.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _load_ed25519_keypair(
    context: ConformanceContext, agent_id: str
) -> tuple[Any, Any] | None:
    from arsia_protocol.hazmat.primitives.ed25519 import (
        private_key_from_hex,
        public_key_from_hex,
    )

    entry = context.keypairs.get(agent_id)
    if not isinstance(entry, dict):
        return None
    private_hex = entry.get("private_key_hex")
    public_hex = entry.get("public_key_hex")
    if not isinstance(private_hex, str) or not isinstance(public_hex, str):
        return None
    return private_key_from_hex(private_hex), public_key_from_hex(public_hex)


def _build_and_encrypt(
    plaintext_payload: dict[str, Any],
    from_agent: str,
    to_agent: str,
) -> tuple[dict[str, Any], Any]:
    """Build an envelope, encrypt the payload, return (envelope, ec_private_key)."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )

    from arsia_protocol.core.encryption import encrypt_payload
    from arsia_protocol.core.message import create_request

    payload_type = plaintext_payload.get("type", "com.test.encrypted")
    envelope = create_request(
        from_agent=from_agent,
        to_agent=to_agent,
        payload_type=payload_type,
        capabilities=["com.test.encrypted"],
    )
    envelope["payload"] = plaintext_payload

    ec_private = generate_private_key(SECP256R1())
    ec_public = ec_private.public_key()

    from arsia_protocol.hazmat.primitives.jwe import _ec_public_key_to_jwk

    recipient_jwk = _ec_public_key_to_jwk(ec_public)
    recipient_jwk["use"] = "enc"
    recipient_jwk["kid"] = f"{to_agent}#enc-1"

    encrypted = encrypt_payload(envelope, [recipient_jwk])
    return encrypted, ec_private


def _run_decrypt_and_verify(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.encryption import decrypt_and_verify
    from arsia_protocol.core.message import sign_message

    signer = case.input.get("signer_agent_id")
    if not isinstance(signer, str):
        return "error", "input.signer_agent_id must be a string"
    pair = _load_ed25519_keypair(context, signer)
    if pair is None:
        return "error", f"unknown test keypair: {signer!r}"
    private_key, public_key = pair

    plaintext_payload = case.input.get("plaintext_payload")
    if not isinstance(plaintext_payload, dict):
        return "error", "input.plaintext_payload must be an object"

    from_agent = case.input.get("from_agent", signer)
    to_agent = case.input.get("to_agent", "agent:acme.echo-client")
    if not isinstance(from_agent, str) or not isinstance(to_agent, str):
        return "error", "input.from_agent and input.to_agent must be strings"

    encrypted, ec_private = _build_and_encrypt(plaintext_payload, from_agent, to_agent)

    kid = f"{from_agent}#key-1"
    signed = sign_message(encrypted, private_key, kid=kid)

    want_valid = bool(case.expected.get("valid", True))
    try:
        result = decrypt_and_verify(signed, public_key, ec_private)
    except ValueError as exc:
        if not want_valid:
            keyword = case.expected.get("error_contains")
            if isinstance(keyword, str) and keyword:
                if keyword.lower() not in str(exc).lower():
                    return "fail", f"error did not mention {keyword!r}: {exc}"
            return "pass", None
        return "fail", f"decrypt_and_verify raised unexpectedly: {exc}"

    if not want_valid:
        return "fail", "expected rejection but decrypt_and_verify succeeded"

    want_type = case.expected.get("payload_type")
    if isinstance(want_type, str):
        got_type = result.get("payload", {}).get("type")
        if got_type != want_type:
            return "fail", f"payload.type: expected {want_type!r}, got {got_type!r}"

    want_fields = case.expected.get("payload_fields")
    if isinstance(want_fields, dict):
        got_payload = result.get("payload", {})
        for field, value in want_fields.items():
            if got_payload.get(field) != value:
                return (
                    "fail",
                    f"payload.{field}: expected {value!r}, got {got_payload.get(field)!r}",
                )

    if not isinstance(result.get("payload"), dict):
        return "fail", "decrypted payload is not a JSON object"

    return "pass", None


def _run_decrypt_bad_signature(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.encryption import decrypt_and_verify
    from arsia_protocol.core.message import sign_message

    signer = case.input.get("signer_agent_id")
    wrong_signer = case.input.get("wrong_signer_agent_id")
    if not isinstance(signer, str) or not isinstance(wrong_signer, str):
        return "error", "input.signer_agent_id and input.wrong_signer_agent_id required"
    correct_pair = _load_ed25519_keypair(context, signer)
    wrong_pair = _load_ed25519_keypair(context, wrong_signer)
    if correct_pair is None or wrong_pair is None:
        return "error", f"unknown keypair: {signer!r} or {wrong_signer!r}"

    _, correct_public = correct_pair
    wrong_private, _ = wrong_pair

    plaintext_payload = case.input.get("plaintext_payload")
    if not isinstance(plaintext_payload, dict):
        return "error", "input.plaintext_payload must be an object"

    from_agent = case.input.get("from_agent", signer)
    to_agent = case.input.get("to_agent", "agent:acme.echo-client")

    encrypted, ec_private = _build_and_encrypt(plaintext_payload, from_agent, to_agent)

    kid = f"{from_agent}#key-1"
    signed = sign_message(encrypted, wrong_private, kid=kid)

    try:
        decrypt_and_verify(signed, correct_public, ec_private)
    except ValueError as exc:
        keyword = case.expected.get("error_contains")
        if isinstance(keyword, str) and keyword:
            if keyword.lower() not in str(exc).lower():
                return "fail", f"error did not mention {keyword!r}: {exc}"
        return "pass", None

    return "fail", "expected signature rejection but decrypt_and_verify succeeded"


def _run_decrypt_dual_fault(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    """Dual-fault ordering test: bad signature AND malformed JWE.

    If the SDK checks signature first (correct), the error mentions
    "signature".  If it tries to decrypt first (wrong), the error
    mentions "JWE decryption failed".  The error content reveals which
    operation ran first.
    """
    from arsia_protocol.core.encryption import decrypt_and_verify
    from arsia_protocol.core.message import sign_message

    signer = case.input.get("signer_agent_id")
    wrong_signer = case.input.get("wrong_signer_agent_id")
    if not isinstance(signer, str) or not isinstance(wrong_signer, str):
        return "error", "input.signer_agent_id and input.wrong_signer_agent_id required"
    correct_pair = _load_ed25519_keypair(context, signer)
    wrong_pair = _load_ed25519_keypair(context, wrong_signer)
    if correct_pair is None or wrong_pair is None:
        return "error", f"unknown keypair: {signer!r} or {wrong_signer!r}"

    _, correct_public = correct_pair
    wrong_private, _ = wrong_pair

    plaintext_payload = case.input.get("plaintext_payload")
    if not isinstance(plaintext_payload, dict):
        return "error", "input.plaintext_payload must be an object"

    from_agent = case.input.get("from_agent", signer)
    to_agent = case.input.get("to_agent", "agent:acme.echo-client")

    encrypted, ec_private = _build_and_encrypt(plaintext_payload, from_agent, to_agent)

    jwe_string = encrypted.get("payload", "")
    if isinstance(jwe_string, str) and "." in jwe_string:
        encrypted["payload"] = jwe_string.split(".")[0]
    else:
        encrypted["payload"] = "not-a-valid-jwe"

    kid = f"{from_agent}#key-1"
    signed = sign_message(encrypted, wrong_private, kid=kid)

    try:
        decrypt_and_verify(signed, correct_public, ec_private)
    except ValueError as exc:
        err_lower = str(exc).lower()
        keyword = case.expected.get("error_contains")
        if isinstance(keyword, str) and keyword:
            if keyword.lower() not in err_lower:
                return (
                    "fail",
                    f"expected error containing {keyword!r} but got: {exc} "
                    f"(this likely means decryption ran before signature verification)",
                )
        return "pass", None

    return "fail", "expected rejection but decrypt_and_verify succeeded"


def _run_decrypt_not_json_object(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )

    from arsia_protocol.core.encryption import decrypt_and_verify
    from arsia_protocol.hazmat.primitives.jwe import (
        _ec_public_key_to_jwk,
        jwe_encrypt,
    )
    from arsia_protocol.core.message import create_request, sign_message

    signer = case.input.get("signer_agent_id")
    if not isinstance(signer, str):
        return "error", "input.signer_agent_id must be a string"
    pair = _load_ed25519_keypair(context, signer)
    if pair is None:
        return "error", f"unknown test keypair: {signer!r}"
    private_key, public_key = pair

    non_object_json = case.input.get("non_object_json", "[1,2,3]")
    if not isinstance(non_object_json, str):
        return "error", "input.non_object_json must be a string"

    from_agent = case.input.get("from_agent", signer)
    to_agent = case.input.get("to_agent", "agent:acme.echo-client")

    envelope = create_request(
        from_agent=from_agent,
        to_agent=to_agent,
        payload_type="test.placeholder",
        capabilities=["com.test.encrypted"],
    )

    ec_private = generate_private_key(SECP256R1())
    ec_public = ec_private.public_key()

    jwe_string = jwe_encrypt(
        non_object_json.encode("utf-8"),
        ec_public,
    )

    envelope["payload"] = jwe_string
    security = envelope.get("security", {})
    security["encrypted"] = True
    security["enc_alg"] = "ECDH-ES"
    security["enc_method"] = "A256GCM"
    envelope["security"] = security

    kid = f"{from_agent}#key-1"
    signed = sign_message(envelope, private_key, kid=kid)

    try:
        decrypt_and_verify(signed, public_key, ec_private)
    except ValueError as exc:
        keyword = case.expected.get("error_contains")
        if isinstance(keyword, str) and keyword:
            if keyword.lower() not in str(exc).lower():
                return "fail", f"error did not mention {keyword!r}: {exc}"
        return "pass", None

    return "fail", "expected rejection but decrypt_and_verify succeeded"


_OPERATIONS: dict[str, Any] = {
    "decrypt_and_verify": _run_decrypt_and_verify,
    "decrypt_bad_signature": _run_decrypt_bad_signature,
    "decrypt_dual_fault": _run_decrypt_dual_fault,
    "decrypt_not_json_object": _run_decrypt_not_json_object,
}


def execute(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.core.encryption  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol.encryption import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for encryption cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown encryption operation: {operation!r}"
    return handler(case, context)


__all__ = ["execute"]
