# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``authorization`` category.

Dispatches on ``input.operation``. Five offline operations map to
pure, deterministic entry points from
:mod:`arsia_protocol.authorization`:

- ``validate_token`` — builds a signed JWT from the case's
  ``claims`` block using the shared test keypair named by
  ``signer_agent_id``, then validates it via
  :func:`arsia_protocol.authorization.validate_token_claims`. A
  fixed ``now_unix`` makes clock-skew cases deterministic.
- ``check_scope_coverage`` — exact-match scope enforcement per
  ARSIA-Core.md §6.4 step 5.
- ``compute_jwk_thumbprint`` — RFC 7638 thumbprint golden tests.
- ``validate_dpop`` — builds a DPoP proof from the case's
  ``proof`` block, signs it with the named test keypair, and runs
  :func:`arsia_protocol.authorization.validate_dpop_proof`. The
  optional ``bind_token`` field lets cases build a proof bound to
  one token and validate against another (``ath`` mismatch).
- ``verify_dpop_binding`` — compares a literal ``cnf.jkt`` string
  against the thumbprint of a supplied DPoP JWK.

HTTP-dependent live cases (IDENTITY-03..08) live alongside these
in ``authorization.yaml`` with ``skip_until: slice-8`` and are
recorded as skipped by the runner without touching this executor.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _load_test_keypair(
    context: ConformanceContext, agent_id: str
) -> tuple[Any, Any] | None:
    """Resolve a shared test keypair to ``(private_key, public_key)``.

    Returns ``None`` if the agent ID is not present in
    ``shared/test-vectors/keypairs.json``.
    """
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


def _check_expected_valid(
    is_valid: bool,
    errors: tuple[Any, ...] | list[Any],
    expected: dict[str, Any],
) -> tuple[TestStatus, str | None]:
    """Shared ``valid`` / ``error_contains`` assertion."""
    want_valid = bool(expected.get("valid", True))
    if want_valid:
        if not is_valid:
            return "fail", f"expected valid but got errors: {list(errors)}"
        return "pass", None
    if is_valid:
        return "fail", "expected rejection but validation passed"
    keyword = expected.get("error_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in str(e).lower() for e in errors):
            return "fail", f"no error mentioned {keyword!r}; errors={list(errors)}"
    return "pass", None


def _parse_now(case: TestCase) -> datetime | None:
    raw = case.input.get("now_unix")
    if raw is None:
        return None
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        return None
    return datetime.fromtimestamp(float(raw), tz=timezone.utc)


def _run_validate_token(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.authorization import build_jwt, validate_token_claims

    signer = case.input.get("signer_agent_id")
    claims = case.input.get("claims")
    if not isinstance(signer, str):
        return "error", "input.signer_agent_id must be a string"
    if not isinstance(claims, dict):
        return "error", "input.claims must be an object"
    pair = _load_test_keypair(context, signer)
    if pair is None:
        return "error", f"unknown test keypair: {signer!r}"
    private_key, public_key = pair
    token = build_jwt(claims, private_key)

    expected_sub = case.input.get("expected_sub")
    expected_aud = case.input.get("expected_aud")
    required = case.input.get("required_capabilities")
    if required is not None and not isinstance(required, list):
        return "error", "input.required_capabilities must be a list"

    result = validate_token_claims(
        token,
        public_key,
        expected_sub=expected_sub if isinstance(expected_sub, str) else None,
        expected_aud=expected_aud if isinstance(expected_aud, str) else None,
        required_capabilities=(
            [str(c) for c in required] if isinstance(required, list) else None
        ),
        now=_parse_now(case),
    )
    return _check_expected_valid(result.is_valid, result.errors, case.expected)


def _run_check_scope_coverage(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.authorization import check_scope_coverage

    scope = case.input.get("scope")
    required = case.input.get("required")
    if not isinstance(scope, list) or not isinstance(required, list):
        return "error", "input.scope and input.required must be lists"
    covered, missing = check_scope_coverage(
        set(str(s) for s in scope), [str(r) for r in required]
    )
    want_covered = bool(case.expected.get("covered", True))
    if covered != want_covered:
        return "fail", f"covered={covered}, want {want_covered}; missing={missing}"
    want_missing = case.expected.get("missing")
    if isinstance(want_missing, list):
        if missing != [str(m) for m in want_missing]:
            return "fail", f"missing={missing}, want {want_missing}"
    return "pass", None


def _run_compute_jwk_thumbprint(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.authorization import compute_jwk_thumbprint

    jwk = case.input.get("jwk")
    if not isinstance(jwk, dict):
        return "error", "input.jwk must be an object"
    try:
        got = compute_jwk_thumbprint(jwk)
    except ValueError as exc:
        if bool(case.expected.get("raises", False)):
            return "pass", None
        return "fail", f"compute_jwk_thumbprint raised: {exc}"
    if bool(case.expected.get("raises", False)):
        return "fail", f"expected ValueError but got {got!r}"
    want = case.expected.get("thumbprint")
    if not isinstance(want, str):
        return "error", "expected.thumbprint must be a string"
    if got != want:
        return "fail", f"thumbprint={got!r}, want {want!r}"
    return "pass", None


def _run_validate_dpop(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.authorization import build_dpop_proof, validate_dpop_proof

    signer = case.input.get("signer_agent_id")
    if not isinstance(signer, str):
        return "error", "input.signer_agent_id must be a string"
    pair = _load_test_keypair(context, signer)
    if pair is None:
        return "error", f"unknown test keypair: {signer!r}"
    private_key, public_key = pair

    access_token = case.input.get("access_token")
    if not isinstance(access_token, str):
        return "error", "input.access_token must be a string"
    # ``bind_token`` lets the suite bind the DPoP proof to one token
    # and validate it against a different one — used for AUTH-DPOP-05
    # (ath mismatch). Defaults to the validation token so the
    # one-token case is the common path.
    bind_token = case.input.get("bind_token")
    if not isinstance(bind_token, str):
        bind_token = access_token

    proof_block = case.input.get("proof")
    if not isinstance(proof_block, dict):
        return "error", "input.proof must be an object"
    htm = proof_block.get("htm", "POST")
    htu = proof_block.get("htu")
    if not isinstance(htu, str):
        return "error", "input.proof.htu must be a string"
    iat = proof_block.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return "error", "input.proof.iat must be an integer"
    jti = proof_block.get("jti")
    if jti is not None and not isinstance(jti, str):
        return "error", "input.proof.jti must be a string if present"

    proof = build_dpop_proof(
        private_key,
        public_key,
        htm=str(htm),
        htu=str(htu),
        access_token=bind_token,
        jti=jti,
        iat=int(iat),
    )

    expected_htm = case.input.get("expected_htm", "POST")
    expected_htu = case.input.get("expected_htu")
    if not isinstance(expected_htu, str):
        return "error", "input.expected_htu must be a string"

    seen_jti_raw = case.input.get("seen_jti")
    seen_jti: set[str] | None
    if isinstance(seen_jti_raw, list):
        seen_jti = {str(j) for j in seen_jti_raw}
    else:
        seen_jti = None

    result = validate_dpop_proof(
        proof,
        access_token,
        expected_htm=str(expected_htm),
        expected_htu=expected_htu,
        now=_parse_now(case),
        seen_jti=seen_jti,
    )
    return _check_expected_valid(result.is_valid, result.errors, case.expected)


def _run_verify_dpop_binding(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.authorization import verify_dpop_binding

    jkt = case.input.get("token_cnf_jkt")
    jwk = case.input.get("dpop_jwk")
    if not isinstance(jkt, str):
        return "error", "input.token_cnf_jkt must be a string"
    if not isinstance(jwk, dict):
        return "error", "input.dpop_jwk must be an object"
    token_claims = {"cnf": {"jkt": jkt}}
    dpop_header = {"jwk": jwk}
    got = verify_dpop_binding(token_claims, dpop_header)
    want = bool(case.expected.get("bound", True))
    if got != want:
        return "fail", f"verify_dpop_binding = {got}, want {want}"
    return "pass", None


_OPERATIONS = {
    "validate_token": _run_validate_token,
    "check_scope_coverage": _run_check_scope_coverage,
    "compute_jwk_thumbprint": _run_compute_jwk_thumbprint,
    "validate_dpop": _run_validate_dpop,
    "verify_dpop_binding": _run_verify_dpop_binding,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    """Dispatch an ``authorization`` case to its handler.

    Unknown operations surface as ``error`` results so a typo in a
    suite file cannot silently pass.
    """
    try:
        import arsia_protocol.core.authorization  # noqa: F401
    except ImportError as exc:  # pragma: no cover - defensive
        return "error", f"arsia_protocol.authorization import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for authorization cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown authorization operation: {operation!r}"
    return handler(case, context)


__all__ = ["execute"]
