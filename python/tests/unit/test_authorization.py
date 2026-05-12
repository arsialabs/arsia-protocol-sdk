# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for :mod:`arsia_protocol.authorization`.

Covers the Slice 4B JWT access-token and DPoP proof validation
layer:

- JWT decode / signature verification basics.
- Full access-token claim validation per ARSIA-Core.md §6.4.
- Exact-match scope coverage (§6.4 step 5).
- DPoP proof decode, signature, htm/htu/iat/ath/jti checks
  (ARSIA-Identity.md §3.3).
- ``cnf.jkt`` binding between an access token and its DPoP proof.
- RFC 7638 JWK Thumbprint correctness against a golden value.
- Defensive rejection of ``alg: "none"`` tokens.

All tests are offline, deterministic, and use the shared Ed25519
keypair fixtures from :mod:`tests.conftest`.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from arsia_protocol.core.authorization import (
    DEFAULT_CLOCK_SKEW_SECONDS,
    DPOP_TYP,
    SUPPORTED_ALGORITHMS,
    DPoPValidationResult,
    TokenValidationResult,
    build_dpop_proof,
    build_jwt,
    build_token_request,
    check_scope_coverage,
    compute_jwk_thumbprint,
    decode_jwt,
    parse_scope,
    validate_dpop_proof,
    validate_token_claims,
    verify_dpop_binding,
    verify_jwt_signature,
)
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_decode,
    base64url_encode,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_FIXED_NOW = datetime(2026, 4, 12, 12, 0, 0, tzinfo=timezone.utc)
_FIXED_IAT = int(_FIXED_NOW.timestamp())


def _base_claims(**overrides: Any) -> dict[str, Any]:
    """Return a minimally valid token claim set for ``_FIXED_NOW``."""
    claims: dict[str, Any] = {
        "iss": "https://as.example.com",
        "sub": "agent:acme.echo-client",
        "aud": "agent:contoso.crm",
        "exp": _FIXED_IAT + 3600,
        "iat": _FIXED_IAT,
        "jti": "11111111-1111-1111-1111-111111111111",
        "scope": "notes.read notes.write",
    }
    claims.update(overrides)
    return claims


def _sign_token(claims: dict[str, Any], keypair: dict[str, Any]) -> str:
    return build_jwt(claims, keypair["private_key"])


# ---------------------------------------------------------------------------
# JWT basics — decode, signing input, signature
# ---------------------------------------------------------------------------


def test_decode_jwt_valid(keypair_acme: dict[str, Any]) -> None:
    """Spec: RFC 7519 §7.1 — three-part compact serialization splits cleanly."""
    token = _sign_token(_base_claims(), keypair_acme)
    header, payload, signature = decode_jwt(token)
    assert header == {"alg": "EdDSA", "typ": "JWT"}
    assert payload["sub"] == "agent:acme.echo-client"
    assert isinstance(signature, bytes)
    assert len(signature) == 64  # Ed25519 invariant


def test_decode_jwt_malformed_two_parts() -> None:
    """Spec: RFC 7519 §7.2 — missing third part must be rejected."""
    with pytest.raises(ValueError, match="exactly 3 dot-separated parts"):
        decode_jwt("abc.def")


def test_decode_jwt_garbage_parts() -> None:
    """Spec: RFC 7515 §3 — parts that do not decode to JSON are rejected.

    Note: Python's ``base64.urlsafe_b64decode`` silently ignores
    non-alphabet characters, so ``@@@`` decodes to empty bytes.
    That still fails JSON parsing, which is what we rely on.
    """
    with pytest.raises(ValueError, match="not valid JSON"):
        decode_jwt("@@@.###.$$$")


def test_decode_jwt_non_object_header(keypair_acme: dict[str, Any]) -> None:
    """Spec: RFC 7515 §4 — header MUST be a JSON object."""
    # Header = JSON number, payload = valid, signature = anything.
    bad_header = base64url_encode(b"42")
    good_payload = base64url_encode(b'{"iss":"x"}')
    signing_input = f"{bad_header}.{good_payload}".encode("ascii")
    from arsia_protocol.hazmat.primitives.ed25519 import sign

    sig = sign(keypair_acme["private_key"], signing_input)
    token = f"{bad_header}.{good_payload}.{base64url_encode(sig)}"
    with pytest.raises(ValueError, match="header must decode to a JSON object"):
        decode_jwt(token)


def test_decode_jwt_non_string_raises() -> None:
    """Spec: defensive — non-string input rejected at boundary."""
    with pytest.raises(ValueError, match="must be a string"):
        decode_jwt(42)  # type: ignore[arg-type]


def test_build_jwt_roundtrip(keypair_acme: dict[str, Any]) -> None:
    """Spec: RFC 7519 §7.1 — build → decode must round-trip claims."""
    claims = _base_claims()
    token = _sign_token(claims, keypair_acme)
    _header, payload, _sig = decode_jwt(token)
    assert payload == claims


def test_build_jwt_default_eddsa_header(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.1 — default alg MUST be EdDSA."""
    token = _sign_token(_base_claims(), keypair_acme)
    header, _payload, _sig = decode_jwt(token)
    assert header["alg"] == "EdDSA"
    assert header["typ"] == "JWT"


def test_build_jwt_custom_header(keypair_acme: dict[str, Any]) -> None:
    """Spec: RFC 7515 — caller can supply full replacement header."""
    token = build_jwt(
        {"any": "claim"},
        keypair_acme["private_key"],
        header={"alg": "EdDSA", "typ": "JOSE+JSON"},
    )
    header, _, _ = decode_jwt(token)
    assert header["typ"] == "JOSE+JSON"


def test_verify_jwt_signature_valid(keypair_acme: dict[str, Any]) -> None:
    """Spec: RFC 7515 §5.2 — correct key returns True."""
    token = _sign_token(_base_claims(), keypair_acme)
    assert verify_jwt_signature(token, keypair_acme["public_key"]) is True


def test_verify_jwt_signature_wrong_key(
    keypair_acme: dict[str, Any],
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: RFC 7515 §5.2 — wrong key must return False (no exception)."""
    token = _sign_token(_base_claims(), keypair_acme)
    assert verify_jwt_signature(token, keypair_risk_assessor["public_key"]) is False


def test_verify_jwt_signature_tampered_payload(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: RFC 7515 — modifying the payload invalidates the signature."""
    token = _sign_token(_base_claims(), keypair_acme)
    header_b64, payload_b64, sig_b64 = token.split(".")
    tampered_payload = base64url_encode(
        json.dumps(_base_claims(sub="agent:evil.imposter")).encode("utf-8")
    )
    tampered = f"{header_b64}.{tampered_payload}.{sig_b64}"
    assert verify_jwt_signature(tampered, keypair_acme["public_key"]) is False


def test_verify_jwt_signature_malformed_returns_false(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: defensive — malformed JWT must return False, not raise."""
    assert verify_jwt_signature("not.a.jwt", keypair_acme["public_key"]) is False


def test_verify_jwt_signature_alg_none_rejected(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Core.md §6.1 — alg:"none" attack vector MUST be rejected.

    Even if a caller supplies an unsigned token whose signing input
    bytes match, SUPPORTED_ALGORITHMS allows EdDSA only.
    """
    header = base64url_encode(b'{"alg":"none","typ":"JWT"}')
    payload = base64url_encode(json.dumps(_base_claims()).encode("utf-8"))
    token = f"{header}.{payload}."  # empty signature
    assert verify_jwt_signature(token, keypair_acme["public_key"]) is False


def test_verify_jwt_signature_rs256_rejected(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: Slice 4B supports EdDSA only. RS256 tokens MUST be rejected.

    Defensive: even if a future slice adds RSA, this test pins the
    current SUPPORTED_ALGORITHMS shape so the decision is explicit.
    """
    token = build_jwt(
        _base_claims(),
        keypair_acme["private_key"],
        header={"alg": "RS256", "typ": "JWT"},
    )
    assert verify_jwt_signature(token, keypair_acme["public_key"]) is False


def test_supported_algorithms_is_eddsa_only() -> None:
    """Spec: Slice 4B — SUPPORTED_ALGORITHMS contains EdDSA only."""
    assert SUPPORTED_ALGORITHMS == frozenset({"EdDSA"})


# ---------------------------------------------------------------------------
# Access-token claim validation (§6.4)
# ---------------------------------------------------------------------------


def test_validate_token_valid(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.4 — fully-valid token returns is_valid=True."""
    token = _sign_token(_base_claims(), keypair_acme)
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        expected_sub="agent:acme.echo-client",
        expected_aud="agent:contoso.crm",
        required_capabilities=["notes.read", "notes.write"],
        now=_FIXED_NOW,
    )
    assert result.is_valid is True
    assert result.errors == ()
    assert result.claims is not None
    assert result.claims["sub"] == "agent:acme.echo-client"


def test_validate_token_expired(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.4 step 3 — expired tokens are rejected."""
    claims = _base_claims(exp=_FIXED_IAT - 1000)
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("expired" in str(e) for e in result.errors)


def test_validate_token_iat_in_future(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.4 step 3 — iat in the future is rejected."""
    claims = _base_claims(iat=_FIXED_IAT + 10_000)
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("iat is in the future" in str(e) for e in result.errors)


def test_validate_token_nbf_in_future_rejected(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.2 step 3 — nbf in the future is rejected."""
    claims = _base_claims(nbf=_FIXED_IAT + 10_000)
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("not yet valid" in str(e) for e in result.errors)


def test_validate_token_nbf_in_past_accepted(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.2 — nbf in the past is accepted."""
    claims = _base_claims(nbf=_FIXED_IAT - 1000)
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is True


def test_validate_token_nbf_within_skew_accepted(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.2 — nbf within clock skew is accepted."""
    claims = _base_claims(nbf=_FIXED_IAT + 100)  # < ±300s default
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is True


def test_validate_token_nbf_absent_accepted(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.2 — nbf is OPTIONAL; absence is valid."""
    claims = _base_claims()
    assert "nbf" not in claims
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is True


def test_validate_token_nbf_non_numeric_rejected(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.2 — non-numeric nbf is rejected."""
    claims = _base_claims(nbf="not-a-number")
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("'nbf' must be a numeric date" in str(e) for e in result.errors)


def test_validate_token_within_clock_skew(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §8.3 — exp 100s past but within ±300s is valid."""
    claims = _base_claims(exp=_FIXED_IAT - 100)
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is True


def test_validate_token_beyond_clock_skew(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §8.3 — exp 400s past is beyond ±300s tolerance."""
    claims = _base_claims(exp=_FIXED_IAT - 400)
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("expired" in str(e) for e in result.errors)


def test_validate_token_custom_clock_skew_zero(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Core.md §8.3 — callers may pass clock_skew_seconds=0."""
    claims = _base_claims(exp=_FIXED_IAT - 1)
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        clock_skew_seconds=0,
        now=_FIXED_NOW,
    )
    assert result.is_valid is False


def test_validate_token_wrong_sub(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.4 step 3 — sub mismatch is rejected."""
    token = _sign_token(_base_claims(), keypair_acme)
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        expected_sub="agent:acme.other",
        now=_FIXED_NOW,
    )
    assert result.is_valid is False
    assert any("sub" in str(e) for e in result.errors)


def test_validate_token_wrong_aud(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.4 step 3 — aud mismatch is rejected."""
    token = _sign_token(_base_claims(), keypair_acme)
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        expected_aud="agent:other.target",
        now=_FIXED_NOW,
    )
    assert result.is_valid is False
    assert any("aud" in str(e) for e in result.errors)


def test_validate_token_missing_exp(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.1 — missing exp is rejected."""
    claims = _base_claims()
    del claims["exp"]
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("'exp'" in str(e) for e in result.errors)


def test_validate_token_missing_sub(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.1 — missing sub is rejected."""
    claims = _base_claims()
    del claims["sub"]
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("'sub'" in str(e) for e in result.errors)


def test_validate_token_missing_scope(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.1 — missing scope is rejected."""
    claims = _base_claims()
    del claims["scope"]
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        required_capabilities=["notes.read"],
        now=_FIXED_NOW,
    )
    assert result.is_valid is False
    assert any("'scope'" in str(e) for e in result.errors)


def test_validate_token_scope_covers(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.4 step 5 — scope covers all required."""
    token = _sign_token(
        _base_claims(scope="notes.read notes.write notes.delete"),
        keypair_acme,
    )
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        required_capabilities=["notes.read", "notes.write"],
        now=_FIXED_NOW,
    )
    assert result.is_valid is True


def test_validate_token_scope_partial(keypair_acme: dict[str, Any]) -> None:
    """Spec: ARSIA-Core.md §6.4 step 5 — missing capabilities are reported."""
    token = _sign_token(
        _base_claims(scope="notes.read"),
        keypair_acme,
    )
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        required_capabilities=["notes.read", "notes.write", "notes.delete"],
        now=_FIXED_NOW,
    )
    assert result.is_valid is False
    assert any("missing=" in str(e) for e in result.errors)
    assert any("notes.write" in str(e) for e in result.errors)


def test_validate_token_scope_exact_match_not_wildcards(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: ARSIA-Core.md §6.4 step 5 — exact match, NO wildcard expansion.

    A scope of ``notes.*`` does NOT cover ``notes.read`` for token
    enforcement purposes. This is the critical discriminator
    between token-level and capability-level matching.
    """
    token = _sign_token(_base_claims(scope="notes.*"), keypair_acme)
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        required_capabilities=["notes.read"],
        now=_FIXED_NOW,
    )
    assert result.is_valid is False
    assert any(e.code == "token_scope_insufficient" for e in result.errors)


def test_validate_token_result_has_claims_on_success(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: API shape — claims dict returned on success."""
    token = _sign_token(_base_claims(), keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert result.claims is not None
    assert result.claims["iss"] == "https://as.example.com"


def test_validate_token_result_errors_tuple_is_frozen(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: frozen dataclass — errors must be a tuple (immutable)."""
    token = _sign_token(_base_claims(exp=_FIXED_IAT - 10_000), keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    assert isinstance(result.errors, tuple)
    assert len(result.errors) >= 1


def test_validate_token_result_is_frozen_dataclass(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: TokenValidationResult is a frozen dataclass — cannot mutate."""
    token = _sign_token(_base_claims(), keypair_acme)
    result = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    with pytest.raises(Exception):  # FrozenInstanceError
        result.is_valid = False  # type: ignore[misc]


def test_validate_token_now_injection_is_deterministic(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: API shape — now kwarg makes validation deterministic."""
    token = _sign_token(_base_claims(), keypair_acme)
    # Same token, different now → different outcomes.
    r_ok = validate_token_claims(
        token, keypair_acme["public_key"], now=_FIXED_NOW
    )
    r_future = validate_token_claims(
        token,
        keypair_acme["public_key"],
        now=_FIXED_NOW.replace(year=2099),
    )
    assert r_ok.is_valid is True
    assert r_future.is_valid is False


def test_validate_token_undecodable_returns_error(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: decoding failure short-circuits with claims=None."""
    result = validate_token_claims("not.a.jwt", keypair_acme["public_key"])
    assert result.is_valid is False
    assert result.claims is None
    assert any("could not be decoded" in str(e) for e in result.errors)


def test_validate_token_accumulates_multiple_errors(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: all checks accumulate — a single result can list many failures."""
    claims = _base_claims(
        exp=_FIXED_IAT - 10_000,
        sub="agent:other",
        aud="agent:wrong",
        scope="foo.bar",
    )
    token = _sign_token(claims, keypair_acme)
    result = validate_token_claims(
        token,
        keypair_acme["public_key"],
        expected_sub="agent:acme.echo-client",
        expected_aud="agent:contoso.crm",
        required_capabilities=["notes.read"],
        now=_FIXED_NOW,
    )
    assert result.is_valid is False
    # exp + sub + aud + scope = at least 4 errors
    assert len(result.errors) >= 4


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------


def test_parse_scope_single() -> None:
    """Spec: ARSIA-Core.md §6.1 — single scope entry parses to singleton set."""
    assert parse_scope("notes.read") == {"notes.read"}


def test_parse_scope_multiple() -> None:
    """Spec: ARSIA-Core.md §6.1 — space-separated scopes parse to a set."""
    assert parse_scope("a b c") == {"a", "b", "c"}


def test_parse_scope_empty() -> None:
    """Spec: ARSIA-Core.md §6.1 — empty string parses to empty set."""
    assert parse_scope("") == set()


def test_parse_scope_non_string_raises() -> None:
    """Spec: defensive — non-string input must raise at the boundary."""
    with pytest.raises(TypeError):
        parse_scope(42)  # type: ignore[arg-type]


def test_check_scope_all_covered() -> None:
    """Spec: ARSIA-Core.md §6.4 step 5 — complete coverage returns (True, [])."""
    covered, missing = check_scope_coverage(
        {"a", "b", "c"}, ["a", "b"]
    )
    assert covered is True
    assert missing == []


def test_check_scope_partial() -> None:
    """Spec: ARSIA-Core.md §6.4 step 5 — missing list preserves request order."""
    covered, missing = check_scope_coverage(
        {"a"}, ["a", "b", "c"]
    )
    assert covered is False
    assert missing == ["b", "c"]


def test_check_scope_empty_required() -> None:
    """Spec: ARSIA-Core.md §6.4 step 5 — empty requirement is vacuously covered."""
    covered, missing = check_scope_coverage({"a"}, [])
    assert covered is True
    assert missing == []


def test_check_scope_exact_match_not_wildcard() -> None:
    """Spec: ARSIA-Core.md §6.4 step 5 — ``notes.*`` in scope does NOT match ``notes.read``."""
    covered, missing = check_scope_coverage({"notes.*"}, ["notes.read"])
    assert covered is False
    assert missing == ["notes.read"]


# ---------------------------------------------------------------------------
# JWK Thumbprint (RFC 7638)
# ---------------------------------------------------------------------------


def test_compute_jwk_thumbprint_golden_acme() -> None:
    """Spec: RFC 7638 §3.2 — thumbprint of the acme test keypair is deterministic.

    This is a reproducible golden value: canonical form
    ``{"crv":"Ed25519","kty":"OKP","x":"2yBga3e_Y0iNdj9COkyqEcksOlTLhF7ySNaR3IxyIL0"}``
    then SHA-256 then base64url-no-padding.
    """
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "2yBga3e_Y0iNdj9COkyqEcksOlTLhF7ySNaR3IxyIL0",
    }
    assert compute_jwk_thumbprint(jwk) == "EokVh4xzjb5Ynb7coQLVYCvcbkPySMsVzyAsBEE8DMM"


def test_compute_jwk_thumbprint_ignores_extra_members(
    keypair_acme: dict[str, Any],
) -> None:
    """Spec: RFC 7638 §3.2 — extra members (``kid``, ``use``) MUST be ignored."""
    x_b64 = base64url_encode(keypair_acme["public_key"].public_bytes_raw())
    minimal = {"kty": "OKP", "crv": "Ed25519", "x": x_b64}
    extended = {**minimal, "kid": "foo#1", "use": "sig"}
    assert compute_jwk_thumbprint(minimal) == compute_jwk_thumbprint(extended)


def test_compute_jwk_thumbprint_rejects_non_ed25519() -> None:
    """Spec: RFC 7638 — non-Ed25519 curves not supported by this module."""
    with pytest.raises(ValueError, match="crv"):
        compute_jwk_thumbprint({"kty": "OKP", "crv": "X25519", "x": "aa"})


def test_compute_jwk_thumbprint_rejects_wrong_kty() -> None:
    """Spec: RFC 7638 — non-OKP kty rejected."""
    with pytest.raises(ValueError, match="kty"):
        compute_jwk_thumbprint({"kty": "RSA", "crv": "Ed25519", "x": "aa"})


def test_compute_jwk_thumbprint_rejects_missing_x() -> None:
    """Spec: RFC 7638 §3.2 — required member 'x' must be present."""
    with pytest.raises(ValueError, match="'x'"):
        compute_jwk_thumbprint({"kty": "OKP", "crv": "Ed25519"})


def test_compute_jwk_thumbprint_rejects_non_dict() -> None:
    """Spec: defensive — non-dict input rejected at boundary."""
    with pytest.raises(ValueError):
        compute_jwk_thumbprint("not a dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# DPoP proof validation (Identity §3.3)
# ---------------------------------------------------------------------------

_HTU = "https://contoso.crm/arsia/inbox"


def _valid_dpop(
    keypair: dict[str, Any],
    access_token: str,
    **overrides: Any,
) -> str:
    """Build a DPoP proof bound to ``_FIXED_NOW`` for deterministic tests."""
    kwargs = {
        "htm": "POST",
        "htu": _HTU,
        "access_token": access_token,
        "iat": _FIXED_IAT,
    }
    kwargs.update(overrides)
    return build_dpop_proof(
        keypair["private_key"],
        keypair["public_key"],
        **kwargs,
    )


def test_build_dpop_proof_header_structure(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.3 — header MUST contain typ, alg, jwk."""
    proof = _valid_dpop(keypair_risk_assessor, "test-token")
    header, _payload, _sig = decode_jwt(proof)
    assert header["typ"] == DPOP_TYP
    assert header["alg"] == "EdDSA"
    assert header["jwk"]["kty"] == "OKP"
    assert header["jwk"]["crv"] == "Ed25519"
    assert "x" in header["jwk"]
    # DPoP JWK MUST NOT include kid or use per Identity §3.3.
    assert "kid" not in header["jwk"]
    assert "use" not in header["jwk"]


def test_build_dpop_proof_payload_claims(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.3 — payload has jti/htm/htu/iat/ath."""
    proof = _valid_dpop(keypair_risk_assessor, "test-token")
    _hdr, payload, _sig = decode_jwt(proof)
    assert payload["htm"] == "POST"
    assert payload["htu"] == _HTU
    assert payload["iat"] == _FIXED_IAT
    assert "jti" in payload and isinstance(payload["jti"], str)
    assert "ath" in payload and isinstance(payload["ath"], str)


def test_build_dpop_proof_ath_matches_token_sha256(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 5 — ath = base64url(SHA-256(access_token))."""
    access = "abc.def.ghi"
    proof = _valid_dpop(keypair_risk_assessor, access)
    _hdr, payload, _sig = decode_jwt(proof)
    expected = base64url_encode(hashlib.sha256(access.encode("ascii")).digest())
    assert payload["ath"] == expected


def test_validate_dpop_valid(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: ARSIA-Identity.md §3.3 — well-formed DPoP proof is accepted."""
    access = "test-access-token"
    proof = _valid_dpop(keypair_risk_assessor, access)
    result = validate_dpop_proof(
        proof,
        access,
        expected_htu=_HTU,
        now=_FIXED_NOW,
        seen_jti=set(),
    )
    assert result.is_valid is True
    assert result.errors == ()


def test_validate_dpop_wrong_htm(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 3 — htm mismatch rejected."""
    proof = _valid_dpop(keypair_risk_assessor, "tok", htm="GET")
    result = validate_dpop_proof(
        proof, "tok", expected_htm="POST", expected_htu=_HTU, now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("htm" in str(e) for e in result.errors)


def test_validate_dpop_wrong_htu(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 2 — htu mismatch rejected."""
    proof = _valid_dpop(keypair_risk_assessor, "tok", htu="https://other/x")
    result = validate_dpop_proof(
        proof, "tok", expected_htu=_HTU, now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("htu" in str(e) for e in result.errors)


def test_validate_dpop_expired_iat(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 4 — iat too old (>±300s) rejected."""
    proof = _valid_dpop(keypair_risk_assessor, "tok", iat=_FIXED_IAT - 1000)
    result = validate_dpop_proof(
        proof, "tok", expected_htu=_HTU, now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("iat is too old" in str(e) for e in result.errors)


def test_validate_dpop_future_iat(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 4 — iat in the future rejected."""
    proof = _valid_dpop(keypair_risk_assessor, "tok", iat=_FIXED_IAT + 1000)
    result = validate_dpop_proof(
        proof, "tok", expected_htu=_HTU, now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("iat is in the future" in str(e) for e in result.errors)


def test_validate_dpop_wrong_ath(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 5 — ath mismatch rejected.

    Build a DPoP proof bound to token A, then validate it against
    token B. The computed expected ath will differ.
    """
    proof = _valid_dpop(keypair_risk_assessor, "token-a")
    result = validate_dpop_proof(
        proof, "token-b", expected_htu=_HTU, now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("ath" in str(e) for e in result.errors)


def test_validate_dpop_replay_jti_rejected(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 8 — seen jti rejects replay attempts."""
    proof = _valid_dpop(keypair_risk_assessor, "tok", jti="FIXED-JTI")
    seen = {"FIXED-JTI"}
    result = validate_dpop_proof(
        proof,
        "tok",
        expected_htu=_HTU,
        now=_FIXED_NOW,
        seen_jti=seen,
    )
    assert result.is_valid is False
    assert any("replay" in str(e) for e in result.errors)


def test_validate_dpop_replay_none_skip(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: API shape — seen_jti=None disables replay check."""
    proof = _valid_dpop(keypair_risk_assessor, "tok", jti="ANY-JTI")
    result = validate_dpop_proof(
        proof, "tok", expected_htu=_HTU, now=_FIXED_NOW, seen_jti=None
    )
    assert result.is_valid is True


def test_validate_dpop_tampered_signature(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 1 — modified proof invalidates signature."""
    proof = _valid_dpop(keypair_risk_assessor, "tok")
    header_b64, payload_b64, sig_b64 = proof.split(".")
    tampered_payload_json = json.dumps(
        {
            "jti": "evil",
            "htm": "POST",
            "htu": _HTU,
            "iat": _FIXED_IAT,
            "ath": base64url_encode(hashlib.sha256(b"tok").digest()),
        }
    ).encode()
    tampered_payload = base64url_encode(tampered_payload_json)
    tampered = f"{header_b64}.{tampered_payload}.{sig_b64}"
    result = validate_dpop_proof(
        tampered, "tok", expected_htu=_HTU, now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("signature is invalid" in str(e) for e in result.errors)


def test_validate_dpop_wrong_typ(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 — typ MUST be 'dpop+jwt'."""
    raw_public = keypair_risk_assessor["public_key"].public_bytes_raw()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(raw_public)}
    bad_header = {"typ": "JWT", "alg": "EdDSA", "jwk": jwk}
    ath = base64url_encode(hashlib.sha256(b"tok").digest())
    payload = {
        "jti": "x",
        "htm": "POST",
        "htu": _HTU,
        "iat": _FIXED_IAT,
        "ath": ath,
    }
    proof = build_jwt(payload, keypair_risk_assessor["private_key"], header=bad_header)
    result = validate_dpop_proof(
        proof, "tok", expected_htu=_HTU, now=_FIXED_NOW
    )
    assert result.is_valid is False
    assert any("typ" in str(e) for e in result.errors)


def test_validate_dpop_malformed_returns_errors() -> None:
    """Spec: defensive — malformed DPoP proof returns errors, no exception."""
    result = validate_dpop_proof("bad", "tok", expected_htu=_HTU)
    assert result.is_valid is False
    assert len(result.errors) >= 1


def test_dpop_result_is_frozen(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: DPoPValidationResult is a frozen dataclass."""
    result = validate_dpop_proof(
        _valid_dpop(keypair_risk_assessor, "tok"),
        "tok",
        expected_htu=_HTU,
        now=_FIXED_NOW,
    )
    with pytest.raises(Exception):  # FrozenInstanceError
        result.is_valid = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DPoP binding (cnf.jkt)
# ---------------------------------------------------------------------------


def test_verify_dpop_binding_valid(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §3.3 step 6 — cnf.jkt matches DPoP JWK thumbprint."""
    raw = keypair_risk_assessor["public_key"].public_bytes_raw()
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(raw)}
    jkt = compute_jwk_thumbprint(jwk)
    token_claims = {"cnf": {"jkt": jkt}}
    dpop_header = {"typ": DPOP_TYP, "alg": "EdDSA", "jwk": jwk}
    assert verify_dpop_binding(token_claims, dpop_header) is True


def test_verify_dpop_binding_mismatch(
    keypair_acme: dict[str, Any],
    keypair_risk_assessor: dict[str, Any],
) -> None:
    """Spec: Identity §9.2 — token bound to a different key MUST fail binding."""
    acme_raw = keypair_acme["public_key"].public_bytes_raw()
    acme_jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(acme_raw)}
    acme_jkt = compute_jwk_thumbprint(acme_jwk)
    token_claims = {"cnf": {"jkt": acme_jkt}}
    # DPoP signed with the other keypair.
    other_raw = keypair_risk_assessor["public_key"].public_bytes_raw()
    other_jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64url_encode(other_raw)}
    dpop_header = {"typ": DPOP_TYP, "alg": "EdDSA", "jwk": other_jwk}
    assert verify_dpop_binding(token_claims, dpop_header) is False


def test_verify_dpop_binding_missing_cnf() -> None:
    """Spec: Identity §3.3 — missing cnf claim returns False."""
    assert verify_dpop_binding({}, {"jwk": {}}) is False


def test_verify_dpop_binding_missing_jkt() -> None:
    """Spec: Identity §3.3 — cnf without jkt returns False."""
    assert verify_dpop_binding({"cnf": {}}, {"jwk": {}}) is False


def test_verify_dpop_binding_non_dict_inputs() -> None:
    """Spec: defensive — non-dict inputs return False (never raise)."""
    assert verify_dpop_binding(None, None) is False  # type: ignore[arg-type]
    assert verify_dpop_binding({}, None) is False  # type: ignore[arg-type]


def test_verify_dpop_binding_bad_jwk_shape() -> None:
    """Spec: defensive — malformed DPoP JWK returns False."""
    token_claims = {"cnf": {"jkt": "whatever"}}
    dpop_header = {"jwk": {"kty": "RSA"}}  # not Ed25519
    assert verify_dpop_binding(token_claims, dpop_header) is False


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


def test_all_symbols_exported() -> None:
    """Spec: API hygiene — __all__ matches the module's public surface."""
    import arsia_protocol.core.authorization as mod

    expected = {
        "DEFAULT_CLOCK_SKEW_SECONDS",
        "SUPPORTED_ALGORITHMS",
        "DPOP_TYP",
        "JWT_TYP",
        "TokenValidationResult",
        "DPoPValidationResult",
        "decode_jwt",
        "verify_jwt_signature",
        "validate_token_claims",
        "parse_scope",
        "check_scope_coverage",
        "validate_dpop_proof",
        "verify_dpop_binding",
        "compute_jwk_thumbprint",
        "build_jwt",
        "build_dpop_proof",
        "build_token_request",
    }
    assert set(mod.__all__) == expected


def test_default_clock_skew_is_300_seconds() -> None:
    """Spec: ARSIA-Core.md §8.3 — default clock skew tolerance is 300s."""
    assert DEFAULT_CLOCK_SKEW_SECONDS == 300


def test_token_validation_result_type_alias() -> None:
    """Spec: smoke check on TokenValidationResult shape."""
    result = TokenValidationResult(is_valid=True, claims={"x": 1}, errors=())
    assert result.is_valid is True
    assert result.claims == {"x": 1}
    assert result.errors == ()


def test_dpop_validation_result_type_alias() -> None:
    """Spec: smoke check on DPoPValidationResult shape."""
    from arsia_protocol._errors import ValidationError as VE
    ve = VE(code="test", message="x")
    result = DPoPValidationResult(is_valid=False, errors=(ve,))
    assert result.is_valid is False
    assert result.errors == (ve,)


def test_base64url_decode_unused_import_defense() -> None:
    """Spec: ensure base64url_decode is importable (used by helpers)."""
    assert base64url_decode("YWJj") == b"abc"


# ── §6.2 Token Request ──────────────────────────────────────────────


class TestBuildTokenRequest:
    """Spec: ARSIA-Core.md §6.2 — OAuth 2.0 client-credentials request."""

    def test_valid_request(self) -> None:
        """All required fields produce a well-formed dict."""
        result = build_token_request(
            client_id="agent:acme.billing",
            scope="com.example.notes.read com.example.notes.write",
            audience="agent:contoso.crm",
        )
        assert result == {
            "grant_type": "client_credentials",
            "client_id": "agent:acme.billing",
            "scope": "com.example.notes.read com.example.notes.write",
            "audience": "agent:contoso.crm",
        }

    def test_grant_type_always_client_credentials(self) -> None:
        """grant_type is always 'client_credentials' — not caller-overridable."""
        result = build_token_request(
            client_id="agent:x.y",
            scope="read",
            audience="agent:a.b",
        )
        assert result["grant_type"] == "client_credentials"

    def test_missing_client_id_raises(self) -> None:
        """Empty client_id raises ValueError per §6.2 REQUIRED."""
        with pytest.raises(ValueError, match="client_id"):
            build_token_request(client_id="", scope="read", audience="agent:a.b")

    def test_missing_scope_raises(self) -> None:
        """Empty scope raises ValueError per §6.2 REQUIRED."""
        with pytest.raises(ValueError, match="scope"):
            build_token_request(client_id="agent:x.y", scope="", audience="agent:a.b")

    def test_missing_audience_raises(self) -> None:
        """Empty audience raises ValueError per §6.2 REQUIRED."""
        with pytest.raises(ValueError, match="audience"):
            build_token_request(client_id="agent:x.y", scope="read", audience="")

    def test_output_values_are_strings(self) -> None:
        """All values are strings (suitable for form-urlencoded encoding)."""
        result = build_token_request(
            client_id="agent:x.y",
            scope="a b",
            audience="agent:a.b",
        )
        assert all(isinstance(v, str) for v in result.values())
