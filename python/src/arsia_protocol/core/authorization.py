# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""JWT access-token and DPoP proof validation.

This module is Layer 4 (Primitives) in the SDK dependency graph. It
depends only on :mod:`arsia_protocol.hazmat.primitives.ed25519`
(Layer 0) — never on ``message``, ``errors``, ``compliance``,
``validation``, ``actions``, ``identity``, ``certificates``,
or ``discovery``. In particular, it deliberately
does NOT depend on :mod:`arsia_protocol.actions`: token scope
enforcement uses **exact string comparison (no wildcards, no
hierarchical expansion)** per ARSIA-Core.md §6.4 step 5, which is a
strictly simpler rule than the capability matcher in §1.2 that
``actions.match_capability`` implements.

What this module does:

- **§6.1 Access Token Structure** — decodes JWTs into header /
  payload / signature, exposes the 7 required claims (``iss``,
  ``sub``, ``aud``, ``exp``, ``iat``, ``jti``, ``scope``) and the
  optional ``cnf`` DPoP binding claim.
- **§6.4 Capability Enforcement** — the 6-step receiver procedure:
  decode → signature → claim presence → timing → sub/aud match →
  exact-match scope coverage. All checks accumulate into a single
  :class:`TokenValidationResult` rather than short-circuiting, so
  test vectors and logs can surface the full set of failures.
- **Identity §3.3 DPoP** — validates DPoP proof JWTs: embedded-JWK
  signature, ``htm``/``htu`` binding, ``iat`` within clock skew,
  ``ath`` (base64url-SHA-256 of the access token), ``jti`` replay
  protection, and ``cnf.jkt`` binding between the access token and
  the DPoP proof's signing key.
- **RFC 7638 JWK Thumbprint** — the exact ``jkt`` that goes into a
  token's ``cnf`` claim, computed over the canonical JSON form
  ``{"crv":"Ed25519","kty":"OKP","x":"..."}`` (members sorted
  alphabetically, no whitespace).
- **Test/consumer helpers** — :func:`build_jwt` and
  :func:`build_dpop_proof` construct signed tokens for unit tests,
  conformance suites, and SDK consumers that need to present DPoP
  proofs. Production tokens are issued by an Authorization Server,
  which is out of scope for the SDK.

What this module does NOT do:

- Extract tokens from HTTP ``Authorization`` or ``DPoP`` headers —
  that is a transport concern.
- Issue access tokens — that is the Authorization Server's job.
- Support ES256 or RS256 — §6.1 allows them, but Slice 4B
  implements EdDSA only, matching envelope signing. Other
  algorithms MUST be rejected via :data:`SUPPORTED_ALGORITHMS`.
- Persist ``jti`` replay-protection state — callers pass
  ``seen_jti`` in; storage is the consumer's concern.

Spec discrepancies resolved in this module
------------------------------------------

1. **Clock skew.** ARSIA-Core.md §8.3 specifies ±300 seconds for
   every timestamp validation including access-token ``exp``/``iat``.
   ARSIA-Identity.md §3.2 step 3 mentions a 60-second tolerance for
   ``iat`` alone. Core is the authoritative document for timestamp
   rules, so :data:`DEFAULT_CLOCK_SKEW_SECONDS` is 300 and applies
   uniformly. Callers that need a stricter rule can pass
   ``clock_skew_seconds=60`` explicitly.

2. **``alg: "none"``.** RFC 7515 §4.1.1 permits unsigned JWTs but
   they are a classic attack vector. :data:`SUPPORTED_ALGORITHMS`
   contains ``"EdDSA"`` only, so tokens with any other ``alg``
   header — including ``"none"`` — are rejected at signature
   verification regardless of claim content.

3. **DPoP JWK shape.** Identity §3.3 specifies the DPoP proof
   header ``jwk`` as the three RFC 7517 members ``{kty, crv, x}``
   with no ``kid`` or ``use``. The helper
   :func:`arsia_protocol.hazmat.primitives.ed25519.public_key_to_jwk_dict`
   adds those fields, so :func:`build_dpop_proof` constructs the
   3-field DPoP JWK manually. :func:`compute_jwk_thumbprint`
   similarly looks only at the required members per RFC 7638 §3.2.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from arsia_protocol._errors import ValidationError
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_decode,
    base64url_encode,
    public_key_from_bytes,
    sign,
    verify,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CLOCK_SKEW_SECONDS: Final[int] = 300
"""Default clock skew tolerance for token and DPoP timing checks.

Per ARSIA-Core.md §8.3, all timestamp validation — including access
token ``exp``/``iat`` and DPoP proof ``iat`` — allows ±300 seconds.
"""

SUPPORTED_ALGORITHMS: Final[frozenset[str]] = frozenset({"EdDSA"})
"""JWS signing algorithms accepted by this module.

ARSIA-Core.md §6.1 permits EdDSA, ES256, and RS256, but Slice 4B
implements EdDSA only — the same algorithm used for envelope
signing. Any ``alg`` header outside this set (including ``"none"``)
is rejected. ES256 / RS256 support is deferred to a future slice.
"""

DPOP_TYP: Final[str] = "dpop+jwt"
"""Required ``typ`` header value for DPoP proof JWTs (RFC 9449 §4.2)."""

JWT_TYP: Final[str] = "JWT"
"""Conventional ``typ`` header value for access-token JWTs."""

_REQUIRED_TOKEN_CLAIMS: Final[tuple[str, ...]] = (
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "jti",
    "scope",
)
"""The 7 required access-token claims from ARSIA-Core.md §6.1."""

_REQUIRED_DPOP_HEADER: Final[tuple[str, ...]] = ("typ", "alg", "jwk")
"""The 3 required DPoP proof header fields from Identity §3.3."""

_REQUIRED_DPOP_CLAIMS: Final[tuple[str, ...]] = ("jti", "htm", "htu", "iat", "ath")
"""The 5 required DPoP proof payload claims from Identity §3.3."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenValidationResult:
    """Outcome of :func:`validate_token_claims`.

    Attributes:
        is_valid: ``True`` if every check in the §6.4 procedure
            passed. ``False`` if any check failed — in which case
            ``errors`` is non-empty.
        claims: The parsed JWT payload if decoding succeeded. May be
            populated even when ``is_valid`` is ``False`` (e.g. a
            token with a valid signature but a wrong ``aud``), so
            callers can log the offending claims. ``None`` only when
            the token could not be decoded at all.
        errors: All accumulated error messages. Checks do not
            short-circuit — a single result may report a bad
            signature *and* an expired ``exp`` *and* an
            insufficient scope, which makes debugging much easier.
    """

    is_valid: bool
    claims: dict[str, Any] | None
    errors: tuple[ValidationError, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DPoPValidationResult:
    """Outcome of :func:`validate_dpop_proof`.

    Attributes:
        is_valid: ``True`` if every DPoP check from Identity §3.3
            passed.
        errors: All accumulated error messages.
    """

    is_valid: bool
    errors: tuple[ValidationError, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Low-level JWT helpers
# ---------------------------------------------------------------------------


def _json_canonical(obj: dict[str, Any]) -> bytes:
    """Serialize ``obj`` as compact JSON, sorted keys, UTF-8.

    Used by :func:`build_jwt` and :func:`compute_jwk_thumbprint`.
    The sort-keys + no-whitespace form coincides with the RFC 7638
    canonical form used for JWK thumbprints, and produces
    byte-stable JWTs for tests even though RFC 7515 does not
    require canonicality for signing.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Decode a compact-serialization JWT into ``(header, payload, signature)``.

    Splits on ``.``, base64url-decodes each part, and parses the
    header and payload as JSON objects. Does NOT verify the
    signature — use :func:`verify_jwt_signature` for that.

    Args:
        token: A compact JWT string ``<header>.<payload>.<signature>``.

    Returns:
        A ``(header, payload, signature_bytes)`` tuple.

    Raises:
        ValueError: if ``token`` is not a string, does not have
            exactly three base64url-separated parts, if any part
            fails to base64url-decode, or if the header/payload are
            not JSON objects.

    Spec: RFC 7519 §7.
    """
    if not isinstance(token, str):
        raise ValueError(f"JWT must be a string, got {type(token).__name__}")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"JWT must have exactly 3 dot-separated parts, got {len(parts)}"
        )
    header_b64, payload_b64, sig_b64 = parts
    try:
        header_bytes = base64url_decode(header_b64)
        payload_bytes = base64url_decode(payload_b64)
        signature = base64url_decode(sig_b64)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"JWT contains invalid base64url: {exc}") from exc
    try:
        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"JWT header or payload is not valid JSON: {exc}") from exc
    if not isinstance(header, dict):
        raise ValueError("JWT header must decode to a JSON object")
    if not isinstance(payload, dict):
        raise ValueError("JWT payload must decode to a JSON object")
    return header, payload, signature


def _signing_input(token: str) -> bytes:
    """Return the ``header.payload`` bytes that JWT signatures cover.

    RFC 7515 §5.1 defines the JWS Signing Input as the
    ASCII-encoded concatenation of the base64url-encoded header, a
    literal ``"."``, and the base64url-encoded payload. This helper
    does not re-encode — it just slices the first two parts of
    ``token``.
    """
    first_dot = token.find(".")
    last_dot = token.rfind(".")
    if first_dot == -1 or first_dot == last_dot:
        raise ValueError("JWT must contain two '.' separators")
    return token[:last_dot].encode("ascii")


def verify_jwt_signature(token: str, public_key: Ed25519PublicKey) -> bool:
    """Verify a JWT signature with Ed25519.

    The signing input is the ASCII form of
    ``"{header_b64url}.{payload_b64url}"`` per RFC 7515 §5.1. This
    function also enforces :data:`SUPPORTED_ALGORITHMS` — a token
    whose header advertises any ``alg`` outside that set is rejected
    even if the signature would verify, so ``alg: "none"`` tokens
    never slip through.

    Never raises: returns ``False`` for any decoding, algorithm, or
    cryptographic failure so callers can log the result without a
    ``try`` block.

    Args:
        token: The JWT to verify.
        public_key: The Authorization Server's Ed25519 verification
            key (loaded by the caller from the AS's JWKS).

    Returns:
        ``True`` if the signature is valid and the header ``alg`` is
        supported, ``False`` otherwise.

    Spec: ARSIA-Core.md §6.1, RFC 7515 §5.2.
    """
    try:
        header, _payload, signature = decode_jwt(token)
    except ValueError:
        return False
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in SUPPORTED_ALGORITHMS:
        return False
    try:
        data = _signing_input(token)
    except ValueError:
        return False
    return verify(public_key, data, signature)


# ---------------------------------------------------------------------------
# Access-token claim validation (§6.4)
# ---------------------------------------------------------------------------


def _now_utc(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def parse_scope(scope_str: str) -> set[str]:
    """Parse a space-separated ``scope`` claim into a set.

    ``"notes.read notes.write"`` → ``{"notes.read", "notes.write"}``.
    Empty strings and strings of whitespace collapse to an empty
    set. Non-string inputs raise ``TypeError`` so callers catch the
    error at the boundary rather than silently treating a missing
    scope as "no capabilities".

    Args:
        scope_str: The raw value of the token's ``scope`` claim.

    Returns:
        A set of capability strings.

    Spec: ARSIA-Core.md §6.1 ``scope`` claim format.
    """
    if not isinstance(scope_str, str):
        raise TypeError(f"scope must be a string, got {type(scope_str).__name__}")
    return set(scope_str.split())


def check_scope_coverage(
    scope: set[str],
    required: list[str],
) -> tuple[bool, list[str]]:
    """Return ``(all_covered, missing)`` via exact string comparison.

    Implements the matching half of ARSIA-Core.md §6.4 step 5
    verbatim: **matching is exact string comparison (no wildcards,
    no hierarchical expansion)**. ``"notes.*"`` in the token scope
    does NOT satisfy ``"notes.read"`` — the Authorization Server
    issues a specific set of strings and the receiver enforces them
    as issued.

    The ``missing`` list preserves the order of ``required`` and
    contains no duplicates beyond those already in ``required``.

    Args:
        scope: The granted scope as returned by :func:`parse_scope`.
        required: The capabilities listed in the inbound message's
            ``capabilities`` field.

    Returns:
        A ``(all_covered, missing_list)`` tuple. ``all_covered`` is
        ``True`` iff every entry in ``required`` is present in
        ``scope``.

    Spec: ARSIA-Core.md §6.4 step 5.
    """
    missing = [cap for cap in required if cap not in scope]
    return not missing, missing


def validate_token_claims(
    token: str,
    public_key: Ed25519PublicKey,
    *,
    expected_sub: str | None = None,
    expected_aud: str | None = None,
    required_capabilities: list[str] | None = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    now: datetime | None = None,
) -> TokenValidationResult:
    """Validate an access token per the ARSIA-Core.md §6.4 procedure.

    Executes the six steps of §6.4 in order but accumulates errors
    instead of short-circuiting, so a single result can surface
    multiple failures at once. The only exceptions are failures
    that make later steps impossible: if decoding fails there is
    nothing to check; if the signature fails, claims are still
    reported so callers can log them.

    Args:
        token: The JWT access token to validate.
        public_key: The Authorization Server's Ed25519 public key.
        expected_sub: If provided, the token's ``sub`` MUST match
            the inbound message's ``from`` (§6.4 step 3).
        expected_aud: If provided, the token's ``aud`` MUST match
            the receiving agent's own identifier (§6.4 step 3).
        required_capabilities: If provided, every entry MUST be
            present in the token's ``scope`` via exact string
            comparison (§6.4 step 5).
        clock_skew_seconds: Tolerance added to ``exp`` and
            subtracted from ``iat``. Defaults to ±300 s per
            ARSIA-Core.md §8.3.
        now: Reference time for deterministic testing. Defaults to
            current UTC time.

    Returns:
        A :class:`TokenValidationResult` with ``is_valid=True`` only
        if every check passed.

    Spec: ARSIA-Core.md §6.4, ARSIA-Identity.md §3.2.
    """
    errors: list[ValidationError] = []

    try:
        _header, payload, _sig = decode_jwt(token)
    except ValueError as exc:
        return TokenValidationResult(
            is_valid=False,
            claims=None,
            errors=(
                ValidationError(
                    code="token_decode_error",
                    message=f"token could not be decoded: {exc}",
                    spec_ref="Core §6.1",
                ),
            ),
        )

    if not verify_jwt_signature(token, public_key):
        errors.append(
            ValidationError(
                code="token_signature_invalid",
                message="token signature is invalid or uses an unsupported algorithm",
                spec_ref="Core §6.1, §6.4 step 2",
            )
        )

    for claim in _REQUIRED_TOKEN_CLAIMS:
        if claim not in payload:
            errors.append(
                ValidationError(
                    code="token_missing_claim",
                    message=f"token is missing required claim {claim!r}",
                    details={"claim": claim},
                    spec_ref="Core §6.1",
                )
            )

    reference = _now_utc(now)
    reference_ts = reference.timestamp()

    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool):
        if reference_ts > float(exp) + clock_skew_seconds:
            errors.append(
                ValidationError(
                    code="token_expired",
                    message=f"token expired: exp={exp} now={int(reference_ts)}",
                    details={"exp": exp, "now": int(reference_ts)},
                    spec_ref="Core §6.4 step 3, §8.3",
                )
            )
    elif "exp" in payload:
        errors.append(
            ValidationError(
                code="token_exp_not_numeric",
                message="token claim 'exp' must be a numeric date",
                spec_ref="Core §6.1",
            )
        )

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and not isinstance(iat, bool):
        if float(iat) > reference_ts + clock_skew_seconds:
            errors.append(
                ValidationError(
                    code="token_iat_future",
                    message=f"token iat is in the future: iat={iat} now={int(reference_ts)}",
                    details={"iat": iat, "now": int(reference_ts)},
                    spec_ref="Core §6.4 step 3, §8.3",
                )
            )
    elif "iat" in payload:
        errors.append(
            ValidationError(
                code="token_iat_not_numeric",
                message="token claim 'iat' must be a numeric date",
                spec_ref="Core §6.1",
            )
        )

    # Identity §3.2 step 3: nbf is OPTIONAL. When present, the token MUST
    # NOT be used before this time, modulo clock skew. Absence is valid.
    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and not isinstance(nbf, bool):
        if reference_ts < float(nbf) - clock_skew_seconds:
            errors.append(
                ValidationError(
                    code="token_not_yet_valid",
                    message=f"token not yet valid: nbf={nbf} now={int(reference_ts)}",
                    details={"nbf": nbf, "now": int(reference_ts)},
                    spec_ref="Identity §3.2 step 3",
                )
            )
    elif "nbf" in payload:
        errors.append(
            ValidationError(
                code="token_nbf_not_numeric",
                message="token claim 'nbf' must be a numeric date",
                spec_ref="Identity §3.2",
            )
        )

    if expected_sub is not None:
        sub = payload.get("sub")
        if sub != expected_sub:
            errors.append(
                ValidationError(
                    code="token_sub_mismatch",
                    message=f"token sub {sub!r} does not match expected {expected_sub!r}",
                    details={"sub": sub, "expected_sub": expected_sub},
                    spec_ref="Core §6.4 step 3",
                )
            )

    if expected_aud is not None:
        aud = payload.get("aud")
        if aud != expected_aud:
            errors.append(
                ValidationError(
                    code="token_aud_mismatch",
                    message=f"token aud {aud!r} does not match expected {expected_aud!r}",
                    details={"aud": aud, "expected_aud": expected_aud},
                    spec_ref="Core §6.4 step 3",
                )
            )

    if required_capabilities is not None:
        scope_raw = payload.get("scope")
        if not isinstance(scope_raw, str):
            errors.append(
                ValidationError(
                    code="token_scope_invalid",
                    message="token claim 'scope' must be a space-separated string",
                    spec_ref="Core §6.1",
                )
            )
        else:
            granted = parse_scope(scope_raw)
            covered, missing = check_scope_coverage(granted, required_capabilities)
            if not covered:
                errors.append(
                    ValidationError(
                        code="token_scope_insufficient",
                        message=f"token scope does not cover required capabilities: missing={missing}",
                        details={"missing": missing},
                        spec_ref="Core §6.4 step 5",
                    )
                )

    return TokenValidationResult(
        is_valid=not errors,
        claims=payload,
        errors=tuple(errors),
    )


# ---------------------------------------------------------------------------
# JWK Thumbprint (RFC 7638)
# ---------------------------------------------------------------------------


def compute_jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Compute the RFC 7638 JWK Thumbprint of an Ed25519 public key.

    RFC 7638 §3.2 defines the canonical form as a JSON object
    containing only the required members for the key type, ordered
    lexicographically, with no whitespace:

        {"crv":"Ed25519","kty":"OKP","x":"<base64url>"}

    The thumbprint is the base64url-no-padding encoding of the
    SHA-256 hash of those canonical bytes. This exact value is
    placed in the token's ``cnf.jkt`` claim (RFC 9449 §6.1) and
    compared against the DPoP proof's signing key in
    :func:`verify_dpop_binding`.

    Args:
        jwk: A JWK dict. For Ed25519 it MUST contain ``kty="OKP"``,
            ``crv="Ed25519"``, and a base64url ``x``. Extra members
            such as ``kid`` or ``use`` are ignored — the thumbprint
            is defined over the required members only.

    Returns:
        The base64url-no-padding SHA-256 thumbprint.

    Raises:
        ValueError: if ``jwk`` is not a dict, if ``kty`` is not
            ``"OKP"``, if ``crv`` is not ``"Ed25519"``, or if ``x``
            is missing or not a string.

    Spec: RFC 7638 §3.2, RFC 8037 §2.
    """
    if not isinstance(jwk, dict):
        raise ValueError(f"jwk must be a dict, got {type(jwk).__name__}")
    kty = jwk.get("kty")
    if kty != "OKP":
        raise ValueError(f"JWK Thumbprint: expected kty='OKP', got {kty!r}")
    crv = jwk.get("crv")
    if crv != "Ed25519":
        raise ValueError(f"JWK Thumbprint: expected crv='Ed25519', got {crv!r}")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ValueError("JWK Thumbprint: required member 'x' is missing or non-string")
    canonical = _json_canonical({"crv": "Ed25519", "kty": "OKP", "x": x})
    digest = hashlib.sha256(canonical).digest()
    return base64url_encode(digest)


# ---------------------------------------------------------------------------
# DPoP proof validation (Identity §3.3)
# ---------------------------------------------------------------------------


def _load_public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    """Extract an :class:`Ed25519PublicKey` from a DPoP proof's JWK header.

    Enforces the Identity §3.3 shape: ``kty="OKP"``,
    ``crv="Ed25519"``, and a base64url ``x`` that decodes to 32
    bytes. Raises :class:`ValueError` for any other shape.
    """
    if not isinstance(jwk, dict):
        raise ValueError("DPoP header 'jwk' must be an object")
    if jwk.get("kty") != "OKP":
        raise ValueError("DPoP header 'jwk.kty' must be 'OKP'")
    if jwk.get("crv") != "Ed25519":
        raise ValueError("DPoP header 'jwk.crv' must be 'Ed25519'")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ValueError("DPoP header 'jwk.x' must be a base64url string")
    try:
        raw = base64url_decode(x)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"DPoP header 'jwk.x' is not valid base64url: {exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"DPoP header 'jwk.x' must decode to 32 bytes, got {len(raw)}")
    return public_key_from_bytes(raw)


def validate_dpop_proof(
    dpop_jwt: str,
    access_token: str,
    *,
    expected_htm: str = "POST",
    expected_htu: str,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    now: datetime | None = None,
    seen_jti: set[str] | None = None,
) -> DPoPValidationResult:
    """Validate a DPoP proof JWT per ARSIA-Identity.md §3.3.

    Runs the six §3.3 verification steps, accumulating all failures:

    1. Decode the DPoP proof JWT (``typ`` header MUST be
       ``"dpop+jwt"``).
    2. Extract the embedded ``jwk`` from the header.
    3. Verify the proof's signature using that embedded JWK.
    4. Check ``htm`` equals ``expected_htm``.
    5. Check ``htu`` equals ``expected_htu``.
    6. Check ``iat`` is within ``±clock_skew_seconds`` of ``now``.
    7. Check ``ath`` equals
       ``base64url(SHA-256(access_token_bytes))``.
    8. Check ``jti`` is not already in ``seen_jti`` (replay
       protection).

    ``cnf.jkt`` binding between the access token and this proof is
    NOT checked here — call :func:`verify_dpop_binding` with the
    token's parsed claims and this proof's header to do that check
    separately.

    Args:
        dpop_jwt: The DPoP proof JWT from the ``DPoP`` header.
        access_token: The raw access token string (used to compute
            the expected ``ath``). This is the value that was
            placed in the ``Authorization`` header, unchanged.
        expected_htm: The HTTP method that received the request.
            Defaults to ``"POST"`` per ARSIA inbox conventions.
        expected_htu: The absolute HTTP target URI the request was
            made against. REQUIRED.
        clock_skew_seconds: Tolerance for the ``iat`` check.
            Defaults to ±300 s per Core §8.3.
        now: Reference time for deterministic testing.
        seen_jti: Set of previously-seen ``jti`` values for replay
            protection. Callers are responsible for persistence and
            retention. ``None`` disables the replay check. Caller
            MUST add ``jti`` to this set after a successful
            validation.

    Returns:
        A :class:`DPoPValidationResult` with all accumulated errors.

    Spec: ARSIA-Identity.md §3.3, RFC 9449 §4.3.
    """
    errors: list[ValidationError] = []

    try:
        header, payload, signature = decode_jwt(dpop_jwt)
    except ValueError as exc:
        return DPoPValidationResult(
            is_valid=False,
            errors=(
                ValidationError(
                    code="dpop_decode_error",
                    message=f"DPoP proof could not be decoded: {exc}",
                    spec_ref="Identity §3.3",
                ),
            ),
        )

    for field_name in _REQUIRED_DPOP_HEADER:
        if field_name not in header:
            errors.append(
                ValidationError(
                    code="dpop_missing_header_field",
                    message=f"DPoP header is missing required field {field_name!r}",
                    details={"field": field_name},
                    spec_ref="Identity §3.3",
                )
            )

    typ = header.get("typ")
    if typ != DPOP_TYP:
        errors.append(
            ValidationError(
                code="dpop_typ_invalid",
                message=f"DPoP header 'typ' must be {DPOP_TYP!r}, got {typ!r}",
                details={"typ": typ, "expected": DPOP_TYP},
                spec_ref="Identity §3.3",
            )
        )

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in SUPPORTED_ALGORITHMS:
        errors.append(
            ValidationError(
                code="dpop_alg_unsupported",
                message=f"DPoP header 'alg' {alg!r} is not in {sorted(SUPPORTED_ALGORITHMS)!r}",
                details={"alg": alg, "supported": sorted(SUPPORTED_ALGORITHMS)},
                spec_ref="Identity §3.3",
            )
        )

    jwk = header.get("jwk")
    signature_ok = False
    if jwk is None:
        errors.append(
            ValidationError(
                code="dpop_missing_header_field",
                message="DPoP header is missing required field 'jwk'",
                details={"field": "jwk"},
                spec_ref="Identity §3.3",
            )
        )
    else:
        try:
            proof_public_key = _load_public_key_from_jwk(jwk)
        except ValueError as exc:
            errors.append(
                ValidationError(
                    code="dpop_jwk_invalid",
                    message=f"DPoP embedded JWK is invalid: {exc}",
                    spec_ref="Identity §3.3",
                )
            )
        else:
            try:
                data = _signing_input(dpop_jwt)
            except ValueError as exc:
                errors.append(
                    ValidationError(
                        code="dpop_signing_input_error",
                        message=f"DPoP signing input could not be extracted: {exc}",
                        spec_ref="Identity §3.3",
                    )
                )
            else:
                signature_ok = verify(proof_public_key, data, signature)
                if not signature_ok:
                    errors.append(
                        ValidationError(
                            code="dpop_signature_invalid",
                            message="DPoP proof signature is invalid",
                            spec_ref="Identity §3.3 step 1",
                        )
                    )

    for claim in _REQUIRED_DPOP_CLAIMS:
        if claim not in payload:
            errors.append(
                ValidationError(
                    code="dpop_missing_claim",
                    message=f"DPoP payload is missing required claim {claim!r}",
                    details={"claim": claim},
                    spec_ref="Identity §3.3",
                )
            )

    htm = payload.get("htm")
    if htm != expected_htm:
        errors.append(
            ValidationError(
                code="dpop_htm_mismatch",
                message=f"DPoP htm {htm!r} does not match expected {expected_htm!r}",
                details={"htm": htm, "expected_htm": expected_htm},
                spec_ref="Identity §3.3 step 3",
            )
        )

    htu = payload.get("htu")
    if htu != expected_htu:
        errors.append(
            ValidationError(
                code="dpop_htu_mismatch",
                message=f"DPoP htu {htu!r} does not match expected {expected_htu!r}",
                details={"htu": htu, "expected_htu": expected_htu},
                spec_ref="Identity §3.3 step 2",
            )
        )

    reference = _now_utc(now)
    reference_ts = reference.timestamp()
    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and not isinstance(iat, bool):
        iat_f = float(iat)
        if iat_f > reference_ts + clock_skew_seconds:
            errors.append(
                ValidationError(
                    code="dpop_iat_future",
                    message=f"DPoP iat is in the future: iat={iat} now={int(reference_ts)}",
                    details={"iat": iat, "now": int(reference_ts)},
                    spec_ref="Identity §3.3 step 4",
                )
            )
        elif reference_ts > iat_f + clock_skew_seconds:
            errors.append(
                ValidationError(
                    code="dpop_iat_expired",
                    message=f"DPoP iat is too old: iat={iat} now={int(reference_ts)}",
                    details={"iat": iat, "now": int(reference_ts)},
                    spec_ref="Identity §3.3 step 4",
                )
            )
    elif "iat" in payload:
        errors.append(
            ValidationError(
                code="dpop_iat_not_numeric",
                message="DPoP claim 'iat' must be a numeric date",
                spec_ref="Identity §3.3",
            )
        )

    ath = payload.get("ath")
    if isinstance(ath, str):
        expected_ath = base64url_encode(
            hashlib.sha256(access_token.encode("ascii")).digest()
        )
        if ath != expected_ath:
            errors.append(
                ValidationError(
                    code="dpop_ath_mismatch",
                    message="DPoP ath does not match base64url(SHA-256(access_token))",
                    spec_ref="Identity §3.3 step 5",
                )
            )
    elif "ath" in payload:
        errors.append(
            ValidationError(
                code="dpop_ath_invalid",
                message="DPoP claim 'ath' must be a string",
                spec_ref="Identity §3.3",
            )
        )

    jti = payload.get("jti")
    if isinstance(jti, str):
        if seen_jti is not None and jti in seen_jti:
            errors.append(
                ValidationError(
                    code="dpop_jti_replay",
                    message=f"DPoP jti {jti!r} has already been seen (replay)",
                    details={"jti": jti},
                    spec_ref="Identity §3.3, RFC 9449 §11.1",
                )
            )
    elif "jti" in payload:
        errors.append(
            ValidationError(
                code="dpop_jti_invalid",
                message="DPoP claim 'jti' must be a string",
                spec_ref="Identity §3.3",
            )
        )

    return DPoPValidationResult(is_valid=not errors, errors=tuple(errors))


def verify_dpop_binding(
    token_claims: dict[str, Any],
    dpop_proof_header: dict[str, Any],
) -> bool:
    """Verify the ``cnf.jkt`` binding between a token and a DPoP proof.

    Per ARSIA-Identity.md §3.3 step 6 and §9.2, a DPoP-bound access
    token carries a ``cnf`` confirmation claim whose ``jkt`` member
    is the JWK Thumbprint (RFC 7638) of the agent's DPoP signing
    key. The receiving agent re-computes the thumbprint of the key
    embedded in the DPoP proof header and compares it byte-for-byte
    to ``cnf.jkt``.

    Returns ``False`` (never raises) if either input is malformed,
    if ``cnf``/``jkt`` are missing, or if the embedded JWK cannot
    be thumbprinted. This makes it safe to use inside a larger
    accumulative validation flow without a ``try``.

    Args:
        token_claims: Parsed access-token payload — the ``claims``
            field of a :class:`TokenValidationResult`.
        dpop_proof_header: Parsed DPoP proof header (the first
            element returned by :func:`decode_jwt` on the proof).

    Returns:
        ``True`` if and only if ``token_claims['cnf']['jkt']``
        equals ``compute_jwk_thumbprint(dpop_proof_header['jwk'])``.

    Spec: ARSIA-Identity.md §3.3 step 6, §9.2.
    """
    if not isinstance(token_claims, dict) or not isinstance(dpop_proof_header, dict):
        return False
    cnf = token_claims.get("cnf")
    if not isinstance(cnf, dict):
        return False
    jkt = cnf.get("jkt")
    if not isinstance(jkt, str):
        return False
    jwk = dpop_proof_header.get("jwk")
    if not isinstance(jwk, dict):
        return False
    try:
        computed = compute_jwk_thumbprint(jwk)
    except ValueError:
        return False
    return computed == jkt


# ---------------------------------------------------------------------------
# Test / consumer helpers
# ---------------------------------------------------------------------------


def build_jwt(
    claims: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    header: dict[str, Any] | None = None,
) -> str:
    """Build and sign a JWT in compact serialization.

    This is a test and SDK-consumer helper — production tokens are
    issued by an OAuth 2.0 Authorization Server (§6.2), which is
    out of scope for the SDK. It exists so that unit tests,
    conformance executors, and demo code can mint tokens with
    known keys and claim shapes without pulling in a third-party
    JWT library.

    The default header is ``{"alg": "EdDSA", "typ": "JWT"}``.
    Callers can pass a full replacement header for DPoP proofs
    (which set ``typ="dpop+jwt"`` and embed a ``jwk``). The header
    and payload are serialized with sorted keys and no whitespace
    so tests can compute expected bytes deterministically.

    Args:
        claims: The JWT payload.
        private_key: The Ed25519 signing key.
        header: Optional header dict. Defaults to
            ``{"alg": "EdDSA", "typ": "JWT"}``.

    Returns:
        The compact-serialization JWT
        ``<header_b64>.<payload_b64>.<signature_b64>``.

    Spec: RFC 7515 §7.1, RFC 7519 §7.
    """
    hdr = header if header is not None else {"alg": "EdDSA", "typ": JWT_TYP}
    header_b64 = base64url_encode(_json_canonical(hdr))
    payload_b64 = base64url_encode(_json_canonical(claims))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = sign(private_key, signing_input)
    return f"{header_b64}.{payload_b64}.{base64url_encode(signature)}"


def build_dpop_proof(
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    *,
    htm: str = "POST",
    htu: str,
    access_token: str,
    jti: str | None = None,
    iat: int | None = None,
) -> str:
    """Build and sign a DPoP proof JWT per ARSIA-Identity.md §3.3.

    Constructs the 3-member header ``{typ, alg, jwk}`` with the JWK
    reduced to its required Ed25519 members ``{kty, crv, x}`` — no
    ``kid`` or ``use``, which Identity §3.3 does not specify for
    DPoP. The payload contains the 5 required claims ``jti``,
    ``htm``, ``htu``, ``iat``, ``ath``. ``ath`` is always the
    base64url-SHA-256 of the supplied ``access_token`` string.

    This is a test and SDK-consumer helper — production DPoP
    proofs are minted by agents themselves at request time.

    Args:
        private_key: The DPoP signing key (matches ``public_key``).
        public_key: The DPoP public key to embed in the header JWK.
        htm: HTTP method. Defaults to ``"POST"``.
        htu: Absolute HTTP target URI. REQUIRED.
        access_token: The access token this proof is bound to.
        jti: Optional override for ``jti``. Defaults to a fresh
            UUID v4.
        iat: Optional override for ``iat`` (UNIX seconds). Defaults
            to current UTC time.

    Returns:
        The compact-serialization DPoP proof JWT.

    Spec: ARSIA-Identity.md §3.3, RFC 9449 §4.2.
    """
    raw_public = public_key.public_bytes_raw()
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64url_encode(raw_public),
    }
    header = {"typ": DPOP_TYP, "alg": "EdDSA", "jwk": jwk}
    ath = base64url_encode(hashlib.sha256(access_token.encode("ascii")).digest())
    claims: dict[str, Any] = {
        "jti": jti if jti is not None else str(uuid.uuid4()),
        "htm": htm,
        "htu": htu,
        "iat": iat if iat is not None else int(datetime.now(timezone.utc).timestamp()),
        "ath": ath,
    }
    return build_jwt(claims, private_key, header=header)


def build_token_request(
    *,
    client_id: str,
    scope: str,
    audience: str,
) -> dict[str, str]:
    """Build an OAuth 2.0 client-credentials token request per Core §6.2.

    Returns a dict suitable for ``application/x-www-form-urlencoded``
    submission to an Authorization Server's token endpoint.

    Spec: ARSIA-Core.md §6.2.
    """
    if not client_id:
        raise ValueError("client_id is required (Core §6.2)")
    if not scope:
        raise ValueError("scope is required (Core §6.2)")
    if not audience:
        raise ValueError("audience is required (Core §6.2)")
    return {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "scope": scope,
        "audience": audience,
    }


__all__ = [
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
]
