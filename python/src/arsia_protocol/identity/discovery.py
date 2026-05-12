# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Builders for ARSIA discovery endpoint payloads.

This module is Layer 4 in the SDK dependency graph. It assembles the
JSON payloads that an ARSIA-compliant agent would serve at its three
discovery endpoints, without performing any transport work:

- ``GET /.well-known/arsia`` — agent metadata per ARSIA-Core.md §7.1.
  Built by :func:`build_discovery_document`.
- ``GET /.well-known/arsia/capabilities`` — per-capability descriptors
  per ARSIA-Core.md §7.2. Built by :func:`build_capability_listing`
  (with a pagination envelope layered on top of the spec's bare array
  response, so callers can paginate long capability lists).
- ``GET /.well-known/arsia/jwks.json`` — public-key set per
  ARSIA-Core.md §7.3. Built by :func:`build_jwks` from a list of JWK
  dicts produced by :func:`build_jwk`.

The builders are pure functions: they take typed inputs and return
``dict`` objects. Serialization, HTTP framing, caching headers, and
endpoint wiring are out of scope — those belong to the transport layer.

**Dependency boundary.** This module imports only from
:mod:`arsia_protocol.hazmat.primitives.ed25519` (for
:func:`public_key_to_jwk_dict`) and from the standard library. It
intentionally avoids importing Pydantic models from
:mod:`arsia_protocol.types` so it can stay small and decoupled; the
matching types there (:class:`ArsiaDiscoveryDocument`,
:class:`ArsiaJWK`, :class:`ArsiaJWKS`,
:class:`ArsiaCapabilityDescriptor`) can be used by consumers to
validate the dicts returned here, but that validation is optional.

Spec: ARSIA-Core.md §7.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from arsia_protocol._errors import ValidationError

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_decode,
    base64url_encode,
    public_key_from_bytes,
    public_key_to_jwk_dict,
    sign,
    verify,
)

_DEFAULT_MAX_MESSAGE_BYTES = 1_048_576
"""Conservative default of 1 MiB. Agents SHOULD override for their real limit."""

_DEFAULT_REQUEST_TIMEOUT_MS = 30_000
"""Default request timeout (30 s). Agents SHOULD override for their SLA."""

_DEFAULT_PROTOCOL_VERSION = "1.0"
"""Current ARSIA Protocol version — matches :data:`version.PROTOCOL_VERSION`."""


def build_discovery_document(
    agent_id: str,
    name: str,
    version: str,
    *,
    inbox: str,
    jwks: str,
    capabilities_supported: list[str] | None = None,
    max_message_bytes: int = _DEFAULT_MAX_MESSAGE_BYTES,
    request_timeout_ms: int = _DEFAULT_REQUEST_TIMEOUT_MS,
    server_min: str = _DEFAULT_PROTOCOL_VERSION,
    server_max: str = _DEFAULT_PROTOCOL_VERSION,
    protocol_version: str = _DEFAULT_PROTOCOL_VERSION,
    features: dict[str, bool] | None = None,
    rate_limits: dict[str, int] | None = None,
    compliance_profiles_supported: list[str] | None = None,
) -> dict[str, Any]:
    """Build the payload for ``GET /.well-known/arsia``.

    The eleven §7.1 required fields are always populated; the three
    optional fields (``features``, ``rate_limits``,
    ``compliance_profiles_supported``) are only inserted when the
    caller passes a non-``None`` value, so the resulting dict is
    minimal.

    Args:
        agent_id: Agent identifier (``agent:org.name``).
        name: Human-readable display name.
        version: Agent software version (e.g., ``"2.1.0"``). This is
            the *agent's* version string, not the protocol version
            — the spec separates them deliberately.
        inbox: Absolute URL of the agent's inbox endpoint.
        jwks: Absolute URL of the JWKS endpoint.
        capabilities_supported: List of capability strings the agent
            accepts. Defaults to an empty list.
        max_message_bytes: Maximum accepted envelope size. Defaults
            to 1 MiB.
        request_timeout_ms: Maximum processing time in milliseconds.
            Defaults to 30 s.
        server_min: Minimum supported protocol version. Defaults to
            ``"1.0"``.
        server_max: Maximum supported protocol version. Defaults to
            ``"1.0"``.
        protocol_version: Protocol version this document was built
            for. Defaults to ``"1.0"``.
        features: Optional feature-flag dict
            (``async_responses``/``batch_requests``/``encryption``).
        rate_limits: Optional rate-limit hints
            (``requests_per_minute``/``burst_size``).
        compliance_profiles_supported: Optional list of compliance
            profile names (e.g., ``["GDPR-STANDARD", "MIFID-II"]``).

    Returns:
        A ``dict`` suitable for JSON serialization. Structurally
        validatable with :class:`arsia_protocol.types.ArsiaDiscoveryDocument`.

    Spec: ARSIA-Core.md §7.1.
    """
    document: dict[str, Any] = {
        "agent_id": agent_id,
        "name": name,
        "version": version,
        "protocol_version": protocol_version,
        "inbox": inbox,
        "jwks": jwks,
        "capabilities_supported": list(capabilities_supported or []),
        "max_message_bytes": max_message_bytes,
        "request_timeout_ms": request_timeout_ms,
        "server_min": server_min,
        "server_max": server_max,
    }
    if features is not None:
        document["features"] = dict(features)
    if rate_limits is not None:
        document["rate_limits"] = dict(rate_limits)
    if compliance_profiles_supported is not None:
        document["compliance_profiles_supported"] = list(compliance_profiles_supported)
    return document


def build_jwk(
    public_key: Ed25519PublicKey,
    kid: str,
    *,
    use: str = "sig",
) -> dict[str, str]:
    """Encode a single Ed25519 public key as a JWK dict.

    Delegates to
    :func:`arsia_protocol.hazmat.primitives.ed25519.public_key_to_jwk_dict`
    — this builder exists so discovery-facing consumers have a
    convenient entry point without having to reach into ``hazmat``.

    Args:
        public_key: The Ed25519 public key.
        kid: Key identifier (recommended format: ``"{agent_id}#{label}"``).
        use: JWK ``use`` parameter, default ``"sig"``.

    Returns:
        A JWK dict with ``kty``/``crv``/``x``/``kid``/``use``.

    Spec: ARSIA-Core.md §7.3.
    """
    return public_key_to_jwk_dict(public_key, kid, use=use)


def build_ec_jwk(
    public_key: EllipticCurvePublicKey,
    kid: str,
    *,
    use: str = "enc",
) -> dict[str, str]:
    """Encode a P-256 EC public key as a JWK dict.

    Spec: ARSIA-Core.md §7.3 (EC key table).
    """
    curve = public_key.curve
    if not isinstance(curve, SECP256R1):
        raise ValueError(
            f"public_key: unsupported EC curve {curve.name}. "
            "Expected P-256 (SECP256R1) per Core §7.3."
        )
    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, byteorder="big")
    y_bytes = numbers.y.to_bytes(32, byteorder="big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(x_bytes),
        "y": base64url_encode(y_bytes),
        "kid": kid,
        "use": use,
    }


def build_encryption_jwks(
    signing_keys: list[dict[str, str]],
    encryption_keys: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    """Build a JWKS containing both signing and encryption keys.

    Agents that support payload encryption MUST publish their encryption
    keys alongside signing keys in the JWKS.

    Spec: ARSIA-Core.md §7.3.
    """
    all_keys = list(signing_keys) + list(encryption_keys)
    return {"keys": all_keys}


def build_jwks(keys: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Wrap a list of JWK dicts in the JWK Set envelope.

    Args:
        keys: List of JWK dicts (as produced by :func:`build_jwk`).
            May be empty.

    Returns:
        ``{"keys": [...]}``. Ready to JSON-serialize as the response
        body for ``GET /.well-known/arsia/jwks.json``.

    Spec: ARSIA-Core.md §7.3, RFC 7517.
    """
    return {"keys": list(keys)}


def build_capability_listing(
    actions: list[dict[str, Any]],
    *,
    total: int | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """Build a paginated capability-listing response.

    ARSIA-Core.md §7.2 specifies a bare array as the response body.
    For programmatic clients we wrap that in a dict with ``actions``,
    ``total``, ``limit``, and ``offset`` so large capability catalogues
    can be paginated. The individual entries in ``actions`` still
    match the §7.2 capability descriptor schema (and
    :class:`arsia_protocol.types.ArsiaCapabilityDescriptor`).

    Args:
        actions: List of capability descriptor dicts. Each SHOULD
            conform to
            :class:`arsia_protocol.types.ArsiaCapabilityDescriptor`,
            but this builder does not validate them.
        total: Total number of descriptors across all pages. Defaults
            to ``len(actions)`` when omitted, which is the right
            answer for non-paginated responses.
        limit: Page size. Defaults to 20.
        offset: Starting offset for this page. Defaults to 0.

    Returns:
        ``{"actions": [...], "total": N, "limit": N, "offset": N}``.

    Spec: ARSIA-Core.md §7.2, ARSIA-Actions.md §2.3.
    """
    return {
        "actions": list(actions),
        "total": total if total is not None else len(actions),
        "limit": limit,
        "offset": offset,
    }


def build_identity_record_signature(
    body: bytes,
    private_key: Ed25519PrivateKey,
) -> str:
    """Produce the value for the ``X-ARSIA-Sig`` header.

    Per ARSIA-Identity.md §1.3.3, the header carries a base64url
    (no-padding) Ed25519 signature over the **SHA-256 hash** of the
    raw response body bytes — not over the body directly.

    Note that this differs from envelope signing
    (:func:`arsia_protocol.message.sign_message`), which signs over
    RFC 8785-canonicalized envelope bytes. Identity-record signing
    follows §1.3 exactly: hash the body, sign the hash.

    Args:
        body: Raw response body bytes (before any transport-level
            compression or transcoding).
        private_key: The agent's Ed25519 private key. The ``kid``
            carried in the JWKS for this key MUST start with
            ``{agent_id}#`` so verifiers can locate it.

    Returns:
        Base64url-encoded Ed25519 signature, no ``=`` padding.

    Spec: ARSIA-Identity.md §1.3.3.
    """
    digest = hashlib.sha256(body).digest()
    signature = sign(private_key, digest)
    return base64url_encode(signature)


def verify_identity_record_signature(
    body: bytes,
    signature: str,
    public_key: Ed25519PublicKey,
) -> bool:
    """Verify the ``X-ARSIA-Sig`` header against a response body.

    Implements steps 1, 2, and 4 of ARSIA-Identity.md §1.3.4:

    1. Compute SHA-256 of the raw response body bytes.
    2. Base64url-decode the header value.
    3. *(Caller's responsibility — fetch the public key from the
       agent's JWKS endpoint per ARSIA-Core.md §7.3.)*
    4. Verify the Ed25519 signature over the SHA-256 hash.

    The function never raises on an invalid signature — it returns
    ``False`` for tampered bodies, wrong keys, or malformed base64url
    input — so callers can branch cleanly on the boolean result.

    Args:
        body: Raw response body bytes as received.
        signature: Value of the ``X-ARSIA-Sig`` header (base64url,
            no padding).
        public_key: Agent's Ed25519 public key, loaded from its JWKS.

    Returns:
        ``True`` iff the signature verifies against SHA-256(body)
        under ``public_key``.

    Spec: ARSIA-Identity.md §1.3.4.
    """
    try:
        signature_bytes = base64url_decode(signature)
    except (ValueError, TypeError):
        return False
    digest = hashlib.sha256(body).digest()
    return verify(public_key, digest, signature_bytes)


def verify_jwks_agent_id_consistency(
    jwks: dict[str, Any] | list[dict[str, Any]],
    agent_id: str,
) -> bool:
    """Check at least one JWK ``kid`` prefix matches ``agent_id``.

    Implements ARSIA-Identity.md §7.2 Step 5 of the onboarding flow:
    the ``kid`` of at least one JWKS entry must take the form
    ``"{agent_id}#{label}"`` so the cryptographic identity is bound
    to the technical identity advertised in the IdentityRecord.

    The check accepts either the wrapped JWK Set form
    (``{"keys": [...]}`` per RFC 7517) or a bare list of JWK dicts,
    so callers can pass either the raw JWKS endpoint body or the
    pre-extracted ``keys`` array. Entries without a ``kid`` field
    are skipped silently rather than raising.

    Args:
        jwks: JWKS dict (``{"keys": [...]}``) or a list of JWK dicts.
        agent_id: Agent identifier the IdentityRecord declares.

    Returns:
        ``True`` iff at least one JWK has a ``kid`` whose prefix
        (everything before the ``#``) equals ``agent_id``.
        ``False`` for an empty key set, missing ``kid`` values, or
        mismatched prefixes.

    Spec: ARSIA-Identity.md §7.2 Step 5, §1.1.
    """
    if isinstance(jwks, dict):
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            return False
    else:
        keys = jwks
    expected_prefix = f"{agent_id}#"
    for jwk in keys:
        if not isinstance(jwk, dict):
            continue
        kid = jwk.get("kid")
        if isinstance(kid, str) and kid.startswith(expected_prefix):
            return True
    return False


RSA_MINIMUM_KEY_BITS = 2048
"""Minimum RSA key size per §5.1. RS256 keys below this MUST be rejected."""

ROTATION_OVERLAP_HOURS = 24
"""Minimum overlap period for key rotation per §7.3 Rule 1."""

JWKS_MAX_CACHE_SECONDS = 86400
"""Maximum JWKS cache lifetime (24 hours) per §5.2."""


def validate_rsa_key_size(key_size_bits: int) -> None:
    """Reject RSA keys below the §5.1 minimum of 2048 bits.

    Spec: ARSIA-Core.md §5.1.
    """
    if key_size_bits < RSA_MINIMUM_KEY_BITS:
        raise ValueError(
            f"RSA key must be at least {RSA_MINIMUM_KEY_BITS} bits, got {key_size_bits}"
        )


def validate_capability_prerequisites(
    requested_capabilities: list[str],
    descriptors: list[dict[str, Any]],
) -> list[ValidationError]:
    """Check that capability co-requisites are satisfied per §7.2.

    For each descriptor whose ``capability`` appears in
    ``requested_capabilities``, every entry in its ``requires`` array
    MUST also be present in ``requested_capabilities``.

    Returns:
        A list of validation errors (empty if all satisfied).

    Spec: ARSIA-Core.md §7.2.
    """
    cap_set = set(requested_capabilities)
    errors: list[ValidationError] = []
    desc_map = {
        d["capability"]: d
        for d in descriptors
        if isinstance(d, dict) and "capability" in d
    }
    for cap in requested_capabilities:
        desc = desc_map.get(cap)
        if desc is None:
            continue
        requires = desc.get("requires")
        if not isinstance(requires, list):
            continue
        for prereq in requires:
            if prereq not in cap_set:
                errors.append(
                    ValidationError(
                        code="capability_prerequisite_missing",
                        message=f"capability {cap!r} requires {prereq!r} which is not in the request",
                        details={"capability": cap, "requires": prereq},
                        spec_ref="Core §7.2",
                    )
                )
    return errors


def build_rotation_jwks(
    current_keys: list[dict[str, str]],
    new_keys: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    """Build a JWKS containing both current and new keys for rotation.

    Per §7.3 Rule 1, both old and new keys MUST be published
    simultaneously for at least 24 hours during rotation.

    Spec: ARSIA-Core.md §7.3.
    """
    all_keys = list(current_keys) + list(new_keys)
    return {"keys": all_keys}


def filter_compromised_keys(
    keys: list[dict[str, str]],
    compromised_kids: set[str],
) -> list[dict[str, str]]:
    """Remove compromised keys from a key list per §7.3 Rule 4.

    Spec: ARSIA-Core.md §7.3.
    """
    return [k for k in keys if k.get("kid") not in compromised_kids]


def is_kid_revoked(kid: str, revoked_kids: set[str]) -> bool:
    """Check whether a key identifier is in the revoked set.

    Per §7.3 Rule 4, all tokens and signatures produced with a
    compromised key MUST be considered invalid.

    Spec: ARSIA-Core.md §7.3.
    """
    return kid in revoked_kids


@dataclass(frozen=True)
class JWKSCachePolicy:
    """JWKS cache refresh policy per §5.2.

    Implementations MUST refresh cached JWKS entries when:
    - An unknown ``kid`` is encountered.
    - The cached entry's ``Cache-Control`` max-age has expired.
    - At least once every 24 hours regardless of cache headers.

    Spec: ARSIA-Core.md §5.2.
    """

    max_age_seconds: int = 3600
    max_lifetime_seconds: int = JWKS_MAX_CACHE_SECONDS

    def should_refresh(
        self,
        *,
        age_seconds: float,
        kid_known: bool = True,
    ) -> bool:
        """Return True when the cached JWKS should be refreshed."""
        if not kid_known:
            return True
        if age_seconds >= self.max_age_seconds:
            return True
        if age_seconds >= self.max_lifetime_seconds:
            return True
        return False


def select_jwk_from_jwks(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Return the first JWK whose ``kid`` matches, or ``None``."""
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    for jwk in keys:
        if isinstance(jwk, dict) and jwk.get("kid") == kid:
            return jwk
    return None


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    """Load an Ed25519 public key from an OKP/Ed25519 JWK.

    Raises ``ValueError`` when ``kty``/``crv`` are not ``OKP``/``Ed25519``
    or when ``x`` is missing/malformed. The caller is expected to map
    this into an ``unauthorized`` response.
    """
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("jwk is not an OKP/Ed25519 key")
    x = jwk.get("x")
    if not isinstance(x, str) or not x:
        raise ValueError("jwk is missing 'x' (public key material)")
    raw = base64url_decode(x)
    return public_key_from_bytes(raw)


def validate_jwks_kid_uniqueness(
    jwks: dict[str, Any] | list[dict[str, Any]],
) -> list[ValidationError]:
    """Verify all ``kid`` values within a JWKS are unique.

    Spec: ARSIA-Identity.md §2.2 — kid MUST be globally unique
    within the agent's JWKS.
    """
    if isinstance(jwks, dict):
        raw_keys = jwks.get("keys")
        if not isinstance(raw_keys, list):
            return []
        keys: list[dict[str, Any]] = raw_keys
    else:
        keys = jwks

    seen: dict[str, int] = {}
    duplicates: list[str] = []
    for entry in keys:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("kid")
        if not isinstance(kid, str):
            continue
        if kid in seen:
            if kid not in duplicates:
                duplicates.append(kid)
        else:
            seen[kid] = 1

    errors: list[ValidationError] = []
    for kid in duplicates:
        errors.append(
            ValidationError(
                code="duplicate_kid",
                message=f"duplicate kid {kid!r} in JWKS",
                details={"kid": kid},
                spec_ref="Identity §2.2",
            )
        )
    return errors


__all__ = [
    "build_discovery_document",
    "build_jwk",
    "build_ec_jwk",
    "build_jwks",
    "build_encryption_jwks",
    "build_capability_listing",
    "build_identity_record_signature",
    "verify_identity_record_signature",
    "verify_jwks_agent_id_consistency",
    "validate_jwks_kid_uniqueness",
    "RSA_MINIMUM_KEY_BITS",
    "ROTATION_OVERLAP_HOURS",
    "JWKS_MAX_CACHE_SECONDS",
    "validate_rsa_key_size",
    "validate_capability_prerequisites",
    "build_rotation_jwks",
    "filter_compromised_keys",
    "is_kid_revoked",
    "JWKSCachePolicy",
    "select_jwk_from_jwks",
    "public_key_from_jwk",
]
