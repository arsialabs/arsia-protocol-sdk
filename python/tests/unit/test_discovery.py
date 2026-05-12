# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.discovery``.

Covers the four builders for the ARSIA discovery endpoints defined in
ARSIA-Core.md §7:

- :func:`build_discovery_document` — §7.1 agent metadata.
- :func:`build_jwk` / :func:`build_jwks` — §7.3 JWK Set.
- :func:`build_capability_listing` — §7.2 capability catalogue with
  the SDK's pagination wrapper.

The builders are pure functions, so each test just exercises the
shape of the returned dict.
"""

from __future__ import annotations

from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    EllipticCurvePublicKey,
    generate_private_key,
)

from arsia_protocol.identity.discovery import (
    build_capability_listing,
    build_discovery_document,
    build_ec_jwk,
    build_encryption_jwks,
    build_identity_record_signature,
    build_jwk,
    build_jwks,
    validate_jwks_kid_uniqueness,
    verify_identity_record_signature,
    verify_jwks_agent_id_consistency,
)
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_decode,
    generate_keypair,
)
from arsia_protocol.types.identity import (
    ArsiaDiscoveryDocument,
    ArsiaJWK,
    ArsiaJWKS,
)


# ----------------------------------------------------------------------
# build_discovery_document
# ----------------------------------------------------------------------


def _minimal_document() -> dict[str, Any]:
    return build_discovery_document(
        agent_id="agent:acme.bot",
        name="Acme Bot",
        version="2.1.0",
        inbox="https://acme.example/arsia/inbox",
        jwks="https://acme.example/.well-known/arsia/jwks.json",
    )


def test_build_discovery_document_has_eleven_required_fields() -> None:
    """All §7.1 required fields are present.

    Spec: ARSIA-Core.md §7.1.
    """
    doc = _minimal_document()
    for field in (
        "agent_id",
        "name",
        "version",
        "protocol_version",
        "inbox",
        "jwks",
        "capabilities_supported",
        "max_message_bytes",
        "request_timeout_ms",
        "server_min",
        "server_max",
    ):
        assert field in doc, f"required field missing: {field}"


def test_build_discovery_document_omits_optional_fields_by_default() -> None:
    """The three optional fields are absent when not passed.

    Spec: ARSIA-Core.md §7.1 (optional fields).
    """
    doc = _minimal_document()
    assert "features" not in doc
    assert "rate_limits" not in doc
    assert "compliance_profiles_supported" not in doc


def test_build_discovery_document_defaults_match_sdk_conventions() -> None:
    """Default protocol_version/server bounds/size/timeout hit the SDK defaults.

    Spec: ARSIA-Core.md §7.1.
    """
    doc = _minimal_document()
    assert doc["protocol_version"] == "1.0"
    assert doc["server_min"] == "1.0"
    assert doc["server_max"] == "1.0"
    assert doc["max_message_bytes"] == 1_048_576
    assert doc["request_timeout_ms"] == 30_000
    assert doc["capabilities_supported"] == []


def test_build_discovery_document_populates_optional_fields() -> None:
    """Optional fields appear when the caller passes them.

    Spec: ARSIA-Core.md §7.1 (optional fields).
    """
    doc = build_discovery_document(
        agent_id="agent:acme.bot",
        name="Acme Bot",
        version="2.1.0",
        inbox="https://acme.example/arsia/inbox",
        jwks="https://acme.example/.well-known/arsia/jwks.json",
        capabilities_supported=["quotes.get", "orders.*"],
        features={"async_responses": True, "batch_requests": False},
        rate_limits={"requests_per_minute": 120, "burst_size": 20},
        compliance_profiles_supported=["GDPR-STANDARD", "MIFID-II"],
    )
    assert doc["capabilities_supported"] == ["quotes.get", "orders.*"]
    assert doc["features"] == {"async_responses": True, "batch_requests": False}
    assert doc["rate_limits"] == {"requests_per_minute": 120, "burst_size": 20}
    assert doc["compliance_profiles_supported"] == ["GDPR-STANDARD", "MIFID-II"]


def test_build_discovery_document_copies_list_inputs() -> None:
    """The returned dict owns its own list/dict objects (no aliasing).

    This matters because the builder's output is often mutated downstream
    (e.g. adding HTTP headers on top of the JSON body).
    """
    caps = ["a", "b"]
    doc = build_discovery_document(
        agent_id="agent:acme.bot",
        name="Acme Bot",
        version="2.1.0",
        inbox="https://acme.example/arsia/inbox",
        jwks="https://acme.example/.well-known/arsia/jwks.json",
        capabilities_supported=caps,
    )
    caps.append("c")
    assert doc["capabilities_supported"] == ["a", "b"]


def test_build_discovery_document_custom_version_bounds() -> None:
    """Overriding server_min/server_max/protocol_version propagates.

    Spec: ARSIA-Core.md §7.1.
    """
    doc = build_discovery_document(
        agent_id="agent:acme.bot",
        name="Acme Bot",
        version="2.1.0",
        inbox="https://acme.example/arsia/inbox",
        jwks="https://acme.example/.well-known/arsia/jwks.json",
        server_min="1.0",
        server_max="1.2",
        protocol_version="1.2",
    )
    assert doc["server_min"] == "1.0"
    assert doc["server_max"] == "1.2"
    assert doc["protocol_version"] == "1.2"


def test_build_discovery_document_validates_against_pydantic_model() -> None:
    """The output round-trips through :class:`ArsiaDiscoveryDocument`.

    This enforces that the shape matches the types defined in Slice 1B.
    """
    doc = build_discovery_document(
        agent_id="agent:acme.bot",
        name="Acme Bot",
        version="2.1.0",
        inbox="https://acme.example/arsia/inbox",
        jwks="https://acme.example/.well-known/arsia/jwks.json",
        capabilities_supported=["quotes.get"],
        features={"async_responses": True, "batch_requests": False, "encryption": True},
        rate_limits={"requests_per_minute": 100, "burst_size": 10},
        compliance_profiles_supported=["GDPR-STANDARD"],
    )
    model = ArsiaDiscoveryDocument.model_validate(doc)
    assert model.agent_id == "agent:acme.bot"


# ----------------------------------------------------------------------
# build_jwk / build_jwks
# ----------------------------------------------------------------------


def test_build_jwk_has_required_fields() -> None:
    """The single-key builder returns the five §7.3 fields.

    Spec: ARSIA-Core.md §7.3.
    """
    _, public_key = generate_keypair()
    jwk = build_jwk(public_key, "agent:acme.bot#key1")
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == "agent:acme.bot#key1"
    assert isinstance(jwk["x"], str)


def test_build_jwk_x_is_base64url_no_padding() -> None:
    """The ``x`` field is base64url without padding.

    Spec: ARSIA-Core.md §7.3, §5.1 Step 5.
    """
    _, public_key = generate_keypair()
    jwk = build_jwk(public_key, "kid")
    assert "=" not in jwk["x"]
    assert "+" not in jwk["x"]
    assert "/" not in jwk["x"]
    assert base64url_decode(jwk["x"]) == public_key.public_bytes_raw()


def test_build_jwk_custom_use_parameter() -> None:
    """The ``use`` parameter overrides the default ``"sig"``.

    Spec: ARSIA-Core.md §7.3.
    """
    _, public_key = generate_keypair()
    jwk = build_jwk(public_key, "kid", use="enc")
    assert jwk["use"] == "enc"


def test_build_jwk_validates_against_pydantic_model() -> None:
    """The output round-trips through :class:`ArsiaJWK`.

    Spec: ARSIA-Core.md §7.3.
    """
    _, public_key = generate_keypair()
    jwk = build_jwk(public_key, "agent:acme.bot#key1")
    model = ArsiaJWK.model_validate(jwk)
    assert model.kid == "agent:acme.bot#key1"


def test_build_jwks_wraps_keys_in_envelope() -> None:
    """``build_jwks`` returns a dict with a single ``keys`` list.

    Spec: ARSIA-Core.md §7.3, RFC 7517.
    """
    _, pub1 = generate_keypair()
    _, pub2 = generate_keypair()
    keys = [build_jwk(pub1, "kid1"), build_jwk(pub2, "kid2")]
    jwks = build_jwks(keys)
    assert list(jwks.keys()) == ["keys"]
    assert len(jwks["keys"]) == 2


def test_build_jwks_empty_list_is_legal() -> None:
    """An empty JWKS is a valid response (agent has rotated out all keys).

    Spec: ARSIA-Core.md §7.3, RFC 7517.
    """
    jwks = build_jwks([])
    assert jwks == {"keys": []}


def test_build_jwks_copies_input_list() -> None:
    """The returned dict owns its own list (no aliasing).

    Spec: defensive — builder is meant to be immutable from the caller's
    perspective.
    """
    _, pub1 = generate_keypair()
    keys = [build_jwk(pub1, "kid1")]
    jwks = build_jwks(keys)
    keys.append(build_jwk(pub1, "kid2"))
    assert len(jwks["keys"]) == 1


def test_build_jwks_validates_against_pydantic_model() -> None:
    """The output round-trips through :class:`ArsiaJWKS`.

    Spec: ARSIA-Core.md §7.3.
    """
    _, pub1 = generate_keypair()
    jwks = build_jwks([build_jwk(pub1, "agent:acme.bot#key1")])
    model = ArsiaJWKS.model_validate(jwks)
    assert len(model.keys) == 1


# ----------------------------------------------------------------------
# build_capability_listing
# ----------------------------------------------------------------------


def _sample_descriptor(capability: str) -> dict[str, Any]:
    return {
        "capability": capability,
        "description": f"Stub for {capability}",
        "risk_level": 2,
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
        "oversight": {"human_oversight": "none"},
        "pricing": {"type": "free"},
        "retention_days": 30,
    }


def test_build_capability_listing_default_total_is_length() -> None:
    """``total`` defaults to ``len(actions)`` for non-paginated responses.

    Spec: ARSIA-Core.md §7.2.
    """
    actions = [_sample_descriptor("quotes.get"), _sample_descriptor("orders.create")]
    listing = build_capability_listing(actions)
    assert listing["actions"] == actions
    assert listing["total"] == 2
    assert listing["limit"] == 20
    assert listing["offset"] == 0


def test_build_capability_listing_paginated_total_override() -> None:
    """Caller passes an explicit ``total`` for a mid-stream page.

    Spec: ARSIA-Core.md §7.2.
    """
    page = [_sample_descriptor("quotes.get")]
    listing = build_capability_listing(page, total=150, limit=10, offset=20)
    assert listing["actions"] == page
    assert listing["total"] == 150
    assert listing["limit"] == 10
    assert listing["offset"] == 20


def test_build_capability_listing_empty_actions() -> None:
    """An empty page is a valid response (agent exposes no actions).

    Spec: ARSIA-Core.md §7.2.
    """
    listing = build_capability_listing([])
    assert listing == {"actions": [], "total": 0, "limit": 20, "offset": 0}


def test_build_capability_listing_copies_actions_list() -> None:
    """The builder owns its output list (no aliasing).

    Spec: defensive.
    """
    actions = [_sample_descriptor("quotes.get")]
    listing = build_capability_listing(actions)
    actions.append(_sample_descriptor("orders.create"))
    assert len(listing["actions"]) == 1


# ----------------------------------------------------------------------
# Public surface
# ----------------------------------------------------------------------


def test_discovery_module_public_surface() -> None:
    """``__all__`` lists the discovery builders and identity-record helpers."""
    import arsia_protocol.identity.discovery as mod

    assert set(mod.__all__) == {
        "build_discovery_document",
        "build_jwk",
        "build_ec_jwk",
        "build_jwks",
        "build_encryption_jwks",
        "build_capability_listing",
        "build_identity_record_signature",
        "verify_identity_record_signature",
        "verify_jwks_agent_id_consistency",
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
        "validate_jwks_kid_uniqueness",
    }


@pytest.mark.parametrize(
    "capability",
    ["quotes.get", "orders.*", "arsiaprotocol.audit.read"],
)
def test_sample_descriptor_fixture_shape(capability: str) -> None:
    """Sanity check that the test helper produces §7.2-shaped descriptors.

    Spec: ARSIA-Core.md §7.2, ARSIA-Actions.md §2.3.
    """
    descriptor = _sample_descriptor(capability)
    for key in (
        "capability",
        "description",
        "risk_level",
        "input_schema",
        "output_schema",
        "oversight",
        "pricing",
        "retention_days",
    ):
        assert key in descriptor


# ----------------------------------------------------------------------
# build_identity_record_signature / verify_identity_record_signature
# ----------------------------------------------------------------------


def test_identity_record_signature_roundtrip() -> None:
    """build_* then verify_* accepts the same body under the same key.

    Spec: ARSIA-Identity.md §1.3.3, §1.3.4.
    """
    private_key, public_key = generate_keypair()
    body = b'{"agent_id":"agent:arsia.demo"}'

    signature = build_identity_record_signature(body, private_key)

    assert verify_identity_record_signature(body, signature, public_key) is True


def test_identity_record_signature_is_base64url_no_padding() -> None:
    """The returned header value has no ``=`` and uses URL-safe alphabet.

    Spec: ARSIA-Identity.md §1.3.3.
    """
    private_key, _ = generate_keypair()
    body = b'{"agent_id":"agent:arsia.demo"}'

    signature = build_identity_record_signature(body, private_key)

    assert "=" not in signature
    assert "+" not in signature
    assert "/" not in signature
    # Raw Ed25519 sig is 64 bytes → base64url encodes to 86 chars (no padding).
    assert len(signature) == 86
    # Decoding must succeed.
    assert len(base64url_decode(signature)) == 64


def test_identity_record_signature_rejects_tampered_body() -> None:
    """verify_* returns False when the body changes after signing.

    Spec: ARSIA-Identity.md §1.3.4.
    """
    private_key, public_key = generate_keypair()
    body = b'{"agent_id":"agent:arsia.demo"}'
    tampered = b'{"agent_id":"agent:evil.demo"}'

    signature = build_identity_record_signature(body, private_key)

    assert verify_identity_record_signature(tampered, signature, public_key) is False


def test_identity_record_signature_rejects_wrong_key() -> None:
    """verify_* returns False under a different public key.

    Spec: ARSIA-Identity.md §1.3.4.
    """
    signer_private, _ = generate_keypair()
    _, other_public = generate_keypair()
    body = b'{"agent_id":"agent:arsia.demo"}'

    signature = build_identity_record_signature(body, signer_private)

    assert verify_identity_record_signature(body, signature, other_public) is False


def test_identity_record_signature_rejects_malformed_header() -> None:
    """Malformed base64url input returns False rather than raising.

    Spec: ARSIA-Identity.md §1.3.4 (verification is a boolean outcome).
    """
    _, public_key = generate_keypair()
    body = b'{"agent_id":"agent:arsia.demo"}'

    assert verify_identity_record_signature(body, "!!!not-base64!!!", public_key) is False


# ----------------------------------------------------------------------
# verify_jwks_agent_id_consistency
# ----------------------------------------------------------------------


def test_jwks_consistency_accepts_matching_kid_in_dict_form() -> None:
    """JWKS dict form: at least one kid prefix matches agent_id.

    Spec: ARSIA-Identity.md §7.2 Step 5.
    """
    jwks = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "kid": "agent:acme.bot#k1", "x": "AA"},
        ]
    }
    assert verify_jwks_agent_id_consistency(jwks, "agent:acme.bot") is True


def test_jwks_consistency_accepts_matching_kid_in_list_form() -> None:
    """JWKS bare-list form is also accepted.

    Spec: ARSIA-Identity.md §7.2 Step 5.
    """
    keys = [
        {"kty": "OKP", "crv": "Ed25519", "kid": "agent:acme.bot#k1", "x": "AA"},
    ]
    assert verify_jwks_agent_id_consistency(keys, "agent:acme.bot") is True


def test_jwks_consistency_rejects_when_no_kid_matches() -> None:
    """Spec: §7.2 Step 5 — every kid prefix differs from agent_id."""
    jwks = {
        "keys": [
            {"kid": "agent:other.bot#k1"},
            {"kid": "agent:third.bot#k2"},
        ]
    }
    assert verify_jwks_agent_id_consistency(jwks, "agent:acme.bot") is False


def test_jwks_consistency_rejects_empty_keys() -> None:
    """A JWKS with no entries cannot satisfy the check.

    Spec: ARSIA-Identity.md §7.2 Step 5.
    """
    assert verify_jwks_agent_id_consistency({"keys": []}, "agent:acme.bot") is False
    assert verify_jwks_agent_id_consistency([], "agent:acme.bot") is False


def test_jwks_consistency_rejects_jwks_without_keys_array() -> None:
    """Malformed JWKS dict (missing ``keys`` field) returns False."""
    assert verify_jwks_agent_id_consistency({"foo": "bar"}, "agent:acme.bot") is False


def test_jwks_consistency_skips_entries_without_kid() -> None:
    """Entries without a ``kid`` are silently skipped, not rejected."""
    jwks = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": "AA"},  # no kid
            {"kty": "OKP", "crv": "Ed25519", "kid": "agent:acme.bot#k1", "x": "BB"},
        ]
    }
    assert verify_jwks_agent_id_consistency(jwks, "agent:acme.bot") is True


def test_jwks_consistency_requires_hash_separator() -> None:
    """Prefix match must end at '#', not a partial substring.

    Spec: §7.2 Step 5 — "kid prefix (everything before the # character)".
    """
    jwks = {"keys": [{"kid": "agent:acme.botanist#k1"}]}
    assert verify_jwks_agent_id_consistency(jwks, "agent:acme.bot") is False


# ----------------------------------------------------------------------
# build_ec_jwk — P-256 EC key support (§7.3)
# ----------------------------------------------------------------------


def _generate_p256_key() -> EllipticCurvePublicKey:
    return generate_private_key(SECP256R1()).public_key()


class TestBuildEcJwk:
    """P-256 JWK construction per §7.3 EC key table."""

    def test_required_fields_present(self) -> None:
        """All six required fields from the EC key table are present."""
        pub = _generate_p256_key()
        jwk = build_ec_jwk(pub, "agent:acme.bot#enc1")
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["kid"] == "agent:acme.bot#enc1"
        assert jwk["use"] == "enc"
        assert "x" in jwk
        assert "y" in jwk

    def test_coordinates_are_base64url_no_padding(self) -> None:
        """x and y are base64url without '=' padding."""
        pub = _generate_p256_key()
        jwk = build_ec_jwk(pub, "agent:acme.bot#enc1")
        assert "=" not in jwk["x"]
        assert "=" not in jwk["y"]
        x_bytes = base64url_decode(jwk["x"])
        y_bytes = base64url_decode(jwk["y"])
        assert len(x_bytes) == 32
        assert len(y_bytes) == 32

    def test_coordinates_round_trip(self) -> None:
        """Decoded x/y match the original key's public numbers."""
        pub = _generate_p256_key()
        jwk = build_ec_jwk(pub, "agent:acme.bot#enc1")
        numbers = pub.public_numbers()
        assert int.from_bytes(base64url_decode(jwk["x"]), "big") == numbers.x
        assert int.from_bytes(base64url_decode(jwk["y"]), "big") == numbers.y

    def test_use_defaults_to_enc(self) -> None:
        """Default use is 'enc' for encryption keys."""
        pub = _generate_p256_key()
        jwk = build_ec_jwk(pub, "agent:acme.bot#enc1")
        assert jwk["use"] == "enc"

    def test_use_sig_override(self) -> None:
        """Caller can set use='sig' for signing EC keys."""
        pub = _generate_p256_key()
        jwk = build_ec_jwk(pub, "agent:acme.bot#sig1", use="sig")
        assert jwk["use"] == "sig"

    def test_rejects_non_p256_curve(self) -> None:
        """Only P-256 is accepted; P-384 raises ValueError."""
        pub = generate_private_key(SECP384R1()).public_key()
        with pytest.raises(ValueError, match="P-256"):
            build_ec_jwk(pub, "agent:acme.bot#enc1")

    def test_validates_via_arsia_jwk_model(self) -> None:
        """The produced dict passes ArsiaJWK validation."""
        pub = _generate_p256_key()
        jwk = build_ec_jwk(pub, "agent:acme.bot#enc1")
        model = ArsiaJWK.model_validate(jwk)
        assert model.kty == "EC"
        assert model.crv == "P-256"
        assert model.y is not None


class TestBuildEncryptionJwks:
    """JWKS with both signing and encryption keys per §7.3."""

    def test_mixed_key_types(self) -> None:
        """JWKS can contain both Ed25519 signing and P-256 encryption keys."""
        _, ed_pub = generate_keypair()
        ec_pub = _generate_p256_key()
        sig_jwk = build_jwk(ed_pub, "agent:acme.bot#sig1")
        enc_jwk = build_ec_jwk(ec_pub, "agent:acme.bot#enc1")
        jwks = build_encryption_jwks([sig_jwk], [enc_jwk])
        assert len(jwks["keys"]) == 2
        ktypes = {k["kty"] for k in jwks["keys"]}
        assert ktypes == {"OKP", "EC"}
        uses = {k["use"] for k in jwks["keys"]}
        assert uses == {"sig", "enc"}

    def test_validates_via_arsia_jwks_model(self) -> None:
        """The produced dict passes ArsiaJWKS validation."""
        _, ed_pub = generate_keypair()
        ec_pub = _generate_p256_key()
        sig_jwk = build_jwk(ed_pub, "agent:acme.bot#sig1")
        enc_jwk = build_ec_jwk(ec_pub, "agent:acme.bot#enc1")
        jwks = build_encryption_jwks([sig_jwk], [enc_jwk])
        model = ArsiaJWKS.model_validate(jwks)
        assert len(model.keys) == 2

    def test_encryption_key_has_use_enc(self) -> None:
        """Encryption keys in the JWKS carry use='enc'."""
        ec_pub = _generate_p256_key()
        enc_jwk = build_ec_jwk(ec_pub, "agent:acme.bot#enc1")
        jwks = build_encryption_jwks([], [enc_jwk])
        assert jwks["keys"][0]["use"] == "enc"

    def test_build_jwks_also_accepts_mixed(self) -> None:
        """The existing build_jwks still works with mixed key dicts."""
        _, ed_pub = generate_keypair()
        ec_pub = _generate_p256_key()
        sig_jwk = build_jwk(ed_pub, "agent:acme.bot#sig1")
        enc_jwk = build_ec_jwk(ec_pub, "agent:acme.bot#enc1")
        jwks = build_jwks([sig_jwk, enc_jwk])
        assert len(jwks["keys"]) == 2


# ----------------------------------------------------------------------
# §6.8 Private key exclusion (req:07e4df2a)
# ----------------------------------------------------------------------


class TestPrivateKeyExclusion:
    """Private key MUST NOT be transmitted or included in any protocol
    message or IdentityRecord.

    Spec: ARSIA-Identity.md §6.8.
    """

    def test_build_jwk_excludes_private_key_d_parameter(self) -> None:
        """build_jwk output has no 'd' field (private key material)."""
        _, public_key = generate_keypair()
        jwk = build_jwk(public_key, "agent:acme.bot#key1")
        assert "d" not in jwk
        assert set(jwk.keys()) == {"kty", "crv", "x", "kid", "use"}

    def test_build_ec_jwk_excludes_private_key_d_parameter(self) -> None:
        """build_ec_jwk output has no 'd' field."""
        ec_pub = _generate_p256_key()
        jwk = build_ec_jwk(ec_pub, "agent:acme.bot#enc1")
        assert "d" not in jwk

    def test_identity_record_has_no_private_key_field(self) -> None:
        """IdentityRecord schema has no field for private key material."""
        from arsia_protocol.types.identity import IdentityRecord

        field_names = set(IdentityRecord.model_fields.keys())
        private_key_indicators = {"private_key", "secret_key", "d", "signing_key"}
        assert field_names.isdisjoint(private_key_indicators)

    def test_identity_record_serialization_excludes_private_keys(self) -> None:
        """IdentityRecord.model_dump() never contains private key material."""
        from arsia_protocol.types.identity import IdentityRecord

        record = IdentityRecord(
            agent_id="agent:acme.bot",
            owner_id="VAT-DE-123456789",
            owner_name="Acme Corp",
            jurisdiction="DE",
            ai_system_classification="limited-risk",
            created_at="2025-01-01T00:00:00.000Z",
        )
        dumped = record.model_dump()
        for key in dumped:
            assert key not in {"d", "private_key", "secret_key", "signing_key"}
        assert "d" not in dumped


# ----------------------------------------------------------------------
# validate_jwks_kid_uniqueness — §2.2
# ----------------------------------------------------------------------


class TestValidateJwksKidUniqueness:
    """ARSIA-Identity.md §2.2 — kid MUST be unique within JWKS."""

    def test_all_unique_passes(self) -> None:
        """No errors when all kid values are unique."""
        jwks = {"keys": [
            {"kid": "agent:acme.bot#key1", "kty": "OKP"},
            {"kid": "agent:acme.bot#key2", "kty": "OKP"},
        ]}
        assert validate_jwks_kid_uniqueness(jwks) == []

    def test_duplicate_returns_error(self) -> None:
        """Duplicate kid values produce a validation error."""
        jwks = {"keys": [
            {"kid": "agent:acme.bot#key1", "kty": "OKP"},
            {"kid": "agent:acme.bot#key1", "kty": "OKP"},
        ]}
        errors = validate_jwks_kid_uniqueness(jwks)
        assert len(errors) == 1
        assert errors[0].code == "duplicate_kid"

    def test_duplicate_error_lists_kid(self) -> None:
        """Error details include the duplicated kid value."""
        jwks = {"keys": [
            {"kid": "agent:acme.bot#dup", "kty": "OKP"},
            {"kid": "agent:acme.bot#dup", "kty": "OKP"},
        ]}
        errors = validate_jwks_kid_uniqueness(jwks)
        assert errors[0].details["kid"] == "agent:acme.bot#dup"

    def test_accepts_dict_format(self) -> None:
        """Accepts JWKS in {"keys": [...]} format."""
        jwks = {"keys": [{"kid": "k1"}, {"kid": "k2"}]}
        assert validate_jwks_kid_uniqueness(jwks) == []

    def test_accepts_list_format(self) -> None:
        """Accepts JWKS as a bare list of JWK dicts."""
        jwks_list: list[dict[str, Any]] = [{"kid": "k1"}, {"kid": "k2"}]
        assert validate_jwks_kid_uniqueness(jwks_list) == []

    def test_empty_keys_passes(self) -> None:
        """Empty key set produces no errors."""
        assert validate_jwks_kid_uniqueness({"keys": []}) == []

    def test_missing_kid_skipped(self) -> None:
        """Keys without kid are silently skipped."""
        jwks = {"keys": [{"kty": "OKP"}, {"kid": "k1"}]}
        assert validate_jwks_kid_uniqueness(jwks) == []
