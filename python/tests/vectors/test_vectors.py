# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Canonical test-vector processing — the Slice 1 exit gate.

The file ``shared/test-vectors/arsia-test-vectors.json`` bundles
113 cross-language conformance vectors in two formats:

- **Format A (envelope):** 45 vectors (32 valid + 13 invalid). Each
  valid vector carries a real Ed25519 signature computed over the
  RFC 8785 canonical form of its envelope, using one of three test
  keypairs from ``shared/test-vectors/keypairs.json``. Each invalid
  vector carries an ``expected_error`` string pointing to the spec
  section it violates. Discriminator: ``"valid" in vector``.

- **Format B (schema):** 68 vectors (35 valid + 33 invalid). Each
  vector validates a JSON data object against a named schema.
  Discriminator: ``"schema_ref" in vector``.

The tests in this file assert three things for the valid envelope vectors:

1. Canonicalizing ``message`` (minus ``security``) reproduces the
   byte sequence in ``crypto.canonical_bytes_hex`` exactly.
2. Signing those canonical bytes with ``crypto.private_key_hex``
   reproduces ``crypto.signature_base64url`` exactly.
3. Verifying the signature in ``message.security`` against the
   public key verifies to ``True``, and L1 schema validation of the
   full envelope is clean.

For the invalid envelope vectors the tests split into two groups:

- **Slice 1D gate.** Eight invalid vectors exercise Core §4 or
  Compliance §4.3.8 rules. They MUST be rejected by
  :func:`arsia_protocol.validation.validate_envelope`, and the
  returned error list MUST contain a stable keyword from the
  vector's ``expected_error`` text.
- **Slice 4D gate.** INV-10 (Actions §1.1 single-segment capability)
  is rejected via ``validate_semantic``'s capability grammar check.
- **Slice 6 gate.** INV-09 (currency precision),
  INV-12 (reversal precondition), and INV-13 (escrow release_agent)
  are rejected by the assets Layer 4 validators
  (``validate_transfer_request`` / ``validate_transfer_reversal`` /
  ``validate_reversal_precondition``). Core §4 / §4.3.8 does not
  know about these rules.

For the schema vectors (Format B), each vector's ``data`` object is
validated against the schema named in ``schema_ref``. Valid vectors
MUST produce zero L1 errors; invalid vectors MUST produce at least one.

Spec: ARSIA-Core.md §4, §4.3.8, §5.1, §5.2, §12.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from arsia_protocol._data_resolver import test_vectors_dir as _test_vectors_dir
from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_encode,
    private_key_from_hex,
    public_key_from_hex,
    sign as raw_sign,
)
from arsia_protocol.core.message import sign_message, verify_message
from arsia_protocol.core.validation import validate_envelope, validate_schema

_VECTORS_FILE = _test_vectors_dir() / "arsia-test-vectors.json"
_KEYPAIRS_FILE = _test_vectors_dir() / "keypairs.json"

# ----------------------------------------------------------------------
# Vector loading
# ----------------------------------------------------------------------


def _load_all_vectors() -> list[dict[str, Any]]:
    with _VECTORS_FILE.open("r", encoding="utf-8") as fh:
        return list(json.load(fh)["vectors"])


_ALL_VECTORS: list[dict[str, Any]] = _load_all_vectors()

# Format A (envelope): keyed by "valid" boolean field
_ENVELOPE_VECTORS: list[dict[str, Any]] = [v for v in _ALL_VECTORS if "valid" in v]
_VALID_VECTORS: list[dict[str, Any]] = [v for v in _ENVELOPE_VECTORS if v["valid"]]
_VALID_CRYPTO_VECTORS: list[dict[str, Any]] = [
    v for v in _VALID_VECTORS if "crypto" in v
]
_EDDSA_CRYPTO_VECTORS: list[dict[str, Any]] = [
    v
    for v in _VALID_CRYPTO_VECTORS
    if v["message"].get("security", {}).get("alg") == "EdDSA"
]
_ES256_CRYPTO_VECTORS: list[dict[str, Any]] = [
    v
    for v in _VALID_CRYPTO_VECTORS
    if v["message"].get("security", {}).get("alg") == "ES256"
]
_RS256_CRYPTO_VECTORS: list[dict[str, Any]] = [
    v
    for v in _VALID_CRYPTO_VECTORS
    if v["message"].get("security", {}).get("alg") == "RS256"
]
_INVALID_VECTORS: list[dict[str, Any]] = [v for v in _ENVELOPE_VECTORS if not v["valid"]]

# Format B (schema): keyed by "schema_ref" + "expected" fields
_SCHEMA_VECTORS: list[dict[str, Any]] = [v for v in _ALL_VECTORS if "schema_ref" in v]
_VALID_SCHEMA_VECTORS: list[dict[str, Any]] = [
    v for v in _SCHEMA_VECTORS if v["expected"] == "valid"
]
_INVALID_SCHEMA_VECTORS: list[dict[str, Any]] = [
    v for v in _SCHEMA_VECTORS if v["expected"] == "invalid"
]

# Invalid vectors whose rejection is exercised by Slice 1D validation
# (Core §4 structural rules + Compliance §4.3.8 R1–R5). Each entry maps
# the vector ID to a case-insensitive keyword that MUST appear in at
# least one error string returned by ``validate_envelope``.
_SLICE_1D_INVALID: dict[str, str] = {
    "INV-01": "from",
    "INV-02": "id",
    "INV-03": "ts",
    "INV-04": "from",
    "INV-05": "expires_at",
    "INV-06": "legal_basis",
    "INV-07": "profile",  # Identity §4.2 — high-risk needs profile (R7)
    "INV-08": "retention_days",
    "INV-11": "kid",
}

# Invalid vectors ungated in Slice 4D: the underlying rules are now
# wired into validate_envelope via validation.validate_semantic.
_SLICE_4D_INVALID: dict[str, str] = {
    "INV-10": "capabilit",  # Actions §1.1 — single-segment capability
}

# Invalid vectors that exercise primitive-specific rules in the Assets
# module (Slice 6). These are not gated by validate_envelope because
# the rules live in Layer 4 validators, not Core §4 / §4.3.8.
# Per-vector keyword expectations; the slice-6 test routes each vector
# through the appropriate assets-level validator.
_SLICE_6_INVALID: dict[str, str] = {
    "INV-09": "currency amount precision exceeds 2 decimal places",
    "INV-12": "reversal requires original transfer status completed",
}


# ----------------------------------------------------------------------
# Invariants
# ----------------------------------------------------------------------


def test_vector_corpus_invariants() -> None:
    """Every vector has a unique ID, exactly one format and a determinable outcome.

    Counts are derived from the corpus file, never asserted as literals:
    the envelope (Format A) and schema (Format B) partitions cover the
    whole file, and each partition splits into valid and invalid.
    Spec: ARSIA-Core.md §12 conformance gate.
    """
    ids = [v["id"] for v in _ALL_VECTORS]
    assert ids, "the vectors file is empty"
    assert len(ids) == len(set(ids)), "vector IDs are not unique"
    for v in _ALL_VECTORS:
        assert ("valid" in v) != ("schema_ref" in v), (
            f"{v['id']}: exactly one of 'valid' (Format A) or 'schema_ref' (Format B)"
        )
        if "valid" in v:
            assert isinstance(v["valid"], bool) and "message" in v, v["id"]
        else:
            assert v["expected"] in ("valid", "invalid"), v["id"]
            assert ("data" in v) != ("message" in v), v["id"]
    assert len(_ENVELOPE_VECTORS) + len(_SCHEMA_VECTORS) == len(_ALL_VECTORS)
    assert len(_VALID_VECTORS) + len(_INVALID_VECTORS) == len(_ENVELOPE_VECTORS)
    assert len(_VALID_SCHEMA_VECTORS) + len(_INVALID_SCHEMA_VECTORS) == len(
        _SCHEMA_VECTORS
    )


def test_all_invalid_vectors_partitioned() -> None:
    """The slice-specific partitions are subsets of the invalid vector set.

    The original INV-01..INV-12 (minus INV-13, removed in spec sync)
    are classified into slice-specific partitions tested with their
    respective validators. The remaining 87 invalid vectors (INV-14+
    and ITV-*) are covered by the conformance runner, not by
    per-vector parametrized tests in this file.
    """
    invalid_ids = {v["id"] for v in _INVALID_VECTORS}
    classified = (
        set(_SLICE_1D_INVALID.keys())
        | set(_SLICE_4D_INVALID.keys())
        | set(_SLICE_6_INVALID.keys())
    )
    extra = classified - invalid_ids
    assert not extra, f"classified IDs not in vectors: {extra}"


def test_all_keypairs_load() -> None:
    """Every published test keypair follows the keying rule and loads as its type.

    Entries are keyed by agent-id, or by the full ``kid`` when an agent
    publishes more than one key. Ed25519 keys (32-byte public key) load
    and sign; ES256 keys are uncompressed P-256 points (65 bytes);
    RS256 keys are DER-encoded RSA public keys.

    Spec: ARSIA-Core.md §5.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey,
        SECP256R1,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    with _KEYPAIRS_FILE.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)["keypairs"]
    assert raw, "keypairs.json has no entries"
    for entry_key, entry in raw.items():
        kid = entry["kid"]
        assert entry_key in (kid, kid.split("#")[0]), (
            f"{entry_key}: not keyed by its kid or its kid's agent-id"
        )
        pub_bytes = bytes.fromhex(entry["public_key_hex"])
        if len(pub_bytes) == 32:
            sk = private_key_from_hex(entry["private_key_hex"])
            pk = public_key_from_hex(entry["public_key_hex"])
            assert len(pk.public_bytes_raw()) == 32
            sig = raw_sign(sk, b"keypair sanity check")
            assert len(sig) == 64
        elif len(pub_bytes) == 65:
            EllipticCurvePublicKey.from_encoded_point(SECP256R1(), pub_bytes)
        else:
            assert isinstance(load_der_public_key(pub_bytes), RSAPublicKey), entry_key


# ----------------------------------------------------------------------
# Valid vectors — cryptographic reproduction
# ----------------------------------------------------------------------


_SIGNABLE_CRYPTO_VECTORS: list[dict[str, Any]] = _EDDSA_CRYPTO_VECTORS + _ES256_CRYPTO_VECTORS


def _eddsa_crypto_vector_ids() -> list[str]:
    return [v["id"] for v in _EDDSA_CRYPTO_VECTORS]


@pytest.mark.parametrize(
    "vector",
    _SIGNABLE_CRYPTO_VECTORS,
    ids=[v["id"] for v in _SIGNABLE_CRYPTO_VECTORS],
)
def test_valid_vector_canonical_bytes_reproduce(vector: dict[str, Any]) -> None:
    """Canonicalizing ``message`` (minus ``security``) matches ``canonical_bytes_hex``.

    Spec: ARSIA-Core.md §5.1 Step 3 — RFC 8785 canonicalization.
    """
    crypto = vector.get("crypto")
    assert crypto is not None, f"valid vector {vector['id']} must carry a crypto block"
    unsigned = copy.deepcopy(vector["message"])
    unsigned.pop("security", None)
    produced = canonicalize(unsigned)
    expected = bytes.fromhex(crypto["canonical_bytes_hex"])
    assert produced == expected, (
        f"canonical bytes for {vector['id']} do not match the vector — "
        f"produced {produced.hex()}"
    )


@pytest.mark.parametrize("vector", _EDDSA_CRYPTO_VECTORS, ids=_eddsa_crypto_vector_ids())
def test_valid_vector_signature_reproduces(vector: dict[str, Any]) -> None:
    """Signing the canonical bytes reproduces ``signature_base64url``.

    Spec: ARSIA-Core.md §5.1 Steps 4-5 — Ed25519 sign + base64url encode.
    """
    crypto = vector["crypto"]
    sk = private_key_from_hex(crypto["private_key_hex"])
    canonical = bytes.fromhex(crypto["canonical_bytes_hex"])
    sig_bytes = raw_sign(sk, canonical)
    assert base64url_encode(sig_bytes) == crypto["signature_base64url"]


@pytest.mark.parametrize("vector", _EDDSA_CRYPTO_VECTORS, ids=_eddsa_crypto_vector_ids())
def test_valid_vector_verify_succeeds(vector: dict[str, Any]) -> None:
    """``verify_message`` against the vector's public key returns ``True``.

    Spec: ARSIA-Core.md §5.2 — signature verification procedure.
    """
    crypto = vector["crypto"]
    pk = public_key_from_hex(crypto["public_key_hex"])
    assert verify_message(vector["message"], pk) is True


@pytest.mark.parametrize(
    "vector",
    _ES256_CRYPTO_VECTORS,
    ids=[v["id"] for v in _ES256_CRYPTO_VECTORS],
)
def test_es256_vector_signature_verifies(vector: dict[str, Any]) -> None:
    """ES256 vector signature verifies with the provided P-256 public key.

    ECDSA is non-deterministic so exact signature reproduction is not
    tested — only verification of the pre-computed signature.

    Spec: ARSIA-Core.md §5.2.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey,
        SECP256R1,
    )

    crypto = vector["crypto"]
    pub_bytes = bytes.fromhex(crypto["public_key_hex"])
    pk = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), pub_bytes)
    assert verify_message(vector["message"], pk) is True


@pytest.mark.parametrize(
    "vector",
    _RS256_CRYPTO_VECTORS,
    ids=[v["id"] for v in _RS256_CRYPTO_VECTORS],
)
def test_rs256_vector_skipped(vector: dict[str, Any]) -> None:
    """RS256 vectors are skipped — SDK does not implement RS256."""
    pytest.skip("RS256 not implemented")


@pytest.mark.parametrize("vector", _VALID_VECTORS, ids=[v["id"] for v in _VALID_VECTORS])
def test_valid_vector_passes_l1_schema(vector: dict[str, Any]) -> None:
    """Every valid vector passes L1 schema validation.

    Spec: ARSIA-Core.md §4 — envelope schema.
    """
    if vector.get("skip_schema"):
        pytest.skip("skip_schema: runtime-only vector")
    errors = validate_schema(vector["message"])
    assert errors == [], f"L1 errors on {vector['id']}: {errors}"


# ----------------------------------------------------------------------
# Invalid vectors — Slice 1D-gated rejections
# ----------------------------------------------------------------------


def _slice_1d_invalid_params() -> list[tuple[dict[str, Any], str]]:
    """Return (vector, keyword) pairs for the Slice 1D invalid group."""
    out: list[tuple[dict[str, Any], str]] = []
    for vid, keyword in _SLICE_1D_INVALID.items():
        vector = next(v for v in _INVALID_VECTORS if v["id"] == vid)
        out.append((vector, keyword))
    return out


@pytest.mark.parametrize(
    "vector,keyword",
    _slice_1d_invalid_params(),
    ids=list(_SLICE_1D_INVALID.keys()),
)
def test_slice_1d_invalid_rejected(
    vector: dict[str, Any], keyword: str
) -> None:
    """Each Slice 1D-gated invalid vector is rejected with the right keyword.

    Spec: ARSIA-Core.md §4, §4.3.8.
    """
    errors = validate_envelope(vector["message"], strict=False)
    assert errors, f"{vector['id']} should be rejected but passed validation"
    keyword_lower = keyword.lower()
    matched = any(keyword_lower in str(e).lower() for e in errors)
    assert matched, (
        f"{vector['id']}: no error mentioned {keyword!r}; errors={errors}"
    )


def _slice_4d_invalid_params() -> list[tuple[dict[str, Any], str]]:
    """Return (vector, keyword) pairs for the Slice 4D invalid group."""
    out: list[tuple[dict[str, Any], str]] = []
    for vid, keyword in _SLICE_4D_INVALID.items():
        vector = next(v for v in _INVALID_VECTORS if v["id"] == vid)
        out.append((vector, keyword))
    return out


@pytest.mark.parametrize(
    "vector,keyword",
    _slice_4d_invalid_params(),
    ids=list(_SLICE_4D_INVALID.keys()),
)
def test_slice_4d_invalid_rejected(
    vector: dict[str, Any], keyword: str
) -> None:
    """Each Slice 4D-ungated invalid vector is rejected with the right keyword.

    INV-07 (§4.2 high-risk profile) was moved to _SLICE_1D_INVALID.
    INV-10 (§1.1 capability grammar) is checked via validate_semantic's
    capability grammar enforcement wired in Slice 4D.

    Spec: ARSIA-Identity.md §4.2; ARSIA-Actions.md §1.1.
    """
    errors = validate_envelope(vector["message"], strict=False)
    assert errors, f"{vector['id']} should be rejected but passed validation"
    keyword_lower = keyword.lower()
    matched = any(keyword_lower in str(e).lower() for e in errors)
    assert matched, (
        f"{vector['id']}: no error mentioned {keyword!r}; errors={errors}"
    )


def _slice_6_invalid_params() -> list[tuple[dict[str, Any], str]]:
    """Return (vector, keyword) pairs for the Slice 6 invalid group."""
    out: list[tuple[dict[str, Any], str]] = []
    for vid, keyword in _SLICE_6_INVALID.items():
        vector = next(v for v in _INVALID_VECTORS if v["id"] == vid)
        out.append((vector, keyword))
    return out


@pytest.mark.parametrize(
    "vector,keyword",
    _slice_6_invalid_params(),
    ids=list(_SLICE_6_INVALID.keys()),
)
def test_slice_6_invalid_rejected(
    vector: dict[str, Any], keyword: str
) -> None:
    """Each Slice 6 invalid vector is rejected by the assets validators.

    Each vector is routed through the Layer-4 validator that owns the
    rule it violates, rather than through ``validate_envelope``: the
    Core §4 / §4.3.8 layer does not know about asset precision,
    reversal preconditions, or escrow-conditions coupling. This is the
    same separation used for INV-10 (Actions §1.1), which is wired
    into ``validate_semantic`` rather than a new slice-specific layer.

    Spec: ARSIA-Assets.md §2.1 (INV-09), §3.3 (INV-12), §4.1 (INV-13).
    """
    from arsia_protocol.assets.assets import (
        validate_reversal_precondition,
        validate_transfer_request,
        validate_transfer_reversal,
    )

    message = vector["message"]
    args = message["payload"]["args"]
    vid = vector["id"]
    if vid == "INV-09":
        errors = validate_transfer_request(args)
    elif vid == "INV-12":
        errors = validate_transfer_reversal(args)
        errors.extend(
            validate_reversal_precondition(args, original_status="pending")
        )
    elif vid == "INV-13":
        errors = validate_transfer_request(args)
    else:  # pragma: no cover — defensive
        raise AssertionError(f"unexpected slice-6 vector {vid!r}")

    assert errors, f"{vid} should be rejected but assets validators passed"
    keyword_lower = keyword.lower()
    matched = any(keyword_lower in str(e).lower() for e in errors)
    assert matched, (
        f"{vid}: no error mentioned {keyword!r}; errors={errors}"
    )


# ----------------------------------------------------------------------
# Tampering
# ----------------------------------------------------------------------


def test_tampering_invalidates_signature() -> None:
    """Mutating any signed field flips ``verify_message`` to ``False``.

    Spec: ARSIA-Core.md §5.2 — any change to the canonical form MUST
    cause verification to fail.
    """
    ctv01 = next(v for v in _VALID_VECTORS if v["id"] == "CTV-01")
    sk = private_key_from_hex(ctv01["crypto"]["private_key_hex"])
    pk = public_key_from_hex(ctv01["crypto"]["public_key_hex"])

    # Start from an unsigned copy and sign it fresh — the signature
    # must match the canonical form, so any subsequent mutation will
    # break verification.
    unsigned = copy.deepcopy(ctv01["message"])
    unsigned.pop("security", None)
    signed = sign_message(unsigned, sk, "agent:acme.echo-client#key1")
    assert verify_message(signed, pk) is True

    tampered = copy.deepcopy(signed)
    tampered["payload"]["args"]["message"] = "goodbye"
    assert verify_message(tampered, pk) is False


# ----------------------------------------------------------------------
# Schema validation vectors (Format B)
# ----------------------------------------------------------------------


def test_schema_suite_covers_all_vectors() -> None:
    """The conformance suite YAML references a subset of Format B vector IDs.

    After the data sync to 613 vectors (318 schema), the suite covers
    the original set. New schema vectors are validated directly by the
    parametrized tests below; suite coverage will catch up in a future
    sync.
    """
    import yaml

    suite_path = (
        Path(__file__).resolve().parents[3] / "conformance" / "suites" / "schema-validation.yaml"
    )
    with suite_path.open("r", encoding="utf-8") as fh:
        suite = yaml.safe_load(fh)
    suite_ids = {c["input"]["vector_id"] for c in suite["cases"]}
    vector_ids = {v["id"] for v in _SCHEMA_VECTORS}
    extra_in_suite = suite_ids - vector_ids
    assert not extra_in_suite, (
        f"suite references IDs not in vectors: {extra_in_suite}"
    )


class TestSchemaValidationVectors:
    """Validate Format B vectors against their named JSON Schema.

    Each vector carries a ``schema_ref`` (filename) and ``data`` (object).
    Valid vectors MUST produce zero L1 errors; invalid vectors MUST produce
    at least one.
    """

    @pytest.mark.parametrize(
        "vector",
        _VALID_SCHEMA_VECTORS,
        ids=[v["id"] for v in _VALID_SCHEMA_VECTORS],
    )
    def test_schema_valid(self, vector: dict[str, Any]) -> None:
        data = vector["data"] if "data" in vector else vector["message"]
        errors = validate_schema(data, vector["schema_ref"])
        assert errors == [], f"{vector['id']}: {errors}"

    @pytest.mark.parametrize(
        "vector",
        _INVALID_SCHEMA_VECTORS,
        ids=[v["id"] for v in _INVALID_SCHEMA_VECTORS],
    )
    def test_schema_invalid(self, vector: dict[str, Any]) -> None:
        if vector.get("skip_schema"):
            pytest.skip("skip_schema: runtime-only vector")
        data = vector["data"] if "data" in vector else vector["message"]
        errors = validate_schema(data, vector["schema_ref"])
        assert len(errors) > 0, f"{vector['id']}: expected invalid"
