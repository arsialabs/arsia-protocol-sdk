# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Conformance test vectors from ``shared/test-vectors/``.

Every test here derives its cases from the bundled corpus; no vector ID
list or count is hard-coded. The corpus has two formats:

- **Format A (envelope):** ``message`` + ``valid``.
- **Format B (schema):** ``schema_ref`` + ``expected``, with either
  ``data`` (schema-ref) or ``message`` (hybrid).

The tests assert:

1. Corpus invariants: unique IDs, exactly one format per vector, a
   determinable outcome, and published keypairs that follow the keying
   rule and load as their key type.
2. Every vector passes the layered check of ``arsia vectors run``
   (:func:`arsia_protocol._vectors.run_vector`): a valid vector is not
   rejected by any layer, and an invalid vector is rejected by at least
   one. A vector no layer can decide (e.g. a runtime-only constraint) is
   reported as skipped with its reasons.
3. For every vector with a ``crypto`` block, canonicalizing ``message``
   (minus ``security``) reproduces ``crypto.canonical_bytes_hex``. For
   valid ones, the signature also verifies (EdDSA, ES256) and, for EdDSA,
   signing reproduces ``crypto.signature_base64url``; RS256 is skipped.
   This mirrors the protocol's ``validate_vectors.py --check-crypto``.
4. L1 schema validation: valid vectors produce no errors, and invalid
   Format B vectors produce at least one; ``skip_schema`` vectors are
   skipped.

Spec: ARSIA-Core.md §4, §4.3.8, §5.1, §5.2, §12.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from arsia_protocol._data_resolver import test_vectors_dir as _test_vectors_dir
from arsia_protocol._vectors import is_expected_valid, run_vector
from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_encode,
    private_key_from_hex,
    public_key_from_hex,
    sign as raw_sign,
)
from arsia_protocol.core.message import sign_message, verify_message
from arsia_protocol.core.validation import validate_schema

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
_INVALID_VECTORS: list[dict[str, Any]] = [v for v in _ENVELOPE_VECTORS if not v["valid"]]

# Vectors with a ``crypto`` block, in any format (message-only or hybrid)
_CRYPTO_VECTORS: list[dict[str, Any]] = [v for v in _ALL_VECTORS if "crypto" in v]
_VALID_CRYPTO_VECTORS: list[dict[str, Any]] = [
    v for v in _CRYPTO_VECTORS if is_expected_valid(v)
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

# Format B (schema): keyed by "schema_ref" + "expected" fields
_SCHEMA_VECTORS: list[dict[str, Any]] = [v for v in _ALL_VECTORS if "schema_ref" in v]
_VALID_SCHEMA_VECTORS: list[dict[str, Any]] = [
    v for v in _SCHEMA_VECTORS if v["expected"] == "valid"
]
_INVALID_SCHEMA_VECTORS: list[dict[str, Any]] = [
    v for v in _SCHEMA_VECTORS if v["expected"] == "invalid"
]

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
# Every vector — the layered check of ``arsia vectors run``
# ----------------------------------------------------------------------


with _KEYPAIRS_FILE.open("r", encoding="utf-8") as _fh:
    _KEYPAIRS: dict[str, dict[str, Any]] = json.load(_fh)["keypairs"]


@pytest.mark.parametrize("vector", _ALL_VECTORS, ids=[v["id"] for v in _ALL_VECTORS])
def test_vector_passes_layered_check(vector: dict[str, Any]) -> None:
    """The vector's expected outcome holds under schema, semantic and signature checks.

    A valid vector must not be rejected by any layer; an invalid vector
    must be rejected by at least one. A vector that no layer rejects but
    one layer skips (e.g. a runtime-only constraint) is skipped with the
    layers' reasons.

    Spec: ARSIA-Core.md §4, §5.2, §12.
    """
    result = run_vector(vector, _KEYPAIRS)
    if result.result == "FAIL":
        detail = result.reasons("REJECT") if result.expected_valid else ["no layer rejects it"]
        pytest.fail(f"{vector['id']}: " + "; ".join(detail))
    if result.result == "SKIP":
        pytest.skip("; ".join(result.reasons("SKIP")))


# ----------------------------------------------------------------------
# Vectors with a ``crypto`` block — cryptographic reproduction
# ----------------------------------------------------------------------


def _eddsa_crypto_vector_ids() -> list[str]:
    return [v["id"] for v in _EDDSA_CRYPTO_VECTORS]


@pytest.mark.parametrize(
    "vector",
    _CRYPTO_VECTORS,
    ids=[v["id"] for v in _CRYPTO_VECTORS],
)
def test_crypto_vector_canonical_bytes_reproduce(vector: dict[str, Any]) -> None:
    """Canonicalizing ``message`` (minus ``security``) matches ``canonical_bytes_hex``.

    Checked for every vector with a ``crypto`` block, valid or invalid.
    Spec: ARSIA-Core.md §5.1 Step 3 — RFC 8785 canonicalization.
    """
    crypto = vector["crypto"]
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
    """RS256 vectors are skipped — the SDK does not verify RS256."""
    pytest.skip("RS256 is not verified by the SDK (Core §5.1: MAY)")


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

    The suite is a deliberate fixed subset; every Format B vector is
    validated by the parametrized tests below and by
    ``test_vector_passes_layered_check``.
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
