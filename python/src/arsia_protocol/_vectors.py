# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Evaluate the bundled conformance test vectors.

Used by ``arsia vectors run`` and by the vector tests. Every vector is
checked in layers, and an overall result is derived from the layers.
Nothing here depends on vector IDs: the classification comes from the
corpus itself.

Format is chosen by key presence: ``schema_ref`` + ``data`` is a
schema-ref vector (the envelope, if any, is ``data``); ``schema_ref`` +
``message`` is a hybrid vector; otherwise the vector is message-only.

Layers:

- **schema** — JSON Schema (L1): the vector's ``schema_ref``, or the
  message schema for message-only vectors. A vector with
  ``skip_schema: true`` reports this layer as SKIP with its
  ``skip_reason``.
- **semantic** — the SDK's L2 rules (:func:`validate_semantic`), for
  message envelopes that L1 did not reject, including ``skip_schema``
  vectors.
- **signature** — when the envelope carries ``security.sig``: the key
  comes from the vector's ``crypto`` block, otherwise from the published
  ``keypairs.json`` (entries keyed by agent-id, or by the full ``kid``
  when an agent publishes more than one key). EdDSA and ES256 are
  verified; RS256 is reported as SKIP because the SDK does not verify
  it (Core §5.1: MAY). A ``kid`` that cannot be resolved is a rejection
  (Core §5.2 Step 2). A valid request, response, pending_approval or
  approval_decision envelope without a signature is a failure
  (Core §5.2).

Overall result:

- valid vector — FAIL if any layer rejects it, otherwise SKIP if any
  layer was skipped, otherwise PASS;
- invalid vector — PASS if any layer rejects it, otherwise SKIP if any
  layer was skipped, otherwise FAIL.

A SKIP is never counted as a PASS. ``expected_error`` is reported but
never matched.

Spec: ARSIA-Core.md §4, §4.3.5, §5.1, §5.2, §12.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arsia_protocol import _data_resolver
from arsia_protocol.core.message import verify_message
from arsia_protocol.core.validation import validate_schema, validate_semantic
from arsia_protocol.hazmat.primitives.ed25519 import public_key_from_hex

LayerStatus = Literal["OK", "REJECT", "SKIP"]
Result = Literal["PASS", "FAIL", "SKIP"]

# Core §5.2: receivers MUST verify signatures on these intents.
_SIGNATURE_REQUIRED_INTENTS = frozenset(
    {"request", "response", "pending_approval", "approval_decision"}
)


@dataclass(frozen=True)
class Layer:
    """Outcome of one check applied to a vector."""

    name: str
    status: LayerStatus
    detail: str = ""


@dataclass(frozen=True)
class VectorResult:
    """Outcome of evaluating one vector."""

    vector_id: str
    vector_format: str
    expected_valid: bool
    result: Result
    layers: tuple[Layer, ...]
    expected_error: str | None

    def reasons(self, status: LayerStatus) -> list[str]:
        """Return ``"<layer>: <detail>"`` for every layer with ``status``."""
        return [
            f"{layer.name}: {layer.detail}"
            for layer in self.layers
            if layer.status == status
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector_id": self.vector_id,
            "format": self.vector_format,
            "expected": "valid" if self.expected_valid else "invalid",
            "result": self.result,
            "expected_error": self.expected_error,
            "layers": [
                {
                    "name": layer.name,
                    "status": layer.status,
                    "detail": layer.detail or None,
                }
                for layer in self.layers
            ],
        }


def load_corpus() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Load the bundled vectors and published keypairs."""
    root = _data_resolver.test_vectors_dir()
    vectors = json.loads((root / "arsia-test-vectors.json").read_text(encoding="utf-8"))
    keypairs = json.loads((root / "keypairs.json").read_text(encoding="utf-8"))
    return list(vectors["vectors"]), dict(keypairs["keypairs"])


def vector_format(vector: dict[str, Any]) -> tuple[str, Any, str | None]:
    """Return ``(format, envelope, schema_ref)`` by key presence, never by truthiness."""
    if "schema_ref" in vector and "data" in vector:
        return "schema-ref", vector["data"], vector["schema_ref"]
    if "schema_ref" in vector:
        return "hybrid", vector["message"], vector["schema_ref"]
    return "message-only", vector["message"], None


def is_expected_valid(vector: dict[str, Any]) -> bool:
    """Return the vector's expected outcome (``valid`` or ``expected``)."""
    if isinstance(vector.get("valid"), bool):
        return bool(vector["valid"])
    return vector.get("expected") == "valid"


def resolve_published_key(
    kid: str, keypairs: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """Find the published keypair for ``kid`` under the keying rule.

    Entries are keyed by agent-id, or by the full ``kid`` when an agent
    publishes more than one key. An agent-id entry matches only when its
    own ``kid`` equals ``kid``.
    """
    entry = keypairs.get(kid)
    if entry is not None:
        return entry
    entry = keypairs.get(kid.split("#", 1)[0])
    if entry is not None and entry.get("kid") == kid:
        return entry
    return None


def _schema_layer(
    vector: dict[str, Any], envelope: Any, schema_ref: str | None
) -> Layer:
    if vector.get("skip_schema"):
        return Layer("schema", "SKIP", str(vector.get("skip_reason") or "skip_schema"))
    errors = (
        validate_schema(envelope, schema_ref)
        if schema_ref
        else validate_schema(envelope)
    )
    if errors:
        return Layer("schema", "REJECT", str(errors[0]))
    return Layer("schema", "OK")


def _semantic_layer(envelope: dict[str, Any]) -> Layer:
    errors = validate_semantic(envelope)
    if errors:
        return Layer("semantic", "REJECT", str(errors[0]))
    return Layer("semantic", "OK")


def _signature_layer(
    vector: dict[str, Any],
    envelope: dict[str, Any],
    keypairs: dict[str, dict[str, Any]],
) -> Layer | None:
    security = envelope.get("security")
    if not (isinstance(security, dict) and "sig" in security):
        return None
    alg = security.get("alg")
    if alg == "RS256":
        return Layer(
            "signature", "SKIP", "RS256 is not verified by the SDK (Core §5.1: MAY)"
        )
    crypto = vector.get("crypto")
    if isinstance(crypto, dict) and "public_key_hex" in crypto:
        public_hex, source = str(crypto["public_key_hex"]), "crypto block"
    else:
        kid = str(security.get("kid", ""))
        entry = resolve_published_key(kid, keypairs)
        if entry is None:
            return Layer(
                "signature",
                "REJECT",
                f"no published key for kid {kid!r} (Core §5.2 Step 2)",
            )
        public_hex, source = str(entry["public_key_hex"]), "keypairs.json"
    public_key: Ed25519PublicKey | ec.EllipticCurvePublicKey
    try:
        if alg == "EdDSA":
            public_key = public_key_from_hex(public_hex)
        elif alg == "ES256":
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), bytes.fromhex(public_hex)
            )
        else:
            return Layer("signature", "REJECT", f"unsupported alg {alg!r}")
    except ValueError as exc:
        return Layer("signature", "REJECT", f"key is not usable for {alg}: {exc}")
    try:
        verified = verify_message(envelope, public_key)
    except KeyError as exc:
        return Layer("signature", "REJECT", str(exc))
    if verified:
        return Layer("signature", "OK", f"verified ({source})")
    return Layer("signature", "REJECT", f"signature does not verify ({source})")


def run_vector(
    vector: dict[str, Any], keypairs: dict[str, dict[str, Any]]
) -> VectorResult:
    """Evaluate one vector; see the module docstring for the rules."""
    fmt, envelope, schema_ref = vector_format(vector)
    expected_valid = is_expected_valid(vector)
    layers: list[Layer] = [_schema_layer(vector, envelope, schema_ref)]
    is_message_envelope = fmt != "schema-ref" and isinstance(envelope, dict)
    if is_message_envelope and layers[0].status != "REJECT":
        layers.append(_semantic_layer(envelope))
    if isinstance(envelope, dict):
        signature = _signature_layer(vector, envelope, keypairs)
        if signature is not None:
            layers.append(signature)
        elif (
            expected_valid
            and is_message_envelope
            and envelope.get("intent") in _SIGNATURE_REQUIRED_INTENTS
        ):
            layers.append(
                Layer(
                    "signature",
                    "REJECT",
                    f"intent {envelope.get('intent')!r} requires a signature (Core §5.2)",
                )
            )
    statuses = {layer.status for layer in layers}
    result: Result
    if expected_valid:
        result = (
            "FAIL" if "REJECT" in statuses else "SKIP" if "SKIP" in statuses else "PASS"
        )
    else:
        result = (
            "PASS" if "REJECT" in statuses else "SKIP" if "SKIP" in statuses else "FAIL"
        )
    return VectorResult(
        vector_id=str(vector["id"]),
        vector_format=fmt,
        expected_valid=expected_valid,
        result=result,
        layers=tuple(layers),
        expected_error=vector.get("expected_error"),
    )


__all__ = [
    "Layer",
    "VectorResult",
    "is_expected_valid",
    "load_corpus",
    "resolve_published_key",
    "run_vector",
    "vector_format",
]
