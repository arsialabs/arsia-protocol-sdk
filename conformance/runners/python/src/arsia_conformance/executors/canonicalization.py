# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``canonicalization`` category.

Each case references a test vector by ID. The executor pulls the
envelope and the expected canonical bytes from the same vector, strips
the ``security`` field, runs RFC 8785 canonicalization via the SDK, and
compares hex output. Spec: ARSIA-Core §5.1 Step 3.
"""

from __future__ import annotations

import copy
from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        from arsia_protocol.hazmat.canonicalization import canonicalize
    except ImportError as exc:  # pragma: no cover - SDK missing
        return "error", f"arsia_protocol import failed: {exc}"

    vector_id = case.input.get("vector_id")
    if not isinstance(vector_id, str):
        return "error", "input.vector_id is required for canonicalization cases"
    try:
        vector = context.get_vector(vector_id)
    except KeyError as exc:
        return "error", str(exc)

    envelope: Any = vector.get("message")
    if not isinstance(envelope, dict):
        return "error", f"{vector_id}: vector.message is not an object"
    crypto = vector.get("crypto")
    if not isinstance(crypto, dict):
        return "error", f"{vector_id}: vector.crypto block is missing"

    unsigned = copy.deepcopy(envelope)
    unsigned.pop("security", None)
    try:
        produced = canonicalize(unsigned)
    except Exception as exc:  # pragma: no cover - defensive
        return "error", f"canonicalize raised: {exc}"

    expected_field = case.expected.get("match_vector_field", "canonical_bytes_hex")
    expected_hex = crypto.get(expected_field)
    if not isinstance(expected_hex, str):
        return "error", f"{vector_id}: vector.crypto.{expected_field} missing"

    if produced.hex() != expected_hex:
        return (
            "fail",
            f"canonical bytes differ for {vector_id}: produced {produced.hex()[:80]}…",
        )
    return "pass", None


__all__ = ["execute"]
