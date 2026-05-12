# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``schema-validation`` category.

Validates a Format B test vector's ``data`` object against the JSON Schema
named in ``schema_ref``. Valid vectors must produce zero L1 errors; invalid
vectors must produce at least one. Optional ``error_contains`` keyword
matching follows the same pattern as the envelope ``validation`` executor.
"""

from __future__ import annotations

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        from arsia_protocol.core.validation import validate_schema
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol import failed: {exc}"

    vector_id = case.input.get("vector_id")
    if not isinstance(vector_id, str):
        return "error", "input.vector_id is required for schema-validation cases"
    try:
        vector = context.get_vector(vector_id)
    except KeyError as exc:
        return "error", str(exc)

    data = vector.get("data")
    if not isinstance(data, dict):
        return "error", f"{vector_id}: vector.data is not an object"

    schema_ref = vector.get("schema_ref")
    if not isinstance(schema_ref, str):
        return "error", f"{vector_id}: vector.schema_ref is not a string"

    errors = validate_schema(data, schema_ref)
    want_valid = bool(case.expected.get("valid", True))

    if want_valid:
        if errors:
            return "fail", f"{vector_id}: expected valid but got errors: {errors[:3]}"
        return "pass", None

    if not errors:
        return "fail", f"{vector_id}: expected rejection but data passed schema validation"
    keyword = case.expected.get("error_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in str(e).lower() for e in errors):
            return (
                "fail",
                f"{vector_id}: no error mentioned {keyword!r}; errors={errors}",
            )
    return "pass", None


__all__ = ["execute"]
