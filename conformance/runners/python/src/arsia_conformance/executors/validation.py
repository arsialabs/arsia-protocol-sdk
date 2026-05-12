# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``validation`` category.

Dispatches on ``input.operation`` (defaults to ``validate_envelope``):

- ``validate_envelope`` — pulls an envelope from a test vector and
  runs :func:`arsia_protocol.validation.validate_envelope`. Asserts
  ``expected.valid`` and optional ``expected.error_contains``.
- ``validate_identity_consistency`` — calls
  :func:`arsia_protocol.validation.validate_identity_consistency`
  with ``from_agent``, ``kid``, and optional ``identity_agent_id``.
  Asserts ``expected.consistent`` (bool) and optional
  ``expected.warning_contains``.
"""

from __future__ import annotations

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _run_validate_envelope(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.validation import validate_envelope

    vector_id = case.input.get("vector_id")
    if not isinstance(vector_id, str):
        return "error", "input.vector_id is required for validate_envelope"
    try:
        vector = context.get_vector(vector_id)
    except KeyError as exc:
        return "error", str(exc)

    envelope = vector.get("message")
    if not isinstance(envelope, dict):
        return "error", f"{vector_id}: vector.message is not an object"

    want_valid = bool(case.expected.get("valid", True))
    errors = validate_envelope(envelope, strict=False)

    if want_valid:
        if errors:
            return "fail", f"{vector_id}: expected valid but got errors: {errors[:3]}"
        return "pass", None

    if not errors:
        return "fail", f"{vector_id}: expected rejection but envelope passed validation"
    keyword = case.expected.get("error_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in str(e).lower() for e in errors):
            return (
                "fail",
                f"{vector_id}: no error mentioned {keyword!r}; errors={errors}",
            )
    return "pass", None


def _run_validate_identity_consistency(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.validation import check_identity_consistency

    from_agent = case.input.get("from_agent")
    kid = case.input.get("kid")
    if not isinstance(from_agent, str) or not isinstance(kid, str):
        return "error", "input.from_agent and input.kid must be strings"

    identity_agent_id = case.input.get("identity_agent_id")
    if identity_agent_id is not None and not isinstance(identity_agent_id, str):
        return "error", "input.identity_agent_id must be a string or null"

    result = check_identity_consistency(
        from_agent=from_agent, kid=kid, identity_agent_id=identity_agent_id
    )

    want_consistent = case.expected.get("consistent")
    if isinstance(want_consistent, bool) and result.is_consistent != want_consistent:
        return (
            "fail",
            f"consistent: expected {want_consistent}, got {result.is_consistent}; "
            f"warnings={list(result.warnings)}",
        )

    want_count = case.expected.get("warning_count")
    if isinstance(want_count, int):
        if len(result.warnings) != want_count:
            return (
                "fail",
                f"warning_count: expected {want_count}, got {len(result.warnings)}; "
                f"warnings={list(result.warnings)}",
            )

    keyword = case.expected.get("warning_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in w.lower() for w in result.warnings):
            return (
                "fail",
                f"no warning mentioned {keyword!r}; warnings={list(result.warnings)}",
            )

    return "pass", None


_OPERATIONS = {
    "validate_envelope": _run_validate_envelope,
    "validate_identity_consistency": _run_validate_identity_consistency,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.core.validation  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol import failed: {exc}"

    operation = case.input.get("operation", "validate_envelope")
    if not isinstance(operation, str):
        return "error", "input.operation must be a string"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown validation operation: {operation!r}"
    return handler(case, context)


__all__ = ["execute"]
