# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``identity`` category.

Dispatches on ``input.operation`` (defaults to ``parse_or_validate``):

- ``parse_or_validate`` — takes ``input.agent_id``, asserts parse or
  rejection with optional ``error_contains``.
- ``compare_agent_ids`` — takes ``input.agent_id_a`` and
  ``input.agent_id_b``, parses both, asserts ``expected.equal``.
"""

from __future__ import annotations

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _run_parse_or_validate(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.agent_id import parse_agent_id, validate_agent_id

    agent_id = case.input.get("agent_id")
    if not isinstance(agent_id, str):
        return "error", "input.agent_id must be a string"

    want_valid = bool(case.expected.get("valid", True))
    errors = validate_agent_id(agent_id)

    if want_valid:
        if errors:
            return "fail", f"expected valid but got errors: {errors}"
        want_parsed = case.expected.get("parsed")
        if isinstance(want_parsed, dict):
            parsed = parse_agent_id(agent_id)
            mismatches: list[str] = []
            if "org" in want_parsed and parsed.org != want_parsed["org"]:
                mismatches.append(f"org: expected {want_parsed['org']!r}, got {parsed.org!r}")
            if "name" in want_parsed and parsed.name != want_parsed["name"]:
                mismatches.append(f"name: expected {want_parsed['name']!r}, got {parsed.name!r}")
            if "sub" in want_parsed:
                want_sub = tuple(want_parsed["sub"])
                if parsed.sub != want_sub:
                    mismatches.append(f"sub: expected {list(want_sub)}, got {list(parsed.sub)}")
            if "resource" in want_parsed and parsed.resource != want_parsed["resource"]:
                mismatches.append(
                    f"resource: expected {want_parsed['resource']!r}, got {parsed.resource!r}"
                )
            if mismatches:
                return "fail", "; ".join(mismatches)
        return "pass", None

    if not errors:
        return "fail", f"expected rejection but {agent_id!r} was accepted"
    keyword = case.expected.get("error_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in str(e).lower() for e in errors):
            return "fail", f"no error mentioned {keyword!r}; errors={errors}"
    return "pass", None


def _run_compare_agent_ids(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.agent_id import parse_agent_id

    a = case.input.get("agent_id_a")
    b = case.input.get("agent_id_b")
    if not isinstance(a, str) or not isinstance(b, str):
        return "error", "input.agent_id_a and input.agent_id_b must be strings"

    parsed_a = parse_agent_id(a)
    parsed_b = parse_agent_id(b)
    got_equal = parsed_a == parsed_b

    want_equal = case.expected.get("equal")
    if isinstance(want_equal, bool) and got_equal != want_equal:
        return (
            "fail",
            f"equal: expected {want_equal}, got {got_equal}; "
            f"a={parsed_a.full!r}, b={parsed_b.full!r}",
        )

    return "pass", None


_OPERATIONS = {
    "parse_or_validate": _run_parse_or_validate,
    "compare_agent_ids": _run_compare_agent_ids,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        from arsia_protocol.identity.agent_id import parse_agent_id, validate_agent_id  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol import failed: {exc}"

    operation = case.input.get("operation", "parse_or_validate")
    if not isinstance(operation, str):
        return "error", "input.operation must be a string"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown identity operation: {operation!r}"
    return handler(case, context)


__all__ = ["execute"]
