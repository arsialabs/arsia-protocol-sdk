# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``actions`` category.

Dispatches on ``input.operation``. Every operation maps to a pure,
offline entry point from :mod:`arsia_protocol.actions`:

- ``validate_capability`` — §1.1 grammar + reserved-prefix check.
- ``match_capability`` — §1.2 single-entry matching rule.
- ``match_capabilities`` — §1.2 multi-entry matching.
- ``downgrade_capabilities`` — §1.3 authorised subset.
- ``is_reserved_capability`` — §1.4 membership check.
- ``get_risk_classification`` — §2.2 five-bucket mapping.
- ``validate_action_descriptor`` — §2.1 L1 schema validation.
- ``validate_explanation`` — §5.2 L1 schema validation.
- ``is_valid_transition`` — §4.1 state-machine edge check.

Cases whose operations map to pure SDK functions run directly.
Remaining HTTP-dependent spec tests in Actions §6 are marked
``skip_until: http-harness``.
"""

from __future__ import annotations

from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _check_errors(
    errors: list[Any],
    expected: dict[str, Any],
) -> tuple[TestStatus, str | None]:
    """Compare a validator's error list to ``expected.valid`` / ``error_contains``.

    Shared helper used by the schema / grammar / descriptor /
    explanation operations. Mirrors the shape of the compliance
    executor so suite authors see the same idiom across categories.
    """
    want_valid = bool(expected.get("valid", True))
    if want_valid:
        if errors:
            return "fail", f"expected valid but got errors: {errors}"
        return "pass", None
    if not errors:
        return "fail", "expected rejection but validation passed"
    keyword = expected.get("error_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in str(e).lower() for e in errors):
            return "fail", f"no error mentioned {keyword!r}; errors={errors}"
    return "pass", None


def _run_validate_capability(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import validate_capability

    capability = case.input.get("capability")
    if not isinstance(capability, str):
        return "error", "input.capability must be a string"
    errors = validate_capability(capability)
    return _check_errors(errors, case.expected)


def _run_match_capability(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import match_capability

    scope = case.input.get("scope_entry")
    requested = case.input.get("requested")
    if not isinstance(scope, str) or not isinstance(requested, str):
        return "error", "input.scope_entry and input.requested must be strings"
    got = match_capability(scope, requested)
    want = bool(case.expected.get("matches"))
    if got != want:
        return "fail", f"match_capability({scope!r}, {requested!r}) = {got}, want {want}"
    return "pass", None


def _run_match_capabilities(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import find_unsatisfied_capabilities, match_capabilities

    scope = case.input.get("scope")
    requested = case.input.get("requested")
    if not isinstance(scope, list) or not isinstance(requested, list):
        return "error", "input.scope and input.requested must be lists"
    scope_list = [str(s) for s in scope]
    requested_list = [str(r) for r in requested]
    got = match_capabilities(scope_list, requested_list)
    want = bool(case.expected.get("matches"))
    if got != want:
        gaps = find_unsatisfied_capabilities(scope_list, requested_list)
        return (
            "fail",
            f"match_capabilities = {got}, want {want}; unsatisfied={gaps}",
        )
    return "pass", None


def _run_downgrade_capabilities(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import downgrade_capabilities

    requested = case.input.get("requested")
    scope = case.input.get("scope")
    if not isinstance(requested, list) or not isinstance(scope, list):
        return "error", "input.requested and input.scope must be lists"
    got = downgrade_capabilities([str(r) for r in requested], [str(s) for s in scope])
    want = case.expected.get("effective")
    if not isinstance(want, list):
        return "error", "expected.effective must be a list"
    if got != [str(w) for w in want]:
        return "fail", f"downgrade_capabilities = {got}, want {want}"
    return "pass", None


def _run_is_reserved_capability(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import is_reserved_capability

    capability = case.input.get("capability")
    if not isinstance(capability, str):
        return "error", "input.capability must be a string"
    got = is_reserved_capability(capability)
    want = bool(case.expected.get("reserved"))
    if got != want:
        return "fail", f"is_reserved_capability({capability!r}) = {got}, want {want}"
    return "pass", None


def _run_get_risk_classification(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import get_risk_classification

    risk_level = case.input.get("risk_level")
    if not isinstance(risk_level, int) or isinstance(risk_level, bool):
        return "error", "input.risk_level must be an integer"
    want_raises = bool(case.expected.get("raises", False))
    try:
        got = get_risk_classification(risk_level)
    except ValueError as exc:
        if want_raises:
            return "pass", None
        return "fail", f"get_risk_classification raised unexpectedly: {exc}"
    if want_raises:
        return "fail", f"expected ValueError but got {got!r}"
    want = case.expected.get("classification")
    if got != want:
        return "fail", f"classification = {got!r}, want {want!r}"
    return "pass", None


def _run_validate_action_descriptor(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import validate_action_descriptor

    descriptor = case.input.get("descriptor")
    if not isinstance(descriptor, dict):
        return "error", "input.descriptor must be an object"
    errors = validate_action_descriptor(descriptor)
    return _check_errors(errors, case.expected)


def _run_validate_explanation(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import validate_explanation

    explanation = case.input.get("explanation")
    if not isinstance(explanation, dict):
        return "error", "input.explanation must be an object"
    errors = validate_explanation(explanation)
    return _check_errors(errors, case.expected)


def _run_is_valid_transition(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.actions.actions import is_valid_transition

    from_state = case.input.get("from_state")
    to_state = case.input.get("to_state")
    if not isinstance(from_state, str) or not isinstance(to_state, str):
        return "error", "input.from_state and input.to_state must be strings"
    got = is_valid_transition(from_state, to_state)
    want = bool(case.expected.get("valid"))
    if got != want:
        return (
            "fail",
            f"is_valid_transition({from_state!r}, {to_state!r}) = {got}, want {want}",
        )
    return "pass", None


_OPERATIONS = {
    "validate_capability": _run_validate_capability,
    "match_capability": _run_match_capability,
    "match_capabilities": _run_match_capabilities,
    "downgrade_capabilities": _run_downgrade_capabilities,
    "is_reserved_capability": _run_is_reserved_capability,
    "get_risk_classification": _run_get_risk_classification,
    "validate_action_descriptor": _run_validate_action_descriptor,
    "validate_explanation": _run_validate_explanation,
    "is_valid_transition": _run_is_valid_transition,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    """Dispatch an ``actions`` case to its handler.

    Unknown operations surface as ``error`` results so a typo in a
    suite file cannot silently pass.
    """
    try:
        import arsia_protocol.actions.actions  # noqa: F401
    except ImportError as exc:  # pragma: no cover - defensive
        return "error", f"arsia_protocol.actions import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for actions cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown actions operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
