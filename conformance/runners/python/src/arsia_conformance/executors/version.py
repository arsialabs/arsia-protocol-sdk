# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``version`` category.

Supports ``parse_version``, ``compare_versions``, and ``is_compatible``
from :mod:`arsia_protocol.version`. Operations that expect a rejection
set ``expected.raises: true``.
"""

from __future__ import annotations

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _run_parse_version(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.version import parse_version

    value = case.input.get("value")
    if not isinstance(value, str):
        return "error", "input.value must be a string"
    want_raises = bool(case.expected.get("raises", False))
    try:
        major, minor = parse_version(value)
    except ValueError as exc:
        if want_raises:
            return "pass", None
        return "fail", f"parse_version raised unexpectedly: {exc}"
    if want_raises:
        return "fail", f"expected ValueError but got ({major}, {minor})"

    mismatches: list[str] = []
    if "major" in case.expected and major != case.expected["major"]:
        mismatches.append(f"major: expected {case.expected['major']}, got {major}")
    if "minor" in case.expected and minor != case.expected["minor"]:
        mismatches.append(f"minor: expected {case.expected['minor']}, got {minor}")
    if mismatches:
        return "fail", "; ".join(mismatches)
    return "pass", None


def _run_compare_versions(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.version import compare_versions

    a = case.input.get("a")
    b = case.input.get("b")
    if not isinstance(a, str) or not isinstance(b, str):
        return "error", "input.a and input.b must be strings"
    result = compare_versions(a, b)
    expected = case.expected.get("result")
    if result != expected:
        return "fail", f"expected {expected}, got {result}"
    return "pass", None


def _run_is_compatible(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.version import is_compatible

    our = case.input.get("our_version")
    theirs = case.input.get("their_version")
    their_min = case.input.get("their_min_v")
    if not isinstance(our, str) or not isinstance(theirs, str):
        return "error", "input.our_version and input.their_version must be strings"
    if their_min is not None and not isinstance(their_min, str):
        return "error", "input.their_min_v must be a string when present"
    compatible = is_compatible(our, theirs, their_min)
    expected = case.expected.get("compatible")
    if compatible != expected:
        return "fail", f"expected compatible={expected}, got {compatible}"
    return "pass", None


_OPERATIONS = {
    "parse_version": _run_parse_version,
    "compare_versions": _run_compare_versions,
    "is_compatible": _run_is_compatible,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.core.version  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for version cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown version operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
