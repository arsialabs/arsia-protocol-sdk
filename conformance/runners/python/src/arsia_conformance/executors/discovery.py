# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``discovery`` category.

Dispatches on ``input.operation``. Each operation maps to a pure,
offline entry point from :mod:`arsia_protocol.discovery`:

- ``build_discovery_document`` — §7.1 metadata payload.
- ``build_jwks`` — §7.3 JWK Set envelope wrapping pre-built JWK dicts.
- ``build_capability_listing`` — §7.2 capability catalogue with the
  SDK's pagination wrapper.

Spec tests that require a live HTTP agent (``DISCOVERY-*``) can be
added later with ``skip_until: slice-8``; this slice only ships the
offline builder coverage.
"""

from __future__ import annotations

from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _check_subset(
    actual: dict[str, Any],
    expected: dict[str, Any],
) -> tuple[TestStatus, str | None]:
    """Assert that every ``expected`` key/value appears in ``actual``.

    Keeps suites forward-compatible: a suite asserting a handful of
    keys doesn't break when the SDK starts emitting extra (optional)
    ones.
    """
    for key, want in expected.items():
        if key not in actual:
            return "fail", f"missing key {key!r} in output"
        got = actual[key]
        if got != want:
            return "fail", f"{key}: got {got!r}, want {want!r}"
    return "pass", None


def _check_absent(
    actual: dict[str, Any],
    keys: list[Any],
) -> tuple[TestStatus, str | None]:
    for key in keys:
        if not isinstance(key, str):
            return "error", "expected.absent_keys entries must be strings"
        if key in actual:
            return "fail", f"key {key!r} should be absent but is present"
    return "pass", None


def _run_build_discovery_document(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.discovery import build_discovery_document

    args = case.input.get("args")
    if not isinstance(args, dict):
        return "error", "input.args must be an object"
    try:
        doc = build_discovery_document(**args)
    except TypeError as exc:
        return "error", f"build_discovery_document rejected args: {exc}"

    contains = case.expected.get("contains")
    if isinstance(contains, dict):
        status, message = _check_subset(doc, contains)
        if status != "pass":
            return status, message

    absent = case.expected.get("absent_keys")
    if isinstance(absent, list):
        status, message = _check_absent(doc, absent)
        if status != "pass":
            return status, message

    required = case.expected.get("required_keys")
    if isinstance(required, list):
        for key in required:
            if not isinstance(key, str):
                return "error", "expected.required_keys entries must be strings"
            if key not in doc:
                return "fail", f"required key {key!r} missing from document"

    return "pass", None


def _run_build_jwks(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.discovery import build_jwks

    keys = case.input.get("keys")
    if not isinstance(keys, list):
        return "error", "input.keys must be a list"
    jwks = build_jwks([dict(k) for k in keys if isinstance(k, dict)])
    want = case.expected.get("jwks")
    if want is not None and jwks != want:
        return "fail", f"build_jwks output mismatch: got {jwks!r}, want {want!r}"
    if "count" in case.expected:
        got_count = len(jwks["keys"])
        want_count = case.expected["count"]
        if got_count != want_count:
            return "fail", f"keys count = {got_count}, want {want_count}"
    return "pass", None


def _run_build_capability_listing(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.discovery import build_capability_listing

    actions = case.input.get("actions")
    if not isinstance(actions, list):
        return "error", "input.actions must be a list"
    kwargs: dict[str, Any] = {}
    for key in ("total", "limit", "offset"):
        if key in case.input:
            kwargs[key] = case.input[key]
    listing = build_capability_listing(
        [dict(a) for a in actions if isinstance(a, dict)],
        **kwargs,
    )
    want = case.expected.get("listing")
    if want is not None and listing != want:
        return "fail", f"build_capability_listing mismatch: got {listing!r}, want {want!r}"
    for key in ("total", "limit", "offset"):
        if key in case.expected:
            got = listing[key]
            if got != case.expected[key]:
                return "fail", f"{key} = {got!r}, want {case.expected[key]!r}"
    return "pass", None


_OPERATIONS = {
    "build_discovery_document": _run_build_discovery_document,
    "build_jwks": _run_build_jwks,
    "build_capability_listing": _run_build_capability_listing,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    """Dispatch a ``discovery`` case to its handler."""
    try:
        import arsia_protocol.identity.discovery  # noqa: F401
    except ImportError as exc:  # pragma: no cover - defensive
        return "error", f"arsia_protocol.discovery import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for discovery cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown discovery operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
