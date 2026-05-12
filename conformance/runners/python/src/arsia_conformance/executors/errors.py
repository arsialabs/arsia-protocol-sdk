# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``errors`` category.

Two operations:

- ``get_error_info`` — look up a standard code and compare
  ``http_status`` / ``retryable`` to expected values.
- ``compute_retry_delay`` — evaluate the §11.3 exponential backoff
  formula for a given attempt number.

Both operations support ``expected.raises: true`` when the case asserts
that the call rejects an invalid input.
"""

from __future__ import annotations

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _run_get_error_info(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.errors import get_error_info

    code = case.input.get("code")
    if not isinstance(code, str):
        return "error", "input.code must be a string"
    want_raises = bool(case.expected.get("raises", False))
    try:
        info = get_error_info(code)
    except ValueError as exc:
        if want_raises:
            return "pass", None
        return "fail", f"get_error_info raised unexpectedly: {exc}"
    if want_raises:
        return "fail", f"expected ValueError but got {info!r}"

    mismatches: list[str] = []
    if "http_status" in case.expected and info.http_status != case.expected["http_status"]:
        mismatches.append(
            f"http_status: expected {case.expected['http_status']}, got {info.http_status}"
        )
    if "retryable" in case.expected and info.retryable != case.expected["retryable"]:
        mismatches.append(
            f"retryable: expected {case.expected['retryable']}, got {info.retryable}"
        )
    if mismatches:
        return "fail", "; ".join(mismatches)
    return "pass", None


def _run_compute_retry_delay(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.errors import compute_retry_delay

    attempt = case.input.get("attempt")
    if not isinstance(attempt, int):
        return "error", "input.attempt must be an integer"
    want_raises = bool(case.expected.get("raises", False))
    try:
        delay = compute_retry_delay(attempt)
    except ValueError as exc:
        if want_raises:
            return "pass", None
        return "fail", f"compute_retry_delay raised unexpectedly: {exc}"
    if want_raises:
        return "fail", f"expected ValueError but got delay={delay}"

    want = case.expected.get("delay_seconds")
    if isinstance(want, (int, float)) and abs(delay - float(want)) > 1e-9:
        return "fail", f"expected delay {want}, got {delay}"
    return "pass", None


def _run_verify_descriptions_english(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.errors import ERROR_REGISTRY

    codes = case.input.get("codes")
    if not isinstance(codes, list):
        return "error", "input.codes must be a list of error code strings"

    non_english: list[str] = []
    for code in codes:
        if not isinstance(code, str):
            continue
        info = ERROR_REGISTRY.get(code)
        if info is None:
            continue
        desc = info.description
        if not desc.isprintable():
            non_english.append(f"{code}: contains non-printable chars")
            continue
        non_latin = [
            ch for ch in desc
            if not ch.isascii() and ch not in "§—–''""…·"
        ]
        if non_latin:
            non_english.append(
                f"{code}: contains non-English characters: "
                f"{non_latin!r}"
            )

    if non_english:
        return "fail", f"descriptions not in English: {non_english}"
    return "pass", None


_OPERATIONS = {
    "get_error_info": _run_get_error_info,
    "calculate_retry_delay": _run_compute_retry_delay,
    "verify_descriptions_english": _run_verify_descriptions_english,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.core.errors  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for errors cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown errors operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
