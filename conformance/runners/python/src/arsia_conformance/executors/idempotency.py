# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``idempotency`` category (ARSIA-Core.md §10).

Dispatches on ``input.operation``:

- ``validate_key`` — §10.2. Asserts on ``expected.valid`` +
  ``expected.error_contains``.
- ``scope_tuple`` — §10.1. Asserts on ``expected.from``,
  ``expected.to``, ``expected.payload_type``.
- ``resolve_key`` — §10.4. Asserts on ``expected.key``
  (string or null).
- ``is_record_expired`` — §10.3. Asserts on ``expected.expired``
  (bool).
- ``compute_expiry`` — §10.2(2). Asserts that the returned RFC 3339
  timestamp is greater-than-or-equal to ``expected.min_expires_at``
  (24-hour retention floor for header-only keys).
- ``in_progress_lifecycle`` — §10.3(4). Drives the in-memory store
  through ``mark_pending`` → ``check_status`` → ``mark_pending`` and
  asserts on optional ``expected.first_mark``,
  ``expected.status_after_first``, and ``expected.second_mark``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _check_valid(
    case: TestCase, errors: list[Any]
) -> tuple[TestStatus, str | None]:
    want_valid = bool(case.expected.get("valid", True))
    if want_valid:
        if errors:
            return "fail", f"expected valid but got errors: {errors}"
        return "pass", None
    if not errors:
        return "fail", "expected rejection but got no errors"
    keyword = case.expected.get("error_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in str(e).lower() for e in errors):
            return "fail", f"no error mentioned {keyword!r}; errors={errors}"
    return "pass", None


def _run_validate_key(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.idempotency import validate_idempotency_key

    key = case.input.get("key")
    if not isinstance(key, str):
        return "error", "input.key must be a string"

    errors = validate_idempotency_key(key)
    return _check_valid(case, errors)


def _run_scope_tuple(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.idempotency import scope_tuple

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"

    try:
        scope = scope_tuple(envelope)
    except ValueError as exc:
        if not bool(case.expected.get("valid", True)):
            return "pass", None
        return "fail", f"scope_tuple raised: {exc}"

    for attr, key in (
        ("from_agent", "from"),
        ("to_agent", "to"),
        ("payload_type", "payload_type"),
    ):
        if key in case.expected:
            got = getattr(scope, attr)
            want = case.expected[key]
            if got != want:
                return "fail", f"{key}: expected {want!r}, got {got!r}"
    return "pass", None


def _run_resolve_key(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.idempotency import resolve_idempotency_key

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"
    header_key = case.input.get("header_key")
    if header_key is not None and not isinstance(header_key, str):
        return "error", "input.header_key must be a string or null"

    got = resolve_idempotency_key(envelope, header_key=header_key)
    want = case.expected.get("key")
    if want != got:
        return "fail", f"key: expected {want!r}, got {got!r}"
    return "pass", None


def _run_is_record_expired(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.idempotency import is_idempotency_record_expired

    expires_at = case.input.get("expires_at")
    if not isinstance(expires_at, str):
        return "error", "input.expires_at must be a string"
    now_s = case.input.get("now")
    now: datetime | None = None
    if isinstance(now_s, str):
        try:
            now = datetime.fromisoformat(now_s.replace("Z", "+00:00"))
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
        except ValueError:
            return "error", f"input.now is not a valid timestamp: {now_s!r}"

    got = is_idempotency_record_expired(expires_at, now=now)
    want = case.expected.get("expired")
    if not isinstance(want, bool):
        return "error", "expected.expired must be a bool"
    if got != want:
        return "fail", f"expired: expected {want}, got {got}"
    return "pass", None


def _run_compute_expiry(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.idempotency import compute_idempotency_expiry

    envelope_expires_at = case.input.get("envelope_expires_at")
    if envelope_expires_at is not None and not isinstance(
        envelope_expires_at, str
    ):
        return "error", "input.envelope_expires_at must be a string or null"
    header_only = bool(case.input.get("header_only", False))
    now_s = case.input.get("now")
    now: datetime | None = None
    if isinstance(now_s, str):
        try:
            now = datetime.fromisoformat(now_s.replace("Z", "+00:00"))
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
        except ValueError:
            return "error", f"input.now is not a valid timestamp: {now_s!r}"

    got = compute_idempotency_expiry(
        envelope_expires_at, header_only=header_only, now=now
    )

    want_min = case.expected.get("min_expires_at")
    if isinstance(want_min, str):
        try:
            got_dt = datetime.fromisoformat(got.replace("Z", "+00:00"))
            want_dt = datetime.fromisoformat(want_min.replace("Z", "+00:00"))
        except ValueError as exc:
            return "error", f"timestamp parse failed: {exc}"
        if got_dt < want_dt:
            return (
                "fail",
                f"expires_at {got!r} is before min_expires_at {want_min!r}",
            )

    want_eq = case.expected.get("expires_at")
    if isinstance(want_eq, str) and want_eq != got:
        return "fail", f"expires_at: expected {want_eq!r}, got {got!r}"

    return "pass", None


def _run_in_progress_lifecycle(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.idempotency import scope_tuple

    from arsia_conformance.executors._in_memory_store import InMemoryIdempotencyStore

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"
    key = case.input.get("key")
    if not isinstance(key, str):
        return "error", "input.key must be a string"

    try:
        scope = scope_tuple(envelope)
    except ValueError as exc:
        return "error", f"scope_tuple failed: {exc}"

    store = InMemoryIdempotencyStore()
    first_mark = store.mark_pending(scope, key)
    status_after_first = store.check_status(scope, key)
    second_mark = store.mark_pending(scope, key)

    observed: dict[str, Any] = {
        "first_mark": first_mark,
        "status_after_first": status_after_first,
        "second_mark": second_mark,
    }
    for field, want in case.expected.items():
        if field not in observed:
            continue
        got = observed[field]
        if got != want:
            return "fail", f"{field}: expected {want!r}, got {got!r}"
    return "pass", None


_OPERATIONS: dict[str, Any] = {
    "validate_key": _run_validate_key,
    "scope_tuple": _run_scope_tuple,
    "resolve_key": _run_resolve_key,
    "is_record_expired": _run_is_record_expired,
    "compute_expiry": _run_compute_expiry,
    "in_progress_lifecycle": _run_in_progress_lifecycle,
}


def execute(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.core.idempotency  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol.idempotency import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for idempotency cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown idempotency operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
