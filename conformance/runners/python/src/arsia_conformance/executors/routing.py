# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``routing`` category (ARSIA-Routing.md Slice 7).

Dispatches on ``input.operation``:

- ``select_topology`` — §1.3. Input accepts optional ``brokers``.
  Asserts on ``expected.topology``, optional ``expected.data_residency``,
  optional ``expected.selected_agent_id`` (for brokered), and optional
  ``expected.error`` dict (for the service_unavailable output) whose
  keys may include ``code``, ``required_zone``, and ``available_zones``.
- ``validate_broker_entry`` — §7.2 + §7.3 Rule 2. Asserts on
  ``expected.valid`` + optional ``expected.error_contains``.
- ``is_eu_eea_member`` — §7.3 Rule 2. Asserts on
  ``expected.is_member`` (bool).
- ``select_broker_by_priority`` — §7.4. Asserts on
  ``expected.selected_agent_id`` (string or null).
- ``lifecycle_transition`` — §4.1. Asserts on ``expected.valid``.
- ``validate_relay_preconditions`` — §7.3 Rules 2/3/9. Asserts on
  ``expected.valid`` + optional ``expected.error_contains``.
- ``parse_rate_limit_headers`` — §6. Asserts on
  ``expected.limit``/``remaining``/``reset_at``/``retry_after``.
- ``resolve_priority`` — §5. Asserts on ``expected.priority``.
- ``compute_retry_delay`` — Core §11.3. Asserts on
  ``expected.delay_seconds``.
- ``build_relay_audit_record`` — §7.4. Asserts on ``expected.valid``,
  optional ``expected.fields`` (dict of field→value equality), and
  optional ``expected.fields_present`` / ``expected.fields_absent``
  (lists of field names).
"""

from __future__ import annotations

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


def _run_select_topology(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import select_topology

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"

    brokers_in = case.input.get("brokers")
    if brokers_in is None:
        decision = select_topology(envelope)
    elif isinstance(brokers_in, list):
        decision = select_topology(envelope, brokers=brokers_in)
    else:
        return "error", "input.brokers must be an array when present"

    want = case.expected.get("topology")
    if want != decision.topology:
        return "fail", f"topology: expected {want!r}, got {decision.topology!r}"
    if "data_residency" in case.expected:
        want_res = case.expected["data_residency"]
        if want_res != decision.data_residency:
            return (
                "fail",
                f"data_residency: expected {want_res!r}, "
                f"got {decision.data_residency!r}",
            )
    if "selected_agent_id" in case.expected:
        want_id = case.expected["selected_agent_id"]
        got_id = decision.broker.get("agent_id") if decision.broker else None
        if want_id != got_id:
            return (
                "fail",
                f"selected_agent_id: expected {want_id!r}, got {got_id!r}",
            )
    if "error" in case.expected:
        want_err = case.expected["error"]
        if not isinstance(want_err, dict):
            return "error", "expected.error must be an object when present"
        if decision.error is None:
            return "fail", "expected error payload but decision.error is None"
        got_err: Any = decision.error
        if "code" in want_err and want_err["code"] != got_err.get("code"):
            return (
                "fail",
                f"error.code: expected {want_err['code']!r}, "
                f"got {got_err.get('code')!r}",
            )
        got_details = got_err.get("details") or {}
        if "required_zone" in want_err:
            want_zone = want_err["required_zone"]
            got_zone = got_details.get("required_zone")
            if want_zone != got_zone:
                return (
                    "fail",
                    f"error.details.required_zone: expected {want_zone!r}, "
                    f"got {got_zone!r}",
                )
        if "available_zones" in want_err:
            want_zones = want_err["available_zones"]
            got_zones = list(got_details.get("available_zones") or ())
            if list(want_zones) != got_zones:
                return (
                    "fail",
                    f"error.details.available_zones: expected {want_zones!r}, "
                    f"got {got_zones!r}",
                )
    return "pass", None


def _run_validate_broker_entry(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import validate_broker_entry

    entry = case.input.get("entry")
    if not isinstance(entry, dict):
        return "error", "input.entry must be an object"

    errors = validate_broker_entry(entry)
    return _check_valid(case, errors)


def _run_is_eu_eea_member(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import is_eu_eea_member

    code = case.input.get("country_code")
    if not isinstance(code, str):
        return "error", "input.country_code must be a string"

    got = is_eu_eea_member(code)
    want = case.expected.get("is_member")
    if not isinstance(want, bool):
        return "error", "expected.is_member must be a bool"
    if got != want:
        return "fail", f"is_member: expected {want}, got {got}"
    return "pass", None


def _run_select_broker_by_priority(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import select_broker_by_priority

    brokers = case.input.get("brokers")
    zone = case.input.get("zone")
    include_degraded = bool(case.input.get("include_degraded", False))
    if not isinstance(brokers, list) or not isinstance(zone, str):
        return "error", "input.brokers must be a list and input.zone a string"

    selected = select_broker_by_priority(
        brokers, zone=zone, include_degraded=include_degraded
    )
    want = case.expected.get("selected_agent_id")
    got = selected.get("agent_id") if selected is not None else None
    if want != got:
        return "fail", f"selected_agent_id: expected {want!r}, got {got!r}"
    return "pass", None


def _run_lifecycle_transition(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import is_valid_lifecycle_transition

    from_state = case.input.get("from_state")
    to_state = case.input.get("to_state")
    if not isinstance(from_state, str) or not isinstance(to_state, str):
        return "error", "input.from_state and input.to_state must be strings"

    got = is_valid_lifecycle_transition(from_state, to_state)
    want = bool(case.expected.get("valid", True))
    if got != want:
        return "fail", f"valid: expected {want}, got {got}"
    return "pass", None


def _run_validate_relay_preconditions(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from datetime import datetime, timezone

    from arsia_protocol.routing.routing import validate_relay_preconditions

    envelope = case.input.get("envelope")
    broker = case.input.get("broker")
    if not isinstance(envelope, dict) or not isinstance(broker, dict):
        return "error", "input.envelope and input.broker must be objects"
    now_s = case.input.get("now")
    now: datetime | None = None
    if isinstance(now_s, str):
        try:
            now = datetime.fromisoformat(now_s.replace("Z", "+00:00"))
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
        except ValueError:
            return "error", f"input.now is not a valid timestamp: {now_s!r}"

    errors = validate_relay_preconditions(envelope, broker, now=now)
    return _check_valid(case, errors)


def _run_parse_rate_limit_headers(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import parse_rate_limit_headers

    headers = case.input.get("headers")
    if not isinstance(headers, dict):
        return "error", "input.headers must be an object"

    status = parse_rate_limit_headers(headers)
    for field in ("limit", "remaining", "reset_at", "retry_after_seconds"):
        if field in case.expected:
            got = getattr(status, field)
            want = case.expected[field]
            if got != want:
                return "fail", f"{field}: expected {want!r}, got {got!r}"
    return "pass", None


def _run_resolve_priority(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import resolve_priority

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"
    override = case.input.get("override")
    if override is not None and not isinstance(override, int):
        return "error", "input.override must be an int or null"

    try:
        got = resolve_priority(envelope, override=override)
    except ValueError as exc:
        if not bool(case.expected.get("valid", True)):
            return "pass", None
        return "fail", f"resolve_priority raised: {exc}"

    want = case.expected.get("priority")
    if not isinstance(want, int):
        return "error", "expected.priority must be an int"
    if got != want:
        return "fail", f"priority: expected {want}, got {got}"
    return "pass", None


def _run_compute_retry_delay(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import compute_retry_delay

    attempt = case.input.get("attempt")
    if not isinstance(attempt, int):
        return "error", "input.attempt must be an int"

    try:
        got = compute_retry_delay(attempt)
    except ValueError as exc:
        if not bool(case.expected.get("valid", True)):
            return "pass", None
        return "fail", f"compute_retry_delay raised: {exc}"

    want = case.expected.get("delay_seconds")
    if not isinstance(want, (int, float)):
        return "error", "expected.delay_seconds must be a number"
    if float(got) != float(want):
        return "fail", f"delay_seconds: expected {want}, got {got}"
    return "pass", None


def _run_build_relay_audit_record(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from pydantic import ValidationError

    from arsia_protocol.routing.routing import build_broker_relay_audit_record

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"

    kwargs: dict[str, Any] = {}
    for key in (
        "broker_agent_id",
        "payload_hash",
        "forwarding_result",
        "relay_latency_ms",
        "residency_zone",
        "relay_id",
    ):
        if key in case.input:
            kwargs[key] = case.input[key]

    want_valid = bool(case.expected.get("valid", True))
    try:
        record = build_broker_relay_audit_record(envelope, **kwargs)
    except (ValueError, ValidationError) as exc:
        if not want_valid:
            keyword = case.expected.get("error_contains")
            if isinstance(keyword, str) and keyword:
                if keyword.lower() not in str(exc).lower():
                    return (
                        "fail",
                        f"error did not mention {keyword!r}; got {exc!s}",
                    )
            return "pass", None
        return "fail", f"build_broker_relay_audit_record raised: {exc}"

    if not want_valid:
        return "fail", "expected rejection but record was built"

    dumped = record.model_dump()

    want_fields = case.expected.get("fields")
    if isinstance(want_fields, dict):
        for field_name, want_value in want_fields.items():
            got_value = dumped.get(field_name)
            if got_value != want_value:
                return (
                    "fail",
                    f"fields[{field_name!r}]: expected {want_value!r}, "
                    f"got {got_value!r}",
                )

    want_present = case.expected.get("fields_present")
    if isinstance(want_present, list):
        for field_name in want_present:
            if field_name not in dumped:
                return (
                    "fail",
                    f"expected field {field_name!r} to be present; "
                    f"got {sorted(dumped)!r}",
                )

    want_absent = case.expected.get("fields_absent")
    if isinstance(want_absent, list):
        for field_name in want_absent:
            if field_name in dumped:
                return (
                    "fail",
                    f"expected field {field_name!r} to be absent; "
                    f"got {sorted(dumped)!r}",
                )

    return "pass", None


def _run_select_broker_random(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.routing.routing import select_broker_random

    brokers = case.input.get("brokers")
    zone = case.input.get("zone")
    iterations = case.input.get("iterations", 20)
    if not isinstance(brokers, list) or not isinstance(zone, str):
        return "error", "input.brokers must be a list and input.zone a string"
    if not isinstance(iterations, int) or iterations < 2:
        return "error", "input.iterations must be an integer >= 2"

    selected_ids: set[str | None] = set()
    for _ in range(iterations):
        result = select_broker_random(brokers, zone=zone)
        agent_id = result.get("agent_id") if result is not None else None
        selected_ids.add(agent_id)

    want_not_always_first = case.expected.get("not_always_first", False)
    if want_not_always_first and len(selected_ids) < 2:
        return (
            "fail",
            f"select_broker_random returned the same broker {iterations} "
            f"times; expected variation among equal candidates "
            f"(got {selected_ids!r})",
        )

    want_any_selected = case.expected.get("any_selected", False)
    if want_any_selected:
        non_none = {s for s in selected_ids if s is not None}
        if not non_none:
            return "fail", "no broker was ever selected"

    return "pass", None


_OPERATIONS: dict[str, Any] = {
    "select_topology": _run_select_topology,
    "validate_broker_entry": _run_validate_broker_entry,
    "is_eu_eea_member": _run_is_eu_eea_member,
    "select_broker_by_priority": _run_select_broker_by_priority,
    "select_broker_random": _run_select_broker_random,
    "lifecycle_transition": _run_lifecycle_transition,
    "validate_relay_preconditions": _run_validate_relay_preconditions,
    "parse_rate_limit_headers": _run_parse_rate_limit_headers,
    "resolve_priority": _run_resolve_priority,
    "compute_retry_delay": _run_compute_retry_delay,
    "build_relay_audit_record": _run_build_relay_audit_record,
}


def execute(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.routing.routing  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol.routing import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for routing cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown routing operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
