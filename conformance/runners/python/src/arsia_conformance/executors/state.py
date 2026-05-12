# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``state`` category (ARSIA-State.md Slice 5).

Dispatches on ``input.operation``:

- ``validate_state_entry`` — structural + compliance-coupled
  validation of a :class:`StateEntry` (§2.1). Asserts on
  ``expected.valid`` + optional ``expected.error_contains``.
- ``validate_state_key`` — §2.1.1 key grammar. Asserts on
  ``expected.valid`` + optional ``expected.error_contains``.
- ``effective_retention`` — §4.1.1 ``max(profile, entry)``. Asserts
  on ``expected.retention_days`` (int or null).
- ``required_capability`` — §8.2 operation → capability mapping.
  Asserts on ``expected.capability``.
- ``wildcard_covers`` — §8.2 wildcard exclusion. Asserts on
  ``expected.covered`` (bool).
- ``compute_payload_hash`` — §7.1 ``payload_hash`` reproduction.
  Asserts on ``expected.sha256_hex``.
- ``build_audit_record`` — §7.1 audit builder, asserts on
  ``expected.required_keys`` / ``expected.compliance_profile`` /
  ``expected.event_type``.
- ``enforce_value_size`` — §2.1.2 1 MiB limit. Asserts on
  ``expected.valid`` + optional ``expected.error_contains``.
- ``purge_args_shape`` — §3.2.2: PURGE args carry no value.
  Asserts on ``expected.absent_keys`` / ``expected.required_keys``.
- ``set_args_shape`` — §3.1.2: SET args are FLAT (no ``entry``
  wrapper). Asserts on ``expected.required_keys`` / ``absent_keys``
  (or ``expected.valid: false`` when scope='global' must be
  rejected).
- ``query_args_shape`` — §3.1.4: QUERY uses ``key_prefix`` (not
  ``prefix``); all filters optional.
- ``snapshot_args_shape`` — §3.2.1: SNAPSHOT requires ``as_of``,
  optional ``filter``.
- ``grant_args_shape`` — §3.3.1: GRANT uses ``key_pattern`` +
  ``grantee_agent_id`` + ``access_level``.
- ``revoke_args_shape`` — §3.3.2: REVOKE uses ``grant_id`` only.

HTTP-/storage-dependent cases (round-trip GET after SET, version
conflict detection, QUERY filtering, SNAPSHOT listing, DELETE ->
not_found) are marked ``skip_until: http-harness`` in the YAML
suite.
"""

from __future__ import annotations

import hashlib
from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _check_valid(
    case: TestCase, errors: list[object]
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


def _run_validate_state_entry(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import validate_state_entry
    from arsia_protocol.types.state import StateEntry

    entry_input = case.input.get("entry")
    if not isinstance(entry_input, dict):
        return "error", "input.entry must be an object"
    sender = case.input.get("sender_agent_id")
    if sender is not None and not isinstance(sender, str):
        return "error", "input.sender_agent_id must be a string"
    envelope_compliance = case.input.get("envelope_compliance")
    if envelope_compliance is not None and not isinstance(envelope_compliance, dict):
        return "error", "input.envelope_compliance must be an object or null"

    try:
        entry = StateEntry.model_validate(entry_input)
    except Exception as exc:  # noqa: BLE001
        if not bool(case.expected.get("valid", True)):
            keyword = case.expected.get("error_contains")
            if isinstance(keyword, str) and keyword:
                if keyword.lower() in str(exc).lower():
                    return "pass", None
                return "fail", f"pydantic rejection did not mention {keyword!r}: {exc}"
            return "pass", None
        return "error", f"entry failed to build: {exc}"

    errors = validate_state_entry(
        entry,
        sender_agent_id=sender,
        envelope_compliance=envelope_compliance,
    )
    return _check_valid(case, errors)


def _run_validate_state_key(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import validate_state_key

    key = case.input.get("key")
    if not isinstance(key, str):
        return "error", "input.key must be a string"
    expected_owner = case.input.get("expected_owner")
    expected_scope = case.input.get("expected_scope")
    allow_reserved = bool(case.input.get("allow_reserved", False))

    errors = validate_state_key(
        key,
        expected_owner=expected_owner,
        expected_scope=expected_scope,
        allow_reserved=allow_reserved,
    )
    return _check_valid(case, errors)


def _run_effective_retention(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import compute_effective_retention

    profile = case.input.get("profile_name")
    if profile is not None and not isinstance(profile, str):
        return "error", "input.profile_name must be a string or null"
    entry_retention = case.input.get("entry_retention_days")
    if entry_retention is not None and not isinstance(entry_retention, int):
        return "error", "input.entry_retention_days must be an int or null"

    got = compute_effective_retention(profile, entry_retention)
    want = case.expected.get("retention_days")
    if want is None and got is None:
        return "pass", None
    if want != got:
        return "fail", f"retention_days: expected {want}, got {got}"
    return "pass", None


def _run_required_capability(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import required_capability_for

    op = case.input.get("operation_name")
    if not isinstance(op, str):
        return "error", "input.operation_name must be a string"

    try:
        got = required_capability_for(op)
    except ValueError as exc:
        if not bool(case.expected.get("valid", True)):
            return "pass", None
        return "fail", f"required_capability_for raised: {exc}"

    want = case.expected.get("capability")
    if not isinstance(want, str):
        return "error", "expected.capability must be a string"
    if got != want:
        return "fail", f"capability: expected {want!r}, got {got!r}"
    return "pass", None


def _run_wildcard_covers(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import wildcard_covers_state_capability

    wildcard = case.input.get("wildcard")
    capability = case.input.get("capability")
    if not isinstance(wildcard, str) or not isinstance(capability, str):
        return "error", "input.wildcard and input.capability must be strings"

    got = wildcard_covers_state_capability(wildcard, capability)
    want = case.expected.get("covered")
    if not isinstance(want, bool):
        return "error", "expected.covered must be a boolean"
    if got != want:
        return "fail", f"covered: expected {want}, got {got}"
    return "pass", None


def _run_compute_payload_hash(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.audit import compute_payload_hash

    payload = case.input.get("payload")
    if not isinstance(payload, dict):
        return "error", "input.payload must be an object"

    got = compute_payload_hash(payload)
    want = case.expected.get("sha256_hex")
    if want is None:
        # Reproducibility: the case simply asserts that the hash equals
        # a self-computed SHA-256 over the canonical bytes.
        from arsia_protocol.hazmat.canonicalization import canonicalize

        want = hashlib.sha256(canonicalize(payload)).hexdigest()
    if not isinstance(want, str):
        return "error", "expected.sha256_hex must be a hex string"
    if got != want:
        return "fail", f"payload_hash: expected {want}, got {got}"
    return "pass", None


def _run_build_audit_record(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.audit import build_audit_record

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"
    event_type = case.input.get("event_type")
    if not isinstance(event_type, str):
        return "error", "input.event_type must be a string"
    operator_id = case.input.get("operator_id")
    if not isinstance(operator_id, str):
        return "error", "input.operator_id must be a string"
    retention = case.input.get("effective_retention_days")
    if not isinstance(retention, int):
        return "error", "input.effective_retention_days must be an int"
    oversight_status = case.input.get("oversight_status")
    approver_id = case.input.get("approver_id")
    data_residency = case.input.get("data_residency")

    try:
        record = build_audit_record(
            envelope,
            event_type=event_type,  # type: ignore[arg-type]
            operator_id=operator_id,
            effective_retention_days=retention,
            oversight_status=oversight_status,
            approver_id=approver_id,
            data_residency=data_residency,
        )
    except ValueError as exc:
        if not bool(case.expected.get("valid", True)):
            keyword = case.expected.get("error_contains")
            if isinstance(keyword, str) and keyword:
                if keyword.lower() in str(exc).lower():
                    return "pass", None
                return "fail", f"builder did not mention {keyword!r}: {exc}"
            return "pass", None
        return "fail", f"build_audit_record raised: {exc}"

    payload = record.model_dump(mode="json", exclude_none=True)

    want_event_type = case.expected.get("event_type")
    if isinstance(want_event_type, str) and payload["event_type"] != want_event_type:
        return (
            "fail",
            f"event_type: expected {want_event_type!r}, got {payload['event_type']!r}",
        )

    want_profile = case.expected.get("compliance_profile")
    if isinstance(want_profile, str) and payload["compliance_profile"] != want_profile:
        return (
            "fail",
            f"compliance_profile: expected {want_profile!r}, "
            f"got {payload['compliance_profile']!r}",
        )

    required_keys = case.expected.get("required_keys")
    if isinstance(required_keys, list):
        missing = [k for k in required_keys if k not in payload]
        if missing:
            return "fail", f"record missing required keys: {missing}"

    absent_keys = case.expected.get("absent_keys")
    if isinstance(absent_keys, list):
        present = [k for k in absent_keys if k in payload]
        if present:
            return "fail", f"record has forbidden keys: {present}"

    return "pass", None


def _run_enforce_value_size(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import enforce_value_size_limit

    value = case.input.get("value")
    want_valid = bool(case.expected.get("valid", True))
    try:
        enforce_value_size_limit(value)
    except ValueError as exc:
        if want_valid:
            return "fail", f"expected valid but got error: {exc}"
        keyword = case.expected.get("error_contains")
        if isinstance(keyword, str) and keyword:
            if keyword.lower() not in str(exc).lower():
                return "fail", f"error did not mention {keyword!r}: {exc}"
        return "pass", None
    if not want_valid:
        return "fail", "expected rejection but enforce_value_size_limit passed"
    return "pass", None


def _run_purge_args_shape(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import build_purge_args

    key = case.input.get("key")
    reason = case.input.get("reason")
    if not isinstance(key, str) or not isinstance(reason, str):
        return "error", "input.key and input.reason must be strings"

    try:
        args = build_purge_args(key, reason)
    except ValueError as exc:
        if not bool(case.expected.get("valid", True)):
            return "pass", None
        return "fail", f"build_purge_args raised: {exc}"

    absent = case.expected.get("absent_keys") or []
    if not isinstance(absent, list):
        return "error", "expected.absent_keys must be a list"
    present = [k for k in absent if k in args]
    if present:
        return "fail", f"purge args contain forbidden keys: {present}"

    required = case.expected.get("required_keys") or []
    if not isinstance(required, list):
        return "error", "expected.required_keys must be a list"
    missing = [k for k in required if k not in args]
    if missing:
        return "fail", f"purge args missing required keys: {missing}"
    return "pass", None


def _check_args_shape(
    case: TestCase, args: dict[str, Any]
) -> tuple[TestStatus, str | None]:
    required = case.expected.get("required_keys") or []
    if not isinstance(required, list):
        return "error", "expected.required_keys must be a list"
    missing = [k for k in required if k not in args]
    if missing:
        return "fail", f"args missing required keys: {missing}"
    absent = case.expected.get("absent_keys") or []
    if not isinstance(absent, list):
        return "error", "expected.absent_keys must be a list"
    present = [k for k in absent if k in args]
    if present:
        return "fail", f"args contain forbidden keys: {present}"
    return "pass", None


def _run_set_args_shape(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import build_set_args
    from arsia_protocol.types.state import StateEntry

    entry_input = case.input.get("entry")
    if not isinstance(entry_input, dict):
        return "error", "input.entry must be an object"
    expected_version = case.input.get("expected_version")
    if expected_version is not None and not isinstance(expected_version, int):
        return "error", "input.expected_version must be an int or null"

    want_valid = bool(case.expected.get("valid", True))
    try:
        entry = StateEntry.model_validate(entry_input)
    except Exception as exc:  # noqa: BLE001
        if not want_valid:
            return "pass", None
        return "error", f"entry failed to build: {exc}"

    try:
        args = build_set_args(entry, expected_version=expected_version)
    except ValueError as exc:
        if not want_valid:
            return "pass", None
        return "fail", f"build_set_args raised: {exc}"
    if not want_valid:
        return "fail", "expected rejection but build_set_args returned"
    return _check_args_shape(case, args)


def _run_query_args_shape(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import build_query_args

    kwargs: dict[str, Any] = {}
    for field in (
        "scope",
        "key_prefix",
        "owner_agent_id",
        "pii_classification",
        "created_after",
        "created_before",
        "limit",
        "offset",
    ):
        if field in case.input:
            kwargs[field] = case.input[field]

    want_valid = bool(case.expected.get("valid", True))
    try:
        scope = kwargs.pop("scope", None)
        args = build_query_args(scope, **kwargs)
    except ValueError as exc:
        if not want_valid:
            return "pass", None
        return "fail", f"build_query_args raised: {exc}"
    if not want_valid:
        return "fail", "expected rejection but build_query_args returned"
    return _check_args_shape(case, args)


def _run_snapshot_args_shape(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import build_snapshot_args

    as_of = case.input.get("as_of")
    if not isinstance(as_of, str):
        return "error", "input.as_of must be a string"
    filter_ = case.input.get("filter")
    if filter_ is not None and not isinstance(filter_, dict):
        return "error", "input.filter must be an object or null"

    want_valid = bool(case.expected.get("valid", True))
    try:
        args = build_snapshot_args(as_of, filter=filter_)
    except ValueError as exc:
        if not want_valid:
            return "pass", None
        return "fail", f"build_snapshot_args raised: {exc}"
    if not want_valid:
        return "fail", "expected rejection but build_snapshot_args returned"
    return _check_args_shape(case, args)


def _run_grant_args_shape(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import build_grant_args

    key_pattern = case.input.get("key_pattern")
    grantee_agent_id = case.input.get("grantee_agent_id")
    access_level = case.input.get("access_level")
    valid_until = case.input.get("valid_until")
    if not isinstance(key_pattern, str):
        return "error", "input.key_pattern must be a string"
    if not isinstance(grantee_agent_id, str):
        return "error", "input.grantee_agent_id must be a string"
    if not isinstance(access_level, str):
        return "error", "input.access_level must be a string"

    want_valid = bool(case.expected.get("valid", True))
    try:
        args = build_grant_args(
            key_pattern,
            grantee_agent_id,
            access_level,  # type: ignore[arg-type]
            valid_until=valid_until,
        )
    except ValueError as exc:
        if not want_valid:
            return "pass", None
        return "fail", f"build_grant_args raised: {exc}"
    if not want_valid:
        return "fail", "expected rejection but build_grant_args returned"
    return _check_args_shape(case, args)


def _run_revoke_args_shape(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.state import build_revoke_args

    grant_id = case.input.get("grant_id")
    if not isinstance(grant_id, str):
        return "error", "input.grant_id must be a string"

    want_valid = bool(case.expected.get("valid", True))
    try:
        args = build_revoke_args(grant_id)
    except ValueError as exc:
        if not want_valid:
            return "pass", None
        return "fail", f"build_revoke_args raised: {exc}"
    if not want_valid:
        return "fail", "expected rejection but build_revoke_args returned"
    return _check_args_shape(case, args)


_OPERATIONS = {
    "validate_state_entry": _run_validate_state_entry,
    "validate_state_key": _run_validate_state_key,
    "effective_retention": _run_effective_retention,
    "required_capability": _run_required_capability,
    "wildcard_covers": _run_wildcard_covers,
    "compute_payload_hash": _run_compute_payload_hash,
    "build_audit_record": _run_build_audit_record,
    "enforce_value_size": _run_enforce_value_size,
    "purge_args_shape": _run_purge_args_shape,
    "set_args_shape": _run_set_args_shape,
    "query_args_shape": _run_query_args_shape,
    "snapshot_args_shape": _run_snapshot_args_shape,
    "grant_args_shape": _run_grant_args_shape,
    "revoke_args_shape": _run_revoke_args_shape,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.state.state  # noqa: F401
        import arsia_protocol.state.audit  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol.state/audit import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for state cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown state operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
