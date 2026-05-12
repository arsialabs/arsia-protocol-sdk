# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``compliance`` category.

Dispatches on ``input.operation``:

- ``get_profile`` — assert profile exists in the registry.
- ``get_profile_names`` — assert the set of bundled profile names.
- ``validate_compliance`` — receiver-side rejection, checks
  ``expected.valid`` and optional ``expected.error_contains``.
- ``apply_profile`` — sender-side normalization, checks
  ``expected.compliance_after`` sub-fields.
- ``audit_from_envelope`` — payload-type-agnostic audit record
  derivation via :func:`arsia_protocol.audit.build_audit_record`;
  asserts ``expected.audit.compliance_profile`` and
  ``expected.audit.payload_type``. Used by CORE-COMPLIANCE-03
  (ARSIA-Core.md §12.4) to verify the SDK builds correct audit
  rows for MCP-wrapped envelopes without special-casing the
  payload type.

Envelope inputs are inlined in the YAML — no SDK-specific helpers.
"""

from __future__ import annotations

from typing import Any

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _run_validate(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.compliance import validate_compliance

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object for validate_compliance"
    strict = bool(case.input.get("strict", False))
    # §12.4 CORE-COMPLIANCE-02 relies on R6, which only fires when the
    # caller has resolved the sender's IdentityRecord classification and
    # passed it through. The YAML carries it at the top level of ``input``.
    identity_classification = case.input.get("identity_classification")
    if identity_classification is not None and not isinstance(
        identity_classification, str
    ):
        return (
            "error",
            "input.identity_classification must be a string when present",
        )
    errors = validate_compliance(
        envelope,
        strict=strict,
        identity_classification=identity_classification,
    )
    want_valid = bool(case.expected.get("valid", True))

    if want_valid:
        if errors:
            return "fail", f"expected valid but got errors: {errors}"
        return "pass", None

    if not errors:
        return "fail", "expected rejection but compliance passed validation"
    keyword = case.expected.get("error_contains")
    if isinstance(keyword, str) and keyword:
        keyword_lower = keyword.lower()
        if not any(keyword_lower in str(e).lower() for e in errors):
            return (
                "fail",
                f"no error mentioned {keyword!r}; errors={errors}",
            )
    return "pass", None


def _run_apply_profile(case: TestCase) -> tuple[TestStatus, str | None]:
    import logging

    from arsia_protocol.core.compliance import apply_profile

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object for apply_profile"
    strict = bool(case.input.get("strict", False))

    captured: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: captured.append(record.getMessage())  # type: ignore[assignment]
    sdk_logger = logging.getLogger("arsia_protocol.compliance")
    sdk_logger.addHandler(handler)
    old_level = sdk_logger.level
    sdk_logger.setLevel(logging.WARNING)
    try:
        out = apply_profile(envelope, strict=strict)
    except ValueError as exc:
        return "fail", f"apply_profile raised: {exc}"
    finally:
        sdk_logger.removeHandler(handler)
        sdk_logger.setLevel(old_level)

    want = case.expected.get("compliance_after")
    if not isinstance(want, dict):
        return "error", "expected.compliance_after must be an object for apply_profile"
    got = out.get("compliance")
    if not isinstance(got, dict):
        return "fail", "apply_profile did not set envelope.compliance"
    mismatches: list[str] = []
    for key, expected_value in want.items():
        actual = got.get(key)
        if actual != expected_value:
            mismatches.append(f"{key}: expected {expected_value!r}, got {actual!r}")
    if mismatches:
        return "fail", "; ".join(mismatches)

    warning_keyword = case.expected.get("warning_contains")
    if isinstance(warning_keyword, str) and warning_keyword:
        kw_lower = warning_keyword.lower()
        if not any(kw_lower in msg.lower() for msg in captured):
            return (
                "fail",
                f"no log warning mentioned {warning_keyword!r}; "
                f"captured={captured}",
            )

    return "pass", None


def _run_get_profile(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.compliance import get_profile

    profile_name = case.input.get("profile_name")
    if not isinstance(profile_name, str):
        return "error", "input.profile_name is required for get_profile"
    want_exists = bool(case.expected.get("exists", True))
    try:
        profile = get_profile(profile_name)
    except ValueError:
        if not want_exists:
            return "pass", None
        return "fail", f"profile {profile_name!r} not found"
    if not isinstance(profile, dict):
        return "fail", f"get_profile returned non-dict: {type(profile).__name__}"
    return "pass", None


def _run_get_profile_names(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.core.compliance import get_profile_names

    want: Any = case.expected.get("names")
    if not isinstance(want, list):
        return "error", "expected.names must be a list for get_profile_names"
    got = get_profile_names()
    if sorted(got) != sorted(str(n) for n in want):
        return "fail", f"expected {sorted(want)}, got {sorted(got)}"
    return "pass", None


def _run_audit_from_envelope(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.state.audit import build_audit_record

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object for audit_from_envelope"
    event_type = case.input.get("event_type")
    if not isinstance(event_type, str):
        return "error", "input.event_type is required for audit_from_envelope"
    operator_id = case.input.get("operator_id")
    if not isinstance(operator_id, str):
        return "error", "input.operator_id is required for audit_from_envelope"
    retention = case.input.get("effective_retention_days")
    if not isinstance(retention, int):
        return (
            "error",
            "input.effective_retention_days must be an int for audit_from_envelope",
        )

    try:
        record = build_audit_record(
            envelope,
            event_type=event_type,  # type: ignore[arg-type]
            operator_id=operator_id,
            effective_retention_days=retention,
        )
    except (ValueError, KeyError) as exc:
        return "fail", f"build_audit_record raised: {exc}"

    want = case.expected.get("audit")
    if not isinstance(want, dict):
        return "error", "expected.audit must be an object for audit_from_envelope"
    dumped = record.model_dump(mode="json")
    mismatches: list[str] = []
    for key, expected_value in want.items():
        actual = dumped.get(key)
        if actual != expected_value:
            mismatches.append(f"{key}: expected {expected_value!r}, got {actual!r}")
    if mismatches:
        return "fail", "; ".join(mismatches)
    return "pass", None


_OPERATIONS = {
    "get_profile": _run_get_profile,
    "get_profile_names": _run_get_profile_names,
    "validate_compliance": _run_validate,
    "apply_profile": _run_apply_profile,
    "audit_from_envelope": _run_audit_from_envelope,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.core.compliance  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for compliance cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown compliance operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
