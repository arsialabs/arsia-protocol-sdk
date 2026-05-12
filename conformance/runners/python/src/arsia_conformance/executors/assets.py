# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``assets`` category (ARSIA-Assets.md Slice 6).

Dispatches on ``input.operation``:

- ``validate_transfer_request`` — Layer-4 validation of an
  ``AssetTransferRequest`` ``payload.args`` dict. Args may be taken
  from ``input.args`` or resolved from a vector via ``input.vector_id``.
  Asserts on ``expected.valid`` + optional ``expected.error_contains``.
- ``validate_transfer_receipt`` — schema validation of a
  ``payload.result`` dict from ``input.result``.
- ``validate_transfer_reversal`` — schema validation from ``input.args``
  or a vector, optionally composed with a precondition check driven by
  ``input.precondition`` (original_status / original_amount / now / …).
- ``validate_reversal_precondition`` — precondition-only, with
  ``input.reversal_args`` plus the precondition fields.
- ``validate_escrow_conditions`` — schema + timeout check with an
  optional ``input.envelope_ts``.
- ``escrow_transition`` — asserts ``is_valid_escrow_transition(from, to)``
  matches ``expected.valid``.
- ``two_party_auth`` — ``validate_two_party_auth`` driven by
  ``input.initiator_agent_id`` / ``approver_agent_id`` /
  ``approver_capabilities``.
- ``requires_psd2_sca`` — ``requires_psd2_sca(input.risk_level)``
  compared to ``expected.required`` (bool).
- ``classify_dora_incident`` — asserts ``classify_dora_incident_type``
  matches ``expected.incident_type``.
- ``build_dora_incident`` — builder-shape check, asserts on
  ``expected.required_keys`` / ``expected.incident_type`` /
  ``expected.severity``.
- ``validate_psd2_sca_factors`` — asserts on ``expected.valid`` +
  optional ``expected.error_contains``.
- ``enforce_mifid_retention`` — asserts on ``expected.valid`` +
  optional ``expected.error_contains``.
- ``validate_escrow_dispute`` / ``validate_escrow_cancel`` — Layer-4
  validation of §4.2.3 / §5.1.6 payload args from ``input.args``.
- ``build_escrow_audit`` — §4.3 builder dispatch on
  ``input.sub_type`` (``escrow_created`` / ``escrow_released`` /
  ``escrow_returned`` / ``escrow_disputed``); asserts on
  ``expected.required_keys`` + ``expected.values``.
- ``build_reversal_audit`` — §3.3.2 chain-of-custody projection;
  asserts on ``expected.required_keys`` + ``expected.values``.
- ``validate_receipt_match`` — §3.2.1 cross-message check between
  ``input.request_args`` and ``input.receipt_result``.
- ``capability_risk_levels`` — asserts the §5.1 risk-level map
  matches ``expected.levels`` entry-for-entry.
- ``is_sca_exempt`` — §6.3.3 classifier; asserts ``expected.exempt``
  + ``expected.reason``.
- ``validate_token_scope`` — §5.1.2 separation-of-duties check over
  ``input.scope``.
"""

from __future__ import annotations

from datetime import datetime
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
    error_code = case.expected.get("error_code")
    if isinstance(error_code, str) and error_code:
        if not any(getattr(e, "code", None) == error_code for e in errors):
            return "fail", f"no error with code {error_code!r}; errors={errors}"
    return "pass", None


def _resolve_args_from_vector(
    case: TestCase, context: ConformanceContext, key: str = "args"
) -> tuple[dict[str, Any] | None, tuple[TestStatus, str | None] | None]:
    vector_id = case.input.get("vector_id")
    if not isinstance(vector_id, str):
        return None, ("error", "input.vector_id must be a string")
    try:
        vector = context.get_vector(vector_id)
    except KeyError as exc:
        return None, ("error", str(exc))
    if "data" in vector and "message" not in vector:
        data = vector["data"]
        if not isinstance(data, dict):
            return None, ("error", f"{vector_id}: vector.data is not an object")
        return data, None
    message = vector.get("message")
    if not isinstance(message, dict):
        return None, ("error", f"{vector_id}: vector.message is not an object")
    payload = message.get("payload")
    if not isinstance(payload, dict):
        return None, ("error", f"{vector_id}: vector.message.payload is not an object")
    args = payload.get(key)
    if not isinstance(args, dict):
        return None, ("error", f"{vector_id}: vector.message.payload.{key} is not an object")
    return args, None


def _run_validate_transfer_request(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_transfer_request

    args = case.input.get("args")
    if args is None:
        resolved, error = _resolve_args_from_vector(case, context)
        if error is not None:
            return error
        args = resolved
    if not isinstance(args, dict):
        return "error", "input.args must be an object or input.vector_id must resolve to one"
    errors = validate_transfer_request(args)
    return _check_valid(case, errors)


def _run_validate_transfer_receipt(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_transfer_receipt

    result = case.input.get("result")
    if not isinstance(result, dict):
        return "error", "input.result must be an object"
    errors = validate_transfer_receipt(result)
    return _check_valid(case, errors)


def _run_validate_transfer_reversal(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import (
        validate_reversal_precondition,
        validate_transfer_reversal,
    )

    args = case.input.get("args")
    if args is None:
        resolved, error = _resolve_args_from_vector(case, context)
        if error is not None:
            return error
        args = resolved
    if not isinstance(args, dict):
        return "error", "input.args must be an object"

    errors = validate_transfer_reversal(args)

    precond = case.input.get("precondition")
    if isinstance(precond, dict):
        original_status = precond.get("original_status")
        if not isinstance(original_status, str):
            return "error", "input.precondition.original_status must be a string"
        kwargs: dict[str, Any] = {"original_status": original_status}
        if "original_amount" in precond:
            kwargs["original_amount"] = precond["original_amount"]
        if "original_settled_at" in precond:
            kwargs["original_settled_at"] = precond["original_settled_at"]
        if "now" in precond and isinstance(precond["now"], str):
            try:
                kwargs["now"] = datetime.fromisoformat(
                    precond["now"].replace("Z", "+00:00")
                )
            except ValueError as exc:
                return "error", f"input.precondition.now is not ISO 8601: {exc}"
        if "already_reversed_total" in precond:
            kwargs["already_reversed_total"] = precond["already_reversed_total"]
        if "full_reversal_window_days" in precond:
            kwargs["full_reversal_window_days"] = precond["full_reversal_window_days"]
        if "partial_reversal_window_days" in precond:
            kwargs["partial_reversal_window_days"] = precond[
                "partial_reversal_window_days"
            ]
        errors.extend(validate_reversal_precondition(args, **kwargs))

    return _check_valid(case, errors)


def _run_validate_reversal_precondition(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_reversal_precondition

    reversal_args = case.input.get("reversal_args")
    if not isinstance(reversal_args, dict):
        return "error", "input.reversal_args must be an object"
    original_status = case.input.get("original_status")
    if not isinstance(original_status, str):
        return "error", "input.original_status must be a string"

    kwargs: dict[str, Any] = {"original_status": original_status}
    for key in (
        "original_amount",
        "original_settled_at",
        "already_reversed_total",
        "full_reversal_window_days",
        "partial_reversal_window_days",
    ):
        if key in case.input:
            kwargs[key] = case.input[key]
    if "now" in case.input and isinstance(case.input["now"], str):
        try:
            kwargs["now"] = datetime.fromisoformat(
                case.input["now"].replace("Z", "+00:00")
            )
        except ValueError as exc:
            return "error", f"input.now is not ISO 8601: {exc}"

    errors = validate_reversal_precondition(reversal_args, **kwargs)
    return _check_valid(case, errors)


def _run_validate_escrow_conditions(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_escrow_conditions

    conditions = case.input.get("conditions")
    if not isinstance(conditions, dict):
        return "error", "input.conditions must be an object"
    envelope_ts = case.input.get("envelope_ts")
    if envelope_ts is not None and not isinstance(envelope_ts, str):
        return "error", "input.envelope_ts must be a string or null"

    errors = validate_escrow_conditions(conditions, envelope_ts=envelope_ts)
    return _check_valid(case, errors)


def _run_escrow_transition(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import is_valid_escrow_transition

    from_state = case.input.get("from_state")
    to_state = case.input.get("to_state")
    if not isinstance(from_state, str) or not isinstance(to_state, str):
        return "error", "input.from_state and input.to_state must be strings"

    got = is_valid_escrow_transition(from_state, to_state)
    want = bool(case.expected.get("valid", True))
    if got != want:
        return "fail", f"transition {from_state}→{to_state}: expected {want}, got {got}"
    return "pass", None


def _run_two_party_auth(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_two_party_auth

    initiator = case.input.get("initiator_agent_id")
    approver = case.input.get("approver_agent_id")
    caps = case.input.get("approver_capabilities")
    if not isinstance(initiator, str) or not isinstance(approver, str):
        return "error", "initiator_agent_id and approver_agent_id must be strings"
    if not isinstance(caps, list):
        return "error", "approver_capabilities must be a list"

    errors = validate_two_party_auth(
        initiator_agent_id=initiator,
        approver_agent_id=approver,
        approver_capabilities=list(caps),
    )
    return _check_valid(case, errors)


def _run_requires_psd2_sca(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import requires_psd2_sca

    risk_level = case.input.get("risk_level")
    if not isinstance(risk_level, int) or isinstance(risk_level, bool):
        return "error", "input.risk_level must be an int"
    got = requires_psd2_sca(risk_level)
    want = case.expected.get("required")
    if not isinstance(want, bool):
        return "error", "expected.required must be a bool"
    if got != want:
        return "fail", f"required: expected {want}, got {got}"
    return "pass", None


def _run_classify_dora_incident(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import classify_dora_incident_type

    failure_reason = case.input.get("failure_reason")
    if failure_reason is not None and not isinstance(failure_reason, str):
        return "error", "input.failure_reason must be a string or null"

    got = classify_dora_incident_type(failure_reason)
    if "incident_type" not in case.expected:
        return "error", "expected.incident_type is required (string or null)"
    want = case.expected.get("incident_type")
    if want is not None and not isinstance(want, str):
        return "error", "expected.incident_type must be a string or null"
    if got != want:
        return "fail", f"incident_type: expected {want!r}, got {got!r}"
    return "pass", None


def _run_build_dora_incident(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import build_dora_incident_event

    fields = case.input.get("fields")
    if not isinstance(fields, dict):
        return "error", "input.fields must be an object"

    try:
        data = build_dora_incident_event(**fields)
    except (TypeError, ValueError) as exc:
        if not bool(case.expected.get("valid", True)):
            keyword = case.expected.get("error_contains")
            if isinstance(keyword, str) and keyword:
                if keyword.lower() not in str(exc).lower():
                    return "fail", f"builder did not mention {keyword!r}: {exc}"
            return "pass", None
        return "fail", f"build_dora_incident_event raised: {exc}"

    if not bool(case.expected.get("valid", True)):
        return "fail", "expected rejection but builder succeeded"

    want_type = case.expected.get("incident_type")
    if isinstance(want_type, str) and data.get("incident_type") != want_type:
        return "fail", f"incident_type: expected {want_type!r}, got {data.get('incident_type')!r}"
    want_sev = case.expected.get("severity")
    if isinstance(want_sev, str) and data.get("severity") != want_sev:
        return "fail", f"severity: expected {want_sev!r}, got {data.get('severity')!r}"
    required_keys = case.expected.get("required_keys")
    if isinstance(required_keys, list):
        missing = [k for k in required_keys if k not in data]
        if missing:
            return "fail", f"payload.data missing keys: {missing}"
    return "pass", None


def _run_validate_psd2_sca_factors(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_psd2_sca_factors

    knowledge = case.input.get("knowledge_factor_present", False)
    possession = case.input.get("possession_factor_present", False)
    cnf_claim = case.input.get("cnf_claim")
    if not isinstance(knowledge, bool) or not isinstance(possession, bool):
        return "error", "knowledge_factor_present/possession_factor_present must be bools"
    if cnf_claim is not None and not isinstance(cnf_claim, dict):
        return "error", "cnf_claim must be an object or null"

    errors = validate_psd2_sca_factors(
        knowledge_factor_present=knowledge,
        possession_factor_present=possession,
        cnf_claim=cnf_claim,
    )
    return _check_valid(case, errors)


def _run_enforce_mifid_retention(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import enforce_mifid_retention

    envelope = case.input.get("envelope")
    if not isinstance(envelope, dict):
        return "error", "input.envelope must be an object"

    errors = enforce_mifid_retention(envelope)
    return _check_valid(case, errors)


def _run_validate_escrow_dispute(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_escrow_dispute

    args = case.input.get("args")
    if not isinstance(args, dict):
        return "error", "input.args must be an object"

    kwargs: dict[str, Any] = {}
    sender = case.input.get("sender_agent_id")
    if isinstance(sender, str):
        kwargs["sender_agent_id"] = sender
    parties = case.input.get("escrow_parties")
    if isinstance(parties, list) and len(parties) == 2:
        kwargs["escrow_parties"] = (parties[0], parties[1])

    errors = validate_escrow_dispute(args, **kwargs)
    return _check_valid(case, errors)


def _run_validate_escrow_cancel(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_escrow_cancel

    args = case.input.get("args")
    if not isinstance(args, dict):
        return "error", "input.args must be an object"

    kwargs: dict[str, Any] = {}
    sender = case.input.get("sender_agent_id")
    if isinstance(sender, str):
        kwargs["sender_agent_id"] = sender
    fa = case.input.get("from_agent")
    if isinstance(fa, str):
        kwargs["from_agent"] = fa

    errors = validate_escrow_cancel(args, **kwargs)
    return _check_valid(case, errors)


_ESCROW_AUDIT_BUILDERS = {
    "escrow_created": "build_escrow_created_audit",
    "escrow_released": "build_escrow_released_audit",
    "escrow_returned": "build_escrow_returned_audit",
    "escrow_disputed": "build_escrow_disputed_audit",
}


def _assert_record_shape(
    case: TestCase, record: dict[str, Any]
) -> tuple[TestStatus, str | None]:
    required_keys = case.expected.get("required_keys")
    if isinstance(required_keys, list):
        missing = [k for k in required_keys if k not in record]
        if missing:
            return "fail", f"record missing keys: {missing}"
    values = case.expected.get("values")
    if isinstance(values, dict):
        for key, want in values.items():
            got = record.get(key)
            if got != want:
                return "fail", f"{key}: expected {want!r}, got {got!r}"
    return "pass", None


def _run_build_escrow_audit(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    import arsia_protocol.assets.assets as assets_mod

    sub_type = case.input.get("sub_type")
    if not isinstance(sub_type, str):
        return "error", "input.sub_type must be a string"
    builder_name = _ESCROW_AUDIT_BUILDERS.get(sub_type)
    if builder_name is None:
        return "error", f"unknown escrow audit sub_type: {sub_type!r}"
    fields = case.input.get("fields")
    if not isinstance(fields, dict):
        return "error", "input.fields must be an object"

    builder = getattr(assets_mod, builder_name)
    try:
        record = builder(**fields)
    except TypeError as exc:
        return "error", f"{builder_name} raised: {exc}"

    want_event = case.expected.get("event_type")
    if isinstance(want_event, str) and record.get("event_type") != want_event:
        return "fail", (
            f"event_type: expected {want_event!r}, "
            f"got {record.get('event_type')!r}"
        )
    want_sub = case.expected.get("sub_type")
    if isinstance(want_sub, str) and record.get("sub_type") != want_sub:
        return "fail", f"sub_type: expected {want_sub!r}, got {record.get('sub_type')!r}"
    return _assert_record_shape(case, record)


def _run_build_reversal_audit(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import build_reversal_audit_fields

    fields = case.input.get("fields")
    if not isinstance(fields, dict):
        return "error", "input.fields must be an object"

    try:
        record = build_reversal_audit_fields(**fields)
    except TypeError as exc:
        return "error", f"build_reversal_audit_fields raised: {exc}"
    return _assert_record_shape(case, record)


def _run_validate_receipt_match(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_receipt_against_request

    request_args = case.input.get("request_args")
    receipt_result = case.input.get("receipt_result")
    if not isinstance(request_args, dict):
        return "error", "input.request_args must be an object"
    if not isinstance(receipt_result, dict):
        return "error", "input.receipt_result must be an object"
    errors = validate_receipt_against_request(
        request_args=request_args, receipt_result=receipt_result
    )
    return _check_valid(case, errors)


def _run_capability_risk_levels(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import ASSETS_CAPABILITY_RISK_LEVELS

    want = case.expected.get("levels")
    if not isinstance(want, dict):
        return "error", "expected.levels must be an object"

    got = dict(ASSETS_CAPABILITY_RISK_LEVELS)
    if got != want:
        return "fail", f"risk levels mismatch: want={want}, got={got}"
    return "pass", None


def _run_is_sca_exempt(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import is_sca_exempt

    kwargs: dict[str, Any] = {}
    for key in ("amount", "currency", "beneficiary_trusted", "recurring", "tra_risk_level"):
        if key in case.input:
            kwargs[key] = case.input[key]

    try:
        exempt, reason = is_sca_exempt(**kwargs)
    except TypeError as exc:
        return "error", f"is_sca_exempt raised: {exc}"

    want_exempt = case.expected.get("exempt")
    if not isinstance(want_exempt, bool):
        return "error", "expected.exempt must be a bool"
    if exempt != want_exempt:
        return "fail", f"exempt: expected {want_exempt}, got {exempt}"
    want_reason = case.expected.get("reason")
    if isinstance(want_reason, str) and reason != want_reason:
        return "fail", f"reason: expected {want_reason!r}, got {reason!r}"
    return "pass", None


def _run_validate_token_scope(
    case: TestCase, context: ConformanceContext
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.assets.assets import validate_assets_token_scope

    scope = case.input.get("scope")
    if not isinstance(scope, list):
        return "error", "input.scope must be a list of strings"
    errors = validate_assets_token_scope(scope)
    return _check_valid(case, errors)


_OPERATIONS = {
    "validate_transfer_request": _run_validate_transfer_request,
    "validate_transfer_receipt": _run_validate_transfer_receipt,
    "validate_transfer_reversal": _run_validate_transfer_reversal,
    "validate_reversal_precondition": _run_validate_reversal_precondition,
    "validate_escrow_conditions": _run_validate_escrow_conditions,
    "escrow_transition": _run_escrow_transition,
    "two_party_auth": _run_two_party_auth,
    "requires_psd2_sca": _run_requires_psd2_sca,
    "classify_dora_incident": _run_classify_dora_incident,
    "build_dora_incident": _run_build_dora_incident,
    "validate_psd2_sca_factors": _run_validate_psd2_sca_factors,
    "enforce_mifid_retention": _run_enforce_mifid_retention,
    "validate_escrow_dispute": _run_validate_escrow_dispute,
    "validate_escrow_cancel": _run_validate_escrow_cancel,
    "build_escrow_audit": _run_build_escrow_audit,
    "build_reversal_audit": _run_build_reversal_audit,
    "validate_receipt_match": _run_validate_receipt_match,
    "capability_risk_levels": _run_capability_risk_levels,
    "is_sca_exempt": _run_is_sca_exempt,
    "validate_token_scope": _run_validate_token_scope,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.assets.assets  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol.assets import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for assets cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown assets operation: {operation!r}"
    return handler(case, context)


__all__ = ["execute"]
