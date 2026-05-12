# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``onboarding`` category.

Dispatches on ``input.operation``:

- ``evaluate_policy`` — §8.3 deny-by-default evaluation. Asserts on
  ``expected.approved`` + optional ``expected.freely_allowed`` /
  ``expected.oversight_required`` / ``expected.denied`` /
  ``expected.denial_reason``. Prohibited capabilities are merged
  into ``denied`` per §8.3, so there is no separate
  ``expected.prohibited`` field.
- ``validate_policy`` — structural validation of a
  :class:`CapabilityPolicy`. Asserts on ``expected.valid`` and
  optional ``expected.error_contains``.
- ``validate_profile_requirement`` — §4.2 profile-declaration rule
  (high-risk MUST declare profile, unacceptable-risk MUST NOT be
  onboarded, ``error``/``event`` intents exempt). Asserts on
  ``expected.valid`` and optional ``expected.error_contains``.
- ``is_classification_consistent`` — §4.3.8 Rule 6 rank
  predicate. Asserts on ``expected.consistent`` (bool).
- ``verify_provenance`` — §7.5 informational summary. Asserts on
  ``expected.verified`` and optional
  ``expected.notes_contain``.
- ``build_decision_payload`` — full §7.6 flow: runs
  ``evaluate_capability_policy`` + ``build_onboarding_decision``
  + ``build_decision_payload`` and asserts on ``expected.outcome``
  + optional ``expected.required_keys`` / ``expected.absent_keys``.
- ``get_audit_events`` — read-only sanity check on
  :data:`ONBOARDING_AUDIT_EVENTS`. Asserts on
  ``expected.event_names``.

Policies are inlined in the YAML as plain dicts and passed to
:class:`CapabilityPolicy.model_validate`, keeping the suite runnable
from any language that has Pydantic-equivalent models (or a TS
implementation of :mod:`arsia_protocol.types.routing`).
"""

from __future__ import annotations

from typing import Any, cast

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _check_valid(
    case: TestCase, errors: list[str]
) -> tuple[TestStatus, str | None]:
    """Shared ``expected.valid`` / ``expected.error_contains`` check."""
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
            return (
                "fail",
                f"no error mentioned {keyword!r}; errors={errors}",
            )
    return "pass", None


def _build_policy(policy_input: Any) -> Any:
    from arsia_protocol.types.routing import CapabilityPolicy

    return CapabilityPolicy.model_validate(policy_input)


def _run_evaluate_policy(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.onboarding import evaluate_capability_policy

    policy_input = case.input.get("policy")
    if not isinstance(policy_input, dict):
        return "error", "input.policy must be an object for evaluate_policy"
    requested = case.input.get("requested_capabilities", [])
    if not isinstance(requested, list):
        return "error", "input.requested_capabilities must be a list"
    try:
        policy = _build_policy(policy_input)
    except Exception as exc:  # noqa: BLE001 - report as test error
        return "error", f"policy is not a valid CapabilityPolicy: {exc}"

    risk_levels_raw = case.input.get("action_risk_levels")
    action_risk_levels: dict[str, int] | None = None
    if isinstance(risk_levels_raw, dict):
        action_risk_levels = {str(k): int(v) for k, v in risk_levels_raw.items()}

    result = evaluate_capability_policy(
        policy,
        [str(c) for c in requested],
        action_risk_levels=action_risk_levels,
    )

    want_approved = case.expected.get("approved")
    if isinstance(want_approved, bool) and result.is_approved != want_approved:
        return (
            "fail",
            f"approved: expected {want_approved}, got {result.is_approved}",
        )

    for field_name, expected_key in (
        ("freely_allowed", "freely_allowed"),
        ("oversight_required", "oversight_required"),
        ("denied", "denied"),
    ):
        want = case.expected.get(expected_key)
        if isinstance(want, list):
            got = list(getattr(result, field_name))
            if sorted(got) != sorted(str(c) for c in want):
                return (
                    "fail",
                    f"{expected_key}: expected {sorted(want)}, got {sorted(got)}",
                )

    want_reason = case.expected.get("denial_reason")
    if want_reason is not None:
        if result.denial_reason != want_reason:
            return (
                "fail",
                f"denial_reason: expected {want_reason!r}, "
                f"got {result.denial_reason!r}",
            )

    return "pass", None


def _run_validate_policy(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.onboarding import validate_capability_policy

    policy_input = case.input.get("policy")
    if not isinstance(policy_input, dict):
        return "error", "input.policy must be an object for validate_policy"
    try:
        policy = _build_policy(policy_input)
    except Exception as exc:  # noqa: BLE001
        # The Pydantic validation step can itself detect violations —
        # treat that as a structural rejection so we can exercise the
        # whole pipeline from a YAML file.
        if not bool(case.expected.get("valid", True)):
            return "pass", None
        return "error", f"policy failed to build: {exc}"

    errors = validate_capability_policy(policy)
    return _check_valid(case, errors)


def _run_validate_profile_requirement(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.onboarding import validate_profile_requirement

    identity_classification = case.input.get("identity_classification")
    if not isinstance(identity_classification, str):
        return "error", "input.identity_classification is required"
    declared_profile = case.input.get("declared_profile")
    if declared_profile is not None and not isinstance(declared_profile, str):
        return "error", "input.declared_profile must be a string or null"
    intent = case.input.get("intent")
    if intent is not None and not isinstance(intent, str):
        return "error", "input.intent must be a string or null"

    errors = validate_profile_requirement(
        identity_classification=identity_classification,
        declared_profile=declared_profile,
        intent=intent,
    )
    return _check_valid(case, errors)


def _run_is_classification_consistent(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.onboarding import is_classification_consistent

    per_message = case.input.get("per_message_classification")
    if not isinstance(per_message, str):
        return "error", "input.per_message_classification is required"
    identity = case.input.get("identity_classification")
    if not isinstance(identity, str):
        return "error", "input.identity_classification is required"

    result = is_classification_consistent(per_message, identity)

    want = case.expected.get("consistent")
    if not isinstance(want, bool):
        return "error", "expected.consistent must be a boolean"
    if result != want:
        return (
            "fail",
            f"consistent: expected {want}, got {result} "
            f"(per_message={per_message!r}, identity={identity!r})",
        )
    return "pass", None


def _run_verify_provenance(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.onboarding import verify_provenance

    identity_created_at = case.input.get("identity_created_at")
    earliest_audit_record = case.input.get("earliest_audit_record")
    if identity_created_at is not None and not isinstance(
        identity_created_at, str
    ):
        return "error", "input.identity_created_at must be a string or null"
    if earliest_audit_record is not None and not isinstance(
        earliest_audit_record, str
    ):
        return "error", "input.earliest_audit_record must be a string or null"

    result = verify_provenance(
        identity_created_at=identity_created_at,
        earliest_audit_record=earliest_audit_record,
    )

    want_verified = case.expected.get("verified")
    if isinstance(want_verified, bool) and result.provenance_verified != want_verified:
        return (
            "fail",
            f"verified: expected {want_verified}, got {result.provenance_verified}",
        )

    notes_contain = case.expected.get("notes_contain")
    if isinstance(notes_contain, str) and notes_contain:
        keyword = notes_contain.lower()
        if not any(keyword in n.lower() for n in result.notes):
            return (
                "fail",
                f"no note mentioned {notes_contain!r}; notes={list(result.notes)}",
            )

    return "pass", None


def _run_build_decision_payload(
    case: TestCase,
) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.onboarding import (
        DenialReason,
        OnboardingPhase,
        build_decision_payload,
        build_onboarding_decision,
        evaluate_capability_policy,
    )

    policy_input = case.input.get("policy")
    if not isinstance(policy_input, dict):
        return "error", "input.policy must be an object for build_decision_payload"
    requested = case.input.get("requested_capabilities", [])
    if not isinstance(requested, list):
        return "error", "input.requested_capabilities must be a list"
    agent_id = case.input.get("agent_id")
    if not isinstance(agent_id, str):
        return "error", "input.agent_id must be a string"

    upstream_raw = case.input.get("denial_reasons") or []
    if not isinstance(upstream_raw, list):
        return "error", "input.denial_reasons must be a list or null"
    phase_raw = case.input.get("phase", "decision")
    if not isinstance(phase_raw, str):
        return "error", "input.phase must be a string"

    try:
        policy = _build_policy(policy_input)
    except Exception as exc:  # noqa: BLE001
        return "error", f"policy is not a valid CapabilityPolicy: {exc}"

    evaluation = evaluate_capability_policy(
        policy, [str(c) for c in requested]
    )
    # The YAML input carries strings; cast to the Literal unions the
    # builder expects. An unknown value would be caught by the type
    # checker in-SDK, not here.
    upstream_reasons = cast("list[DenialReason]", [str(r) for r in upstream_raw])
    phase = cast("OnboardingPhase", phase_raw)
    try:
        decision = build_onboarding_decision(
            agent_id=agent_id,
            policy=policy,
            evaluation=evaluation,
            denial_reasons=upstream_reasons,
            phase=phase,
        )
    except ValueError as exc:
        return "fail", f"build_onboarding_decision raised: {exc}"

    payload = build_decision_payload(decision)

    want_outcome = case.expected.get("outcome")
    if isinstance(want_outcome, str) and payload["outcome"] != want_outcome:
        return (
            "fail",
            f"outcome: expected {want_outcome!r}, got {payload['outcome']!r}",
        )

    required_keys = case.expected.get("required_keys")
    if isinstance(required_keys, list):
        missing = [k for k in required_keys if k not in payload]
        if missing:
            return "fail", f"payload missing required keys: {missing}"

    absent_keys = case.expected.get("absent_keys")
    if isinstance(absent_keys, list):
        present = [k for k in absent_keys if k in payload]
        if present:
            return "fail", f"payload contains forbidden keys: {present}"

    required_denial_reasons = case.expected.get("denial_reasons")
    if isinstance(required_denial_reasons, list):
        got = payload.get("denial_reasons") or []
        if sorted(str(r) for r in got) != sorted(
            str(r) for r in required_denial_reasons
        ):
            return (
                "fail",
                f"denial_reasons: expected {required_denial_reasons}, got {got}",
            )

    want_phase = case.expected.get("phase")
    if isinstance(want_phase, str):
        got_phase = payload.get("phase")
        if got_phase != want_phase:
            return (
                "fail",
                f"phase: expected {want_phase!r}, got {got_phase!r}",
            )

    want_decision = case.expected.get("decision")
    if isinstance(want_decision, str):
        got_decision = payload.get("decision")
        if got_decision != want_decision:
            return (
                "fail",
                f"decision: expected {want_decision!r}, got {got_decision!r}",
            )

    return "pass", None


def _run_get_audit_events(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.onboarding import ONBOARDING_AUDIT_EVENTS

    want_names = case.expected.get("event_names")
    if not isinstance(want_names, list):
        return "error", "expected.event_names must be a list"
    got = sorted(ONBOARDING_AUDIT_EVENTS.keys())
    if got != sorted(str(n) for n in want_names):
        return "fail", f"event_names: expected {sorted(want_names)}, got {got}"

    # Also verify every payload_type is namespaced under the onboarding prefix.
    prefix = "arsiaprotocol/audit.onboarding."
    bad = [
        (k, v) for k, v in ONBOARDING_AUDIT_EVENTS.items() if not v.startswith(prefix)
    ]
    if bad:
        return "fail", f"payload_type not namespaced: {bad}"
    return "pass", None


_OPERATIONS = {
    "evaluate_policy": _run_evaluate_policy,
    "validate_policy": _run_validate_policy,
    "check_profile_requirement": _run_validate_profile_requirement,
    "check_classification_consistency": _run_is_classification_consistent,
    "verify_provenance": _run_verify_provenance,
    "build_decision_payload": _run_build_decision_payload,
    "get_audit_events": _run_get_audit_events,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    try:
        import arsia_protocol.identity.onboarding  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        return "error", f"arsia_protocol.onboarding import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for onboarding cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown onboarding operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
