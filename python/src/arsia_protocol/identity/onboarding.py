# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""External-agent onboarding primitive (ARSIA-Identity.md §7).

This module is Layer 4 in the SDK dependency graph and is the widest
of the Layer 4 primitives: it composes :mod:`arsia_protocol.types`,
:mod:`arsia_protocol.identity`, :mod:`arsia_protocol.actions`, and
:mod:`arsia_protocol.compliance` to model the onboarding flow
from §7. It does **not** implement the HTTP orchestration — the
SDK ships a transport-agnostic *data* surface that a consumer gateway
(see ``arsiactl``) can drive.

Scope
-----

The spec defines six phases (§7.1):

1. **Phase 1 — Discovery & Identity** (§7.2). SIX spec steps: fetch
   ``/.well-known/arsia``, fetch the :class:`IdentityRecord`, fetch the
   JWKS, verify the identity signature, match ``kid`` prefix, record
   the agent-level classification. Transport-bound; SDK exposes
   :mod:`arsia_protocol.discovery` and
   :func:`arsia_protocol.authorization.verify_jwt_signature` as the
   building blocks. This module adds two classification helpers:

   - :func:`is_classification_consistent` — the §4.3.8 Rule 6
     rank-comparison check (per-message ≤ identity).
   - :func:`validate_profile_requirement` — the §4.2 profile-declaration
     check (high-risk agents MUST declare a profile,
     unacceptable-risk MUST NOT be onboarded, ``error``/``event``
     intents exempt).

2. **Phase 2 — Compliance Conformance** (§7.3). CHECK-01 .. CHECK-05.
   Pure data checks performed by consumers with
   :func:`arsia_protocol.validation.validate_envelope` and
   :func:`arsia_protocol.compliance.validate_compliance`; no helper is
   needed here.
3. **Phase 3 — Capability Scoping** (§7.4). Driven by
   :class:`~arsia_protocol.types.routing.CapabilityPolicy`. The §8.3
   deny-by-default evaluation procedure is the core deliverable of
   this module: :func:`evaluate_capability_policy`.
4. **Phase 4 — Provenance** (§7.5). Informational, not a gate:
   compare the agent's ``identity_created_at`` against the earliest
   audit record the gateway has seen and expose the delta.
   :func:`verify_provenance`.
5. **Phase 5 — Decision** (§7.6). Assemble the ``approval_decision``
   payload that the gateway will wrap in
   :func:`arsia_protocol.message.create_approval_decision`.
   :func:`build_decision_payload` + :func:`build_onboarding_decision`.
6. **Phase 6 — Operational** (§7.7). Once onboarded, the external
   agent messages through the bearer-token path already implemented
   in :mod:`arsia_protocol.authorization`. No helper lives here.

Two classification rules, two helpers
-------------------------------------

§4.2 (Classification Consistency Rule in ARSIA-Identity.md) and
§4.3.8 Rule 6 (Classification Escalation in ARSIA-Core.md) are
**different** rules that happen to live near the same topic. We
expose each under its own name so the spec-to-code trace is
unambiguous:

- :func:`is_classification_consistent(per_message, identity)` —
  the R6 rank check. Returns ``True`` when the per-message
  ``ai_system_classification`` rank is ≤ the identity-level rank,
  ``False`` otherwise (or when either classification is unknown).
  This is the exact semantics that
  :func:`arsia_protocol.compliance.validate_compliance` enforces as
  R6; exposing it as a pure predicate lets consumers gate decisions
  without dragging in the full six-rule engine.
- :func:`validate_profile_requirement(*, identity_classification,
  declared_profile, intent)` — the §4.2 profile-declaration rule.
  Returns a ``list[ValidationError]`` (empty means consistent)
  so callers can surface the reason on rejection.

Dependency boundary
-------------------

Onboarding deliberately does **not** import
:mod:`arsia_protocol.audit`. The §9.3 audit event table is exposed
as the read-only mapping :data:`ONBOARDING_AUDIT_EVENTS`: consumers
feed each event's ``payload_type`` value into
:func:`arsia_protocol.audit.build_audit_record` (Layer 5) themselves
to produce the record. Keeping onboarding free of the audit import
preserves the one-way Layer 4 → Layer 5 edge — onboarding is a
decision producer, and audit records are built from the decision's
envelope, not from within onboarding.

It also deliberately does NOT import :mod:`arsia_protocol.authorization`
even though Phase 5 issues an access token: the JWT is built
by :func:`arsia_protocol.authorization.build_jwt` and passed into
:func:`build_onboarding_decision` as the ``token`` parameter (§7.6
requires it in the approval payload). Keeping the two modules
uncoupled means a consumer that only wants the decision-payload
builder doesn't pay for the JWT machinery.

Two wildcards to watch for
--------------------------

The onboarding flow touches two risk vocabularies that must not be
confused:

- The **4-level classification hierarchy** (``minimal-risk`` →
  ``unacceptable-risk``) from :data:`arsia_protocol.compliance.CLASSIFICATION_HIERARCHY`.
  This is the EU AI Act agent-level risk category used by §4.2 and
  §4.3.8 Rule 6.
- The **5-bucket risk classification** (``minimal`` → ``critical``)
  from :data:`arsia_protocol.actions.RISK_LEVEL_CLASSIFICATION`. This
  is the per-action scoring derived from ``risk_level`` integers 0-10
  and has nothing to do with the agent-level hierarchy.

The :class:`~arsia_protocol.types.routing.CapabilityRule.max_risk_level`
field (§8.2) is an **invocation-time** regulator that belongs to the
5-bucket vocabulary. §8.3 (policy-scoping-time evaluation) does NOT
reference ``max_risk_level``, and :func:`evaluate_capability_policy`
therefore ignores it. A separate ``check_invocation_risk`` helper can
be added when a later slice wires up action-dispatch.

Spec: ARSIA-Identity.md §7, §8, §9.3; ARSIA-Core.md §4.2, §4.3.8.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Final, Literal, Mapping, get_args

from arsia_protocol._errors import ValidationError

from arsia_protocol.actions.actions import (
    match_capability,
    validate_capability,
)
from arsia_protocol.core.compliance import (
    CLASSIFICATION_HIERARCHY,
    _is_profile_required_for_classification,
)
from arsia_protocol.identity.agent_id import is_valid_agent_id
from arsia_protocol.types.routing import CapabilityPolicy, CapabilityRuleStatus

# ----------------------------------------------------------------------
# Public literals
# ----------------------------------------------------------------------

ONBOARDING_EVALUATE_CAPABILITY: Final[str] = "arsiaprotocol.onboarding.evaluate"
"""Capability string required to invoke the onboarding evaluation flow.

Spec: ARSIA-Identity.md §7.1.1.
"""

CapabilityStatus = CapabilityRuleStatus
"""Re-export of :data:`arsia_protocol.types.routing.CapabilityRuleStatus`.

Alias to the Literal-union that
:attr:`~arsia_protocol.types.routing.CapabilityRule.status` uses
(``"allowed" | "oversight_required" | "prohibited"``). Exposed from
``onboarding`` so consumers that only import this module do not need
to reach into ``types.routing`` for the status vocabulary.

Spec: ARSIA-Identity.md §8.2.
"""

OnboardingPhase = Literal[
    "discovery_and_identity",
    "compliance_conformance",
    "capability_scoping",
    "provenance",
    "decision",
    "operational",
]
"""The six phases from ARSIA-Identity.md §7.1.

Used as a tag on audit records and on :class:`OnboardingDecision`
failures so the gateway can attribute a rejection to the specific
phase that raised it.
"""

OnboardingOutcome = Literal["approved", "denied"]
"""Terminal outcome of the onboarding flow (§7.6)."""

DenialReason = Literal[
    "discovery_failed",
    "identity_verification_failed",
    "unacceptable_risk_classification",
    "conformance_failed",
    "no_permitted_capabilities",
]
"""Denial reasons enumerated by §7.6 + §8.3.

``no_permitted_capabilities`` is the specific denial raised by
:func:`evaluate_capability_policy` when the intersection of
requested-capabilities and freely-allowed-or-oversight-required
capabilities is empty (§8.3 step 5).
"""

# ----------------------------------------------------------------------
# §9.3 audit event table
# ----------------------------------------------------------------------

_ONBOARDING_AUDIT_EVENTS: dict[str, str] = {
    "approval_decision": "arsiaprotocol/audit.onboarding.approval_decision",
    "agent_onboarded": "arsiaprotocol/audit.onboarding.agent_onboarded",
    "agent_rejected": "arsiaprotocol/audit.onboarding.agent_rejected",
    "capability_granted": "arsiaprotocol/audit.onboarding.capability_granted",
    "capability_revoked": "arsiaprotocol/audit.onboarding.capability_revoked",
    "token_issued": "arsiaprotocol/audit.onboarding.token_issued",
    "token_revoked": "arsiaprotocol/audit.onboarding.token_revoked",
}

ONBOARDING_AUDIT_EVENTS: Final[Mapping[str, str]] = MappingProxyType(
    _ONBOARDING_AUDIT_EVENTS
)
"""Read-only mapping of onboarding audit event names to ``payload_type`` strings.

The six entries mirror the table in ARSIA-Identity.md §9.3. Consumers
feed the ``payload_type`` value into
:func:`arsia_protocol.audit.build_audit_record` to produce a record
for each onboarding event.

Spec: ARSIA-Identity.md §9.3.
"""

# ----------------------------------------------------------------------
# Frozen dataclasses (result envelopes)
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityEvaluationResult:
    """Outcome of :func:`evaluate_capability_policy`.

    Matches the immutability/accumulation pattern of
    :class:`arsia_protocol.certificates.CertificateVerificationResult`
    and :class:`arsia_protocol.authorization.TokenValidationResult`.

    The field names track ARSIA-Identity.md §8.3 vocabulary exactly:
    §8.3 partitions capabilities into ``freely_allowed`` (status
    ``"allowed"``) and ``oversight_required`` (status
    ``"oversight_required"``), and treats every other outcome —
    explicit ``"prohibited"`` rules AND capabilities not listed at all
    — as rejected. This class therefore exposes a single ``denied``
    tuple that collects both cases, with prohibited entries first (in
    source order) followed by deny-by-default entries. Callers that
    need to distinguish the two should compare against the policy
    directly; the evaluation result is deliberately spec-shaped.

    Attributes:
        is_approved: ``True`` when at least one requested capability
            is in the effective set (``freely_allowed`` ∪
            ``oversight_required``) **and** no requested capability
            was explicitly prohibited by the policy.
        freely_allowed: Capabilities the agent may invoke freely
            (status ``"allowed"``). Subset of the input ``requested``
            list; matches the §8.3 "freely_allowed" set name.
        oversight_required: Capabilities the agent may invoke only
            with prior human oversight (status ``"oversight_required"``).
            Subset of the input ``requested`` list.
        denied: Every requested capability that is NOT in the
            effective set — both explicit ``"prohibited"`` matches and
            deny-by-default matches. Ordered: prohibited entries
            first, deny-by-default entries second, both in source
            order (§8.3 step 3 before step 4).
        denial_reason: Populated when ``is_approved`` is ``False``.
            ``"no_permitted_capabilities"`` is the §8.3 step 5 reason.

    Spec: ARSIA-Identity.md §7.4, §8.3.
    """

    is_approved: bool
    freely_allowed: tuple[str, ...]
    oversight_required: tuple[str, ...]
    denied: tuple[str, ...]
    denial_reason: DenialReason | None = None


@dataclass(frozen=True)
class ProvenanceResult:
    """Informational provenance summary for Phase 4.

    Phase 4 is not a gate (§7.5): it never blocks onboarding, but the
    gateway SHOULD record the delta between the agent's
    ``identity_created_at`` and the earliest audit record observed, so
    consumers can spot agents whose identity is much younger than
    their operational history.

    Attributes:
        provenance_verified: ``True`` when every structural
            precondition holds (timestamps parseable, ordering sane).
            A ``False`` value is surfaced to the gateway as a warning,
            not a rejection.
        earliest_audit_record: The timestamp the gateway passed in
            (echoed so ``OnboardingDecision`` can embed it).
        identity_created_at: The timestamp from the agent's
            :class:`IdentityRecord` (echoed).
        delta_seconds: ``earliest_audit_record − identity_created_at``
            in seconds when both are present; ``None`` otherwise.
        notes: Any ``WARN:``-prefixed strings describing why
            ``provenance_verified`` is ``False`` or pointing at
            suspicious deltas.

    Spec: ARSIA-Identity.md §7.5.
    """

    provenance_verified: bool
    earliest_audit_record: str | None
    identity_created_at: str | None
    delta_seconds: int | None
    notes: tuple[str, ...]


@dataclass(frozen=True)
class OnboardingDecision:
    """The final Phase 5 decision (§7.6).

    Attributes:
        outcome: ``"approved"`` or ``"denied"``.
        agent_id: The onboarded (or rejected) agent's identifier.
        policy_version: The ``policy_version`` from the
            :class:`CapabilityPolicy` evaluated in Phase 3.
        granted_capabilities: Capabilities the decision authorises.
            Empty tuple on denial. Matches the §7.6 decision payload
            field name (which speaks of "granted" at the decision
            level even though §8.3 speaks of "freely_allowed" at the
            evaluation level — the rename is intentional per §7.6's
            prose).
        oversight_required: Capabilities authorised only under human
            oversight. Empty tuple on denial.
        token_lifetime_seconds: Lifetime the issued access token will
            carry (copied from the evaluated policy). Zero on denial.
        denial_reasons: Non-empty exactly when ``outcome=="denied"``.
        phase: The phase in which the decision was reached. Approvals
            always report ``"decision"``; denials report the phase
            that raised the rejection.
        token: JWT access token whose ``scope`` claim includes the
            granted capabilities. Present on approval, ``None`` on
            denial. Spec: §7.6.
        token_expires_at: Token expiry in RFC 3339 format. Present on
            approval, ``None`` on denial. Spec: §7.6.

    Spec: ARSIA-Identity.md §7.6.
    """

    outcome: OnboardingOutcome
    agent_id: str
    policy_version: str
    granted_capabilities: tuple[str, ...]
    oversight_required: tuple[str, ...]
    token_lifetime_seconds: int
    denial_reasons: tuple[DenialReason, ...]
    phase: OnboardingPhase
    token: str | None = None
    token_expires_at: str | None = None


# ----------------------------------------------------------------------
# Phase 1 — classification helpers
# ----------------------------------------------------------------------


def is_classification_consistent(
    per_message_classification: str,
    identity_classification: str,
) -> bool:
    """Return ``True`` iff ``per_message ≤ identity`` in the §4.3.8 R6 sense.

    ARSIA-Core.md §4.3.8 Rule 6 (Classification Escalation) forbids a
    single message from declaring a classification *higher* than the
    sender's agent-level ``ai_system_classification``. In other words,
    an agent registered as ``minimal-risk`` cannot retroactively
    escalate itself to ``high-risk`` via a per-message claim. The
    reverse — downgrading a high-risk agent's single message to
    ``minimal-risk`` — is allowed because nothing in R6 prevents an
    agent from *under*-claiming risk on a benign envelope.

    This helper exposes the R6 predicate directly, independent of the
    full six-rule engine in :func:`arsia_protocol.compliance.validate_compliance`.
    It is intended for call sites that need to gate a decision on
    this one rule without triggering the other five
    (e.g. a router deciding whether to forward a message before it
    has the receiver's compliance profile loaded).

    This is a **different** rule from
    :func:`validate_profile_requirement`, which implements the §4.2
    Classification Consistency Rule (a profile-declaration rule, not
    a rank-comparison rule).

    Args:
        per_message_classification: The
            ``ai_system_classification`` value carried on the
            individual message (``compliance.ai_system_classification``).
        identity_classification: The ``ai_system_classification``
            declared on the sender's :class:`IdentityRecord`.

    Returns:
        ``True`` if the per-message rank is ≤ the identity rank
        (consistent / downgrade / equal). ``False`` if the per-message
        rank is strictly greater (escalation) **or** if either
        classification is unknown (conservative).

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    if per_message_classification not in CLASSIFICATION_HIERARCHY:
        return False
    if identity_classification not in CLASSIFICATION_HIERARCHY:
        return False
    message_rank = CLASSIFICATION_HIERARCHY.index(per_message_classification)
    identity_rank = CLASSIFICATION_HIERARCHY.index(identity_classification)
    return message_rank <= identity_rank


def validate_profile_requirement(
    *,
    identity_classification: str,
    declared_profile: str | None,
    intent: str | None = None,
) -> list[ValidationError]:
    """Enforce the §4.2 Classification Consistency Rule (profile declaration).

    §4.2 requires that:

    - An agent whose :class:`IdentityRecord` declares
      ``ai_system_classification == "high-risk"`` MUST carry a
      compliance profile on every request and MUST therefore have a
      declared profile resolvable at Phase 2 time.
    - An agent whose classification is ``"unacceptable-risk"`` MUST
      NOT be onboarded at all.
    - Intents ``"error"`` and ``"event"`` are exempt from this rule
      (they are operational envelopes, not business requests).

    This is a distinct rule from §4.3.8 Rule 6 (classification
    escalation on an individual message), which is implemented by
    :func:`is_classification_consistent` (and equivalently by
    :func:`arsia_protocol.compliance.validate_compliance`). Callers
    should run both checks: R6 catches per-message rank escalation,
    this function catches agent-level configuration mistakes.

    Args:
        identity_classification: ``ai_system_classification`` from the
            sender's :class:`IdentityRecord`.
        declared_profile: The compliance profile the agent declared
            (or ``None`` when no profile is declared).
        intent: The envelope intent being onboarded against. Passing
            ``"error"`` or ``"event"`` skips the profile check for
            high-risk agents per §4.2.

    Returns:
        A list of validation errors. Empty means consistent.

    Spec: ARSIA-Identity.md §4.2.
    """
    errors: list[ValidationError] = []

    if identity_classification not in CLASSIFICATION_HIERARCHY:
        errors.append(
            ValidationError(
                code="unknown_classification",
                message=f"unknown identity classification {identity_classification!r} — expected one of {list(CLASSIFICATION_HIERARCHY)}",
                details={
                    "classification": identity_classification,
                    "valid": list(CLASSIFICATION_HIERARCHY),
                },
                spec_ref="Identity §4.2",
            )
        )
        return errors

    if identity_classification == "unacceptable-risk":
        errors.append(
            ValidationError(
                code="unacceptable_risk",
                message="agent with identity classification 'unacceptable-risk' MUST NOT be onboarded",
                spec_ref="Identity §4.2",
            )
        )
        return errors

    if _is_profile_required_for_classification(identity_classification, intent):
        if declared_profile is None:
            errors.append(
                ValidationError(
                    code="profile_required",
                    message="high-risk agents MUST declare a compliance profile",
                    spec_ref="Identity §4.2",
                )
            )

    return errors


# ----------------------------------------------------------------------
# Phase 2 — Compliance Conformance CHECKs (§7.3)
# ----------------------------------------------------------------------

_UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_ARSIA_AUDIT_RECORD_REQUIRED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "record_id",
        "message_id",
        "event_type",
        "from_agent",
        "to_agent",
        "intent",
        "payload_type",
        "payload_hash",
        "compliance_profile",
        "processed_at",
        "retained_until",
        "operator_id",
    }
)


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single Phase 2 CHECK validator.

    Attributes:
        check_id: Short label (e.g. ``"CHECK-01"``).
        status: ``"pass"``, ``"fail"``, or ``"skip"``.
        errors: Non-empty only when ``status == "fail"``.
    """

    check_id: str
    status: Literal["pass", "fail", "skip"]
    errors: tuple[ValidationError, ...] = ()


def check_correlation_id(
    response_envelope: Mapping[str, Any],
    expected_request_id: str,
) -> CheckResult:
    """CHECK-01/CHECK-03: correlation_id MUST match request id.

    Spec: ARSIA-Identity.md §7.3 — CHECK-01 step 2, CHECK-03 step 2.
    """
    correlation_id = response_envelope.get("correlation_id")
    if correlation_id is None:
        return CheckResult(
            check_id="CHECK-CORR",
            status="fail",
            errors=(
                ValidationError(
                    code="missing_correlation_id",
                    message="response envelope is missing correlation_id",
                    details={"field": "correlation_id"},
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    if correlation_id != expected_request_id:
        return CheckResult(
            check_id="CHECK-CORR",
            status="fail",
            errors=(
                ValidationError(
                    code="correlation_mismatch",
                    message=(
                        f"correlation_id {correlation_id!r} does not match "
                        f"request id {expected_request_id!r}"
                    ),
                    details={
                        "correlation_id": correlation_id,
                        "request_id": expected_request_id,
                    },
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    return CheckResult(check_id="CHECK-CORR", status="pass")


def check_discovery_response(response: Mapping[str, Any]) -> CheckResult:
    """CHECK: discovery response MUST include agent_id, protocol_version, capabilities.

    Spec: ARSIA-Identity.md §7.2.
    """
    errors: list[ValidationError] = []
    for f in ("agent_id", "protocol_version", "capabilities"):
        if f not in response:
            errors.append(
                ValidationError(
                    code="discovery_missing_field",
                    message=f"discovery response missing required field {f!r}",
                    details={"field": f},
                    spec_ref="Identity §7.2",
                )
            )
    if errors:
        return CheckResult(check_id="CHECK-DISC", status="fail", errors=tuple(errors))
    return CheckResult(check_id="CHECK-DISC", status="pass")


def check_envelope_id(envelope: Mapping[str, Any]) -> CheckResult:
    """CHECK-01: id field MUST be a valid UUID.

    Spec: ARSIA-Identity.md §7.3.
    """
    id_value = envelope.get("id")
    if id_value is None:
        return CheckResult(
            check_id="CHECK-01",
            status="fail",
            errors=(
                ValidationError(
                    code="envelope_missing_id",
                    message="envelope missing 'id' field",
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    if not isinstance(id_value, str) or not _UUID_V4_RE.fullmatch(id_value):
        return CheckResult(
            check_id="CHECK-01",
            status="fail",
            errors=(
                ValidationError(
                    code="envelope_id_invalid",
                    message=f"id {id_value!r} is not a valid UUID v4",
                    details={"id": id_value},
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    return CheckResult(check_id="CHECK-01", status="pass")


def check_envelope_required_fields(envelope: Mapping[str, Any]) -> CheckResult:
    """CHECK-01: v, ts, from, to fields MUST be present.

    Spec: ARSIA-Identity.md §7.3.
    """
    errors: list[ValidationError] = []
    for f in ("v", "ts", "from", "to"):
        if f not in envelope:
            errors.append(
                ValidationError(
                    code="envelope_missing_field",
                    message=f"envelope missing required field {f!r}",
                    details={"field": f},
                    spec_ref="Identity §7.3",
                )
            )
    if errors:
        return CheckResult(check_id="CHECK-01", status="fail", errors=tuple(errors))
    return CheckResult(check_id="CHECK-01", status="pass")


def check_pending_approval(envelope: Mapping[str, Any]) -> CheckResult:
    """CHECK-03: external agent MUST respond with pending_approval.

    Spec: ARSIA-Identity.md §7.3, ARSIA-Actions.md §3.2.
    """
    intent = envelope.get("intent")
    if intent != "pending_approval":
        return CheckResult(
            check_id="CHECK-03",
            status="fail",
            errors=(
                ValidationError(
                    code="envelope_intent_invalid",
                    message=f"expected intent 'pending_approval', got {intent!r}",
                    details={"intent": intent, "expected": "pending_approval"},
                    spec_ref="Identity §7.3, Actions §3.2",
                ),
            ),
        )
    return CheckResult(check_id="CHECK-03", status="pass")


def check_expires_at(envelope: Mapping[str, Any]) -> CheckResult:
    """CHECK-03: expires_at MUST be present and set to a future timestamp.

    Spec: ARSIA-Identity.md §7.3.
    """
    expires_at = envelope.get("expires_at")
    if expires_at is None:
        return CheckResult(
            check_id="CHECK-03",
            status="fail",
            errors=(
                ValidationError(
                    code="envelope_expires_at_missing",
                    message="expires_at field is missing",
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    if not isinstance(expires_at, str):
        return CheckResult(
            check_id="CHECK-03",
            status="fail",
            errors=(
                ValidationError(
                    code="envelope_expires_at_invalid_type",
                    message=f"expires_at must be a string, got {type(expires_at).__name__}",
                    details={"type": type(expires_at).__name__},
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    try:
        ts = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return CheckResult(
            check_id="CHECK-03",
            status="fail",
            errors=(
                ValidationError(
                    code="envelope_expires_at_invalid_format",
                    message=f"expires_at {expires_at!r} is not a valid RFC 3339 timestamp",
                    details={"expires_at": expires_at},
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    now = datetime.now(tz=timezone.utc)
    if ts <= now:
        return CheckResult(
            check_id="CHECK-03",
            status="fail",
            errors=(
                ValidationError(
                    code="envelope_expires_at_past",
                    message=f"expires_at {expires_at!r} is not a future timestamp",
                    details={"expires_at": expires_at},
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    return CheckResult(check_id="CHECK-03", status="pass")


def check_audit_records_array(response: Any) -> CheckResult:
    """CHECK-04: response MUST be a JSON array of audit records.

    Spec: ARSIA-Identity.md §7.3.
    """
    if not isinstance(response, list):
        return CheckResult(
            check_id="CHECK-04",
            status="fail",
            errors=(
                ValidationError(
                    code="audit_response_not_array",
                    message=f"expected a JSON array of audit records, got {type(response).__name__}",
                    details={"type": type(response).__name__},
                    spec_ref="Identity §7.3",
                ),
            ),
        )
    return CheckResult(check_id="CHECK-04", status="pass")


def check_audit_record_fields(records: list[Mapping[str, Any]]) -> CheckResult:
    """CHECK-04: each record MUST include ArsiaAuditRecord fields.

    Spec: ARSIA-Identity.md §7.3, ARSIA-State.md §7.1.
    """
    errors: list[ValidationError] = []
    for i, record in enumerate(records):
        missing = _ARSIA_AUDIT_RECORD_REQUIRED_FIELDS - set(record.keys())
        if missing:
            errors.append(
                ValidationError(
                    code="audit_record_missing_fields",
                    message=f"record[{i}] missing ArsiaAuditRecord fields: {sorted(missing)}",
                    details={"index": i, "missing": sorted(missing)},
                    spec_ref="Identity §7.3, State §7.1",
                )
            )
    if errors:
        return CheckResult(check_id="CHECK-04", status="fail", errors=tuple(errors))
    return CheckResult(check_id="CHECK-04", status="pass")


def check_audit_payload_hash(records: list[Mapping[str, Any]]) -> CheckResult:
    """CHECK-04: records MUST use payload_hash, NOT raw payload.

    Spec: ARSIA-Identity.md §7.3.
    """
    errors: list[ValidationError] = []
    for i, record in enumerate(records):
        if "payload" in record:
            errors.append(
                ValidationError(
                    code="audit_record_raw_payload",
                    message=f"record[{i}] contains raw 'payload' field — MUST use payload_hash instead",
                    details={"index": i},
                    spec_ref="Identity §7.3",
                )
            )
        if "payload_hash" not in record:
            errors.append(
                ValidationError(
                    code="audit_record_missing_payload_hash",
                    message=f"record[{i}] missing 'payload_hash' field",
                    details={"index": i},
                    spec_ref="Identity §7.3",
                )
            )
    if errors:
        return CheckResult(check_id="CHECK-04", status="fail", errors=tuple(errors))
    return CheckResult(check_id="CHECK-04", status="pass")


def evaluate_phase2_checks(
    checks: list[CheckResult],
) -> CheckResult:
    """Phase 2 gate: ALL checks MUST have status pass or skip.

    Spec: ARSIA-Identity.md §7.3.
    """
    failures: list[ValidationError] = []
    for check in checks:
        if check.status == "fail":
            failures.append(
                ValidationError(
                    code="phase2_gate_failure",
                    message=f"{check.check_id}: {'; '.join(str(e) for e in check.errors)}",
                    details={"check_id": check.check_id},
                    spec_ref="Identity §7.3",
                )
            )
    if failures:
        return CheckResult(
            check_id="PHASE-2-GATE",
            status="fail",
            errors=tuple(failures),
        )
    return CheckResult(check_id="PHASE-2-GATE", status="pass")


# ----------------------------------------------------------------------
# Phase 3 — CapabilityPolicy evaluation
# ----------------------------------------------------------------------


def validate_capability_policy(policy: CapabilityPolicy) -> list[ValidationError]:
    """Structural validation of a :class:`CapabilityPolicy`.

    Complements Pydantic structural validation with three checks that
    the Pydantic model cannot express:

    - Every rule's ``capability`` string passes
      :func:`arsia_protocol.actions.validate_capability` (grammar +
      reserved-prefix misuse).
    - Duplicate capability entries are reported as errors. §8 does
      not specify duplicate handling; we treat them as configuration
      bugs because under the §8.3 procedure the observable
      behaviour of a duplicate depends on entry order, which is
      a footgun.
    - ``token_lifetime_seconds`` is positive (redundant with the
      Pydantic ``ge=1`` constraint; included so callers that built a
      policy via a raw dict still see a friendly error).

    Args:
        policy: The policy to validate.

    Returns:
        A list of validation errors. Empty means structurally sound.

    Spec: ARSIA-Identity.md §8.1, §8.2.
    """
    errors: list[ValidationError] = []

    if policy.token_lifetime_seconds < 1:
        errors.append(
            ValidationError(
                code="invalid_token_lifetime",
                message="token_lifetime_seconds must be >= 1",
                details={"token_lifetime_seconds": policy.token_lifetime_seconds},
                spec_ref="Identity §8.1",
            )
        )

    seen: set[str] = set()
    for rule in policy.capabilities:
        cap_errors = validate_capability(rule.capability)
        for err in cap_errors:
            errors.append(
                ValidationError(
                    code=err.code,
                    message=f"{rule.capability}: {err.message}",
                    details={"capability": rule.capability, **err.details},
                    spec_ref=err.spec_ref,
                )
            )
        if rule.capability in seen:
            errors.append(
                ValidationError(
                    code="duplicate_capability",
                    message=f"duplicate capability {rule.capability!r} in policy",
                    details={"capability": rule.capability},
                    spec_ref="Identity §8.2",
                )
            )
        seen.add(rule.capability)

    return errors


def _expand_rule_set(policy: CapabilityPolicy, status: str) -> list[str]:
    """Return the capability strings in ``policy`` with the given status.

    Preserves source order so §8.3 evaluation is deterministic.
    """
    return [rule.capability for rule in policy.capabilities if rule.status == status]


def evaluate_capability_policy(
    policy: CapabilityPolicy,
    requested_capabilities: list[str],
    *,
    action_risk_levels: Mapping[str, int] | None = None,
) -> CapabilityEvaluationResult:
    """Evaluate ``requested_capabilities`` against ``policy`` per §8.3.

    Implements the deny-by-default procedure from ARSIA-Identity.md §8.3:

    1. Compute the three rule sets from the policy:
       ``freely_allowed``, ``oversight_required``, ``prohibited``.
    2. Compute the **effective set** as
       ``freely_allowed ∪ oversight_required``. The §8.3 formula
       ``effective = (agent ∩ freely_allowed) ∪ (agent ∩ oversight_required)``
       is implemented here as the filtered intersection of that
       effective set with ``requested_capabilities``.
    3. Any requested capability that matches a ``prohibited`` rule is
       an immediate denial (``is_approved=False``) — even if other
       requested capabilities are granted. Prohibition is an explicit
       "never this capability for this agent" and overrides the rest
       of the request.
    4. Any requested capability that matches **no** rule at all is
       denied by default.
    5. When the effective granted set is empty AND there are no
       prohibitions, the denial reason is
       :data:`"no_permitted_capabilities"`.

    §8.3 does not distinguish explicitly-prohibited capabilities from
    deny-by-default capabilities in its *output* — both are simply
    "not granted". We surface them together in
    :attr:`CapabilityEvaluationResult.denied` (prohibited entries
    first, deny-by-default second, each in source order) so callers
    that iterate denied capabilities see a stable, spec-shaped view
    without having to union two fields.

    Matching uses :func:`arsia_protocol.actions.match_capability`, so
    a policy entry of ``notes.*`` (scope-side wildcard) grants
    ``notes.read``, but the policy schema currently rejects
    wildcards in the rule strings — leaving the wildcard machinery
    available for a later slice without changing the procedure here.
    Token *scope* exact-match vs action *capability* wildcard-match
    is the same split documented in
    :mod:`arsia_protocol.authorization`.

    ``CapabilityRule.max_risk_level`` (§8.2) is enforced **only when**
    ``action_risk_levels`` is supplied. §8.2 makes ``max_risk_level``
    an invocation-time regulator: "If the action's declared risk level
    exceeds this value, the invocation MUST be treated as prohibited
    regardless of the status field." When a per-capability risk level
    is provided and exceeds the matching rule's ``max_risk_level``, the
    capability is treated as prohibited (added to ``denied`` and forces
    ``is_approved=False``). Without ``action_risk_levels`` the field is
    ignored, preserving the policy-scoping-only evaluation of §8.3.

    Args:
        policy: The :class:`CapabilityPolicy` to evaluate against.
        requested_capabilities: The capabilities the onboarding agent
            wants to invoke. May be empty (the request is vacuously
            denied with ``"no_permitted_capabilities"`` because §8.3
            step 5 expects a non-empty effective set).
        action_risk_levels: Optional mapping of capability string →
            declared risk level (1–5). When provided, capabilities
            whose risk exceeds the matching rule's ``max_risk_level``
            are forced into the prohibited bucket per §8.2.

    Returns:
        A :class:`CapabilityEvaluationResult`. ``is_approved`` is
        ``True`` only when at least one requested capability is
        granted AND no requested capability is prohibited.

    Spec: ARSIA-Identity.md §7.4, §8.3.
    """
    prohibited_rules = _expand_rule_set(policy, "prohibited")

    freely_allowed: list[str] = []
    oversight: list[str] = []
    prohibited_hits: list[str] = []
    deny_by_default: list[str] = []
    seen_prohibited: set[str] = set()
    has_prohibited = False

    for cap in requested_capabilities:
        # Step 3 first: a prohibition on this exact request wins over
        # any allowed/oversight match and forces denial.
        if any(match_capability(rule, cap) for rule in prohibited_rules):
            has_prohibited = True
            if cap not in seen_prohibited:
                prohibited_hits.append(cap)
                seen_prohibited.add(cap)
            continue
        matched_rule = next(
            (
                rule
                for rule in policy.capabilities
                if rule.status in ("allowed", "oversight_required")
                and match_capability(rule.capability, cap)
            ),
            None,
        )
        # §8.2: max_risk_level enforcement (opt-in via action_risk_levels).
        # Exceeding the rule's declared cap forces a prohibited outcome
        # regardless of the status field.
        if (
            matched_rule is not None
            and matched_rule.max_risk_level is not None
            and action_risk_levels is not None
            and cap in action_risk_levels
            and action_risk_levels[cap] > matched_rule.max_risk_level
        ):
            has_prohibited = True
            if cap not in seen_prohibited:
                prohibited_hits.append(cap)
                seen_prohibited.add(cap)
            continue
        if matched_rule is not None and matched_rule.status == "allowed":
            freely_allowed.append(cap)
            continue
        if matched_rule is not None and matched_rule.status == "oversight_required":
            oversight.append(cap)
            continue
        # Step 4: deny-by-default.
        deny_by_default.append(cap)

    effective_granted_count = len(freely_allowed) + len(oversight)

    # §8.3 does not distinguish prohibited from not-listed in the
    # output — merge both into a single denied tuple, prohibited
    # entries first so callers iterating the list see the loudest
    # reason early.
    denied = tuple(prohibited_hits) + tuple(deny_by_default)

    denial_reason: DenialReason | None = None
    is_approved = True

    if has_prohibited:
        # Explicit prohibition is the loudest signal; report it even
        # though `no_permitted_capabilities` also applies when the
        # effective set ends up empty. Per §7.6 the gateway needs the
        # specific reason to choose the right audit event.
        is_approved = False
        denial_reason = "no_permitted_capabilities"
    elif effective_granted_count == 0:
        is_approved = False
        denial_reason = "no_permitted_capabilities"

    return CapabilityEvaluationResult(
        is_approved=is_approved,
        freely_allowed=tuple(freely_allowed),
        oversight_required=tuple(oversight),
        denied=denied,
        denial_reason=denial_reason,
    )


# ----------------------------------------------------------------------
# Phase 4 — provenance
# ----------------------------------------------------------------------


def verify_provenance(
    *,
    identity_created_at: str | None,
    earliest_audit_record: str | None,
) -> ProvenanceResult:
    """Assemble a §7.5 provenance summary.

    Phase 4 is **informational** — it never fails onboarding. This
    helper computes a delta between ``identity_created_at`` and
    ``earliest_audit_record`` and tags the result with any
    warnings that an auditor might want to see (both timestamps
    missing, audit record preceding identity, unparseable strings).

    The timestamps are expected to be RFC 3339 millisecond-precision
    strings (``%Y-%m-%dT%H:%M:%S.%fZ``), the same format the rest of
    the SDK emits (Core §4.1.3). Any other format is reported as a
    warning and leaves ``delta_seconds`` as ``None``.

    Args:
        identity_created_at: ``created_at`` from the agent's
            :class:`IdentityRecord`. ``None`` when the agent's
            identity record has no such field.
        earliest_audit_record: Timestamp of the earliest audit record
            the gateway has seen for this agent. ``None`` when the
            gateway has no prior history.

    Returns:
        A :class:`ProvenanceResult`.

    Spec: ARSIA-Identity.md §7.5.
    """
    from datetime import datetime

    notes: list[str] = []
    parsed_identity: datetime | None = None
    parsed_audit: datetime | None = None

    def _parse(label: str, value: str) -> datetime | None:
        try:
            # Python 3.12 ``fromisoformat`` accepts RFC 3339 ``Z``.
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            notes.append(f"WARN: {label} {value!r} is not a parseable timestamp")
            return None

    if identity_created_at is None:
        notes.append("WARN: identity_created_at is missing")
    else:
        parsed_identity = _parse("identity_created_at", identity_created_at)

    if earliest_audit_record is None:
        notes.append("WARN: earliest_audit_record is missing")
    else:
        parsed_audit = _parse("earliest_audit_record", earliest_audit_record)

    delta_seconds: int | None = None
    provenance_verified = True

    if parsed_identity is None or parsed_audit is None:
        # Structural preconditions unmet; verification cannot complete.
        provenance_verified = False
    else:
        delta_seconds = int((parsed_audit - parsed_identity).total_seconds())
        if delta_seconds < 0:
            notes.append(
                "WARN: earliest_audit_record precedes identity_created_at — "
                "audit predates identity (Identity §7.5)"
            )
            provenance_verified = False

    return ProvenanceResult(
        provenance_verified=provenance_verified,
        earliest_audit_record=earliest_audit_record,
        identity_created_at=identity_created_at,
        delta_seconds=delta_seconds,
        notes=tuple(notes),
    )


# ----------------------------------------------------------------------
# Phase 5 — decision assembly
# ----------------------------------------------------------------------


def build_onboarding_decision(
    *,
    agent_id: str,
    policy: CapabilityPolicy,
    evaluation: CapabilityEvaluationResult,
    denial_reasons: list[DenialReason] | None = None,
    phase: OnboardingPhase = "decision",
    token: str | None = None,
    token_expires_at: str | None = None,
) -> OnboardingDecision:
    """Build an :class:`OnboardingDecision` from Phase 3/earlier results.

    A decision is ``"approved"`` iff:

    - ``evaluation.is_approved`` is ``True``, AND
    - ``denial_reasons`` is ``None`` or empty (no upstream phase
      raised a failure).

    Otherwise the decision is ``"denied"`` and the ``denial_reasons``
    list is carried through into the result. If the evaluation raised
    a capability-specific reason it is appended to the list of
    upstream denial reasons (preserving their order).

    On approval, ``granted_capabilities`` is populated from
    ``evaluation.freely_allowed`` — §7.6 speaks of "granted
    capabilities" at the decision-payload level even though §8.3
    partitions the effective set into ``freely_allowed`` and
    ``oversight_required``. The two vocabularies are intentionally
    preserved: the evaluation result tracks §8.3 terminology; the
    decision result tracks §7.6 terminology.

    Args:
        agent_id: The agent being onboarded.
        policy: The :class:`CapabilityPolicy` evaluated in Phase 3.
            Its ``policy_version`` and ``token_lifetime_seconds`` are
            carried into the decision.
        evaluation: The Phase 3 evaluation result.
        denial_reasons: Upstream denial reasons raised in Phases 1-2.
            When provided, the decision is denied regardless of the
            evaluation outcome. Defaults to ``None``.
        phase: The phase to attribute the decision to. Approvals
            always report ``"decision"``; denials should pass the
            phase where the failure originated
            (``"discovery_and_identity"``, etc.).
        token: JWT access token for the approved agent. Its ``scope``
            claim must include the granted capabilities (§7.6).
            Ignored on denial.
        token_expires_at: Token expiry in RFC 3339 format (§7.6).
            Ignored on denial.

    Returns:
        An :class:`OnboardingDecision`.

    Raises:
        ValueError: if ``agent_id`` is not a valid ARSIA agent
            identifier.

    Spec: ARSIA-Identity.md §7.6.
    """
    if not is_valid_agent_id(agent_id):
        raise ValueError(
            f"{agent_id!r} is not a valid ARSIA agent identifier (Core §3.3)"
        )

    valid_denial_reasons = get_args(DenialReason)
    for reason in denial_reasons or ():
        if reason not in valid_denial_reasons:
            raise ValueError(
                f"{reason!r} is not a valid denial reason "
                f"(Identity §7.6 + §8.3); valid values are "
                f"{list(valid_denial_reasons)}"
            )

    upstream = list(denial_reasons or [])
    all_reasons: list[DenialReason] = list(upstream)

    if not evaluation.is_approved and evaluation.denial_reason is not None:
        if evaluation.denial_reason not in all_reasons:
            all_reasons.append(evaluation.denial_reason)

    outcome: OnboardingOutcome
    if upstream or not evaluation.is_approved:
        outcome = "denied"
    else:
        outcome = "approved"

    if outcome == "approved":
        return OnboardingDecision(
            outcome="approved",
            agent_id=agent_id,
            policy_version=policy.policy_version,
            granted_capabilities=evaluation.freely_allowed,
            oversight_required=evaluation.oversight_required,
            token_lifetime_seconds=policy.token_lifetime_seconds,
            denial_reasons=(),
            phase="decision",
            token=token,
            token_expires_at=token_expires_at,
        )

    return OnboardingDecision(
        outcome="denied",
        agent_id=agent_id,
        policy_version=policy.policy_version,
        granted_capabilities=(),
        oversight_required=(),
        token_lifetime_seconds=0,
        denial_reasons=tuple(all_reasons),
        phase=phase,
    )


def build_decision_payload(
    decision: OnboardingDecision,
    *,
    compliance_profile: str | None = None,
    conformance_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialise an :class:`OnboardingDecision` as an ``approval_decision`` payload.

    The returned dict is the ``result`` sub-object of an
    ``approval_decision`` envelope (per Core §4.4.7). Callers wrap it
    with :func:`arsia_protocol.message.create_approval_decision`:

    .. code-block:: python

        env = create_approval_decision(
            from_agent="agent:arsialabs.gateway",
            to_agent=decision.agent_id,
            correlation_id=original_request_id,
            payload_type="arsiaprotocol/onboarding.decision",
            result=build_decision_payload(decision),
        )

    On approval the payload carries ``granted_capabilities``,
    ``oversight_required``, ``policy_version``,
    ``token_lifetime_seconds``, ``token`` (JWT access token whose
    ``scope`` claim includes the granted capabilities, §7.6), and
    ``token_expires_at`` (token expiry in RFC 3339 format, §7.6);
    on denial it carries ``denial_reasons`` and an empty
    ``granted_capabilities`` list.

    Args:
        decision: The decision to serialise.
        compliance_profile: The organization's applicable compliance
            profile. REQUIRED per §7.6 (IDENT-§7.6-02), but the SDK
            does not reject its absence — the consumer is responsible
            for providing it.
        conformance_result: Conformance check results for operator
            feedback. SHOULD be included on denial per §7.6
            (IDENT-§7.6-09).

    Returns:
        A JSON-serialisable dict.

    Spec: ARSIA-Identity.md §7.6.
    """
    freely_allowed = list(decision.granted_capabilities)
    oversight_required = list(decision.oversight_required)
    effective_capabilities = list(dict.fromkeys(freely_allowed + oversight_required))

    payload: dict[str, Any] = {
        "decision": decision.outcome,
        "agent_id": decision.agent_id,
        "policy_version": decision.policy_version,
        "effective_capabilities": effective_capabilities,
        "freely_allowed": freely_allowed,
        "oversight_required": oversight_required,
        "token_lifetime_seconds": decision.token_lifetime_seconds,
        "phase": decision.phase,
    }
    if compliance_profile is not None:
        payload["compliance_profile"] = compliance_profile
    if decision.outcome == "approved":
        if decision.token is not None:
            payload["token"] = decision.token
        if decision.token_expires_at is not None:
            payload["token_expires_at"] = decision.token_expires_at
    if decision.outcome == "denied":
        payload["denial_reason"] = (
            decision.denial_reasons[0] if decision.denial_reasons else None
        )
        if conformance_result is not None:
            payload["conformance_result"] = conformance_result
    return payload


__all__ = [
    "CLASSIFICATION_HIERARCHY",
    "CapabilityEvaluationResult",
    "CapabilityStatus",
    "CheckResult",
    "DenialReason",
    "ONBOARDING_AUDIT_EVENTS",
    "ONBOARDING_EVALUATE_CAPABILITY",
    "OnboardingDecision",
    "OnboardingOutcome",
    "OnboardingPhase",
    "ProvenanceResult",
    "build_decision_payload",
    "build_onboarding_decision",
    "check_audit_payload_hash",
    "check_audit_record_fields",
    "check_audit_records_array",
    "is_classification_consistent",
    "check_correlation_id",
    "check_discovery_response",
    "check_envelope_id",
    "check_envelope_required_fields",
    "check_expires_at",
    "check_pending_approval",
    "validate_profile_requirement",
    "evaluate_capability_policy",
    "evaluate_phase2_checks",
    "validate_capability_policy",
    "verify_provenance",
]
