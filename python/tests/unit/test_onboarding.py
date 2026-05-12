# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for ``arsia_protocol.onboarding`` (Layer 4, Slice 4C).

Covers the seven public function groups:

- :func:`is_classification_consistent` (§4.3.8 Rule 6 rank
  predicate).
- :func:`validate_profile_requirement` (§4.2 profile declaration rule).
- :func:`validate_capability_policy` (§8.1/§8.2 structural checks on
  top of the Pydantic model).
- :func:`evaluate_capability_policy` (§8.3 deny-by-default evaluation).
- :func:`verify_provenance` (§7.5 informational summary).
- :func:`build_onboarding_decision` + :func:`build_decision_payload`
  (§7.6 Phase 5 assembly).
- :data:`ONBOARDING_AUDIT_EVENTS` (§9.3 table sanity check).

All dataclass results are asserted to be frozen (hashable) and to
expose the specified public fields.
"""

from __future__ import annotations

import pytest

from arsia_protocol.identity import onboarding
from arsia_protocol.identity.onboarding import (
    CapabilityEvaluationResult,
    CapabilityStatus,
    CheckResult,
    ONBOARDING_AUDIT_EVENTS,
    OnboardingDecision,
    ProvenanceResult,
    build_decision_payload,
    build_onboarding_decision,
    check_audit_payload_hash,
    check_audit_record_fields,
    check_audit_records_array,
    is_classification_consistent,
    check_correlation_id,
    check_discovery_response,
    check_envelope_id,
    check_envelope_required_fields,
    check_expires_at,
    check_pending_approval,
    validate_profile_requirement,
    evaluate_capability_policy,
    evaluate_phase2_checks,
    validate_capability_policy,
    verify_provenance,
)
from arsia_protocol.types.routing import CapabilityPolicy


# ----------------------------------------------------------------------
# Fixtures / helpers
# ----------------------------------------------------------------------


def _policy(
    *,
    version: str = "test-policy-1",
    lifetime: int = 3600,
    rules: list[dict[str, object]] | None = None,
) -> CapabilityPolicy:
    """Build a :class:`CapabilityPolicy` via the Pydantic model."""
    return CapabilityPolicy.model_validate(
        {
            "policy_version": version,
            "token_lifetime_seconds": lifetime,
            "capabilities": rules
            or [
                {"capability": "notes.read", "status": "allowed"},
                {"capability": "notes.write", "status": "oversight_required"},
                {"capability": "notes.delete", "status": "prohibited"},
            ],
        }
    )


# ----------------------------------------------------------------------
# is_classification_consistent — §4.3.8 Rule 6 (rank predicate)
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("per_message", "identity"),
    [
        ("minimal-risk", "minimal-risk"),
        ("minimal-risk", "limited-risk"),
        ("minimal-risk", "high-risk"),
        ("minimal-risk", "unacceptable-risk"),
        ("limited-risk", "limited-risk"),
        ("limited-risk", "high-risk"),
        ("high-risk", "high-risk"),
        ("high-risk", "unacceptable-risk"),
    ],
)
def test_classification_consistency_downgrade_or_equal_passes(
    per_message: str, identity: str
) -> None:
    """Any per-message rank ≤ identity rank is consistent.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    assert is_classification_consistent(per_message, identity) is True


@pytest.mark.parametrize(
    ("per_message", "identity"),
    [
        ("limited-risk", "minimal-risk"),
        ("high-risk", "minimal-risk"),
        ("high-risk", "limited-risk"),
        ("unacceptable-risk", "minimal-risk"),
        ("unacceptable-risk", "high-risk"),
    ],
)
def test_classification_consistency_escalation_is_false(
    per_message: str, identity: str
) -> None:
    """A per-message rank strictly greater than identity rank is an escalation.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    assert is_classification_consistent(per_message, identity) is False


def test_classification_consistency_unknown_per_message_is_false() -> None:
    """An unknown per-message classification returns False conservatively.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    assert (
        is_classification_consistent("not-a-real-class", "high-risk") is False
    )


def test_classification_consistency_unknown_identity_is_false() -> None:
    """An unknown identity classification returns False conservatively.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    assert (
        is_classification_consistent("minimal-risk", "not-a-real-class")
        is False
    )


# ----------------------------------------------------------------------
# validate_profile_requirement — §4.2 (profile declaration)
# ----------------------------------------------------------------------


def test_profile_requirement_minimal_risk_passes() -> None:
    """minimal-risk agents need no profile.

    Spec: ARSIA-Identity.md §4.2.
    """
    assert (
        validate_profile_requirement(
            identity_classification="minimal-risk",
            declared_profile=None,
        )
        == []
    )


def test_profile_requirement_high_risk_requires_profile() -> None:
    """high-risk agents MUST declare a compliance profile.

    Spec: ARSIA-Identity.md §4.2.
    """
    errors = validate_profile_requirement(
        identity_classification="high-risk",
        declared_profile=None,
    )
    assert len(errors) == 1
    assert "high-risk agents MUST declare a compliance profile" in str(errors[0])


def test_profile_requirement_high_risk_with_profile_passes() -> None:
    """high-risk + profile is conformant.

    Spec: ARSIA-Identity.md §4.2.
    """
    assert (
        validate_profile_requirement(
            identity_classification="high-risk",
            declared_profile="EU-AI-ACT-HIGH-RISK",
        )
        == []
    )


@pytest.mark.parametrize("intent", ["error", "event"])
def test_profile_requirement_high_risk_error_event_exempt(
    intent: str,
) -> None:
    """Error and event intents skip the high-risk profile check.

    Spec: ARSIA-Identity.md §4.2.
    """
    assert (
        validate_profile_requirement(
            identity_classification="high-risk",
            declared_profile=None,
            intent=intent,
        )
        == []
    )


def test_profile_requirement_unacceptable_is_denied() -> None:
    """unacceptable-risk MUST NOT be onboarded.

    Spec: ARSIA-Identity.md §4.2.
    """
    errors = validate_profile_requirement(
        identity_classification="unacceptable-risk",
        declared_profile="EU-AI-ACT-HIGH-RISK",
    )
    assert len(errors) == 1
    assert "MUST NOT be onboarded" in str(errors[0])


def test_profile_requirement_unknown_classification() -> None:
    """An unknown classification is surfaced rather than silently passed.

    Spec: ARSIA-Identity.md §4.2.
    """
    errors = validate_profile_requirement(
        identity_classification="not-a-real-class",
        declared_profile=None,
    )
    assert len(errors) == 1
    assert "unknown identity classification" in str(errors[0])


# ----------------------------------------------------------------------
# validate_capability_policy — §8.1/§8.2 structural checks
# ----------------------------------------------------------------------


def test_validate_capability_policy_valid() -> None:
    """A well-formed policy reports no errors.

    Spec: ARSIA-Identity.md §8.1.
    """
    assert validate_capability_policy(_policy()) == []


def test_validate_capability_policy_duplicate_is_error() -> None:
    """Duplicate rule capability strings are treated as a config bug.

    Spec: ARSIA-Identity.md §8.2 (duplicate handling decision — see
    module docstring).
    """
    policy = _policy(
        rules=[
            {"capability": "notes.read", "status": "allowed"},
            {"capability": "notes.read", "status": "oversight_required"},
        ]
    )
    errors = validate_capability_policy(policy)
    assert len(errors) == 1
    assert "duplicate capability" in str(errors[0])


def test_validate_capability_policy_reserved_prefix_misuse() -> None:
    """A capability using ``arsiaprotocol.`` but not in the reserved set is flagged.

    Spec: ARSIA-Actions.md §1.1 rule 5.
    """
    policy = _policy(
        rules=[
            {"capability": "arsiaprotocol.bogus", "status": "allowed"},
        ]
    )
    errors = validate_capability_policy(policy)
    assert any("reserved" in str(e) for e in errors)


# ----------------------------------------------------------------------
# evaluate_capability_policy — §8.3 deny-by-default
# ----------------------------------------------------------------------


def test_evaluate_policy_grants_allowed() -> None:
    """``allowed`` rules populate ``freely_allowed`` and approve.

    Spec: ARSIA-Identity.md §8.3.
    """
    result = evaluate_capability_policy(_policy(), ["notes.read"])
    assert isinstance(result, CapabilityEvaluationResult)
    assert result.is_approved is True
    assert result.freely_allowed == ("notes.read",)
    assert result.oversight_required == ()
    assert result.denied == ()
    assert result.denial_reason is None


def test_evaluate_policy_oversight_counts_as_effective() -> None:
    """``oversight_required`` rules count toward the effective set.

    Spec: ARSIA-Identity.md §8.3 step 2 (effective set formula).
    """
    result = evaluate_capability_policy(_policy(), ["notes.write"])
    assert result.is_approved is True
    assert result.oversight_required == ("notes.write",)
    assert result.freely_allowed == ()


def test_evaluate_policy_prohibited_forces_denial() -> None:
    """A single prohibited entry in the request forces denial.

    Even if other requested capabilities are allowed, the whole
    evaluation is denied. Prohibited entries land in ``denied``
    ahead of any deny-by-default entries so the loudest reason
    appears first.

    Spec: ARSIA-Identity.md §8.3 step 3 (prohibition).
    """
    result = evaluate_capability_policy(
        _policy(), ["notes.read", "notes.delete"]
    )
    assert result.is_approved is False
    assert result.freely_allowed == ("notes.read",)
    assert result.denied == ("notes.delete",)
    assert result.denial_reason == "no_permitted_capabilities"


def test_evaluate_policy_prohibited_precedes_deny_by_default_in_denied() -> None:
    """Prohibited matches come before deny-by-default matches in ``denied``.

    Spec: ARSIA-Identity.md §8.3 steps 3 and 4 (ordering).
    """
    policy = _policy(
        rules=[
            {"capability": "notes.read", "status": "allowed"},
            {"capability": "notes.delete", "status": "prohibited"},
        ]
    )
    result = evaluate_capability_policy(
        policy, ["payments.charge", "notes.delete"]
    )
    assert result.is_approved is False
    # Prohibited first, deny-by-default second.
    assert result.denied == ("notes.delete", "payments.charge")


def test_evaluate_policy_unknown_capability_denied_by_default() -> None:
    """Capabilities not listed in the policy are deny-by-default.

    Spec: ARSIA-Identity.md §8.3 step 4 (deny-by-default).
    """
    result = evaluate_capability_policy(_policy(), ["payments.charge"])
    assert result.is_approved is False
    assert result.denied == ("payments.charge",)
    assert result.denial_reason == "no_permitted_capabilities"


def test_evaluate_policy_empty_request_denied() -> None:
    """An empty request list is denied with no_permitted_capabilities.

    Spec: ARSIA-Identity.md §8.3 step 5.
    """
    result = evaluate_capability_policy(_policy(), [])
    assert result.is_approved is False
    assert result.freely_allowed == ()
    assert result.oversight_required == ()
    assert result.denial_reason == "no_permitted_capabilities"


def test_evaluate_policy_mix_allowed_and_denied() -> None:
    """Partial approval: allowed caps freely_allowed, unknown caps denied, overall approved.

    When no prohibition is hit and at least one cap is granted, the
    evaluation is approved; unknown requests show up in ``denied``
    as informational.

    Spec: ARSIA-Identity.md §8.3.
    """
    result = evaluate_capability_policy(
        _policy(), ["notes.read", "payments.charge"]
    )
    assert result.is_approved is True
    assert result.freely_allowed == ("notes.read",)
    assert result.denied == ("payments.charge",)
    assert result.denial_reason is None


def test_evaluate_policy_ignores_max_risk_level_without_action_risk_levels() -> None:
    """``max_risk_level`` is ignored unless ``action_risk_levels`` is supplied.

    Spec: ARSIA-Identity.md §8.2 (``max_risk_level`` docs), §8.3.
    """
    policy = _policy(
        rules=[
            {
                "capability": "notes.read",
                "status": "allowed",
                "max_risk_level": 1,
            },
        ]
    )
    result = evaluate_capability_policy(policy, ["notes.read"])
    assert result.is_approved is True
    assert result.freely_allowed == ("notes.read",)


def test_evaluate_policy_enforces_max_risk_level_when_exceeded() -> None:
    """A capability whose declared risk exceeds ``max_risk_level`` is prohibited.

    Spec: ARSIA-Identity.md §8.2.
    """
    policy = _policy(
        rules=[
            {
                "capability": "notes.read",
                "status": "allowed",
                "max_risk_level": 2,
            },
        ]
    )
    result = evaluate_capability_policy(
        policy,
        ["notes.read"],
        action_risk_levels={"notes.read": 4},
    )
    assert result.is_approved is False
    assert result.freely_allowed == ()
    assert "notes.read" in result.denied
    assert result.denial_reason == "no_permitted_capabilities"


def test_evaluate_policy_max_risk_level_at_or_below_cap_allowed() -> None:
    """A capability at or below the ``max_risk_level`` cap stays granted.

    Spec: ARSIA-Identity.md §8.2.
    """
    policy = _policy(
        rules=[
            {
                "capability": "notes.read",
                "status": "allowed",
                "max_risk_level": 3,
            },
        ]
    )
    result = evaluate_capability_policy(
        policy,
        ["notes.read"],
        action_risk_levels={"notes.read": 3},
    )
    assert result.is_approved is True
    assert result.freely_allowed == ("notes.read",)


def test_evaluate_policy_max_risk_level_no_cap_set_ignored() -> None:
    """Rules without ``max_risk_level`` are unaffected by ``action_risk_levels``.

    Spec: ARSIA-Identity.md §8.2.
    """
    policy = _policy(
        rules=[
            {"capability": "notes.read", "status": "allowed"},
        ]
    )
    result = evaluate_capability_policy(
        policy,
        ["notes.read"],
        action_risk_levels={"notes.read": 5},
    )
    assert result.is_approved is True
    assert result.freely_allowed == ("notes.read",)


def test_evaluate_policy_result_is_frozen() -> None:
    """``CapabilityEvaluationResult`` is frozen."""
    result = evaluate_capability_policy(_policy(), ["notes.read"])
    with pytest.raises((AttributeError, TypeError)):
        result.is_approved = False  # type: ignore[misc]


# ----------------------------------------------------------------------
# verify_provenance — §7.5
# ----------------------------------------------------------------------


def test_verify_provenance_normal_case() -> None:
    """Identity older than audit: delta positive, verified.

    Spec: ARSIA-Identity.md §7.5.
    """
    result = verify_provenance(
        identity_created_at="2026-01-01T00:00:00.000Z",
        earliest_audit_record="2026-03-01T00:00:00.000Z",
    )
    assert result.provenance_verified is True
    assert result.delta_seconds is not None
    assert result.delta_seconds > 0
    assert result.notes == ()


def test_verify_provenance_audit_before_identity_is_warned() -> None:
    """An audit record older than the identity is flagged but still informational.

    Spec: ARSIA-Identity.md §7.5.
    """
    result = verify_provenance(
        identity_created_at="2026-03-01T00:00:00.000Z",
        earliest_audit_record="2026-01-01T00:00:00.000Z",
    )
    assert result.provenance_verified is False
    assert result.delta_seconds is not None
    assert result.delta_seconds < 0
    assert any("audit predates identity" in n for n in result.notes)


def test_verify_provenance_missing_values_warn() -> None:
    """Missing values surface warnings but never raise.

    Spec: ARSIA-Identity.md §7.5.
    """
    result = verify_provenance(
        identity_created_at=None,
        earliest_audit_record=None,
    )
    assert result.provenance_verified is False
    assert result.delta_seconds is None
    assert any("identity_created_at is missing" in n for n in result.notes)
    assert any("earliest_audit_record is missing" in n for n in result.notes)


def test_verify_provenance_unparseable_timestamp() -> None:
    """Unparseable timestamps are warned but do not raise.

    Spec: ARSIA-Identity.md §7.5.
    """
    result = verify_provenance(
        identity_created_at="not-a-timestamp",
        earliest_audit_record="2026-03-01T00:00:00.000Z",
    )
    assert result.provenance_verified is False
    assert result.delta_seconds is None
    assert any("not a parseable timestamp" in n for n in result.notes)


def test_verify_provenance_result_is_frozen() -> None:
    """``ProvenanceResult`` is frozen."""
    result = verify_provenance(
        identity_created_at="2026-01-01T00:00:00.000Z",
        earliest_audit_record="2026-03-01T00:00:00.000Z",
    )
    with pytest.raises((AttributeError, TypeError)):
        result.provenance_verified = False  # type: ignore[misc]


# ----------------------------------------------------------------------
# build_onboarding_decision — §7.6
# ----------------------------------------------------------------------


def test_build_decision_approves_on_clean_evaluation() -> None:
    """Clean Phase 3 evaluation + no upstream denials → approved.

    Spec: ARSIA-Identity.md §7.6.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    assert decision.outcome == "approved"
    assert decision.agent_id == "agent:acme.echo-client"
    assert decision.policy_version == policy.policy_version
    assert decision.granted_capabilities == ("notes.read",)
    assert decision.token_lifetime_seconds == policy.token_lifetime_seconds
    assert decision.denial_reasons == ()
    assert decision.phase == "decision"


def test_build_decision_denies_on_upstream_failure() -> None:
    """A Phase 1/2 failure forces denial even with a clean evaluation.

    Spec: ARSIA-Identity.md §7.6.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        denial_reasons=["discovery_failed"],
        phase="discovery_and_identity",
    )
    assert decision.outcome == "denied"
    assert decision.denial_reasons == ("discovery_failed",)
    assert decision.granted_capabilities == ()
    assert decision.token_lifetime_seconds == 0
    assert decision.phase == "discovery_and_identity"


def test_build_decision_denies_on_empty_evaluation() -> None:
    """Evaluation with no permitted capabilities → denial with that reason.

    Spec: ARSIA-Identity.md §7.6 + §8.3 step 5.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["payments.charge"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    assert decision.outcome == "denied"
    assert "no_permitted_capabilities" in decision.denial_reasons
    assert decision.phase == "decision"


def test_build_decision_combines_upstream_and_evaluation_reasons() -> None:
    """Upstream + evaluation reasons are both preserved, in order.

    Spec: ARSIA-Identity.md §7.6.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["payments.charge"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        denial_reasons=["conformance_failed"],
        phase="compliance_conformance",
    )
    assert decision.outcome == "denied"
    assert decision.denial_reasons == (
        "conformance_failed",
        "no_permitted_capabilities",
    )
    assert decision.phase == "compliance_conformance"


def test_build_decision_invalid_agent_id_raises() -> None:
    """A malformed agent ID raises ``ValueError``.

    Spec: ARSIA-Core.md §3.3.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    with pytest.raises(ValueError, match="not a valid ARSIA agent identifier"):
        build_onboarding_decision(
            agent_id="NOT_AN_AGENT_ID",
            policy=policy,
            evaluation=evaluation,
        )


def test_build_decision_invalid_denial_reason_raises() -> None:
    """An unknown denial reason raises ``ValueError``.

    Spec: ARSIA-Identity.md §7.6 + §8.3.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    with pytest.raises(ValueError, match="not a valid denial reason"):
        build_onboarding_decision(
            agent_id="agent:acme.echo-client",
            policy=policy,
            evaluation=evaluation,
            denial_reasons=["bogus_reason"],  # type: ignore[list-item]
        )


def test_onboarding_decision_is_frozen() -> None:
    """``OnboardingDecision`` is frozen."""
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    with pytest.raises((AttributeError, TypeError)):
        decision.outcome = "denied"  # type: ignore[misc]


# ----------------------------------------------------------------------
# build_decision_payload — §7.6 + §4.4.7
# ----------------------------------------------------------------------


def test_build_decision_payload_approved() -> None:
    """Approval payload carries granted caps and token lifetime.

    Spec: ARSIA-Identity.md §7.6; ARSIA-Core.md §4.4.7.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(
        policy, ["notes.read", "notes.write"]
    )
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token="header.payload.sig",
        token_expires_at="2024-04-20T12:00:00.000Z",
    )
    payload = build_decision_payload(decision)
    assert payload["decision"] == "approved"
    assert payload["agent_id"] == "agent:acme.echo-client"
    assert payload["freely_allowed"] == ["notes.read"]
    assert payload["oversight_required"] == ["notes.write"]
    assert payload["effective_capabilities"] == ["notes.read", "notes.write"]
    assert payload["policy_version"] == policy.policy_version
    assert payload["token_lifetime_seconds"] == policy.token_lifetime_seconds
    assert payload["token"] == "header.payload.sig"
    assert payload["token_expires_at"] == "2024-04-20T12:00:00.000Z"
    assert "denial_reason" not in payload


def test_build_decision_payload_denied() -> None:
    """Denial payload carries denial_reasons and empty grants.

    Spec: ARSIA-Identity.md §7.6.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["payments.charge"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    payload = build_decision_payload(decision)
    assert payload["decision"] == "denied"
    assert payload["freely_allowed"] == []
    assert payload["oversight_required"] == []
    assert payload["effective_capabilities"] == []
    assert payload["denial_reason"] == "no_permitted_capabilities"
    assert payload["token_lifetime_seconds"] == 0


def test_build_decision_payload_denial_no_token_material() -> None:
    """Denial payload NEVER contains token fields.

    Spec: ARSIA-Identity.md §7.6.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["payments.charge"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    payload = build_decision_payload(decision)
    assert "token" not in payload
    assert "token_expires_at" not in payload


# ----------------------------------------------------------------------
# token + token_expires_at in approval payload — §7.6
# ----------------------------------------------------------------------


def test_build_decision_payload_approval_includes_token() -> None:
    """Approval payload includes ``token`` field with a valid JWT.

    Spec: ARSIA-Identity.md §7.6 (req:2dc1fc6a).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from arsia_protocol.core.authorization import build_jwt

    private_key = Ed25519PrivateKey.generate()
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    scope = " ".join(evaluation.freely_allowed)
    exp = 1713600000
    token = build_jwt(
        {"sub": "agent:acme.echo-client", "scope": scope, "exp": exp},
        private_key,
    )
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token=token,
        token_expires_at="2024-04-20T12:00:00.000Z",
    )
    payload = build_decision_payload(decision)
    assert "token" in payload
    assert payload["token"] == token
    parts = token.split(".")
    assert len(parts) == 3


def test_build_decision_payload_approval_includes_token_expires_at() -> None:
    """Approval payload includes ``token_expires_at`` in RFC 3339.

    Spec: ARSIA-Identity.md §7.6 (req:057662b1).
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token="header.payload.signature",
        token_expires_at="2024-04-20T12:00:00.000Z",
    )
    payload = build_decision_payload(decision)
    assert "token_expires_at" in payload
    assert payload["token_expires_at"] == "2024-04-20T12:00:00.000Z"


def test_build_decision_token_scope_matches_capabilities() -> None:
    """Token ``scope`` claim matches granted capabilities.

    Spec: ARSIA-Identity.md §7.6 (req:2dc1fc6a).
    """
    import json
    from base64 import urlsafe_b64decode

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from arsia_protocol.core.authorization import build_jwt

    private_key = Ed25519PrivateKey.generate()
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    granted = list(evaluation.freely_allowed)
    scope = " ".join(granted)
    token = build_jwt(
        {"sub": "agent:acme.echo-client", "scope": scope, "exp": 9999999999},
        private_key,
    )
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token=token,
        token_expires_at="2286-11-20T17:46:39.000Z",
    )
    payload = build_decision_payload(decision)
    payload_b64 = payload["token"].split(".")[1]
    pad = 4 - len(payload_b64) % 4
    if pad != 4:
        payload_b64 += "=" * pad
    claims = json.loads(urlsafe_b64decode(payload_b64))
    assert claims["scope"].split() == granted


def test_build_decision_token_expires_at_matches_exp() -> None:
    """``token_expires_at`` matches the token's ``exp`` claim.

    Spec: ARSIA-Identity.md §7.6 (req:057662b1).
    """
    from datetime import datetime, timezone

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from arsia_protocol.core.authorization import build_jwt

    private_key = Ed25519PrivateKey.generate()
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    exp = 1713614400
    token = build_jwt(
        {"sub": "agent:acme.echo-client", "scope": "notes.read", "exp": exp},
        private_key,
    )
    expires_at = (
        datetime.fromtimestamp(exp, tz=timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.000Z")
    )
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token=token,
        token_expires_at=expires_at,
    )
    payload = build_decision_payload(decision)
    assert payload["token_expires_at"] == expires_at


# ----------------------------------------------------------------------
# ONBOARDING_AUDIT_EVENTS — §9.3
# ----------------------------------------------------------------------


def test_onboarding_audit_events_has_seven_entries() -> None:
    """The §9.3 table has seven events (including approval_decision from §7.6).

    Spec: ARSIA-Identity.md §9.3, §7.6.
    """
    assert len(ONBOARDING_AUDIT_EVENTS) == 7


def test_onboarding_audit_events_names() -> None:
    """All seven event names match the §9.3 table.

    Spec: ARSIA-Identity.md §9.3, §7.6.
    """
    assert set(ONBOARDING_AUDIT_EVENTS.keys()) == {
        "approval_decision",
        "agent_onboarded",
        "agent_rejected",
        "capability_granted",
        "capability_revoked",
        "token_issued",
        "token_revoked",
    }


def test_onboarding_audit_events_payload_types_namespaced() -> None:
    """Every event's payload type lives under the reserved onboarding namespace.

    Spec: ARSIA-Identity.md §9.3.
    """
    for event, payload_type in ONBOARDING_AUDIT_EVENTS.items():
        assert payload_type.startswith("arsiaprotocol/audit.onboarding."), (
            f"event {event} has payload_type {payload_type!r}"
        )


def test_onboarding_audit_events_is_read_only() -> None:
    """``ONBOARDING_AUDIT_EVENTS`` is a read-only mapping.

    Spec: ARSIA-Identity.md §9.3 (defensive).
    """
    with pytest.raises(TypeError):
        ONBOARDING_AUDIT_EVENTS["new_event"] = "x"  # type: ignore[index]


# ----------------------------------------------------------------------
# Public surface sanity
# ----------------------------------------------------------------------


def test_onboarding_public_all_symbols_importable() -> None:
    """Every symbol in ``__all__`` is importable from the module."""
    for name in onboarding.__all__:
        assert hasattr(onboarding, name), f"missing symbol {name}"


def test_result_dataclasses_are_hashable() -> None:
    """Frozen dataclasses are hashable (sanity check).

    Used by callers that want to put results into a set or dict key.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    provenance = verify_provenance(
        identity_created_at="2026-01-01T00:00:00.000Z",
        earliest_audit_record="2026-03-01T00:00:00.000Z",
    )
    # All three should be hashable (frozen dataclass without mutable
    # default fields beyond tuples/strs).
    assert hash(evaluation) is not None
    assert hash(decision) is not None
    assert hash(provenance) is not None


def test_evaluation_result_type_exported() -> None:
    """``CapabilityEvaluationResult`` is exposed from the module surface."""
    assert onboarding.CapabilityEvaluationResult is CapabilityEvaluationResult
    assert onboarding.OnboardingDecision is OnboardingDecision
    assert onboarding.ProvenanceResult is ProvenanceResult


def test_capability_status_reexport() -> None:
    """``CapabilityStatus`` aliases ``types.routing.CapabilityRuleStatus``.

    Callers that import only ``onboarding`` should see the same
    Literal union that :attr:`CapabilityRule.status` uses, without
    having to drill into ``types.routing``.
    """
    from arsia_protocol.types.routing import CapabilityRuleStatus

    assert CapabilityStatus is CapabilityRuleStatus


# ----------------------------------------------------------------------
# Phase 2 CHECK validators — §7.3
# ----------------------------------------------------------------------

# --- check_discovery_response (req:7911a1bf) ---


def test_check_discovery_response_pass() -> None:
    """Valid discovery response with all required fields passes.

    Spec: ARSIA-Identity.md §7.2.
    """
    response = {
        "agent_id": "agent:example.bot",
        "protocol_version": "0.2.0",
        "capabilities": ["notes.read"],
    }
    result = check_discovery_response(response)
    assert result.status == "pass"
    assert result.check_id == "CHECK-DISC"


def test_check_discovery_response_missing_fields() -> None:
    """Discovery response missing required fields fails.

    Spec: ARSIA-Identity.md §7.2.
    """
    result = check_discovery_response({"agent_id": "agent:example.bot"})
    assert result.status == "fail"
    assert any("protocol_version" in str(e) for e in result.errors)
    assert any("capabilities" in str(e) for e in result.errors)


# --- check_envelope_id (req:06f1c812) ---


def test_check_envelope_id_pass() -> None:
    """Valid UUID v4 passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    env = {"id": "550e8400-e29b-41d4-a716-446655440000"}
    result = check_envelope_id(env)
    assert result.status == "pass"


def test_check_envelope_id_invalid() -> None:
    """Non-UUID id fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_envelope_id({"id": "not-a-uuid"})
    assert result.status == "fail"
    assert "UUID" in str(result.errors[0])


def test_check_envelope_id_missing() -> None:
    """Missing id field fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_envelope_id({})
    assert result.status == "fail"


# --- check_envelope_required_fields (req:befd03ee) ---


def test_check_envelope_required_fields_pass() -> None:
    """Envelope with v, ts, from, to passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    env = {"v": "0.2.0", "ts": "2026-01-01T00:00:00.000Z", "from": "agent:a.b", "to": "agent:c.d"}
    result = check_envelope_required_fields(env)
    assert result.status == "pass"


def test_check_envelope_required_fields_missing() -> None:
    """Envelope missing fields fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_envelope_required_fields({"v": "0.2.0"})
    assert result.status == "fail"
    assert len(result.errors) == 3  # ts, from, to missing


# --- check_pending_approval (req:f2b36ac1) ---


def test_check_pending_approval_pass() -> None:
    """Intent 'pending_approval' passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_pending_approval({"intent": "pending_approval"})
    assert result.status == "pass"


def test_check_pending_approval_wrong_intent() -> None:
    """Intent other than 'pending_approval' fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_pending_approval({"intent": "response"})
    assert result.status == "fail"
    assert "pending_approval" in str(result.errors[0])


# --- check_expires_at (req:908e754e) ---


def test_check_expires_at_pass() -> None:
    """Future timestamp passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_expires_at({"expires_at": "2099-12-31T23:59:59.999Z"})
    assert result.status == "pass"


def test_check_expires_at_missing() -> None:
    """Missing expires_at fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_expires_at({})
    assert result.status == "fail"
    assert "missing" in str(result.errors[0])


def test_check_expires_at_past() -> None:
    """Past timestamp fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_expires_at({"expires_at": "2020-01-01T00:00:00.000Z"})
    assert result.status == "fail"
    assert "future" in str(result.errors[0])


def test_check_expires_at_invalid_format() -> None:
    """Non-RFC 3339 value fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_expires_at({"expires_at": "not-a-timestamp"})
    assert result.status == "fail"
    assert "RFC 3339" in str(result.errors[0])


# --- check_audit_records_array (req:120f8d2f) ---


def test_check_audit_records_array_pass() -> None:
    """A list passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_audit_records_array([{"record_id": "abc"}])
    assert result.status == "pass"


def test_check_audit_records_array_not_list() -> None:
    """Non-list fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_audit_records_array({"record_id": "abc"})
    assert result.status == "fail"
    assert "array" in str(result.errors[0])


# --- check_audit_record_fields (req:f6747d46) ---


def _valid_audit_record() -> dict[str, str]:
    return {
        "record_id": "550e8400-e29b-41d4-a716-446655440000",
        "message_id": "550e8400-e29b-41d4-a716-446655440001",
        "event_type": "message.sent",
        "from_agent": "agent:a.b",
        "to_agent": "agent:c.d",
        "intent": "request",
        "payload_type": "arsiaprotocol/notes.read",
        "payload_hash": "a" * 64,
        "compliance_profile": "none",
        "processed_at": "2026-01-01T00:00:00.000Z",
        "retained_until": "2027-01-01T00:00:00.000Z",
        "operator_id": "org:example",
    }


def test_check_audit_record_fields_pass() -> None:
    """Record with all required fields passes.

    Spec: ARSIA-Identity.md §7.3, ARSIA-State.md §7.1.
    """
    result = check_audit_record_fields([_valid_audit_record()])
    assert result.status == "pass"


def test_check_audit_record_fields_missing() -> None:
    """Record missing fields fails.

    Spec: ARSIA-Identity.md §7.3, ARSIA-State.md §7.1.
    """
    incomplete = {"record_id": "abc", "message_id": "def"}
    result = check_audit_record_fields([incomplete])
    assert result.status == "fail"
    assert "missing" in str(result.errors[0])


# --- check_audit_payload_hash (req:16d7a69c) ---


def test_check_audit_payload_hash_pass() -> None:
    """Record with payload_hash and no raw payload passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_audit_payload_hash([{"payload_hash": "a" * 64}])
    assert result.status == "pass"


def test_check_audit_payload_hash_raw_payload_present() -> None:
    """Record with raw 'payload' field fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_audit_payload_hash([{"payload_hash": "a" * 64, "payload": {"data": "raw"}}])
    assert result.status == "fail"
    assert "payload" in str(result.errors[0])


def test_check_audit_payload_hash_missing() -> None:
    """Record missing payload_hash fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    result = check_audit_payload_hash([{"some_field": "value"}])
    assert result.status == "fail"
    assert "payload_hash" in str(result.errors[0])


# --- evaluate_phase2_checks / Phase 2 gate (req:04871d33) ---


def test_evaluate_phase2_checks_all_pass() -> None:
    """All checks passing means Phase 2 gate passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    checks = [
        CheckResult(check_id="CHECK-01", status="pass"),
        CheckResult(check_id="CHECK-03", status="pass"),
        CheckResult(check_id="CHECK-04", status="pass"),
    ]
    result = evaluate_phase2_checks(checks)
    assert result.status == "pass"
    assert result.check_id == "PHASE-2-GATE"


def test_evaluate_phase2_checks_skip_is_ok() -> None:
    """A skipped check does not block Phase 2 gate.

    Spec: ARSIA-Identity.md §7.3.
    """
    checks = [
        CheckResult(check_id="CHECK-01", status="pass"),
        CheckResult(check_id="CHECK-03", status="skip"),
        CheckResult(check_id="CHECK-04", status="pass"),
    ]
    result = evaluate_phase2_checks(checks)
    assert result.status == "pass"


def test_evaluate_phase2_checks_failure_blocks() -> None:
    """A failed check blocks Phase 2 gate.

    Spec: ARSIA-Identity.md §7.3.
    """
    checks = [
        CheckResult(check_id="CHECK-01", status="pass"),
        CheckResult(check_id="CHECK-03", status="fail", errors=("bad intent",)),
        CheckResult(check_id="CHECK-04", status="pass"),
    ]
    result = evaluate_phase2_checks(checks)
    assert result.status == "fail"
    assert "CHECK-03" in str(result.errors[0])


def test_check_result_is_frozen() -> None:
    """``CheckResult`` is frozen (immutable)."""
    r = CheckResult(check_id="CHECK-01", status="pass")
    with pytest.raises((AttributeError, TypeError)):
        r.status = "fail"  # type: ignore[misc]


# ----------------------------------------------------------------------
# check_correlation_id — §7.3 CHECK-01/CHECK-03
# ----------------------------------------------------------------------


def test_check_correlation_id_matching_passes() -> None:
    """Matching correlation_id passes.

    Spec: ARSIA-Identity.md §7.3.
    """
    env = {"correlation_id": "abc-123"}
    result = check_correlation_id(env, "abc-123")
    assert result.status == "pass"
    assert result.check_id == "CHECK-CORR"


def test_check_correlation_id_mismatch_fails() -> None:
    """Mismatched correlation_id fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    env = {"correlation_id": "wrong-id"}
    result = check_correlation_id(env, "abc-123")
    assert result.status == "fail"
    assert result.errors[0].code == "correlation_mismatch"


def test_check_correlation_id_missing_fails() -> None:
    """Missing correlation_id fails.

    Spec: ARSIA-Identity.md §7.3.
    """
    env: dict[str, object] = {}
    result = check_correlation_id(env, "abc-123")
    assert result.status == "fail"
    assert result.errors[0].code == "missing_correlation_id"


# ----------------------------------------------------------------------
# build_decision_payload — compliance_profile (§7.6-02)
# ----------------------------------------------------------------------


def test_build_decision_payload_approved_with_compliance_profile() -> None:
    """Approval payload includes compliance_profile when provided.

    Spec: ARSIA-Identity.md §7.6 (IDENT-§7.6-02).
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token="header.payload.sig",
    )
    payload = build_decision_payload(decision, compliance_profile="eu-ai-act")
    assert payload["compliance_profile"] == "eu-ai-act"


def test_build_decision_payload_approved_without_compliance_profile() -> None:
    """Approval payload omits compliance_profile when not provided.

    Spec: ARSIA-Identity.md §7.6.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token="header.payload.sig",
    )
    payload = build_decision_payload(decision)
    assert "compliance_profile" not in payload


# ----------------------------------------------------------------------
# build_decision_payload — conformance_result (§7.6-09)
# ----------------------------------------------------------------------


def test_build_decision_payload_denied_with_conformance_result() -> None:
    """Denied payload includes conformance_result when provided.

    Spec: ARSIA-Identity.md §7.6 (IDENT-§7.6-09).
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["payments.charge"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    cr = {"checks_passed": 3, "checks_failed": 2, "details": ["CHECK-04 fail"]}
    payload = build_decision_payload(decision, conformance_result=cr)
    assert payload["conformance_result"] == cr


def test_build_decision_payload_denied_without_conformance_result() -> None:
    """Denied payload omits conformance_result when not provided.

    Spec: ARSIA-Identity.md §7.6.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["payments.charge"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
    )
    payload = build_decision_payload(decision)
    assert "conformance_result" not in payload


def test_build_decision_payload_approved_ignores_conformance_result() -> None:
    """Approval payload ignores conformance_result even if provided.

    Spec: ARSIA-Identity.md §7.6 — conformance_result is for denials.
    """
    policy = _policy()
    evaluation = evaluate_capability_policy(policy, ["notes.read"])
    decision = build_onboarding_decision(
        agent_id="agent:acme.echo-client",
        policy=policy,
        evaluation=evaluation,
        token="header.payload.sig",
    )
    cr = {"checks_passed": 5, "checks_failed": 0}
    payload = build_decision_payload(decision, conformance_result=cr)
    assert "conformance_result" not in payload
