# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for ``arsia_protocol.compliance`` (Layer 2 Core module).

Covers the four public groups:

- Profile loading (:func:`load_profiles`, :func:`get_profile`,
  :func:`get_profile_names`).
- Field inheritance (:func:`apply_profile`) per ARSIA-Core.md §4.3.7.
- Retention floor (:func:`get_effective_retention`) per §4.3.6.4,
  §4.3.7.
- Compliance validation rules (:func:`validate_compliance`) per
  ARSIA-Core.md §4.3.8 Rules 1-6.
- Oversight timeout (:func:`check_oversight_timeout`) per §4.3.6.5.
- Explainability validation (:func:`validate_explainability`) per §4.3.6.6.

The file is named ``test_compliance_module.py`` rather than
``test_compliance.py`` to avoid a collision with
``tests/unit/types/test_compliance.py`` from Slice 1B, same pattern
as ``test_errors_registry.py`` from Slice 1C.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from arsia_protocol.core import compliance


# ----------------------------------------------------------------------
# Profile loading
# ----------------------------------------------------------------------


def test_load_profiles_returns_seven() -> None:
    """Exactly seven compliance profiles are bundled.

    Spec: ARSIA-State.md §6 (GDPR-STANDARD, EU-AI-ACT-HIGH-RISK,
    EU-AI-ACT-LIMITED-RISK, MIFID-II, PAC-AGRICULTURE, DSA-VLOP, DORA).
    """
    profiles = compliance.load_profiles()
    assert len(profiles) == 7


def test_load_profiles_names() -> None:
    """The seven profile names match the spec.

    Spec: ARSIA-State.md §6.1–§6.7.
    """
    names = set(compliance.load_profiles().keys())
    assert names == {
        "GDPR-STANDARD",
        "EU-AI-ACT-HIGH-RISK",
        "EU-AI-ACT-LIMITED-RISK",
        "MIFID-II",
        "PAC-AGRICULTURE",
        "DSA-VLOP",
        "DORA",
    }


def test_get_profile_valid() -> None:
    """``get_profile`` returns a dict with the expected top-level fields.

    Spec: ARSIA-State.md §6.
    """
    profile = compliance.get_profile("MIFID-II")
    assert profile["name"] == "MIFID-II"
    assert "defaults" in profile
    assert profile["defaults"]["retention_days"] == 1827


def test_get_profile_unknown() -> None:
    """Unknown profile name raises ``ValueError``.

    Spec: ARSIA-Core.md §4.3.8 Rule 1.
    """
    with pytest.raises(ValueError, match="unknown ARSIA compliance profile"):
        compliance.get_profile("NOPE-DOES-NOT-EXIST")


def test_get_profile_names_sorted() -> None:
    """``get_profile_names`` returns the names in lexical order."""
    names = compliance.get_profile_names()
    assert names == sorted(names)
    assert len(names) == 7


# ----------------------------------------------------------------------
# apply_profile — field inheritance
# ----------------------------------------------------------------------


def _bare_envelope(compliance_obj: dict[str, Any] | None) -> dict[str, Any]:
    env: dict[str, Any] = {
        "v": "1.0",
        "id": "00000000-0000-4000-8000-000000000000",
        "ts": "2026-03-24T10:00:00.000Z",
        "from": "agent:acme.echo-client",
        "to": "agent:acme.echo-server",
        "intent": "event",
        "payload": {"type": "com.acme/x"},
    }
    if compliance_obj is not None:
        env["compliance"] = compliance_obj
    return env


def test_apply_profile_gdpr_defaults_when_no_profile_declared() -> None:
    """Priority 3: bare ``compliance`` field inherits GDPR-STANDARD defaults.

    Spec: ARSIA-Core.md §4.3.7 Priority 3.
    """
    env = _bare_envelope({"pii_involved": True, "legal_basis": "consent"})
    out = compliance.apply_profile(env)
    assert out["compliance"]["human_oversight"] == "not_required"
    # GDPR-STANDARD retention_days is null, so it should not get set.
    assert "retention_days" not in out["compliance"] or out["compliance"].get(
        "retention_days"
    ) is None


def test_apply_profile_mifid_defaults() -> None:
    """Priority 2: MIFID-II profile defaults fill unspecified fields.

    Spec: ARSIA-Core.md §4.3.7 Priority 2; ARSIA-State.md §6.3.
    """
    env = _bare_envelope({"profile": "MIFID-II"})
    out = compliance.apply_profile(env)
    c = out["compliance"]
    assert c["retention_days"] == 1827
    assert c["human_oversight"] == "required_before_execution"
    assert c["explainability_required"] is True
    assert c["pii_involved"] is True
    assert c["legal_basis"] == "contract"
    assert c["data_residency"] == "EU"


def test_apply_profile_explicit_override_wins() -> None:
    """Priority 1: explicit per-message values beat profile defaults.

    Spec: ARSIA-Core.md §4.3.7 Priority 1.
    """
    env = _bare_envelope(
        {
            "profile": "EU-AI-ACT-HIGH-RISK",
            # Override one default; other defaults still fill in.
            "human_oversight": "required_within_24h",
        }
    )
    out = compliance.apply_profile(env)
    c = out["compliance"]
    assert c["human_oversight"] == "required_within_24h"  # per-message wins
    assert c["audit_required"] is True  # profile default fills in
    assert c["explainability_required"] is True  # profile default fills in


def test_apply_profile_retention_floor_enforced() -> None:
    """Profile minimum overrides lower per-message retention.

    Spec: ARSIA-Core.md §4.3.7 retention floor clause.
    """
    env = _bare_envelope({"profile": "MIFID-II", "retention_days": 90})
    out = compliance.apply_profile(env)
    assert out["compliance"]["retention_days"] == 1827


def test_apply_profile_no_compliance_returns_unchanged() -> None:
    """Priority 4: absent ``compliance`` means no inheritance applied.

    Spec: ARSIA-Core.md §4.3.7 Priority 4.
    """
    env = _bare_envelope(None)
    out = compliance.apply_profile(env)
    assert "compliance" not in out
    assert out["v"] == env["v"]
    assert out is not env  # must be a new dict


def test_apply_profile_unknown_strict_raises() -> None:
    """Strict mode rejects an unknown profile name.

    Spec: ARSIA-Core.md §4.3.8 Rule 1.
    """
    env = _bare_envelope({"profile": "NOT-A-REAL-PROFILE"})
    with pytest.raises(ValueError, match="unknown compliance profile"):
        compliance.apply_profile(env, strict=True)


def test_apply_profile_unknown_lenient_falls_back_to_gdpr() -> None:
    """Non-strict mode logs a warning and applies GDPR-STANDARD defaults.

    Spec: ARSIA-Core.md §4.3.8 Rule 1 (non-strict branch).
    """
    env = _bare_envelope({"profile": "NOT-A-REAL-PROFILE"})
    out = compliance.apply_profile(env, strict=False)
    # GDPR-STANDARD sets human_oversight to "not_required".
    assert out["compliance"]["human_oversight"] == "not_required"
    # The declared (unknown) profile name stays in the returned dict —
    # apply_profile only backfills defaults, it does not rewrite an
    # unknown profile name.
    assert out["compliance"]["profile"] == "NOT-A-REAL-PROFILE"


def test_apply_profile_does_not_mutate_input() -> None:
    """The returned envelope is a new dict; input is untouched.

    apply_profile returns a new dict — the input must not be mutated.
    """
    env = _bare_envelope({"profile": "MIFID-II"})
    snapshot_before = dict(env["compliance"])
    _ = compliance.apply_profile(env)
    assert env["compliance"] == snapshot_before


# ----------------------------------------------------------------------
# Compliance validation rules
# ----------------------------------------------------------------------


def test_validate_pii_without_legal_basis_is_rule_2() -> None:
    """R2: ``pii_involved=true`` without ``legal_basis`` is an error.

    Spec: ARSIA-Core.md §4.3.8 Rule 2.
    """
    env = _bare_envelope({"pii_involved": True})
    errors = compliance.validate_compliance(env)
    assert any(e.code == "missing_legal_basis" for e in errors)


def test_validate_pii_with_legal_basis_passes() -> None:
    """R2: ``pii_involved=true`` with ``legal_basis`` passes.

    Spec: ARSIA-Core.md §4.3.8 Rule 2.
    """
    env = _bare_envelope({"pii_involved": True, "legal_basis": "contract"})
    errors = compliance.validate_compliance(env)
    assert not any(e.code == "missing_legal_basis" for e in errors)


def test_validate_high_risk_without_oversight_custom_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3: high-risk + no effective human_oversight is an error.

    All four bundled profiles set ``human_oversight`` in their
    defaults, so under normal inheritance R3 never fires. To exercise
    the rule we inject a synthetic profile whose defaults omit
    ``human_oversight`` and then declare high-risk under it.

    Spec: ARSIA-Core.md §4.3.8 Rule 3.
    """
    bundled = dict(compliance.load_profiles())
    bundled["NO-OVERSIGHT-TEST"] = {
        "name": "NO-OVERSIGHT-TEST",
        "description": "synthetic",
        "status": "active",
        "regulatory_references": [],
        "defaults": {"audit_required": True},  # no human_oversight key
    }
    monkeypatch.setattr(compliance, "_PROFILE_CACHE", bundled)
    env = _bare_envelope(
        {
            "profile": "NO-OVERSIGHT-TEST",
            "ai_system_classification": "high-risk",
        }
    )
    errors = compliance.validate_compliance(env)
    assert any(e.code == "missing_human_oversight" for e in errors)


def test_validate_mifid_retention_low_is_rule_4() -> None:
    """R4: MiFID-II with raw ``retention_days`` below 1827 is an error.

    Spec: ARSIA-Core.md §4.3.8 Rule 4.
    """
    env = _bare_envelope({"profile": "MIFID-II", "retention_days": 90})
    errors = compliance.validate_compliance(env)
    assert any(e.code == "insufficient_retention" for e in errors)


def test_validate_mifid_retention_ok_passes_rule_4() -> None:
    """R4: MiFID-II with ``retention_days`` ≥ 1827 passes.

    Spec: ARSIA-Core.md §4.3.8 Rule 4.
    """
    env = _bare_envelope({"profile": "MIFID-II", "retention_days": 2000})
    errors = compliance.validate_compliance(env)
    assert not any(e.code == "insufficient_retention" for e in errors)


def test_validate_data_residency_bad_format_is_rule_5() -> None:
    """R5: non-ISO-3166-alpha-2 ``data_residency`` is an error.

    Spec: ARSIA-Core.md §4.3.8 Rule 5.
    """
    env = _bare_envelope({"data_residency": "european-union"})
    errors = compliance.validate_compliance(env)
    assert any(e.code == "invalid_data_residency" for e in errors)


def test_validate_valid_compliance_returns_empty() -> None:
    """A fully populated MiFID-II compliance block validates cleanly.

    Spec: ARSIA-Core.md §4.3.8 Rules 1-5.
    """
    env = _bare_envelope(
        {
            "profile": "MIFID-II",
            "retention_days": 2000,
            "pii_involved": True,
            "legal_basis": "contract",
            "data_residency": "EU",
        }
    )
    assert compliance.validate_compliance(env) == []


def test_validate_compliance_strict_mode_promotes_unknown_profile() -> None:
    """In strict mode, Rule 1 is promoted to an error.

    Spec: ARSIA-Core.md §4.3.8 Rule 1 strict branch.
    """
    env = _bare_envelope({"profile": "NO-SUCH-PROFILE"})
    lenient = compliance.validate_compliance(env, strict=False)
    assert not any(e.code == "unknown_profile" for e in lenient)
    strict = compliance.validate_compliance(env, strict=True)
    assert any(e.code == "unknown_profile" for e in strict)


# ----------------------------------------------------------------------
# Rule 6 — Classification escalation (Slice 4C)
# ----------------------------------------------------------------------


def test_r6_escalation_from_limited_to_high_is_error() -> None:
    """R6: per-message ``high-risk`` under a ``limited-risk`` agent is rejected.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    env = _bare_envelope(
        {
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
        }
    )
    errors = compliance.validate_compliance(
        env, identity_classification="limited-risk"
    )
    r6 = [e for e in errors if e.code == "classification_escalation"]
    assert len(r6) == 1
    assert r6[0].details["classification_escalation"] is True


def test_r6_no_escalation_passes() -> None:
    """R6: per-message rank <= agent rank passes.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    env = _bare_envelope(
        {
            "profile": "GDPR-STANDARD",
            "ai_system_classification": "minimal-risk",
        }
    )
    errors = compliance.validate_compliance(
        env, identity_classification="high-risk"
    )
    assert not any(e.code == "classification_escalation" for e in errors)


def test_r6_same_level_passes() -> None:
    """R6: per-message rank equal to the agent rank is allowed.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    env = _bare_envelope(
        {
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
        }
    )
    errors = compliance.validate_compliance(
        env, identity_classification="high-risk"
    )
    assert not any(e.code == "classification_escalation" for e in errors)


def test_r6_skipped_when_identity_classification_none() -> None:
    """R6: omitted ``identity_classification`` skips the rule entirely.

    Receivers that do not resolve the sender's IdentityRecord cannot
    check R6. The rule is still enforceable by any call site that does
    resolve identity (e.g. the onboarding gateway).

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    env = _bare_envelope(
        {
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
        }
    )
    # Even with the most restrictive per-message classification, R6 is
    # silent when identity context is not provided.
    errors = compliance.validate_compliance(env)
    assert not any(e.code == "classification_escalation" for e in errors)


def test_r6_unknown_identity_classification_is_rule_6_error() -> None:
    """R6: an unknown ``identity_classification`` is surfaced as R6.

    Catches typos / enum drift instead of silently defaulting to a rank.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    env = _bare_envelope(
        {
            "profile": "GDPR-STANDARD",
            "ai_system_classification": "minimal-risk",
        }
    )
    errors = compliance.validate_compliance(
        env, identity_classification="not-a-real-class"
    )
    r6 = [e for e in errors if e.code == "classification_escalation"]
    assert len(r6) == 1
    assert r6[0].details.get("unknown_identity_classification") == "not-a-real-class"


def test_classification_hierarchy_public_alias() -> None:
    """The public ``CLASSIFICATION_HIERARCHY`` alias matches the private tuple.

    Spec: ARSIA-Core.md §4.3.8 Rule 6.
    """
    assert compliance.CLASSIFICATION_HIERARCHY == (
        "minimal-risk",
        "limited-risk",
        "high-risk",
        "unacceptable-risk",
    )
    # Sanity — make sure it's the same object so memory cost is zero.
    assert compliance.CLASSIFICATION_HIERARCHY is compliance._CLASSIFICATION_HIERARCHY


# ----------------------------------------------------------------------
# get_effective_retention
# ----------------------------------------------------------------------


def test_get_effective_retention_mifid_default() -> None:
    """MiFID-II without a per-message value resolves to 1827.

    Spec: ARSIA-Core.md §4.3.6.4, §4.3.7.
    """
    env = _bare_envelope({"profile": "MIFID-II"})
    assert compliance.get_effective_retention(env) == 1827


def test_get_effective_retention_floor_override() -> None:
    """A low per-message value is floored to the profile minimum.

    Spec: ARSIA-Core.md §4.3.7 retention floor.
    """
    env = _bare_envelope({"profile": "MIFID-II", "retention_days": 90})
    assert compliance.get_effective_retention(env) == 1827


def test_get_effective_retention_no_compliance_returns_none() -> None:
    """Envelopes without a ``compliance`` field return ``None``.

    Spec: ARSIA-Core.md §4.3.7 Priority 4.
    """
    env = _bare_envelope(None)
    assert compliance.get_effective_retention(env) is None


# ----------------------------------------------------------------------
# validate_compliance — structured §12.4 violations
# ----------------------------------------------------------------------


def test_detailed_r2_emits_missing_legal_basis_shape() -> None:
    """R2: structured details carry the §12.4 ``missing_legal_basis`` key.

    Spec: ARSIA-Core.md §12.4 CORE-COMPLIANCE-01; §4.3.8 Rule 2.
    """
    env = _bare_envelope({"profile": "GDPR-STANDARD", "pii_involved": True})
    violations = compliance.validate_compliance(env)
    r2 = [v for v in violations if v.code == "missing_legal_basis"]
    assert len(r2) == 1
    assert r2[0].details == {"missing_legal_basis": True}


def test_detailed_r6_emits_classification_escalation_shape() -> None:
    """R6: structured details carry the §12.4 ``classification_escalation`` key.

    Spec: ARSIA-Core.md §12.4 CORE-COMPLIANCE-02; §4.3.8 Rule 6.
    """
    env = _bare_envelope(
        {
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        }
    )
    violations = compliance.validate_compliance(
        env, identity_classification="minimal-risk"
    )
    r6 = [v for v in violations if v.code == "classification_escalation"]
    assert len(r6) == 1
    assert r6[0].details["classification_escalation"] is True
    assert r6[0].details["identity_classification"] == "minimal-risk"
    assert r6[0].details["per_message_classification"] == "high-risk"


def test_detailed_r6_dormant_without_identity_classification() -> None:
    """R6 only fires when ``identity_classification`` is supplied.

    Preserves historical behaviour: the pipeline's string-only path
    (``validate_semantic`` without a resolver) never fires R6.

    Spec: ARSIA-Core.md §4.3.8 Rule 6 (caller opt-in).
    """
    env = _bare_envelope(
        {
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        }
    )
    violations = compliance.validate_compliance(env)
    assert not any(v.code == "classification_escalation" for v in violations)


def test_detailed_r4_mifid_retention_shape() -> None:
    """R4: MiFID-II retention-floor violation surfaces declared vs minimum.

    Spec: ARSIA-Core.md §4.3.8 Rule 4.
    """
    env = _bare_envelope(
        {"profile": "MIFID-II", "retention_days": 90, "legal_basis": "contract"}
    )
    violations = compliance.validate_compliance(env)
    r4 = [v for v in violations if v.code == "insufficient_retention"]
    assert len(r4) == 1
    assert r4[0].details == {
        "insufficient_retention": True,
        "required": 1827,
        "provided": 90,
    }


def test_validate_compliance_multiple_violations() -> None:
    """Multiple rules fire and each produces a structured ValidationError."""
    env = _bare_envelope(
        {
            "profile": "MIFID-II",
            "retention_days": 60,
            "data_residency": "BRAZIL",
        }
    )
    errors = compliance.validate_compliance(env)
    codes = {e.code for e in errors}
    assert "insufficient_retention" in codes
    assert "invalid_data_residency" in codes


def test_validate_compliance_empty_when_no_compliance_field() -> None:
    """No compliance → no violations."""
    env = _bare_envelope(None)
    assert compliance.validate_compliance(env) == []


# ----------------------------------------------------------------------
# check_oversight_timeout (§4.3.6.5)
# ----------------------------------------------------------------------


class TestCheckOversightTimeout:
    """Tests for :func:`compliance.check_oversight_timeout`.

    Spec: ARSIA-Core.md §4.3.6.5 — ``required_within_24h`` mode.
    """

    def test_not_required_returns_none(self) -> None:
        """Non-24h oversight modes never trigger a timeout."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        far_future = executed + timedelta(days=30)
        for mode in ("not_required", "required_before_execution", "required_post_execution"):
            result = compliance.check_oversight_timeout(
                mode, executed, now=far_future,
            )
            assert result is None

    def test_none_oversight_returns_none(self) -> None:
        """No oversight field at all → no timeout."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = compliance.check_oversight_timeout(
            None, executed, now=executed + timedelta(days=30),
        )
        assert result is None

    def test_reviewed_within_24h_returns_none(self) -> None:
        """Review within deadline → no violation."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        reviewed = executed + timedelta(hours=23)
        result = compliance.check_oversight_timeout(
            "required_within_24h", executed, reviewed_at=reviewed,
            now=executed + timedelta(days=2),
        )
        assert result is None

    def test_no_review_after_24h_returns_violation(self) -> None:
        """No review after 24h → oversight_timeout violation."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        after_deadline = executed + timedelta(hours=25)
        result = compliance.check_oversight_timeout(
            "required_within_24h", executed, now=after_deadline,
        )
        assert result is not None
        assert result.code == "oversight_timeout"
        assert result.details == {"oversight_timeout": True}

    def test_review_after_24h_returns_violation(self) -> None:
        """Review that arrives after the 24h window still triggers."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        late_review = executed + timedelta(hours=30)
        result = compliance.check_oversight_timeout(
            "required_within_24h", executed,
            reviewed_at=late_review,
            now=executed + timedelta(hours=31),
        )
        assert result is not None
        assert result.code == "oversight_timeout"

    def test_within_deadline_no_review_yet(self) -> None:
        """Still within 24h window and no review → no violation yet."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = compliance.check_oversight_timeout(
            "required_within_24h", executed,
            now=executed + timedelta(hours=12),
        )
        assert result is None

    def test_logs_warning_on_timeout(self, caplog: pytest.LogCaptureFixture) -> None:
        """The oversight_timeout event is logged as a warning."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        with caplog.at_level(logging.WARNING, logger="arsia_protocol.compliance"):
            compliance.check_oversight_timeout(
                "required_within_24h", executed,
                now=executed + timedelta(hours=25),
            )
        assert any("oversight_timeout" in r.message for r in caplog.records)

    def test_exact_24h_boundary_no_violation(self) -> None:
        """At exactly 24h, no violation (deadline not yet passed)."""
        executed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = compliance.check_oversight_timeout(
            "required_within_24h", executed,
            now=executed + timedelta(hours=24),
        )
        assert result is None


# ----------------------------------------------------------------------
# validate_explainability (§4.3.6.6)
# ----------------------------------------------------------------------


class TestValidateExplainability:
    """Tests for :func:`compliance.validate_explainability`.

    Spec: ARSIA-Core.md §4.3.6.6; ARSIA-Actions.md §5.2.
    """

    def test_no_compliance_returns_none(self) -> None:
        """No compliance field on request → no explainability check."""
        result = compliance.validate_explainability(
            {"intent": "request"},
            {"intent": "response", "payload": {}},
        )
        assert result is None

    def test_explainability_false_returns_none(self) -> None:
        """explainability_required=false → no check."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": False}},
            {"intent": "response", "payload": {}},
        )
        assert result is None

    def test_explainability_not_set_returns_none(self) -> None:
        """explainability_required not present → no check."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"profile": "GDPR-STANDARD"}},
            {"intent": "response", "payload": {}},
        )
        assert result is None

    def test_missing_explanation_returns_violation(self) -> None:
        """explainability_required=true but no explanation → violation."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": True}},
            {"intent": "response", "payload": {"type": "notes.create"}},
        )
        assert result is not None
        assert result.code == "missing_explanation"
        assert result.details == {"missing_explanation": True}

    def test_complete_explanation_returns_none(self) -> None:
        """Full explanation with all required fields → no violation."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": True}},
            {
                "intent": "response",
                "payload": {
                    "type": "notes.create",
                    "explanation": {
                        "reasoning": "Based on input data.",
                        "confidence": 0.95,
                        "inputs_used": ["document_a"],
                    },
                },
            },
        )
        assert result is None

    def test_missing_reasoning_returns_violation(self) -> None:
        """Explanation without reasoning → violation with missing_fields."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": True}},
            {
                "intent": "response",
                "payload": {
                    "explanation": {
                        "confidence": 0.9,
                        "inputs_used": ["doc_a"],
                    },
                },
            },
        )
        assert result is not None
        assert result.details["incomplete_explanation"] is True
        assert "reasoning" in result.details["missing_fields"]

    def test_missing_confidence_returns_violation(self) -> None:
        """Explanation without confidence → violation."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": True}},
            {
                "intent": "response",
                "payload": {
                    "explanation": {
                        "reasoning": "Some reasoning.",
                        "inputs_used": ["doc_a"],
                    },
                },
            },
        )
        assert result is not None
        assert "confidence" in result.details["missing_fields"]

    def test_missing_inputs_used_returns_violation(self) -> None:
        """Explanation without inputs_used → violation."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": True}},
            {
                "intent": "response",
                "payload": {
                    "explanation": {
                        "reasoning": "Some reasoning.",
                        "confidence": 0.8,
                    },
                },
            },
        )
        assert result is not None
        assert "inputs_used" in result.details["missing_fields"]

    def test_multiple_missing_fields(self) -> None:
        """Empty explanation object → all three fields missing."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": True}},
            {"intent": "response", "payload": {"explanation": {}}},
        )
        assert result is not None
        assert set(result.details["missing_fields"]) == {
            "reasoning", "confidence", "inputs_used",
        }

    def test_null_fields_treated_as_missing(self) -> None:
        """Fields set to None are treated as missing."""
        result = compliance.validate_explainability(
            {"intent": "request", "compliance": {"explainability_required": True}},
            {
                "intent": "response",
                "payload": {
                    "explanation": {
                        "reasoning": None,
                        "confidence": None,
                        "inputs_used": None,
                    },
                },
            },
        )
        assert result is not None
        assert len(result.details["missing_fields"]) == 3


# ----------------------------------------------------------------------
# BL-06 — MiFID retention floor is 1827 (5×365.25)
# ----------------------------------------------------------------------


def test_mifid_retention_floor_constant_is_1827() -> None:
    """The SDK constant matches the schema minimum: 1827."""
    assert compliance._MIFID_RETENTION_FLOOR == 1827


def test_mifid_retention_1826_rejected() -> None:
    """R4: retention_days=1826 is below 1827 → violation."""
    env = _bare_envelope({"profile": "MIFID-II", "retention_days": 1826})
    errors = compliance.validate_compliance(env)
    assert any(e.code == "insufficient_retention" for e in errors)


def test_mifid_retention_1827_passes() -> None:
    """R4: retention_days=1827 exactly meets the floor."""
    env = _bare_envelope(
        {
            "profile": "MIFID-II",
            "retention_days": 1827,
            "pii_involved": True,
            "legal_basis": "contract",
        }
    )
    errors = compliance.validate_compliance(env)
    assert not any(e.code == "insufficient_retention" for e in errors)


def test_mifid_retention_1825_rejected() -> None:
    """R4: the old 1825 value is now below the floor."""
    env = _bare_envelope({"profile": "MIFID-II", "retention_days": 1825})
    errors = compliance.validate_compliance(env)
    assert any(e.code == "insufficient_retention" for e in errors)


# ----------------------------------------------------------------------
# BL-08 — pii_involved=true → force audit_required=true
# ----------------------------------------------------------------------


def test_pii_involved_forces_audit_required_true() -> None:
    """When pii_involved=true, audit_required is silently set to true."""
    env = _bare_envelope(
        {"pii_involved": True, "legal_basis": "consent", "audit_required": False}
    )
    out = compliance.apply_profile(env)
    assert out["compliance"]["audit_required"] is True


def test_pii_involved_audit_required_already_true_unchanged() -> None:
    """When audit_required is already true, no double-forcing."""
    env = _bare_envelope(
        {"pii_involved": True, "legal_basis": "consent", "audit_required": True}
    )
    out = compliance.apply_profile(env)
    assert out["compliance"]["audit_required"] is True


def test_pii_not_involved_audit_required_false_unchanged() -> None:
    """When pii_involved=false, audit_required=false is not forced."""
    env = _bare_envelope({"pii_involved": False, "audit_required": False})
    out = compliance.apply_profile(env)
    assert out["compliance"]["audit_required"] is False


def test_pii_involved_forces_audit_required_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The silent override logs a compliance_warning."""
    env = _bare_envelope(
        {"pii_involved": True, "legal_basis": "consent", "audit_required": False}
    )
    with caplog.at_level(logging.WARNING, logger="arsia_protocol.compliance"):
        compliance.apply_profile(env)
    assert any("compliance_warning" in r.message for r in caplog.records)


def test_pii_involved_no_audit_required_field_set_to_true() -> None:
    """When audit_required is not set and pii_involved=true, it is forced."""
    env = _bare_envelope({"pii_involved": True, "legal_basis": "consent"})
    out = compliance.apply_profile(env)
    assert out["compliance"]["audit_required"] is True


# ----------------------------------------------------------------------
# Art. 9(2) legal basis sets
# ----------------------------------------------------------------------


def test_art_9_legal_bases_contains_all_ten_grounds() -> None:
    """ART_9_LEGAL_BASES matches the 10 Art. 9(2) grounds from Core §4.3.6.8."""
    spec_art_9_grounds = frozenset({
        "explicit_consent",
        "employment_social_security",
        "vital_interests_incapacity",
        "legitimate_activities",
        "manifestly_public",
        "legal_claims",
        "substantial_public_interest",
        "health_medicine",
        "public_health",
        "archiving_research",
    })
    assert compliance.ART_9_LEGAL_BASES == spec_art_9_grounds, (
        f"extra={compliance.ART_9_LEGAL_BASES - spec_art_9_grounds}, "
        f"missing={spec_art_9_grounds - compliance.ART_9_LEGAL_BASES}"
    )


def test_art_6_legal_bases_contains_all_six_grounds() -> None:
    """ART_6_LEGAL_BASES matches the schema enum for Art. 6(1)."""
    assert compliance.ART_6_LEGAL_BASES == frozenset({
        "consent",
        "contract",
        "legal_obligation",
        "vital_interests",
        "public_task",
        "legitimate_interests",
    })


def test_art_6_and_art_9_are_disjoint() -> None:
    """No legal basis appears in both Art. 6(1) and Art. 9(2) sets."""
    assert compliance.ART_6_LEGAL_BASES.isdisjoint(compliance.ART_9_LEGAL_BASES)


# ---------------------------------------------------------------------------
# BL-24: get_clock_skew_seconds (Core §8.3)
# ---------------------------------------------------------------------------


def test_get_clock_skew_seconds_with_profile() -> None:
    """Profile with clock_skew_seconds returns that value."""
    env: dict[str, Any] = {"compliance": {"profile": "EU-AI-ACT-HIGH-RISK"}}
    result = compliance.get_clock_skew_seconds(env)
    assert result == 120


def test_get_clock_skew_seconds_mifid() -> None:
    """MIFID-II profile defines clock_skew_seconds=60."""
    env: dict[str, Any] = {"compliance": {"profile": "MIFID-II"}}
    result = compliance.get_clock_skew_seconds(env)
    assert result == 60


def test_get_clock_skew_seconds_no_profile() -> None:
    """Envelope without compliance returns the 300 s default."""
    env: dict[str, Any] = {"v": "1.0"}
    result = compliance.get_clock_skew_seconds(env)
    assert result == 300


def test_get_clock_skew_seconds_profile_without_clock_skew() -> None:
    """Profile without clock_skew_seconds falls back to default."""
    env: dict[str, Any] = {"compliance": {"profile": "GDPR-STANDARD"}}
    result = compliance.get_clock_skew_seconds(env)
    assert result == 300


def test_get_clock_skew_seconds_unknown_profile() -> None:
    """Unknown profile name falls back to default."""
    env: dict[str, Any] = {"compliance": {"profile": "NONEXISTENT"}}
    result = compliance.get_clock_skew_seconds(env)
    assert result == 300


def test_get_clock_skew_seconds_custom_default() -> None:
    """Custom default value is used when no profile defines clock_skew."""
    env: dict[str, Any] = {"v": "1.0"}
    result = compliance.get_clock_skew_seconds(env, default=600)
    assert result == 600
