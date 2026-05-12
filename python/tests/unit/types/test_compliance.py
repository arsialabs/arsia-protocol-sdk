# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.compliance``.

Spec: ARSIA-Core.md §4.3.6 and
``shared/schemas/arsia-compliance-field.schema.json``.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arsia_protocol.types.compliance import ArsiaCompliance


def test_compliance_empty_object_valid() -> None:
    """An empty compliance object is valid — all fields are optional.

    Spec: ARSIA-Core.md §4.3.6.
    """
    comp = ArsiaCompliance()
    assert comp.profile is None


def test_compliance_minimal_profile_only() -> None:
    """Only setting ``profile`` is valid.

    Spec: ARSIA-Core.md §4.3.6.1.
    """
    comp = ArsiaCompliance(profile="GDPR-STANDARD")
    assert comp.profile == "GDPR-STANDARD"


def test_compliance_full_high_risk_example() -> None:
    """The MiFID-II example from the schema constructs successfully.

    Spec: ``shared/schemas/arsia-compliance-field.schema.json`` examples[2].
    """
    comp = ArsiaCompliance(
        profile="MIFID-II",
        audit_required=True,
        retention_days=1827,
        human_oversight="required_before_execution",
        explainability_required=True,
        pii_involved=True,
        legal_basis="contract",
        data_residency="EU",
        ai_system_classification="high-risk",
    )
    assert comp.retention_days == 1827


def test_compliance_all_four_oversight_levels_accepted() -> None:
    """All four ``human_oversight`` Literal values are accepted.

    Spec: ARSIA-Core.md §4.3.6.5.
    """
    for level in (
        "not_required",
        "required_before_execution",
        "required_within_24h",
        "required_post_execution",
    ):
        comp = ArsiaCompliance(human_oversight=level)  # type: ignore[arg-type]
        assert comp.human_oversight == level


def test_compliance_all_six_legal_basis_values_accepted() -> None:
    """All six GDPR Art. 6(1) legal bases are accepted.

    Spec: ARSIA-Core.md §4.3.6.8.
    """
    for basis in (
        "consent",
        "contract",
        "legal_obligation",
        "vital_interests",
        "public_task",
        "legitimate_interests",
    ):
        comp = ArsiaCompliance(pii_involved=True, legal_basis=basis)  # type: ignore[arg-type]
        assert comp.legal_basis == basis


def test_compliance_all_four_classifications_accepted() -> None:
    """All four AI system classifications are accepted.

    Spec: ARSIA-Core.md §4.3.6.9.
    """
    for cls in ("minimal-risk", "limited-risk", "high-risk", "unacceptable-risk"):
        kwargs = {"ai_system_classification": cls}
        if cls == "high-risk":
            kwargs["human_oversight"] = "required_before_execution"
        comp = ArsiaCompliance(**kwargs)  # type: ignore[arg-type]
        assert comp.ai_system_classification == cls


def test_compliance_rejects_unknown_oversight() -> None:
    """Unknown ``human_oversight`` values are rejected.

    Spec: ARSIA-Core.md §4.3.6.5.
    """
    with pytest.raises(ValidationError):
        ArsiaCompliance(human_oversight="maybe")  # type: ignore[arg-type]


def test_compliance_pii_without_legal_basis_rejected() -> None:
    """``pii_involved=true`` without ``legal_basis`` is rejected.

    Spec: ARSIA-Core.md §4.3.8 Rule 2.
    """
    with pytest.raises(ValidationError, match="legal_basis is required"):
        ArsiaCompliance(pii_involved=True)


def test_compliance_high_risk_without_oversight_rejected() -> None:
    """``high-risk`` without ``human_oversight`` is rejected.

    Spec: ARSIA-Core.md §4.3.8 Rule 3.
    """
    with pytest.raises(ValidationError, match="human_oversight is required"):
        ArsiaCompliance(ai_system_classification="high-risk")


def test_compliance_retention_days_positive() -> None:
    """``retention_days`` must be ≥ 1.

    Spec: ARSIA-Core.md §4.3.6.4.
    """
    with pytest.raises(ValidationError):
        ArsiaCompliance(retention_days=0)
    ok = ArsiaCompliance(retention_days=1)
    assert ok.retention_days == 1


def test_compliance_data_residency_pattern_enforced() -> None:
    """``data_residency`` must be a two-letter uppercase code.

    Spec: ARSIA-Core.md §4.3.6.2.
    """
    with pytest.raises(ValidationError):
        ArsiaCompliance(data_residency="eu")
    with pytest.raises(ValidationError):
        ArsiaCompliance(data_residency="EUR")


def test_compliance_allows_extra_fields() -> None:
    """The schema uses ``additionalProperties: true``; extra fields allowed.

    Spec: ``shared/schemas/arsia-compliance-field.schema.json``.
    """
    comp = ArsiaCompliance(profile="GDPR-STANDARD", custom_flag="yes")  # type: ignore[call-arg]
    dumped = comp.model_dump(exclude_none=True)
    assert dumped.get("custom_flag") == "yes"
