# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic model for the ARSIA ``compliance`` envelope field.

Mirrors ``shared/schemas/arsia-compliance-field.schema.json`` and
ARSIA-Core.md §4.3.6. The compliance object is the first-class
regulatory surface of the ARSIA envelope: profile, data residency,
audit, human oversight, GDPR legal basis, and EU AI Act classification.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

HumanOversightLevel = Literal[
    "not_required",
    "required_before_execution",
    "required_within_24h",
    "required_post_execution",
]
"""Human oversight modes per ARSIA-Core.md §4.3.6.5."""

GDPRLegalBasis = Literal[
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests",
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
]
"""GDPR Article 6(1) + Article 9(2) legal bases per ARSIA-Core.md §4.3.6.8."""

AISystemClassification = Literal[
    "minimal-risk",
    "limited-risk",
    "high-risk",
    "unacceptable-risk",
]
"""EU AI Act risk classifications per ARSIA-Core.md §4.3.6.9."""


class ArsiaCompliance(BaseModel):
    """Compliance sub-object of an ARSIA envelope.

    The schema uses ``additionalProperties: true``, so this model
    allows extra fields for forward compatibility with profile
    extensions.

    Spec: ARSIA-Core.md §4.3.6 and
    ``shared/schemas/arsia-compliance-field.schema.json``.
    """

    model_config = ConfigDict(extra="allow")

    profile: str | None = Field(
        default=None,
        description="Compliance profile name (Core §4.3.6.1).",
    )
    data_residency: str | None = Field(
        default=None,
        pattern=r"^[A-Z]{2}$",
        description="ISO 3166-1 alpha-2 or supranational code (Core §4.3.6.2).",
    )
    audit_required: bool | None = Field(
        default=None,
        description="Whether an ArsiaAuditRecord must be generated (Core §4.3.6.3).",
    )
    retention_days: int | None = Field(
        default=None,
        ge=1,
        description="Minimum retention in days (Core §4.3.6.4).",
    )
    human_oversight: HumanOversightLevel | None = Field(
        default=None,
        description="Human oversight mode (Core §4.3.6.5).",
    )
    explainability_required: bool | None = Field(
        default=None,
        description="Whether responses must include payload.explanation (Core §4.3.6.6).",
    )
    pii_involved: bool | None = Field(
        default=None,
        description="Whether the message processes personal data (Core §4.3.6.7).",
    )
    legal_basis: GDPRLegalBasis | None = Field(
        default=None,
        description="GDPR Art. 6(1) legal basis; required when pii_involved (Core §4.3.6.8).",
    )
    ai_system_classification: AISystemClassification | None = Field(
        default=None,
        description="Per-message EU AI Act classification (Core §4.3.6.9).",
    )

    @model_validator(mode="after")
    def _enforce_cross_field_rules(self) -> "ArsiaCompliance":
        # Rule 2: pii_involved=true requires legal_basis (Core §4.3.8).
        if self.pii_involved is True and self.legal_basis is None:
            raise ValueError(
                "compliance.legal_basis is required when compliance.pii_involved "
                "is true (Core §4.3.8 Rule 2)"
            )
        # Rule 3: high-risk classification requires human_oversight (Core §4.3.8).

        if (
            self.ai_system_classification == "high-risk"
            and self.human_oversight is None
        ):
            raise ValueError(
                "compliance.human_oversight is required when "
                "compliance.ai_system_classification is 'high-risk' "
                "(Core §4.3.8 Rule 3)"
            )
        return self


__all__ = [
    "HumanOversightLevel",
    "GDPRLegalBasis",
    "AISystemClassification",
    "ArsiaCompliance",
]
