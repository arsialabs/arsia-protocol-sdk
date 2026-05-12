# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic models for GDPR breach notification (State §5.7).

Mirrors ``shared/schemas/arsia-breach-notification.schema.json``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NotificationTarget = Literal["supervisory_authority", "data_subject"]
"""Discriminator for the notification type per State §5.7."""

_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
_UUID_V4_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class BreachNotificationPayload(BaseModel):
    """Structured breach notification payload per ARSIA-State.md §5.7.

    Spec: ARSIA-State.md §5.7, ``arsia-breach-notification.schema.json``.
    """

    model_config = ConfigDict(extra="forbid")

    notification_target: NotificationTarget = Field(
        description=(
            "Discriminator: 'supervisory_authority' for Art. 33, "
            "'data_subject' for Art. 34."
        ),
    )
    breach_id: str = Field(
        pattern=_UUID_V4_PATTERN,
        description="UUID v4 identifying this breach for correlation per Art. 33(4).",
    )
    nature_of_breach: str = Field(
        min_length=1,
        max_length=2048,
        description="Nature of the breach per Art. 33(3)(a).",
    )
    awareness_timestamp: str = Field(
        pattern=_TS_PATTERN,
        description="When the controller became aware (RFC 3339 ms UTC).",
    )
    likely_consequences: str = Field(
        min_length=1,
        max_length=2048,
        description="Likely consequences per Art. 33(3)(b).",
    )
    measures_taken: str = Field(
        min_length=1,
        max_length=2048,
        description="Measures taken or proposed per Art. 33(3)(c)/(d).",
    )

    # -- OPTIONAL: supervisory authority SHOULD fields -----------------------

    categories_of_data: list[str] | None = Field(
        default=None,
        description="Categories of personal data affected per Art. 33(3)(a).",
    )
    categories_of_data_subjects: list[str] | None = Field(
        default=None,
        description="Categories of data subjects affected per Art. 33(3)(a).",
    )
    approximate_data_subject_count: int | None = Field(
        default=None,
        ge=0,
        description="Approximate number of data subjects affected.",
    )
    approximate_record_count: int | None = Field(
        default=None,
        ge=0,
        description="Approximate number of records affected.",
    )
    dpo_contact: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="DPO name and contact details per Art. 33(3)(b).",
    )

    # -- OPTIONAL: data subject SHOULD field ---------------------------------

    remediation_advice: str | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description="Steps data subjects can take to protect themselves per Art. 34(2).",
    )
