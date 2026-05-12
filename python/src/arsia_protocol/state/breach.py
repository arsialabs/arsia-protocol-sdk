# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Breach notification builder and validator (State §5.7).

This module is Layer 4 (Primitives) in the SDK dependency graph. It
provides:

- :data:`PAYLOAD_TYPE_BREACH_NOTIFICATION` — the ``payload.type``
  constant for breach notification events.
- :data:`BREACH_CAPABILITY` — the capability required to send a
  breach notification.
- :func:`build_breach_notification` — builds the ``payload.data``
  dict for a breach notification event envelope.
- :func:`validate_breach_notification` — validates a breach
  notification payload dict against the Pydantic model.

The caller wraps the returned dict into an ``intent="event"`` envelope
via :func:`arsia_protocol.message.create_event`. This module
deliberately does not depend on ``message`` to preserve the Layer 4
boundary.

Spec: ARSIA-State.md §5.7.
"""

from __future__ import annotations

from typing import Any, Final

from arsia_protocol._errors import ValidationError
from arsia_protocol.types.breach import (
    BreachNotificationPayload,
    NotificationTarget,
)

PAYLOAD_TYPE_BREACH_NOTIFICATION: Final[str] = (
    "arsiaprotocol.compliance/breach-notification"
)
"""``payload.type`` for breach notification events per State §5.7."""

BREACH_CAPABILITY: Final[str] = "arsiaprotocol.compliance.breach.notify"
"""Capability required to send breach notifications per State §5.7."""

_NOTIFICATION_TARGETS: Final[frozenset[str]] = frozenset(
    {"supervisory_authority", "data_subject"}
)


def build_breach_notification(
    *,
    notification_target: NotificationTarget | str,
    breach_id: str,
    nature_of_breach: str,
    awareness_timestamp: str,
    likely_consequences: str,
    measures_taken: str,
    categories_of_data: list[str] | None = None,
    categories_of_data_subjects: list[str] | None = None,
    approximate_data_subject_count: int | None = None,
    approximate_record_count: int | None = None,
    dpo_contact: str | None = None,
    remediation_advice: str | None = None,
) -> dict[str, Any]:
    """Build the ``payload.data`` dict for a breach notification event.

    The caller wraps this dict into an ``intent="event"`` envelope via
    :func:`arsia_protocol.message.create_event`, setting
    ``payload.type`` to :data:`PAYLOAD_TYPE_BREACH_NOTIFICATION` and
    ``payload.version`` to ``"1.0"``.

    All six REQUIRED fields are positional-keyword. OPTIONAL fields
    (SHOULD-level per the spec) default to ``None`` and are omitted
    from the output when not provided.

    Args:
        notification_target: ``"supervisory_authority"`` (Art. 33) or
            ``"data_subject"`` (Art. 34).
        breach_id: UUID v4 identifying this breach.
        nature_of_breach: Description of the breach (1–2048 chars).
        awareness_timestamp: RFC 3339 ms UTC timestamp of awareness.
        likely_consequences: Likely consequences (1–2048 chars).
        measures_taken: Measures taken or proposed (1–2048 chars).
        categories_of_data: Categories of personal data affected.
        categories_of_data_subjects: Categories of data subjects.
        approximate_data_subject_count: Approximate count of subjects.
        approximate_record_count: Approximate count of records.
        dpo_contact: DPO name and contact details (1–512 chars).
        remediation_advice: Steps data subjects can take (1–2048 chars).

    Returns:
        A plain dict suitable for ``payload.data``.

    Raises:
        ValueError: if ``notification_target`` is not one of the two
            allowed values.

    Spec: ARSIA-State.md §5.7.
    """
    if notification_target not in _NOTIFICATION_TARGETS:
        raise ValueError(
            f"notification_target {notification_target!r} must be one of "
            f"{sorted(_NOTIFICATION_TARGETS)} (State §5.7)"
        )

    data: dict[str, Any] = {
        "notification_target": notification_target,
        "breach_id": breach_id,
        "nature_of_breach": nature_of_breach,
        "awareness_timestamp": awareness_timestamp,
        "likely_consequences": likely_consequences,
        "measures_taken": measures_taken,
    }

    if categories_of_data is not None:
        data["categories_of_data"] = categories_of_data
    if categories_of_data_subjects is not None:
        data["categories_of_data_subjects"] = categories_of_data_subjects
    if approximate_data_subject_count is not None:
        data["approximate_data_subject_count"] = approximate_data_subject_count
    if approximate_record_count is not None:
        data["approximate_record_count"] = approximate_record_count
    if dpo_contact is not None:
        data["dpo_contact"] = dpo_contact
    if remediation_advice is not None:
        data["remediation_advice"] = remediation_advice

    return data


def validate_breach_notification(
    data: dict[str, Any],
) -> list[ValidationError]:
    """Validate a breach notification payload dict against the model.

    Returns a list of validation errors. An empty list means the payload
    is valid.

    Args:
        data: The ``payload.data`` dict to validate.

    Returns:
        Structured validation errors (empty when valid).

    Spec: ARSIA-State.md §5.7.
    """
    errors: list[ValidationError] = []
    try:
        BreachNotificationPayload.model_validate(data)
    except Exception as exc:  # noqa: BLE001
        for line in str(exc).splitlines():
            stripped = line.strip()
            if stripped:
                errors.append(
                    ValidationError(
                        code="breach_notification_invalid",
                        message=stripped,
                        details={"pydantic_error": stripped},
                        spec_ref="State §5.7",
                    )
                )
    return errors


__all__ = [
    "BREACH_CAPABILITY",
    "PAYLOAD_TYPE_BREACH_NOTIFICATION",
    "build_breach_notification",
    "validate_breach_notification",
]
