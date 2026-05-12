# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for arsia_protocol.types.breach — BreachNotificationPayload model."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from arsia_protocol.types.breach import BreachNotificationPayload

_VALID_BREACH_ID = str(uuid.uuid4())
_VALID_TIMESTAMP = "2026-05-06T12:00:00.000Z"


def _minimal_payload(**overrides: object) -> dict:
    base = {
        "notification_target": "supervisory_authority",
        "breach_id": _VALID_BREACH_ID,
        "nature_of_breach": "Unauthorized access to customer database",
        "awareness_timestamp": _VALID_TIMESTAMP,
        "likely_consequences": "Potential identity theft",
        "measures_taken": "Revoked access, notified affected users",
    }
    base.update(overrides)
    return base


# -- Valid payloads ----------------------------------------------------------


class TestValidPayloads:
    def test_minimal_required_fields(self) -> None:
        p = BreachNotificationPayload.model_validate(_minimal_payload())
        assert p.notification_target == "supervisory_authority"
        assert p.breach_id == _VALID_BREACH_ID
        assert p.nature_of_breach == "Unauthorized access to customer database"
        assert p.awareness_timestamp == _VALID_TIMESTAMP
        assert p.likely_consequences == "Potential identity theft"
        assert p.measures_taken == "Revoked access, notified affected users"

    def test_supervisory_authority_target(self) -> None:
        p = BreachNotificationPayload.model_validate(
            _minimal_payload(notification_target="supervisory_authority")
        )
        assert p.notification_target == "supervisory_authority"

    def test_data_subject_target(self) -> None:
        p = BreachNotificationPayload.model_validate(
            _minimal_payload(notification_target="data_subject")
        )
        assert p.notification_target == "data_subject"

    def test_optional_fields_absent_valid(self) -> None:
        p = BreachNotificationPayload.model_validate(_minimal_payload())
        assert p.categories_of_data is None
        assert p.categories_of_data_subjects is None
        assert p.approximate_data_subject_count is None
        assert p.approximate_record_count is None
        assert p.dpo_contact is None
        assert p.remediation_advice is None

    def test_all_optional_supervisory_fields(self) -> None:
        p = BreachNotificationPayload.model_validate(
            _minimal_payload(
                categories_of_data=["names", "financial"],
                categories_of_data_subjects=["customers"],
                approximate_data_subject_count=1500,
                approximate_record_count=3000,
                dpo_contact="Jane Doe, dpo@example.com",
            )
        )
        assert p.categories_of_data == ["names", "financial"]
        assert p.categories_of_data_subjects == ["customers"]
        assert p.approximate_data_subject_count == 1500
        assert p.approximate_record_count == 3000
        assert p.dpo_contact == "Jane Doe, dpo@example.com"

    def test_remediation_advice_for_data_subject(self) -> None:
        p = BreachNotificationPayload.model_validate(
            _minimal_payload(
                notification_target="data_subject",
                remediation_advice="Change your password immediately.",
            )
        )
        assert p.remediation_advice == "Change your password immediately."

    def test_all_fields_present(self) -> None:
        p = BreachNotificationPayload.model_validate(
            _minimal_payload(
                categories_of_data=["health"],
                categories_of_data_subjects=["patients"],
                approximate_data_subject_count=0,
                approximate_record_count=0,
                dpo_contact="DPO",
                remediation_advice="Monitor your accounts.",
            )
        )
        assert p.categories_of_data == ["health"]
        assert p.approximate_data_subject_count == 0
        assert p.remediation_advice == "Monitor your accounts."

    def test_zero_counts_valid(self) -> None:
        p = BreachNotificationPayload.model_validate(
            _minimal_payload(
                approximate_data_subject_count=0,
                approximate_record_count=0,
            )
        )
        assert p.approximate_data_subject_count == 0
        assert p.approximate_record_count == 0


# -- Missing required fields ------------------------------------------------


class TestMissingRequiredFields:
    @pytest.mark.parametrize(
        "field",
        [
            "notification_target",
            "breach_id",
            "nature_of_breach",
            "awareness_timestamp",
            "likely_consequences",
            "measures_taken",
        ],
    )
    def test_missing_required_field(self, field: str) -> None:
        data = _minimal_payload()
        del data[field]
        with pytest.raises(ValidationError) as exc_info:
            BreachNotificationPayload.model_validate(data)
        assert field in str(exc_info.value)


# -- Invalid values ----------------------------------------------------------


class TestInvalidValues:
    def test_invalid_notification_target(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(notification_target="regulator")
            )

    def test_invalid_breach_id_not_uuid(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(breach_id="not-a-uuid")
            )

    def test_invalid_awareness_timestamp_no_ms(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(awareness_timestamp="2026-05-06T12:00:00Z")
            )

    def test_invalid_awareness_timestamp_no_z(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(
                    awareness_timestamp="2026-05-06T12:00:00.000+01:00"
                )
            )

    def test_nature_of_breach_empty(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(nature_of_breach="")
            )

    def test_nature_of_breach_too_long(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(nature_of_breach="x" * 2049)
            )

    def test_likely_consequences_empty(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(likely_consequences="")
            )

    def test_measures_taken_empty(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(measures_taken="")
            )

    def test_measures_taken_too_long(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(measures_taken="m" * 2049)
            )

    def test_negative_data_subject_count(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(approximate_data_subject_count=-1)
            )

    def test_negative_record_count(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(approximate_record_count=-1)
            )

    def test_dpo_contact_empty(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(dpo_contact="")
            )

    def test_dpo_contact_too_long(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(dpo_contact="d" * 513)
            )

    def test_remediation_advice_empty(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(remediation_advice="")
            )

    def test_remediation_advice_too_long(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(remediation_advice="r" * 2049)
            )

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            BreachNotificationPayload.model_validate(
                _minimal_payload(unknown_field="value")
            )


# -- Serialization roundtrip -------------------------------------------------


class TestSerialization:
    def test_roundtrip(self) -> None:
        data = _minimal_payload(
            categories_of_data=["email"],
            remediation_advice="Update your password.",
        )
        p = BreachNotificationPayload.model_validate(data)
        dumped = p.model_dump(exclude_none=True)
        assert dumped["notification_target"] == "supervisory_authority"
        assert dumped["categories_of_data"] == ["email"]
        assert dumped["remediation_advice"] == "Update your password."
        assert "approximate_data_subject_count" not in dumped

    def test_model_dump_includes_none_optional(self) -> None:
        p = BreachNotificationPayload.model_validate(_minimal_payload())
        dumped = p.model_dump()
        assert dumped["categories_of_data"] is None
        assert dumped["remediation_advice"] is None
