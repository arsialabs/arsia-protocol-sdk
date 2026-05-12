# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for arsia_protocol.breach — builder and validator."""

from __future__ import annotations

import uuid

import pytest

from arsia_protocol.state.breach import (
    BREACH_CAPABILITY,
    PAYLOAD_TYPE_BREACH_NOTIFICATION,
    build_breach_notification,
    validate_breach_notification,
)

_VALID_BREACH_ID = str(uuid.uuid4())
_VALID_TIMESTAMP = "2026-05-06T14:30:00.000Z"

_REQUIRED_KWARGS = {
    "notification_target": "supervisory_authority",
    "breach_id": _VALID_BREACH_ID,
    "nature_of_breach": "Unauthorized database access",
    "awareness_timestamp": _VALID_TIMESTAMP,
    "likely_consequences": "Potential identity theft for affected users",
    "measures_taken": "Revoked credentials, initiated forensic investigation",
}


# -- Constants ---------------------------------------------------------------


class TestConstants:
    def test_payload_type(self) -> None:
        assert PAYLOAD_TYPE_BREACH_NOTIFICATION == (
            "arsiaprotocol.compliance/breach-notification"
        )

    def test_capability(self) -> None:
        assert BREACH_CAPABILITY == "arsiaprotocol.compliance.breach.notify"


# -- build_breach_notification -----------------------------------------------


class TestBuildBreachNotification:
    def test_required_fields_only(self) -> None:
        data = build_breach_notification(**_REQUIRED_KWARGS)
        assert data["notification_target"] == "supervisory_authority"
        assert data["breach_id"] == _VALID_BREACH_ID
        assert data["nature_of_breach"] == "Unauthorized database access"
        assert data["awareness_timestamp"] == _VALID_TIMESTAMP
        assert data["likely_consequences"] == "Potential identity theft for affected users"
        assert data["measures_taken"] == "Revoked credentials, initiated forensic investigation"

    def test_no_optional_fields_in_output(self) -> None:
        data = build_breach_notification(**_REQUIRED_KWARGS)
        assert "categories_of_data" not in data
        assert "categories_of_data_subjects" not in data
        assert "approximate_data_subject_count" not in data
        assert "approximate_record_count" not in data
        assert "dpo_contact" not in data
        assert "remediation_advice" not in data

    def test_supervisory_optional_fields(self) -> None:
        data = build_breach_notification(
            **_REQUIRED_KWARGS,
            categories_of_data=["names", "email_addresses"],
            categories_of_data_subjects=["employees"],
            approximate_data_subject_count=250,
            approximate_record_count=500,
            dpo_contact="J. Smith, dpo@corp.example",
        )
        assert data["categories_of_data"] == ["names", "email_addresses"]
        assert data["categories_of_data_subjects"] == ["employees"]
        assert data["approximate_data_subject_count"] == 250
        assert data["approximate_record_count"] == 500
        assert data["dpo_contact"] == "J. Smith, dpo@corp.example"

    def test_data_subject_remediation_advice(self) -> None:
        kwargs = {**_REQUIRED_KWARGS, "notification_target": "data_subject"}
        data = build_breach_notification(
            **kwargs,
            remediation_advice="Change your password and enable MFA.",
        )
        assert data["notification_target"] == "data_subject"
        assert data["remediation_advice"] == "Change your password and enable MFA."

    def test_all_optional_fields(self) -> None:
        data = build_breach_notification(
            **_REQUIRED_KWARGS,
            categories_of_data=["health"],
            categories_of_data_subjects=["patients"],
            approximate_data_subject_count=0,
            approximate_record_count=0,
            dpo_contact="DPO",
            remediation_advice="Monitor accounts.",
        )
        assert len(data) == 12

    def test_invalid_notification_target_raises(self) -> None:
        kwargs = {**_REQUIRED_KWARGS, "notification_target": "regulator"}
        with pytest.raises(ValueError, match="notification_target"):
            build_breach_notification(**kwargs)

    def test_returns_plain_dict(self) -> None:
        data = build_breach_notification(**_REQUIRED_KWARGS)
        assert isinstance(data, dict)

    def test_output_matches_schema_field_names(self) -> None:
        data = build_breach_notification(**_REQUIRED_KWARGS)
        expected_keys = {
            "notification_target",
            "breach_id",
            "nature_of_breach",
            "awareness_timestamp",
            "likely_consequences",
            "measures_taken",
        }
        assert set(data.keys()) == expected_keys


# -- validate_breach_notification --------------------------------------------


class TestValidateBreachNotification:
    def test_valid_payload_no_errors(self) -> None:
        data = build_breach_notification(**_REQUIRED_KWARGS)
        errors = validate_breach_notification(data)
        assert errors == []

    def test_valid_with_all_fields(self) -> None:
        data = build_breach_notification(
            **_REQUIRED_KWARGS,
            categories_of_data=["financial"],
            remediation_advice="Monitor your bank statements.",
        )
        errors = validate_breach_notification(data)
        assert errors == []

    def test_missing_required_field(self) -> None:
        data = build_breach_notification(**_REQUIRED_KWARGS)
        del data["breach_id"]
        errors = validate_breach_notification(data)
        assert len(errors) > 0
        assert any("breach_id" in e.message for e in errors)

    def test_invalid_target(self) -> None:
        data = {**_REQUIRED_KWARGS, "notification_target": "invalid"}
        errors = validate_breach_notification(data)
        assert len(errors) > 0

    def test_extra_field_rejected(self) -> None:
        data = build_breach_notification(**_REQUIRED_KWARGS)
        data["extra_field"] = "unexpected"
        errors = validate_breach_notification(data)
        assert len(errors) > 0

    def test_empty_dict(self) -> None:
        errors = validate_breach_notification({})
        assert len(errors) > 0

    def test_missing_notification_target(self) -> None:
        """State §5.7: notification_target is REQUIRED."""
        data = build_breach_notification(**_REQUIRED_KWARGS)
        del data["notification_target"]
        errors = validate_breach_notification(data)
        assert len(errors) > 0
        assert any("notification_target" in e.message for e in errors)

    def test_missing_nature_of_breach(self) -> None:
        """State §5.7: nature_of_breach is REQUIRED."""
        data = build_breach_notification(**_REQUIRED_KWARGS)
        del data["nature_of_breach"]
        errors = validate_breach_notification(data)
        assert len(errors) > 0
        assert any("nature_of_breach" in e.message for e in errors)

    def test_missing_awareness_timestamp(self) -> None:
        """State §5.7: awareness_timestamp is REQUIRED."""
        data = build_breach_notification(**_REQUIRED_KWARGS)
        del data["awareness_timestamp"]
        errors = validate_breach_notification(data)
        assert len(errors) > 0
        assert any("awareness_timestamp" in e.message for e in errors)

    def test_missing_likely_consequences(self) -> None:
        """State §5.7: likely_consequences is REQUIRED."""
        data = build_breach_notification(**_REQUIRED_KWARGS)
        del data["likely_consequences"]
        errors = validate_breach_notification(data)
        assert len(errors) > 0
        assert any("likely_consequences" in e.message for e in errors)

    def test_missing_measures_taken(self) -> None:
        """State §5.7: measures_taken is REQUIRED."""
        data = build_breach_notification(**_REQUIRED_KWARGS)
        del data["measures_taken"]
        errors = validate_breach_notification(data)
        assert len(errors) > 0
        assert any("measures_taken" in e.message for e in errors)


# -- Re-export availability -------------------------------------------------


class TestReExports:
    def test_available_from_top_level(self) -> None:
        import arsia_protocol

        assert hasattr(arsia_protocol, "build_breach_notification")
        assert hasattr(arsia_protocol, "validate_breach_notification")
        assert hasattr(arsia_protocol, "PAYLOAD_TYPE_BREACH_NOTIFICATION")
        assert hasattr(arsia_protocol, "BREACH_CAPABILITY")
        assert hasattr(arsia_protocol, "BreachNotificationPayload")
        assert hasattr(arsia_protocol, "NotificationTarget")
