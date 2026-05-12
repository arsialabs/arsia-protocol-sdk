# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.state``.

Spec: ARSIA-State.md §2.1 and §7.1.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arsia_protocol.types.state import ArsiaAuditRecord, StateEntry


def _base_state_entry_kwargs() -> dict[str, object]:
    return {
        "key": "agent:acme.billing/session/invoice-draft",
        "value": {"amount": 100},
        "owner_agent_id": "agent:acme.billing",
        "scope": "session",
        "created_at": "2026-03-24T10:15:30.000Z",
        "updated_at": "2026-03-24T10:15:30.000Z",
        "pii_classification": "none",
        "version": 1,
    }


def test_state_entry_minimal_valid() -> None:
    """A minimal StateEntry constructs successfully.

    Spec: ARSIA-State.md §2.1.
    """
    entry = StateEntry(**_base_state_entry_kwargs())  # type: ignore[arg-type]
    assert entry.scope == "session"
    assert entry.pii_classification == "none"
    assert entry.version == 1


def test_state_entry_rejects_invalid_owner_agent_id() -> None:
    """owner_agent_id must be a valid agent identifier.

    Spec: ARSIA-Core.md §3.3.
    """
    kwargs = _base_state_entry_kwargs()
    kwargs["owner_agent_id"] = "not-an-agent-id"
    with pytest.raises(ValidationError):
        StateEntry(**kwargs)  # type: ignore[arg-type]


def test_state_entry_rejects_unknown_scope() -> None:
    """scope must be one of the four Literal values.

    Spec: ARSIA-State.md §1.
    """
    kwargs = _base_state_entry_kwargs()
    kwargs["scope"] = "universe"
    with pytest.raises(ValidationError):
        StateEntry(**kwargs)  # type: ignore[arg-type]


def test_state_entry_pseudonymised_spelling_accepted() -> None:
    """The British spelling 'pseudonymised' is accepted.

    Spec: ARSIA-State.md §2.1.10.
    """
    kwargs = _base_state_entry_kwargs()
    kwargs["pii_classification"] = "pseudonymised"
    entry = StateEntry(**kwargs)  # type: ignore[arg-type]
    assert entry.pii_classification == "pseudonymised"


def _base_audit_kwargs() -> dict[str, object]:
    return {
        "record_id": "550e8400-e29b-41d4-a716-446655440000",
        "message_id": "550e8400-e29b-41d4-a716-446655440001",
        "event_type": "request",
        "from_agent": "agent:acme.billing",
        "to_agent": "agent:acme.payments",
        "intent": "request",
        "payload_type": "com.acme.payments/charge",
        "payload_hash": "a" * 64,
        "compliance_profile": "GDPR-STANDARD",
        "processed_at": "2026-03-24T10:15:30.000Z",
        "retained_until": "2028-03-24T10:15:30.000Z",
        "operator_id": "PT501234567",
    }


def test_audit_record_minimal_valid() -> None:
    """A minimal ArsiaAuditRecord constructs successfully.

    Spec: ARSIA-State.md §7.1.
    """
    rec = ArsiaAuditRecord(**_base_audit_kwargs())  # type: ignore[arg-type]
    assert rec.event_type == "request"
    assert rec.compliance_profile == "GDPR-STANDARD"


def test_audit_record_approved_requires_approver() -> None:
    """human_oversight_status='approved' requires approver_id.

    Spec: ARSIA-State.md §7.1.
    """
    kwargs = _base_audit_kwargs()
    kwargs["human_oversight_status"] = "approved"
    with pytest.raises(ValidationError, match="approver_id is required"):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]


def test_audit_record_approved_with_approver_ok() -> None:
    """human_oversight_status='approved' with approver_id is valid.

    Spec: ARSIA-State.md §7.1.
    """
    kwargs = _base_audit_kwargs()
    kwargs["human_oversight_status"] = "approved"
    kwargs["approver_id"] = "agent:acme.compliance"
    rec = ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]
    assert rec.approver_id == "agent:acme.compliance"


def test_audit_record_rejects_bad_payload_hash() -> None:
    """payload_hash must be a 64-char lowercase hex SHA-256 digest.

    Spec: ARSIA-State.md §7.1.
    """
    kwargs = _base_audit_kwargs()
    kwargs["payload_hash"] = "NOT-A-HASH"
    with pytest.raises(ValidationError):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]
