# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for the :mod:`arsia_protocol.audit` Layer 5 module.

Covers ARSIA-State.md §7.1 — audit record builders and the
``payload_hash`` derivation. Storage-layer behaviour (append-only,
immutability, query endpoint) is out of scope for the SDK and is
tested in the product repo.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest

from arsia_protocol.state.audit import (
    AUDIT_EVENT_TYPES,
    build_audit_record,
    compute_payload_hash,
    derive_event_type_from_intent,
    validate_audit_record,
)
from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.types.state import ArsiaAuditRecord

_SENDER = "agent:acme.alpha"
_RECIPIENT = "agent:acme.beta"
_APPROVER = "agent:acme.oversight"
_MSG_ID = "11111111-1111-4111-9111-111111111111"
_TS = "2026-04-13T12:00:00.000Z"


def _envelope(
    *,
    compliance: dict | None = None,
    intent: str = "request",
    payload_type: str = "arsiaprotocol.state/set",
    payload_body: dict | None = None,
) -> dict:
    payload: dict = {"type": payload_type}
    if payload_body is not None:
        payload.update(payload_body)
    env: dict = {
        "v": "1.0",
        "id": _MSG_ID,
        "ts": _TS,
        "from": _SENDER,
        "to": _RECIPIENT,
        "intent": intent,
        "payload": payload,
    }
    if compliance is not None:
        env["compliance"] = compliance
    return env


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_audit_event_types_exactly_seventeen() -> None:
    assert len(AUDIT_EVENT_TYPES) == 17
    assert {
        "approval_decision",
        "approval_expired",
        "asset_transfer",
        "broker_relay",
        "dora_incident",
        "error",
        "event",
        "key_rotation",
        "pending_approval",
        "request",
        "response",
        "rollback",
        "state_delete",
        "state_grant",
        "state_purge",
        "state_revoke",
        "state_set",
    } == set(AUDIT_EVENT_TYPES)


# ---------------------------------------------------------------------------
# compute_payload_hash
# ---------------------------------------------------------------------------


def test_compute_payload_hash_matches_jcs_sha256() -> None:
    payload = {"type": "arsiaprotocol.state/set", "args": {"key": "k", "value": 1}}
    expected = hashlib.sha256(canonicalize(payload)).hexdigest()
    assert compute_payload_hash(payload) == expected


def test_compute_payload_hash_is_key_order_stable() -> None:
    a = {"type": "x", "args": {"a": 1, "b": 2}}
    b = {"args": {"b": 2, "a": 1}, "type": "x"}
    assert compute_payload_hash(a) == compute_payload_hash(b)


def test_compute_payload_hash_returns_hex_digest() -> None:
    h = compute_payload_hash({"type": "x"})
    assert len(h) == 64
    int(h, 16)  # parses as hex


def test_compute_payload_hash_sensitive_to_value_change() -> None:
    a = compute_payload_hash({"type": "x", "args": {"k": "v1"}})
    b = compute_payload_hash({"type": "x", "args": {"k": "v2"}})
    assert a != b


# ---------------------------------------------------------------------------
# derive_event_type_from_intent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "intent",
    [
        "request",
        "response",
        "event",
        "error",
        "pending_approval",
        "approval_decision",
    ],
)
def test_derive_event_type_from_intent_happy_path(intent: str) -> None:
    assert derive_event_type_from_intent(intent) == intent


def test_derive_event_type_from_intent_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="cannot derive"):
        derive_event_type_from_intent("hello")


def test_derive_event_type_from_intent_rejects_primitive_specific_types() -> None:
    # state_set / state_purge / asset_transfer / broker_relay /
    # key_rotation etc. cannot be inferred from the intent alone.
    for t in ("state_set", "state_purge", "asset_transfer"):
        with pytest.raises(ValueError):
            derive_event_type_from_intent(t)


# ---------------------------------------------------------------------------
# build_audit_record — happy path
# ---------------------------------------------------------------------------


def test_build_audit_record_minimum_happy_path() -> None:
    env = _envelope()
    record = build_audit_record(
        env,
        event_type="request",
        operator_id="LEI:529900T8BM49AURSDO55",
        effective_retention_days=90,
    )
    assert isinstance(record, ArsiaAuditRecord)
    assert record.message_id == _MSG_ID
    assert record.from_agent == _SENDER
    assert record.to_agent == _RECIPIENT
    assert record.intent == "request"
    assert record.payload_type == "arsiaprotocol.state/set"
    assert record.compliance_profile == "none"
    assert record.payload_hash == compute_payload_hash(env["payload"])
    UUID(record.record_id, version=4)


def test_build_audit_record_copies_compliance_profile() -> None:
    env = _envelope(compliance={"profile": "EU-AI-ACT-HIGH-RISK"})
    record = build_audit_record(
        env,
        event_type="request",
        operator_id="LEI:X",
        effective_retention_days=180,
    )
    assert record.compliance_profile == "EU-AI-ACT-HIGH-RISK"


def test_build_audit_record_inherits_data_residency_from_envelope() -> None:
    env = _envelope(compliance={"profile": "GDPR-STANDARD", "data_residency": "PT"})
    record = build_audit_record(
        env,
        event_type="request",
        operator_id="LEI:X",
        effective_retention_days=90,
    )
    assert record.data_residency == "PT"


def test_build_audit_record_explicit_data_residency_overrides_envelope() -> None:
    env = _envelope(compliance={"profile": "GDPR-STANDARD", "data_residency": "PT"})
    record = build_audit_record(
        env,
        event_type="request",
        operator_id="LEI:X",
        effective_retention_days=90,
        data_residency="EU",
    )
    assert record.data_residency == "EU"


def test_build_audit_record_computes_retained_until_from_processed_at() -> None:
    env = _envelope()
    ts = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
    record = build_audit_record(
        env,
        event_type="request",
        operator_id="LEI:X",
        effective_retention_days=180,
        processed_at=ts,
    )
    assert record.processed_at == "2026-04-13T12:00:00.000Z"
    expected_until = ts + timedelta(days=180)
    assert record.retained_until == "2026-10-10T12:00:00.000Z"
    assert record.retained_until.startswith(
        expected_until.strftime("%Y-%m-%dT%H:%M:%S")
    )


def test_build_audit_record_accepts_state_set_event_type() -> None:
    env = _envelope(intent="request", payload_type="arsiaprotocol.state/set")
    record = build_audit_record(
        env,
        event_type="state_set",
        operator_id="LEI:X",
        effective_retention_days=90,
    )
    assert record.event_type == "state_set"


def test_build_audit_record_state_purge_does_not_carry_value() -> None:
    # §3.2.2 / §5.3: the PURGE audit record MUST NOT include the value.
    # That's handled by the purge payload shape (build_purge_args
    # returns only key + reason — per-entry PURGE) and by the fact
    # that payload_hash hashes the canonical payload, not the raw
    # data. No leaked value here:
    env = _envelope(
        intent="request",
        payload_type="arsiaprotocol.state/purge",
        payload_body={
            "args": {
                "key": f"{_SENDER}/agent/personal-data",
                "reason": "GDPR Art. 17 request",
            }
        },
    )
    record = build_audit_record(
        env,
        event_type="state_purge",
        operator_id="LEI:X",
        effective_retention_days=90,
    )
    assert record.payload_type == "arsiaprotocol.state/purge"
    assert "value" not in env["payload"].get("args", {})
    # payload_hash still reproducible from the envelope's payload.
    assert record.payload_hash == compute_payload_hash(env["payload"])


def test_build_audit_record_accepts_caller_supplied_record_id() -> None:
    rid = "22222222-2222-4222-9222-222222222222"
    env = _envelope()
    record = build_audit_record(
        env,
        event_type="request",
        operator_id="LEI:X",
        effective_retention_days=90,
        record_id=rid,
    )
    assert record.record_id == rid


def test_build_audit_record_populates_oversight_status_and_approver() -> None:
    env = _envelope(intent="approval_decision", payload_type="arsiaprotocol.action/approved")
    record = build_audit_record(
        env,
        event_type="approval_decision",
        operator_id="LEI:X",
        effective_retention_days=180,
        oversight_status="approved",
        approver_id=_APPROVER,
    )
    assert record.human_oversight_status == "approved"
    assert record.approver_id == _APPROVER


# ---------------------------------------------------------------------------
# build_audit_record — error paths
# ---------------------------------------------------------------------------


def test_build_audit_record_rejects_unknown_event_type() -> None:
    with pytest.raises(ValueError, match="not one of the 17"):
        build_audit_record(
            _envelope(),
            event_type="bogus",  # type: ignore[arg-type]
            operator_id="LEI:X",
            effective_retention_days=90,
        )


def test_build_audit_record_rejects_zero_retention() -> None:
    with pytest.raises(ValueError, match=">= 1"):
        build_audit_record(
            _envelope(),
            event_type="request",
            operator_id="LEI:X",
            effective_retention_days=0,
        )


def test_build_audit_record_requires_approver_when_approved() -> None:
    with pytest.raises(ValueError, match="approver_id is required"):
        build_audit_record(
            _envelope(),
            event_type="approval_decision",
            operator_id="LEI:X",
            effective_retention_days=90,
            oversight_status="approved",
        )


def test_build_audit_record_requires_approver_when_denied() -> None:
    with pytest.raises(ValueError, match="approver_id is required"):
        build_audit_record(
            _envelope(),
            event_type="approval_decision",
            operator_id="LEI:X",
            effective_retention_days=90,
            oversight_status="denied",
        )


def test_build_audit_record_allows_pending_without_approver() -> None:
    record = build_audit_record(
        _envelope(intent="pending_approval"),
        event_type="pending_approval",
        operator_id="LEI:X",
        effective_retention_days=90,
        oversight_status="pending",
    )
    assert record.approver_id is None
    assert record.human_oversight_status == "pending"


def test_build_audit_record_rejects_missing_envelope_id() -> None:
    env = _envelope()
    del env["id"]
    with pytest.raises(ValueError, match=r"envelope\['id'\]"):
        build_audit_record(
            env,
            event_type="request",
            operator_id="LEI:X",
            effective_retention_days=90,
        )


def test_build_audit_record_rejects_missing_from() -> None:
    env = _envelope()
    del env["from"]
    with pytest.raises(ValueError, match=r"envelope\['from'\]"):
        build_audit_record(
            env,
            event_type="request",
            operator_id="LEI:X",
            effective_retention_days=90,
        )


def test_build_audit_record_rejects_missing_payload_type() -> None:
    env = _envelope()
    env["payload"] = {}
    with pytest.raises(ValueError, match=r"payload"):
        build_audit_record(
            env,
            event_type="request",
            operator_id="LEI:X",
            effective_retention_days=90,
        )


def test_build_audit_record_rejects_non_dict_payload() -> None:
    env = _envelope()
    env["payload"] = "oops"
    with pytest.raises(ValueError, match=r"payload"):
        build_audit_record(
            env,
            event_type="request",
            operator_id="LEI:X",
            effective_retention_days=90,
        )


def test_build_audit_record_default_processed_at_is_close_to_now() -> None:
    record = build_audit_record(
        _envelope(),
        event_type="request",
        operator_id="LEI:X",
        effective_retention_days=90,
    )
    parsed = datetime.fromisoformat(record.processed_at.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    assert abs((now - parsed).total_seconds()) < 5


# ---------------------------------------------------------------------------
# Retention-per-profile sanity: the caller resolves the retention, not audit.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "retention_days,days_later",
    [(90, 90), (180, 180), (365, 365), (1825, 1825)],
)
def test_build_audit_record_retained_until_spans_retention_days(
    retention_days: int, days_later: int
) -> None:
    processed = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    record = build_audit_record(
        _envelope(),
        event_type="request",
        operator_id="LEI:X",
        effective_retention_days=retention_days,
        processed_at=processed,
    )
    parsed = datetime.fromisoformat(record.retained_until.replace("Z", "+00:00"))
    assert (parsed - processed).days == days_later


# ---------------------------------------------------------------------------
# validate_audit_record — §7.1 L1 + L2
# ---------------------------------------------------------------------------


def _valid_record() -> dict:
    record = build_audit_record(
        _envelope(compliance={"profile": "GDPR-STANDARD"}),
        event_type="request",
        operator_id="LEI:529900T8BM49AURSDO55",
        effective_retention_days=90,
    )
    return record.model_dump(mode="json", exclude_none=True)


def test_validate_audit_record_happy_path_returns_no_errors() -> None:
    assert validate_audit_record(_valid_record()) == []


def test_validate_audit_record_reports_missing_required_field() -> None:
    record = _valid_record()
    del record["payload_hash"]
    errors = validate_audit_record(record)
    assert any("payload_hash" in e.message for e in errors)


def test_validate_audit_record_flags_malformed_payload_hash() -> None:
    record = _valid_record()
    record["payload_hash"] = "NOT-HEX"
    errors = validate_audit_record(record)
    assert any(e.code == "invalid_payload_hash" for e in errors)


def test_validate_audit_record_rejects_unknown_event_type() -> None:
    record = _valid_record()
    record["event_type"] = "made_up_event"
    errors = validate_audit_record(record)
    assert any(e.code == "invalid_event_type" for e in errors)


def test_validate_audit_record_requires_approver_when_approved() -> None:
    record = _valid_record()
    record["human_oversight_status"] = "approved"
    record.pop("approver_id", None)
    errors = validate_audit_record(record)
    assert any(e.code == "missing_approver_id" for e in errors)


def test_validate_audit_record_strict_short_circuits_on_l1() -> None:
    record = _valid_record()
    del record["payload_hash"]
    # In strict mode L2 is skipped: only the L1 schema error is
    # returned, not the L2 payload_hash-format check.
    errors = validate_audit_record(record, strict=True)
    assert errors
    assert all(e.code == "schema_violation" for e in errors)


def test_validate_audit_record_accepts_pydantic_model() -> None:
    """build_audit_record → validate_audit_record composes directly."""
    from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
    from arsia_protocol import (
        create_request,
        sign_message,
        build_audit_record,
        validate_audit_record,
    )
    priv, _pub = generate_keypair()
    req = create_request(
        "agent:test.a", "agent:test.b", "com.test/echo", ["test.echo"]
    )
    signed = sign_message(req, priv, "agent:test.a#key1")
    rec = build_audit_record(
        signed,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
    )
    errors = validate_audit_record(rec)
    assert errors == [], f"Expected [], got {errors}"


def test_validate_audit_record_accepts_dict_with_none() -> None:
    """Dict with None optional fields is cleaned before validation."""
    from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
    from arsia_protocol import (
        create_request,
        sign_message,
        build_audit_record,
        validate_audit_record,
    )
    priv, _pub = generate_keypair()
    req = create_request(
        "agent:test.a", "agent:test.b", "com.test/echo", ["test.echo"]
    )
    signed = sign_message(req, priv, "agent:test.a#key1")
    rec = build_audit_record(
        signed,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
    )
    rec_dict = rec.model_dump()
    none_keys = [k for k, v in rec_dict.items() if v is None]
    assert len(none_keys) > 0, "Test requires None values to exist"
    errors = validate_audit_record(rec_dict)
    assert errors == [], f"Expected [], got {errors}"


def test_validate_audit_record_clean_dict_still_works() -> None:
    """Dict without None values passes as before."""
    from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
    from arsia_protocol import (
        create_request,
        sign_message,
        build_audit_record,
        validate_audit_record,
    )
    priv, _pub = generate_keypair()
    req = create_request(
        "agent:test.a", "agent:test.b", "com.test/echo", ["test.echo"]
    )
    signed = sign_message(req, priv, "agent:test.a#key1")
    rec = build_audit_record(
        signed,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
    )
    rec_clean = {k: v for k, v in rec.model_dump().items() if v is not None}
    errors = validate_audit_record(rec_clean)
    assert errors == [], f"Expected [], got {errors}"


def test_validate_audit_record_rejects_invalid_type() -> None:
    """Non-Mapping, non-model input returns error."""
    from arsia_protocol import validate_audit_record
    errors = validate_audit_record("not a record")  # type: ignore[arg-type]
    assert len(errors) == 1
    assert errors[0].code == "invalid_record_type"


# ---------------------------------------------------------------------------
# §7.1 — State-specific audit fields (req:b6808630, b9e1be32, b02d9474, 51c9dc0a)
# ---------------------------------------------------------------------------


def test_build_audit_record_with_state_fields() -> None:
    """State-specific fields (entry_key, owner_agent_id, version) propagate."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="state_set",
        operator_id="org:test",
        effective_retention_days=90,
        entry_key="agent:acme.alpha/agent/k1",
        owner_agent_id="agent:acme.alpha",
        entry_version=3,
    )
    assert rec.entry_key == "agent:acme.alpha/agent/k1"
    assert rec.owner_agent_id == "agent:acme.alpha"
    assert rec.version == 3


def test_build_audit_record_state_fields_default_none() -> None:
    """State-specific fields default to None when not provided."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
    )
    assert rec.entry_key is None
    assert rec.owner_agent_id is None
    assert rec.version is None


def test_audit_record_model_accepts_state_fields() -> None:
    """ArsiaAuditRecord model validates state-specific fields."""
    rec = ArsiaAuditRecord(
        record_id="33333333-3333-4333-a333-333333333333",
        message_id=_MSG_ID,
        event_type="state_set",
        from_agent=_SENDER,
        to_agent=_RECIPIENT,
        intent="request",
        payload_type="arsiaprotocol.state/set",
        payload_hash="a" * 64,
        compliance_profile="none",
        processed_at=_TS,
        retained_until="2026-07-13T12:00:00.000Z",
        operator_id="org:test",
        entry_key="agent:acme.alpha/agent/k1",
        owner_agent_id="agent:acme.alpha",
        version=5,
    )
    assert rec.entry_key == "agent:acme.alpha/agent/k1"
    assert rec.version == 5


# ---------------------------------------------------------------------------
# BL-10: compute_payload_hash with JWE string payloads (Core §5.3.1)
# ---------------------------------------------------------------------------


def test_compute_payload_hash_jwe_string() -> None:
    """JWE Compact Serialization string is hashed as raw UTF-8 bytes."""
    jwe = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9.xx.yy.zz.aa"
    result = compute_payload_hash(jwe)
    expected = hashlib.sha256(jwe.encode("utf-8")).hexdigest()
    assert result == expected
    assert len(result) == 64


def test_compute_payload_hash_dict_unchanged() -> None:
    """Dict payloads still use JCS canonicalization."""
    payload = {"type": "com.example.test", "args": {"key": "value"}}
    result = compute_payload_hash(payload)
    assert len(result) == 64
    assert result == compute_payload_hash(payload)


def test_compute_payload_hash_string_vs_dict_differ() -> None:
    """String and dict paths produce different hashes for equivalent content.

    Dict path applies RFC 8785 (JCS) canonicalization which sorts keys,
    so {"z":1,"a":2} becomes {"a":2,"z":1}. String path hashes raw UTF-8
    bytes without reordering. The hashes MUST differ.
    """
    payload_dict: dict[str, Any] = {"z": 1, "a": 2}
    payload_str = '{"z":1,"a":2}'
    hash_dict = compute_payload_hash(payload_dict)
    hash_str = compute_payload_hash(payload_str)
    assert hash_dict != hash_str, (
        "Dict (RFC 8785 sorted) and string (raw UTF-8) must produce different hashes"
    )
    assert len(hash_dict) == 64
    assert len(hash_str) == 64


# ---------------------------------------------------------------------------
# BL-01 — AuditEventType has 17 values (State §7.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event_type",
    [
        "approval_decision",
        "approval_expired",
        "asset_transfer",
        "broker_relay",
        "dora_incident",
        "error",
        "event",
        "key_rotation",
        "pending_approval",
        "request",
        "response",
        "rollback",
        "state_delete",
        "state_grant",
        "state_purge",
        "state_revoke",
        "state_set",
    ],
)
def test_all_seventeen_event_types_valid(event_type: str) -> None:
    assert event_type in AUDIT_EVENT_TYPES


def test_state_write_not_a_valid_event_type() -> None:
    assert "state_write" not in AUDIT_EVENT_TYPES


def test_build_audit_record_with_new_event_types() -> None:
    for et in ("state_delete", "state_grant", "state_revoke",
               "approval_expired", "dora_incident", "rollback"):
        env = _envelope()
        rec = build_audit_record(
            env,
            event_type=et,  # type: ignore[arg-type]
            operator_id="org:test",
            effective_retention_days=90,
        )
        assert rec.event_type == et


# ---------------------------------------------------------------------------
# BL-14 — actor_agent_id on ArsiaAuditRecord (State §1.2)
# ---------------------------------------------------------------------------


def test_build_audit_record_with_actor_agent_id() -> None:
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="state_set",
        operator_id="org:test",
        effective_retention_days=90,
        actor_agent_id="agent:acme.delegatee",
    )
    assert rec.actor_agent_id == "agent:acme.delegatee"


def test_build_audit_record_actor_agent_id_default_none() -> None:
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
    )
    assert rec.actor_agent_id is None


def test_audit_record_model_accepts_actor_agent_id() -> None:
    rec = ArsiaAuditRecord(
        record_id="44444444-4444-4444-a444-444444444444",
        message_id=_MSG_ID,
        event_type="state_set",
        from_agent=_SENDER,
        to_agent=_RECIPIENT,
        intent="request",
        payload_type="arsiaprotocol.state/set",
        payload_hash="b" * 64,
        compliance_profile="none",
        processed_at=_TS,
        retained_until="2026-07-13T12:00:00.000Z",
        operator_id="org:test",
        actor_agent_id="agent:acme.delegatee",
    )
    assert rec.actor_agent_id == "agent:acme.delegatee"


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


# ---------------------------------------------------------------------------
# BL-12 — Grant audit fields on ArsiaAuditRecord (State §1.3, §3.3.1, §3.3.2)
# ---------------------------------------------------------------------------


def test_build_audit_record_with_grant_fields() -> None:
    """All 6 grant fields propagate through build_audit_record."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="state_grant",
        operator_id="org:test",
        effective_retention_days=90,
        grant_id="aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
        key_pattern="agent:acme.alpha/shared/*",
        grantor_agent_id="agent:acme.alpha",
        grantee_agent_id="agent:acme.beta",
        access_level="read_write",
        valid_until="2027-01-01T00:00:00.000Z",
    )
    assert rec.grant_id == "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
    assert rec.key_pattern == "agent:acme.alpha/shared/*"
    assert rec.grantor_agent_id == "agent:acme.alpha"
    assert rec.grantee_agent_id == "agent:acme.beta"
    assert rec.access_level == "read_write"
    assert rec.valid_until == "2027-01-01T00:00:00.000Z"


def test_build_audit_record_grant_fields_default_none() -> None:
    """Grant fields default to None when not provided (backward compat)."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
    )
    assert rec.grant_id is None
    assert rec.key_pattern is None
    assert rec.grantor_agent_id is None
    assert rec.grantee_agent_id is None
    assert rec.access_level is None
    assert rec.valid_until is None


def test_build_audit_record_revoke_with_grant_id() -> None:
    """Revoke events carry grant_id + grantor/grantee but not key_pattern/access_level."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="state_revoke",
        operator_id="org:test",
        effective_retention_days=90,
        grant_id="bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
        grantor_agent_id="agent:acme.alpha",
        grantee_agent_id="agent:acme.beta",
    )
    assert rec.grant_id == "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
    assert rec.grantor_agent_id == "agent:acme.alpha"
    assert rec.grantee_agent_id == "agent:acme.beta"
    assert rec.key_pattern is None
    assert rec.access_level is None


def test_audit_record_model_accepts_grant_fields() -> None:
    """ArsiaAuditRecord model validates all 6 grant fields."""
    rec = ArsiaAuditRecord(
        record_id="55555555-5555-4555-a555-555555555555",
        message_id=_MSG_ID,
        event_type="state_grant",
        from_agent=_SENDER,
        to_agent=_RECIPIENT,
        intent="request",
        payload_type="arsiaprotocol.state/grant",
        payload_hash="c" * 64,
        compliance_profile="none",
        processed_at=_TS,
        retained_until="2026-07-13T12:00:00.000Z",
        operator_id="org:test",
        grant_id="cccccccc-cccc-4ccc-accc-cccccccccccc",
        key_pattern="agent:acme.alpha/session/*",
        grantor_agent_id="agent:acme.alpha",
        grantee_agent_id="agent:acme.beta",
        access_level="read",
        valid_until="2027-06-01T00:00:00.000Z",
    )
    assert rec.grant_id == "cccccccc-cccc-4ccc-accc-cccccccccccc"
    assert rec.access_level == "read"


def test_audit_record_model_rejects_invalid_access_level() -> None:
    """access_level must be 'read' or 'read_write'."""
    from pydantic import ValidationError
    kwargs = _base_audit_kwargs()
    kwargs["access_level"] = "admin"
    with pytest.raises(ValidationError):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]


def test_audit_record_model_rejects_invalid_grantor_agent_id() -> None:
    """grantor_agent_id must be a valid ARSIA agent identifier."""
    from pydantic import ValidationError
    kwargs = _base_audit_kwargs()
    kwargs["grantor_agent_id"] = "not-an-agent-id"
    with pytest.raises(ValidationError, match="not a valid ARSIA agent"):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]


def test_audit_record_model_rejects_invalid_grantee_agent_id() -> None:
    """grantee_agent_id must be a valid ARSIA agent identifier."""
    from pydantic import ValidationError
    kwargs = _base_audit_kwargs()
    kwargs["grantee_agent_id"] = "bad-id"
    with pytest.raises(ValidationError, match="not a valid ARSIA agent"):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# BL-13 — plaintext_hash, hash_chain, legal_basis (State §7.1-§8.3)
# ---------------------------------------------------------------------------


def test_build_audit_record_with_plaintext_hash() -> None:
    """plaintext_hash propagates for encrypted envelope audit records."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
        plaintext_hash="d" * 64,
    )
    assert rec.plaintext_hash == "d" * 64


def test_build_audit_record_with_hash_chain() -> None:
    """hash_chain propagates for tamper detection."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
        hash_chain="e" * 64,
    )
    assert rec.hash_chain == "e" * 64


def test_build_audit_record_with_legal_basis() -> None:
    """legal_basis propagates for PII audit events."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="state_set",
        operator_id="org:test",
        effective_retention_days=90,
        legal_basis="consent",
    )
    assert rec.legal_basis == "consent"


def test_build_audit_record_bl13_fields_default_none() -> None:
    """plaintext_hash, hash_chain, legal_basis default to None (backward compat)."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="request",
        operator_id="org:test",
        effective_retention_days=90,
    )
    assert rec.plaintext_hash is None
    assert rec.hash_chain is None
    assert rec.legal_basis is None


def test_audit_record_model_accepts_plaintext_hash() -> None:
    """ArsiaAuditRecord accepts plaintext_hash field."""
    kwargs = _base_audit_kwargs()
    kwargs["plaintext_hash"] = "f" * 64
    rec = ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]
    assert rec.plaintext_hash == "f" * 64


def test_audit_record_model_accepts_hash_chain() -> None:
    """ArsiaAuditRecord accepts hash_chain field."""
    kwargs = _base_audit_kwargs()
    kwargs["hash_chain"] = "a1" * 32
    rec = ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]
    assert rec.hash_chain == "a1" * 32


def test_audit_record_model_accepts_legal_basis() -> None:
    """ArsiaAuditRecord accepts legal_basis field."""
    kwargs = _base_audit_kwargs()
    kwargs["legal_basis"] = "legitimate_interests"
    rec = ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]
    assert rec.legal_basis == "legitimate_interests"


@pytest.mark.parametrize(
    "basis",
    [
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
    ],
)
def test_audit_record_model_all_legal_basis_values(basis: str) -> None:
    """All 16 legal_basis enum values are accepted by the model."""
    kwargs = _base_audit_kwargs()
    kwargs["legal_basis"] = basis
    rec = ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]
    assert rec.legal_basis == basis


def test_audit_record_model_rejects_invalid_legal_basis() -> None:
    """Invalid legal_basis is rejected."""
    from pydantic import ValidationError
    kwargs = _base_audit_kwargs()
    kwargs["legal_basis"] = "made_up_basis"
    with pytest.raises(ValidationError):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]


def test_audit_record_model_rejects_invalid_plaintext_hash() -> None:
    """plaintext_hash must be a 64-char lowercase hex string."""
    from pydantic import ValidationError
    kwargs = _base_audit_kwargs()
    kwargs["plaintext_hash"] = "NOT-HEX"
    with pytest.raises(ValidationError):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]


def test_audit_record_model_rejects_invalid_hash_chain() -> None:
    """hash_chain must be a 64-char lowercase hex string."""
    from pydantic import ValidationError
    kwargs = _base_audit_kwargs()
    kwargs["hash_chain"] = "short"
    with pytest.raises(ValidationError):
        ArsiaAuditRecord(**kwargs)  # type: ignore[arg-type]


def test_build_audit_record_all_nine_new_fields_together() -> None:
    """All 9 new fields can be set simultaneously."""
    env = _envelope()
    rec = build_audit_record(
        env,
        event_type="state_grant",
        operator_id="org:test",
        effective_retention_days=90,
        grant_id="dddddddd-dddd-4ddd-addd-dddddddddddd",
        key_pattern="agent:acme.alpha/*",
        grantor_agent_id="agent:acme.alpha",
        grantee_agent_id="agent:acme.beta",
        access_level="read",
        valid_until="2027-12-31T23:59:59.000Z",
        plaintext_hash="b" * 64,
        hash_chain="c" * 64,
        legal_basis="contract",
    )
    assert rec.grant_id == "dddddddd-dddd-4ddd-addd-dddddddddddd"
    assert rec.key_pattern == "agent:acme.alpha/*"
    assert rec.grantor_agent_id == "agent:acme.alpha"
    assert rec.grantee_agent_id == "agent:acme.beta"
    assert rec.access_level == "read"
    assert rec.valid_until == "2027-12-31T23:59:59.000Z"
    assert rec.plaintext_hash == "b" * 64
    assert rec.hash_chain == "c" * 64
    assert rec.legal_basis == "contract"


def test_explanation_changes_produce_distinct_audit_hashes() -> None:
    """ACT-§5.3-02: preliminary and final explanations are distinguishable in audit.

    Two payloads with different explanation.reasoning values MUST produce
    different payload_hash values, proving both are preserved in the audit trail.
    """
    payload_preliminary = {
        "type": "com.example/action",
        "result": {"status": "pending"},
        "explanation": {
            "reasoning": "Initial assessment: likely approve",
            "confidence": 0.7,
            "inputs_used": ["doc-1"],
        },
    }
    payload_final = {
        "type": "com.example/action",
        "result": {"status": "completed"},
        "explanation": {
            "reasoning": "Final decision: approved after review",
            "confidence": 0.95,
            "inputs_used": ["doc-1", "doc-2"],
        },
    }

    hash_preliminary = compute_payload_hash(payload_preliminary)
    hash_final = compute_payload_hash(payload_final)

    assert hash_preliminary != hash_final, (
        "Different explanations must produce different audit hashes"
    )
    assert len(hash_preliminary) == 64, "SHA-256 hex digest"
