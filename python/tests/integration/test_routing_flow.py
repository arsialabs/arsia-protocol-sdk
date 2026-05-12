# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""End-to-end integration for the Routing + Idempotency primitives (Slice 7).

These scenarios compose :mod:`arsia_protocol.routing` and
:mod:`arsia_protocol.idempotency` with the message factory, signing,
envelope validation, the audit builder, and the broker-relay audit
record to cover realistic transport-hop lifecycles:

1. **Direct topology happy path.** An envelope with no residency
   constraint selects the direct topology; idempotency scope + key
   are resolved from the envelope; the in-memory store accepts the
   first put and rejects a duplicate put with the same (scope, key).
2. **Brokered topology + relay preconditions.** EU-residency envelope
   selects the brokered topology in a single :func:`select_topology`
   call when an eligible broker is supplied; §7.3 Rules 2/3/9 pass; a
   ``BrokerRelayAuditRecord`` with ``forwarding_result='success'`` is
   minted and its payload_hash matches
   :func:`arsia_protocol.audit.compute_payload_hash` of the signed
   payload.
3. **Failed relay.** When the envelope's residency zone is not served
   by the broker, the precondition list surfaces a §7.3 Rule 2 error
   and the broker mints a ``forwarding_result='failure'`` audit record
   (§7.4).
4. **Header vs envelope idempotency resolution.** An HTTP header
   ``Idempotency-Key`` overrides the envelope's embedded key for key
   detection — the store keys off the header while ``expires_at``
   still comes from the envelope.

These tests do not touch any transport or storage: the SDK's job
ends at producing conformant envelopes, picking a topology, and
emitting relay audit records. Persistence and actual HTTP relay are
the product repo's responsibility.

Spec: ARSIA-Routing.md §1.3, §7.2-§7.4; ARSIA-Core.md §9, §10.
"""

from __future__ import annotations

from typing import Any

import pytest

from arsia_protocol.state.audit import compute_payload_hash
from arsia_protocol.core.idempotency import (
    DuplicateIdempotencyKey,
    IdempotencyRecord,
    resolve_idempotency_key,
    scope_tuple,
)
from tests.fixtures.in_memory_idempotency_store import InMemoryIdempotencyStore
from arsia_protocol.core.message import create_request, sign_message, verify_message
from arsia_protocol.routing.routing import (
    build_broker_relay_audit_record,
    select_topology,
    validate_broker_entry,
    validate_relay_preconditions,
)
from arsia_protocol.core.validation import validate_envelope

_MSG_TS = "2026-04-14T12:00:00.000Z"
_STORE_TS = "2026-04-14T12:00:00.000Z"
_EXPIRES_TS = "2099-12-31T23:59:59.999Z"


def _broker(
    *,
    agent_id: str,
    jurisdiction: str,
    residency_zones: list[str],
    health: str = "healthy",
) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "inbox": f"https://{agent_id.split(':', 1)[1]}.example/inbox",
        "jurisdiction": jurisdiction,
        "residency_zones": residency_zones,
        "health": health,
        "last_health_check": _MSG_TS,
    }


# ---------------------------------------------------------------------------
# Scenario 1 — Direct topology + idempotency store round-trip
# ---------------------------------------------------------------------------


def test_direct_topology_selects_and_idempotency_store_deduplicates(
    keypair_acme: dict[str, Any],
) -> None:
    sender = "agent:acme.echo-client"
    recipient = "agent:acme.state-store"

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type="arsiaprotocol.state/set",
        capabilities=["arsiaprotocol.state.write"],
        args={"key": f"{sender}/agent/user.profile", "value": {"k": "v"}},
        compliance={
            "profile": "GDPR-STANDARD",
            "legal_basis": "consent",
            "pii_involved": False,
        },
        idempotency={"key": "idem-direct-001", "expires_at": _EXPIRES_TS},
    )
    signed = sign_message(
        envelope, keypair_acme["private_key"], keypair_acme["kid"]
    )
    assert verify_message(signed, keypair_acme["public_key"]) is True
    assert validate_envelope(signed, strict=False) == []

    decision = select_topology(signed)
    assert decision.topology == "direct"
    assert decision.data_residency is None
    assert decision.broker is None
    assert decision.error is None

    scope = scope_tuple(signed)
    key = resolve_idempotency_key(signed)
    assert key == "idem-direct-001"

    store = InMemoryIdempotencyStore()
    record = IdempotencyRecord(
        key=key,
        from_agent=scope.from_agent,
        to_agent=scope.to_agent,
        payload_type=scope.payload_type,
        message_id=signed["id"],
        stored_at=_STORE_TS,
        expires_at=_EXPIRES_TS,
    )
    store.put(record)
    assert store.get(scope, key) is not None

    with pytest.raises(DuplicateIdempotencyKey):
        store.put(record)


# ---------------------------------------------------------------------------
# Scenario 2 — Brokered topology + forwarded relay audit
# ---------------------------------------------------------------------------


def test_brokered_topology_selects_broker_and_mints_forwarded_audit(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.risk-assessor"
    recipient = "agent:arsialabs.demo.compliance-checker"

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type="arsiaprotocol.state/set",
        capabilities=["arsiaprotocol.state.write"],
        args={"key": f"{sender}/agent/flag", "value": {"on": True}},
        compliance={
            "profile": "GDPR-STRICT",
            "legal_basis": "legal_obligation",
            "data_residency": "EU",
            "pii_involved": False,
            "retention_days": 2555,
        },
    )
    signed = sign_message(
        envelope,
        keypair_risk_assessor["private_key"],
        keypair_risk_assessor["kid"],
    )
    assert verify_message(signed, keypair_risk_assessor["public_key"]) is True
    assert validate_envelope(signed, strict=False) == []

    brokers = [
        _broker(
            agent_id="agent:arsialabs.broker-de",
            jurisdiction="DE",
            residency_zones=["EU"],
        ),
        _broker(
            agent_id="agent:arsialabs.broker-fr",
            jurisdiction="FR",
            residency_zones=["EU"],
            health="degraded",
        ),
    ]
    for entry in brokers:
        assert validate_broker_entry(entry) == []

    decision = select_topology(signed, brokers=brokers)
    assert decision.topology == "brokered"
    assert decision.data_residency == "EU"
    assert decision.broker is not None
    selected = decision.broker
    assert selected["agent_id"] == "agent:arsialabs.broker-de"
    assert decision.error is None

    # Use the real signing-time clock so the envelope's auto-generated
    # expires_at satisfies §7.3 Rule 9's safety margin.
    assert validate_relay_preconditions(signed, selected) == []

    payload_hash = compute_payload_hash(signed["payload"])
    relay_record = build_broker_relay_audit_record(
        signed,
        broker_agent_id=selected["agent_id"],
        payload_hash=payload_hash,
        forwarding_result="success",
        relay_latency_ms=42,
    )
    assert relay_record.audit_type == "broker_relay"
    assert relay_record.forwarding_result == "success"
    assert relay_record.broker_agent_id == "agent:arsialabs.broker-de"
    assert relay_record.residency_zone == "EU"
    assert relay_record.payload_hash == payload_hash
    assert relay_record.message_id == signed["id"]
    assert relay_record.relay_latency_ms == 42


# ---------------------------------------------------------------------------
# Scenario 3 — Failed relay (broker does not serve the declared zone)
# ---------------------------------------------------------------------------


def test_refused_relay_surfaces_rule_3_and_mints_failure_audit(
    keypair_risk_assessor: dict[str, Any],
) -> None:
    sender = "agent:arsialabs.demo.risk-assessor"
    recipient = "agent:arsialabs.demo.compliance-checker"

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type="arsiaprotocol.state/set",
        capabilities=["arsiaprotocol.state.write"],
        args={"key": f"{sender}/agent/flag", "value": {"on": True}},
        compliance={
            "profile": "GDPR-STRICT",
            "legal_basis": "legal_obligation",
            "data_residency": "EU",
            "pii_involved": False,
            "retention_days": 2555,
        },
    )
    signed = sign_message(
        envelope,
        keypair_risk_assessor["private_key"],
        keypair_risk_assessor["kid"],
    )

    # Broker is healthy and valid, but its residency_zones do not include
    # 'EU' — §7.3 Rule 2 must fire.
    wrong_zone_broker = _broker(
        agent_id="agent:arsialabs.broker-us",
        jurisdiction="US",
        residency_zones=["US"],
    )
    assert validate_broker_entry(wrong_zone_broker) == []

    errors = validate_relay_preconditions(signed, wrong_zone_broker)
    assert errors
    assert any(e.code == "zone_not_served" for e in errors)

    payload_hash = compute_payload_hash(signed["payload"])
    failed = build_broker_relay_audit_record(
        signed,
        broker_agent_id=wrong_zone_broker["agent_id"],
        payload_hash=payload_hash,
        forwarding_result="failure",
        relay_latency_ms=5,
    )
    assert failed.forwarding_result == "failure"
    assert failed.broker_agent_id == "agent:arsialabs.broker-us"
    assert failed.audit_type == "broker_relay"


# ---------------------------------------------------------------------------
# Scenario 4 — Header vs envelope idempotency resolution
# ---------------------------------------------------------------------------


def test_header_idempotency_key_overrides_envelope_for_scope(
    keypair_acme: dict[str, Any],
) -> None:
    sender = "agent:acme.echo-client"
    recipient = "agent:acme.state-store"

    envelope = create_request(
        from_agent=sender,
        to_agent=recipient,
        payload_type="arsiaprotocol.state/set",
        capabilities=["arsiaprotocol.state.write"],
        args={"key": f"{sender}/agent/user.profile", "value": {"k": "v"}},
        compliance={
            "profile": "GDPR-STANDARD",
            "legal_basis": "consent",
            "data_residency": "PT",
            "pii_involved": False,
        },
        idempotency={"key": "env-key", "expires_at": _EXPIRES_TS},
    )
    signed = sign_message(
        envelope, keypair_acme["private_key"], keypair_acme["kid"]
    )

    scope = scope_tuple(signed)
    # Header wins for key detection ...
    resolved = resolve_idempotency_key(signed, header_key="hdr-key")
    assert resolved == "hdr-key"

    # ... while expires_at remains sourced from the envelope.
    store = InMemoryIdempotencyStore()
    store.put(
        IdempotencyRecord(
            key=resolved,
            from_agent=scope.from_agent,
            to_agent=scope.to_agent,
            payload_type=scope.payload_type,
            message_id=signed["id"],
            stored_at=_STORE_TS,
            expires_at=signed["idempotency"]["expires_at"],
        )
    )
    fetched = store.get(scope, "hdr-key")
    assert fetched is not None
    assert fetched.expires_at == _EXPIRES_TS
    # The envelope-level key is NOT independently recorded.
    assert store.get(scope, "env-key") is None
