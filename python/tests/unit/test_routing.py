# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for :mod:`arsia_protocol.routing`.

Covers ARSIA-Routing.md §1-§7 and ARSIA-Core.md §9, §11.3. The SDK
stays transport-agnostic, so the tests exercise only offline
behaviour: decisions, validations, and the delivery state machine.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from arsia_protocol.routing.routing import (
    BROKER_EXPIRY_SAFETY_MARGIN_S,
    BROKER_FORWARD_TIMEOUT_S,
    BrokerRelayAuditRecord,
    DEFAULT_PRIORITY,
    EU_EEA_MEMBER_STATES,
    LIFECYCLE_STATES,
    LIFECYCLE_TRANSITIONS,
    MAX_RETRIES_RECOMMENDED,
    MAX_RETRY_DELAY_S,
    NON_RETRYABLE_HTTP_CODES,
    PAYLOAD_HASH_HEX_LENGTH,
    RETRYABLE_LIFECYCLE_STATES,
    RETRY_BASE_DELAY_S,
    RETRY_MULTIPLIER,
    RateLimitStatus,
    RoutingDecision,
    TERMINAL_LIFECYCLE_STATES,
    broker_serves_zone,
    build_broker_relay_audit_record,
    compute_retry_delay,
    is_eu_eea_member,
    is_retryable_http_status,
    is_retryable_lifecycle_state,
    is_terminal_lifecycle_state,
    is_valid_lifecycle_transition,
    parse_rate_limit_headers,
    resolve_priority,
    select_broker_by_priority,
    select_broker_random,
    select_topology,
    validate_broker_entry,
    validate_broker_relay_audit_record,
    validate_relay_preconditions,
)
from arsia_protocol.types.routing import BrokerEntry

_SENDER = "agent:acme.alpha"
_RECIPIENT = "agent:acme.beta"
_BROKER_ID = "agent:compliance.broker"
_MSG_ID = "11111111-1111-4111-9111-111111111111"
_TS = "2026-04-14T12:00:00.000Z"
_HASH = "a" * 64


def _envelope(
    *,
    compliance: dict | None = None,
    payload_type: str = "arsiaprotocol.state/set",
    expires_at: str | None = None,
    context: dict | None = None,
    idempotency: dict | None = None,
) -> dict:
    env: dict = {
        "v": "1.0",
        "id": _MSG_ID,
        "ts": _TS,
        "from": _SENDER,
        "to": _RECIPIENT,
        "intent": "request",
        "payload": {"type": payload_type},
    }
    if compliance is not None:
        env["compliance"] = compliance
    if expires_at is not None:
        env["expires_at"] = expires_at
    if context is not None:
        env["context"] = context
    if idempotency is not None:
        env["idempotency"] = idempotency
    return env


def _broker(
    *,
    agent_id: str = _BROKER_ID,
    inbox: str = "https://broker.example.org/inbox",
    jurisdiction: str = "PT",
    zones: list[str] | None = None,
    health: str = "healthy",
    capacity: dict | None = None,
    last_check: str = _TS,
) -> dict:
    b: dict = {
        "agent_id": agent_id,
        "inbox": inbox,
        "jurisdiction": jurisdiction,
        "residency_zones": zones if zones is not None else ["EU"],
        "health": health,
        "last_health_check": last_check,
    }
    if capacity is not None:
        b["capacity"] = capacity
    return b


# ---------------------------------------------------------------------------
# §1.3 — Topology determination
# ---------------------------------------------------------------------------


def test_topology_eu_residency_with_eligible_broker_is_brokered() -> None:
    decision = select_topology(
        _envelope(compliance={"data_residency": "EU"}),
        brokers=[_broker()],
    )
    assert decision.topology == "brokered"
    assert decision.data_residency == "EU"
    assert decision.broker is not None
    assert decision.broker["agent_id"] == _BROKER_ID
    assert decision.error is None
    assert "EU" in decision.reason


def test_topology_eu_residency_without_brokers_is_error() -> None:
    decision = select_topology(_envelope(compliance={"data_residency": "EU"}))
    assert decision.topology == "error"
    assert decision.data_residency == "EU"
    assert decision.broker is None
    assert decision.error is not None
    assert decision.error["code"] == "service_unavailable"
    details = decision.error["details"]
    assert details["data_residency_violation"] is True
    assert details["required_zone"] == "EU"
    assert tuple(details["available_zones"]) == ()


def test_topology_non_eu_residency_without_brokers_is_error() -> None:
    # §1.3 is zone-agnostic: any non-empty data_residency triggers the
    # broker requirement. Without brokers the result is the same error
    # payload.
    decision = select_topology(_envelope(compliance={"data_residency": "US"}))
    assert decision.topology == "error"
    assert decision.data_residency == "US"
    assert decision.error is not None
    assert decision.error["details"]["required_zone"] == "US"


def test_topology_non_eu_residency_with_matching_broker_is_brokered() -> None:
    us_broker = _broker(
        agent_id="agent:us.broker",
        jurisdiction="US",
        zones=["US"],
    )
    decision = select_topology(
        _envelope(compliance={"data_residency": "US"}),
        brokers=[us_broker],
    )
    assert decision.topology == "brokered"
    assert decision.broker is not None
    assert decision.broker["agent_id"] == "agent:us.broker"


def test_topology_no_compliance_is_direct() -> None:
    decision = select_topology(_envelope())
    assert decision.topology == "direct"
    assert decision.data_residency is None
    assert decision.broker is None
    assert decision.error is None


def test_topology_compliance_without_residency_is_direct() -> None:
    decision = select_topology(
        _envelope(compliance={"profile": "GDPR-STANDARD"})
    )
    assert decision.topology == "direct"
    assert decision.data_residency is None


def test_topology_pt_residency_is_zone_agnostic() -> None:
    # Profile field is ignored; PT as a residency zone also triggers
    # the broker requirement per §1.3.
    decision = select_topology(
        _envelope(compliance={"profile": "MIFID-II", "data_residency": "PT"})
    )
    assert decision.topology == "error"
    assert decision.data_residency == "PT"


def test_topology_empty_data_residency_is_direct() -> None:
    # Empty string is equivalent to "not declared" per §1.3 presence
    # check semantics.
    decision = select_topology(_envelope(compliance={"data_residency": ""}))
    assert decision.topology == "direct"
    assert decision.data_residency is None


def test_topology_available_zones_includes_non_matching_candidates() -> None:
    # The error's available_zones union advertises which zones *were*
    # served by the discovery response, so the caller can diagnose
    # the mismatch.
    us_broker = _broker(
        agent_id="agent:us.broker",
        jurisdiction="US",
        zones=["US"],
    )
    ch_broker = _broker(
        agent_id="agent:ch.broker",
        jurisdiction="US",  # not EU/EEA; fine because zone is CH
        zones=["CH"],
    )
    decision = select_topology(
        _envelope(compliance={"data_residency": "EU"}),
        brokers=[us_broker, ch_broker],
    )
    assert decision.topology == "error"
    assert decision.error is not None
    available = decision.error["details"]["available_zones"]
    assert "US" in available
    assert "CH" in available


def test_topology_skips_unhealthy_broker_in_favor_of_healthy() -> None:
    unhealthy = _broker(agent_id="agent:bad.broker", health="unhealthy")
    healthy = _broker(agent_id="agent:good.broker", health="healthy")
    decision = select_topology(
        _envelope(compliance={"data_residency": "EU"}),
        brokers=[unhealthy, healthy],
    )
    assert decision.topology == "brokered"
    assert decision.broker is not None
    assert decision.broker["agent_id"] == "agent:good.broker"


def test_routing_decision_is_frozen() -> None:
    decision = select_topology(_envelope(compliance={"data_residency": "EU"}))
    with pytest.raises(Exception):
        decision.topology = "direct"  # type: ignore[misc]


def test_topology_returns_dataclass_instance() -> None:
    assert isinstance(
        select_topology(_envelope(compliance={"data_residency": "EU"})),
        RoutingDecision,
    )


def test_topology_reason_is_non_empty() -> None:
    for envelope in (
        _envelope(compliance={"data_residency": "EU"}),
        _envelope(compliance={"data_residency": "PT"}),
        _envelope(),
    ):
        decision = select_topology(envelope)
        assert decision.reason


def test_topology_handles_non_mapping_compliance() -> None:
    envelope = _envelope()
    envelope["compliance"] = "not-a-mapping"  # type: ignore[assignment]
    decision = select_topology(envelope)
    assert decision.topology == "direct"


# ---------------------------------------------------------------------------
# §7.3 Rule 2 — EU/EEA helpers
# ---------------------------------------------------------------------------


def test_eu_eea_has_30_members() -> None:
    assert len(EU_EEA_MEMBER_STATES) == 30


def test_eu_eea_contains_all_eu_states() -> None:
    eu27 = {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
        "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
        "PL", "PT", "RO", "SK", "SI", "ES", "SE",
    }
    assert eu27.issubset(EU_EEA_MEMBER_STATES)


def test_eu_eea_contains_iceland_liechtenstein_norway() -> None:
    assert {"IS", "LI", "NO"}.issubset(EU_EEA_MEMBER_STATES)


def test_eu_eea_excludes_switzerland() -> None:
    assert "CH" not in EU_EEA_MEMBER_STATES


def test_is_eu_eea_member_portugal() -> None:
    assert is_eu_eea_member("PT") is True


def test_is_eu_eea_member_iceland() -> None:
    assert is_eu_eea_member("IS") is True


def test_is_eu_eea_member_switzerland_false() -> None:
    assert is_eu_eea_member("CH") is False


def test_is_eu_eea_member_case_sensitive() -> None:
    assert is_eu_eea_member("pt") is False


def test_broker_serves_zone_matches_eu() -> None:
    assert broker_serves_zone(_broker(zones=["EU"]), "EU") is True


def test_broker_serves_zone_matches_multi_zone() -> None:
    assert broker_serves_zone(_broker(zones=["PT", "EU"]), "PT") is True
    assert broker_serves_zone(_broker(zones=["PT", "EU"]), "EU") is True


def test_broker_serves_zone_rejects_missing_zone() -> None:
    assert broker_serves_zone(_broker(zones=["US"]), "EU") is False


def test_broker_serves_zone_rejects_string_field() -> None:
    broker = _broker()
    broker["residency_zones"] = "EU"  # type: ignore[assignment]
    assert broker_serves_zone(broker, "EU") is False


# ---------------------------------------------------------------------------
# §7.2 — Broker-entry validation
# ---------------------------------------------------------------------------


def test_validate_broker_entry_happy_path() -> None:
    assert validate_broker_entry(_broker()) == []


def test_validate_broker_entry_missing_required_fields() -> None:
    broker = _broker()
    del broker["agent_id"]
    errors = validate_broker_entry(broker)
    assert any("agent_id" in e.message for e in errors)


def test_validate_broker_entry_invalid_agent_id_format() -> None:
    broker = _broker(agent_id="not-an-arsia-id")
    errors = validate_broker_entry(broker)
    assert errors


def test_validate_broker_entry_agent_id_semantic_check() -> None:
    broker = _broker()
    broker["agent_id"] = "agent:valid.but-ends-with-"  # type: ignore[assignment]
    errors = validate_broker_entry(broker)
    assert any(e.code == "invalid_broker_agent_id" for e in errors)


def test_validate_broker_entry_eu_requires_eu_jurisdiction() -> None:
    broker = _broker(jurisdiction="CH", zones=["EU"])
    errors = validate_broker_entry(broker)
    assert any(e.code == "eu_zone_non_eea_jurisdiction" for e in errors)


def test_validate_broker_entry_eu_accepts_iceland() -> None:
    assert validate_broker_entry(_broker(jurisdiction="IS", zones=["EU"])) == []


def test_validate_broker_entry_non_eu_zone_any_jurisdiction() -> None:
    assert (
        validate_broker_entry(_broker(jurisdiction="US", zones=["US"])) == []
    )


def test_validate_broker_entry_bad_jurisdiction_pattern() -> None:
    broker = _broker()
    broker["jurisdiction"] = "portugal"  # type: ignore[assignment]
    errors = validate_broker_entry(broker)
    assert errors


def test_validate_broker_entry_bad_health_enum() -> None:
    broker = _broker()
    broker["health"] = "unknown"  # type: ignore[assignment]
    errors = validate_broker_entry(broker)
    assert errors


def test_validate_broker_entry_capacity_accepts_nulls() -> None:
    broker = _broker(capacity={"requests_per_minute": 1000, "current_load_pct": 5})
    assert validate_broker_entry(broker) == []


def test_validate_broker_entry_capacity_out_of_range() -> None:
    broker = _broker(capacity={"current_load_pct": 150})
    errors = validate_broker_entry(broker)
    assert errors


def test_validate_broker_entry_additional_property_rejected() -> None:
    broker = _broker()
    broker["extra"] = "x"
    errors = validate_broker_entry(broker)
    assert errors


# ---------------------------------------------------------------------------
# §7.4 — Broker selection
# ---------------------------------------------------------------------------


def test_select_broker_by_priority_returns_first_healthy() -> None:
    brokers = [_broker(agent_id="agent:b.one"), _broker(agent_id="agent:b.two")]
    selected = select_broker_by_priority(brokers, zone="EU")
    assert selected is not None
    assert selected["agent_id"] == "agent:b.one"


def test_select_broker_by_priority_skips_unhealthy() -> None:
    brokers = [
        _broker(agent_id="agent:b.one", health="unhealthy"),
        _broker(agent_id="agent:b.two"),
    ]
    selected = select_broker_by_priority(brokers, zone="EU")
    assert selected is not None
    assert selected["agent_id"] == "agent:b.two"


def test_select_broker_by_priority_prefers_healthy_over_degraded() -> None:
    """§1.4 criterion 2: degraded brokers are deprioritised, not excluded."""
    brokers = [
        _broker(agent_id="agent:b.one", health="degraded"),
        _broker(agent_id="agent:b.two"),
    ]
    selected = select_broker_by_priority(brokers, zone="EU")
    assert selected is not None
    assert selected["agent_id"] == "agent:b.two"


def test_select_broker_by_priority_falls_back_to_degraded() -> None:
    """Only-degraded pool MUST return a broker (§1.4: SHOULD deprioritise)."""
    brokers = [
        _broker(agent_id="agent:b.one", health="degraded"),
        _broker(agent_id="agent:b.two", health="degraded"),
    ]
    selected = select_broker_by_priority(brokers, zone="EU")
    assert selected is not None
    assert selected["agent_id"] == "agent:b.one"


def test_select_broker_by_priority_healthy_wins_even_with_include_degraded() -> None:
    """include_degraded is a no-op kept for back-compat; §1.4 is fixed."""
    brokers = [
        _broker(agent_id="agent:b.one", health="degraded"),
        _broker(agent_id="agent:b.two"),
    ]
    selected = select_broker_by_priority(
        brokers, zone="EU", include_degraded=True
    )
    assert selected is not None
    assert selected["agent_id"] == "agent:b.two"


def test_select_broker_by_priority_only_unhealthy_returns_none() -> None:
    brokers = [
        _broker(agent_id="agent:b.one", health="unhealthy"),
        _broker(agent_id="agent:b.two", health="unhealthy"),
    ]
    assert select_broker_by_priority(brokers, zone="EU") is None


def test_select_broker_random_falls_back_to_degraded() -> None:
    brokers = [
        _broker(agent_id="agent:b.one", health="degraded"),
        _broker(agent_id="agent:b.two", health="degraded"),
    ]
    selected = select_broker_random(brokers, zone="EU")
    assert selected is not None
    assert selected["agent_id"] in {"agent:b.one", "agent:b.two"}


def test_select_broker_by_priority_filters_zone() -> None:
    brokers = [
        _broker(agent_id="agent:b.one", zones=["US"]),
        _broker(agent_id="agent:b.two", zones=["EU"]),
    ]
    selected = select_broker_by_priority(brokers, zone="EU")
    assert selected is not None
    assert selected["agent_id"] == "agent:b.two"


def test_select_broker_by_priority_empty_returns_none() -> None:
    assert select_broker_by_priority([], zone="EU") is None


def test_select_broker_by_priority_all_filtered_returns_none() -> None:
    brokers = [_broker(health="unhealthy"), _broker(zones=["US"])]
    assert select_broker_by_priority(brokers, zone="EU") is None


def test_select_broker_random_returns_eligible() -> None:
    brokers = [_broker(agent_id="agent:b.one"), _broker(agent_id="agent:b.two")]
    selected = select_broker_random(brokers, zone="EU")
    assert selected is not None
    assert selected["agent_id"] in {"agent:b.one", "agent:b.two"}


def test_select_broker_random_empty_returns_none() -> None:
    assert select_broker_random([], zone="EU") is None


def test_select_broker_random_never_returns_unhealthy() -> None:
    brokers = [_broker(health="unhealthy") for _ in range(20)]
    brokers.append(_broker(agent_id="agent:b.healthy"))
    for _ in range(50):
        selected = select_broker_random(brokers, zone="EU")
        assert selected is not None
        assert selected["agent_id"] == "agent:b.healthy"


def test_select_broker_accepts_pydantic_entry() -> None:
    from arsia_protocol.types.routing import BrokerEntry

    entry = BrokerEntry(
        agent_id=_BROKER_ID,
        inbox="https://broker.example.org/inbox",
        jurisdiction="PT",
        residency_zones=["EU"],
        health="healthy",
        last_health_check=_TS,
    )
    selected = select_broker_by_priority([entry], zone="EU")
    assert selected is not None
    assert selected["agent_id"] == _BROKER_ID


def test_select_broker_skips_non_mapping_entry() -> None:
    selected = select_broker_by_priority(
        [None, 42, "string", _broker()],  # type: ignore[list-item]
        zone="EU",
    )
    assert selected is not None
    assert selected["agent_id"] == _BROKER_ID


# ---------------------------------------------------------------------------
# §4.1 — Delivery lifecycle state machine
# ---------------------------------------------------------------------------


def test_lifecycle_states_has_nine() -> None:
    assert len(LIFECYCLE_STATES) == 9


def test_lifecycle_states_set() -> None:
    assert LIFECYCLE_STATES == {
        "created",
        "signed",
        "dispatched",
        "broker_relayed",
        "delivered",
        "responded",
        "dispatch_failed",
        "delivery_failed",
        "expired",
    }


def test_terminal_states_are_responded_and_expired() -> None:
    assert TERMINAL_LIFECYCLE_STATES == {"responded", "expired"}


def test_retryable_states_are_two_failure_states() -> None:
    assert RETRYABLE_LIFECYCLE_STATES == {"dispatch_failed", "delivery_failed"}


def test_created_transitions_to_signed() -> None:
    assert LIFECYCLE_TRANSITIONS["created"] == {"signed"}


def test_signed_transitions_to_dispatched() -> None:
    assert LIFECYCLE_TRANSITIONS["signed"] == {"dispatched"}


def test_dispatched_transitions_include_broker_relayed() -> None:
    assert "broker_relayed" in LIFECYCLE_TRANSITIONS["dispatched"]


def test_dispatched_transitions_include_delivery_failed() -> None:
    assert "delivery_failed" in LIFECYCLE_TRANSITIONS["dispatched"]


def test_dispatched_transitions_full_set() -> None:
    assert LIFECYCLE_TRANSITIONS["dispatched"] == {
        "delivered",
        "broker_relayed",
        "dispatch_failed",
        "delivery_failed",
        "expired",
    }


def test_broker_relayed_does_not_go_to_delivery_failed() -> None:
    assert "delivery_failed" not in LIFECYCLE_TRANSITIONS["broker_relayed"]


def test_broker_relayed_transitions_to_delivered_dispatch_failed_expired() -> None:
    assert LIFECYCLE_TRANSITIONS["broker_relayed"] == {
        "delivered",
        "dispatch_failed",
        "expired",
    }


def test_delivered_transitions_to_responded() -> None:
    assert LIFECYCLE_TRANSITIONS["delivered"] == {"responded"}


def test_responded_is_strictly_terminal() -> None:
    assert LIFECYCLE_TRANSITIONS["responded"] == frozenset()


def test_expired_is_strictly_terminal() -> None:
    assert LIFECYCLE_TRANSITIONS["expired"] == frozenset()


def test_dispatch_failed_transitions_only_to_dispatched() -> None:
    assert LIFECYCLE_TRANSITIONS["dispatch_failed"] == {"dispatched"}


def test_delivery_failed_transitions_only_to_dispatched() -> None:
    assert LIFECYCLE_TRANSITIONS["delivery_failed"] == {"dispatched"}


def test_created_cannot_go_to_expired() -> None:
    assert is_valid_lifecycle_transition("created", "expired") is False


def test_signed_cannot_go_to_expired() -> None:
    assert is_valid_lifecycle_transition("signed", "expired") is False


def test_delivered_cannot_go_to_delivery_failed() -> None:
    assert is_valid_lifecycle_transition("delivered", "delivery_failed") is False


def test_delivered_cannot_go_to_expired() -> None:
    assert is_valid_lifecycle_transition("delivered", "expired") is False


def test_dispatch_failed_cannot_go_to_expired() -> None:
    assert is_valid_lifecycle_transition("dispatch_failed", "expired") is False


def test_delivery_failed_cannot_go_to_expired() -> None:
    assert is_valid_lifecycle_transition("delivery_failed", "expired") is False


def test_dispatched_can_go_to_delivery_failed() -> None:
    assert is_valid_lifecycle_transition("dispatched", "delivery_failed") is True


def test_is_valid_lifecycle_transition_happy_path() -> None:
    assert is_valid_lifecycle_transition("created", "signed") is True


def test_is_valid_lifecycle_transition_rejects_unknown_from() -> None:
    assert is_valid_lifecycle_transition("foo", "signed") is False


def test_is_valid_lifecycle_transition_rejects_unknown_to() -> None:
    assert is_valid_lifecycle_transition("created", "foo") is False


def test_is_valid_lifecycle_transition_rejects_disallowed_edge() -> None:
    assert is_valid_lifecycle_transition("created", "delivered") is False


def test_is_terminal_lifecycle_state() -> None:
    assert is_terminal_lifecycle_state("expired") is True
    assert is_terminal_lifecycle_state("responded") is True
    assert is_terminal_lifecycle_state("delivered") is False
    assert is_terminal_lifecycle_state("unknown") is False


def test_is_retryable_lifecycle_state() -> None:
    assert is_retryable_lifecycle_state("dispatch_failed") is True
    assert is_retryable_lifecycle_state("delivery_failed") is True
    assert is_retryable_lifecycle_state("dispatched") is False
    assert is_retryable_lifecycle_state("unknown") is False


def test_lifecycle_transitions_mapping_is_read_only() -> None:
    with pytest.raises(TypeError):
        LIFECYCLE_TRANSITIONS["new_state"] = frozenset()  # type: ignore[index]


# ---------------------------------------------------------------------------
# §7.3 — Relay preconditions
# ---------------------------------------------------------------------------


def _future(seconds: int) -> str:
    now = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    millis = now.microsecond // 1000
    return f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{millis:03d}Z"


def test_relay_preconditions_happy_path() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"},
        expires_at=_future(60),
    )
    broker = _broker(jurisdiction="PT", zones=["EU"])
    assert validate_relay_preconditions(envelope, broker) == []


def test_relay_rule2_broker_must_list_zone() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"}, expires_at=_future(60)
    )
    broker = _broker(zones=["US"])
    errors = validate_relay_preconditions(envelope, broker)
    assert any(e.code == "zone_not_served" for e in errors)


def test_relay_rule2_eu_requires_eu_jurisdiction() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"}, expires_at=_future(60)
    )
    broker = _broker(jurisdiction="CH", zones=["EU"])
    errors = validate_relay_preconditions(envelope, broker)
    assert any(e.code == "eu_jurisdiction_required" for e in errors)


def test_relay_rule2_iceland_accepted_as_eu() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"}, expires_at=_future(60)
    )
    broker = _broker(jurisdiction="IS", zones=["EU"])
    assert validate_relay_preconditions(envelope, broker) == []


def test_relay_rule9_rejects_expires_too_soon() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"}, expires_at=_future(1)
    )
    broker = _broker(jurisdiction="PT", zones=["EU"])
    errors = validate_relay_preconditions(envelope, broker)
    assert any(e.code == "expiry_too_soon" for e in errors)


def test_relay_rule9_rejects_past_expiry() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"}, expires_at=_future(-60)
    )
    broker = _broker(jurisdiction="PT", zones=["EU"])
    errors = validate_relay_preconditions(envelope, broker)
    assert any(e.code == "expiry_too_soon" for e in errors)


def test_relay_rule9_accepts_exactly_safety_margin() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"},
        expires_at=_future(BROKER_EXPIRY_SAFETY_MARGIN_S + 10),
    )
    broker = _broker(jurisdiction="PT", zones=["EU"])
    assert validate_relay_preconditions(envelope, broker) == []


def test_relay_rule9_with_injected_now() -> None:
    now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    envelope = _envelope(
        compliance={"data_residency": "EU"},
        expires_at="2026-04-14T12:00:03.000Z",  # 3s in future < 5s margin
    )
    broker = _broker(jurisdiction="PT", zones=["EU"])
    errors = validate_relay_preconditions(envelope, broker, now=now)
    assert any(e.code == "expiry_too_soon" for e in errors)


def test_relay_no_residency_skips_rule_2() -> None:
    envelope = _envelope(expires_at=_future(60))
    broker = _broker(jurisdiction="US", zones=["US"])
    errors = validate_relay_preconditions(envelope, broker)
    assert all(e.code not in ("zone_not_served", "eu_jurisdiction_required") for e in errors)


def test_relay_non_eu_zone_skips_eu_jurisdiction_check() -> None:
    envelope = _envelope(
        compliance={"data_residency": "US"}, expires_at=_future(60)
    )
    broker = _broker(jurisdiction="US", zones=["US"])
    assert validate_relay_preconditions(envelope, broker) == []


def test_relay_country_code_zone_jurisdiction_match() -> None:
    """§5.3: country-code zone 'PT' with jurisdiction 'PT' passes."""
    envelope = _envelope(
        compliance={"data_residency": "PT"}, expires_at=_future(60)
    )
    broker = _broker(jurisdiction="PT", zones=["PT"])
    assert validate_relay_preconditions(envelope, broker) == []


def test_relay_country_code_zone_jurisdiction_mismatch() -> None:
    """§5.3: country-code zone 'PT' with jurisdiction 'ES' fails."""
    envelope = _envelope(
        compliance={"data_residency": "PT"}, expires_at=_future(60)
    )
    broker = _broker(jurisdiction="ES", zones=["PT"])
    errors = validate_relay_preconditions(envelope, broker)
    assert any(e.code == "zone_jurisdiction_mismatch" for e in errors)
    assert any(e.details.get("zone") == "PT" for e in errors)


def test_relay_eu_zone_accepts_any_eea_jurisdiction() -> None:
    """§5.3: zone 'EU' defers to EU/EEA check, not country-code match."""
    envelope = _envelope(
        compliance={"data_residency": "EU"}, expires_at=_future(60)
    )
    broker = _broker(jurisdiction="IE", zones=["EU"])
    assert validate_relay_preconditions(envelope, broker) == []


def test_validate_broker_entry_country_code_zone_jurisdiction_match() -> None:
    """§5.3: validate_broker_entry accepts zone 'PT' with jurisdiction 'PT'."""
    assert validate_broker_entry(_broker(jurisdiction="PT", zones=["PT"])) == []


def test_validate_broker_entry_country_code_zone_jurisdiction_mismatch() -> None:
    """§5.3: validate_broker_entry rejects zone 'PT' with jurisdiction 'ES'."""
    errors = validate_broker_entry(_broker(jurisdiction="ES", zones=["PT"]))
    assert any(e.code == "zone_jurisdiction_mismatch" for e in errors)


def test_relay_bad_expires_at_format_is_error() -> None:
    envelope = _envelope(
        compliance={"data_residency": "EU"}, expires_at="not-a-timestamp"
    )
    broker = _broker(jurisdiction="PT", zones=["EU"])
    errors = validate_relay_preconditions(envelope, broker)
    assert any(e.code == "invalid_expires_at" for e in errors)


def test_broker_forward_timeout_is_10s() -> None:
    assert BROKER_FORWARD_TIMEOUT_S == 10


def test_broker_expiry_safety_margin_is_5s() -> None:
    assert BROKER_EXPIRY_SAFETY_MARGIN_S == 5


# ---------------------------------------------------------------------------
# §7.4 — Broker relay audit record
# ---------------------------------------------------------------------------


def test_build_relay_audit_happy_success() -> None:
    """Spec: ARSIA-Routing.md §7.4."""
    envelope = _envelope(compliance={"data_residency": "EU"})
    record = build_broker_relay_audit_record(
        envelope,
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=47,
    )
    assert isinstance(record, BrokerRelayAuditRecord)
    assert record.audit_type == "broker_relay"
    assert record.forwarding_result == "success"
    assert record.broker_agent_id == _BROKER_ID
    assert record.message_id == _MSG_ID
    assert record.residency_zone == "EU"
    assert record.payload_hash == _HASH
    assert record.relay_latency_ms == 47
    UUID(record.relay_id, version=4)


def test_build_relay_audit_lowercases_hash() -> None:
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash="A" * 64,
        forwarding_result="success",
        relay_latency_ms=10,
    )
    assert record.payload_hash == "a" * 64


def test_build_relay_audit_failure_result() -> None:
    """Spec: ARSIA-Routing.md §7.4 — forwarding_result enum."""
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="failure",
        relay_latency_ms=200,
    )
    assert record.forwarding_result == "failure"


def test_build_relay_audit_timeout_result() -> None:
    """Spec: ARSIA-Routing.md §7.3 Rule 9 — expires_at timeout."""
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="timeout",
        relay_latency_ms=0,
    )
    assert record.forwarding_result == "timeout"


def test_build_relay_audit_invalid_hash_rejected() -> None:
    with pytest.raises(ValueError, match="payload_hash"):
        build_broker_relay_audit_record(
            _envelope(compliance={"data_residency": "EU"}),
            broker_agent_id=_BROKER_ID,
            payload_hash="too-short",
            forwarding_result="success",
            relay_latency_ms=5,
        )


def test_build_relay_audit_negative_latency_rejected() -> None:
    """Spec: ARSIA-Routing.md §7.4 — relay_latency_ms semantics."""
    with pytest.raises(ValueError, match="relay_latency_ms"):
        build_broker_relay_audit_record(
            _envelope(compliance={"data_residency": "EU"}),
            broker_agent_id=_BROKER_ID,
            payload_hash=_HASH,
            forwarding_result="success",
            relay_latency_ms=-1,
        )


def test_build_relay_audit_explicit_relay_id_preserved() -> None:
    rid = "22222222-2222-4222-9222-222222222222"
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=12,
        relay_id=rid,
    )
    assert record.relay_id == rid


def test_build_relay_audit_residency_falls_back_to_envelope() -> None:
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "PT"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=12,
    )
    assert record.residency_zone == "PT"


def test_build_relay_audit_explicit_residency_override() -> None:
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "PT"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=12,
        residency_zone="EU",
    )
    assert record.residency_zone == "EU"


def test_build_relay_audit_without_residency_raises() -> None:
    with pytest.raises(ValueError, match="residency_zone"):
        build_broker_relay_audit_record(
            _envelope(),
            broker_agent_id=_BROKER_ID,
            payload_hash=_HASH,
            forwarding_result="success",
            relay_latency_ms=12,
        )


def test_build_relay_audit_rejects_invalid_broker_agent_id() -> None:
    with pytest.raises(ValueError):
        build_broker_relay_audit_record(
            _envelope(compliance={"data_residency": "EU"}),
            broker_agent_id="not-an-arsia-id",
            payload_hash=_HASH,
            forwarding_result="success",
            relay_latency_ms=12,
        )


def test_build_relay_audit_missing_envelope_id_raises() -> None:
    env = _envelope(compliance={"data_residency": "EU"})
    del env["id"]
    with pytest.raises(ValueError, match="envelope"):
        build_broker_relay_audit_record(
            env,
            broker_agent_id=_BROKER_ID,
            payload_hash=_HASH,
            forwarding_result="success",
            relay_latency_ms=12,
        )


def test_build_relay_audit_timestamp_format_is_ms_utc() -> None:
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=12,
        relayed_at=datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert record.relayed_at == "2026-04-14T12:00:00.000Z"


def test_validate_relay_audit_record_happy() -> None:
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=12,
    )
    assert validate_broker_relay_audit_record(record.model_dump()) == []


def test_validate_relay_audit_record_surfaces_invalid_forwarding_result() -> None:
    """Spec: ARSIA-Routing.md §7.4 — forwarding_result enum is closed."""
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=12,
    )
    as_dict = record.model_dump()
    as_dict["forwarding_result"] = "forwarded"
    errors = validate_broker_relay_audit_record(as_dict)
    assert errors


def test_validate_relay_audit_record_detects_uppercase_hash() -> None:
    record = build_broker_relay_audit_record(
        _envelope(compliance={"data_residency": "EU"}),
        broker_agent_id=_BROKER_ID,
        payload_hash=_HASH,
        forwarding_result="success",
        relay_latency_ms=12,
    )
    as_dict = record.model_dump()
    as_dict["payload_hash"] = "A" * 64
    errors = validate_broker_relay_audit_record(as_dict)
    assert errors


def test_payload_hash_length_constant() -> None:
    assert PAYLOAD_HASH_HEX_LENGTH == 64


# ---------------------------------------------------------------------------
# §6 — Rate-limit headers
# ---------------------------------------------------------------------------


def test_parse_rate_limit_headers_full() -> None:
    headers = {
        "X-RateLimit-Limit": "1000",
        "X-RateLimit-Remaining": "999",
        "X-RateLimit-Reset": "1777777777",
        "Retry-After": "30",
    }
    status = parse_rate_limit_headers(headers)
    assert status == RateLimitStatus(
        limit=1000, remaining=999, reset_at=1777777777, retry_after_seconds=30
    )


def test_parse_rate_limit_headers_case_insensitive() -> None:
    headers = {
        "x-ratelimit-limit": "100",
        "x-ratelimit-remaining": "50",
    }
    status = parse_rate_limit_headers(headers)
    assert status.limit == 100
    assert status.remaining == 50
    assert status.reset_at is None


def test_parse_rate_limit_headers_missing_all() -> None:
    status = parse_rate_limit_headers({})
    assert status == RateLimitStatus()


def test_parse_rate_limit_headers_ignores_negative() -> None:
    status = parse_rate_limit_headers({"X-RateLimit-Limit": "-5"})
    assert status.limit is None


def test_parse_rate_limit_headers_ignores_non_numeric() -> None:
    status = parse_rate_limit_headers({"Retry-After": "soon"})
    assert status.retry_after_seconds is None


def test_parse_rate_limit_headers_strips_whitespace() -> None:
    status = parse_rate_limit_headers({"Retry-After": "  15  "})
    assert status.retry_after_seconds == 15


def test_parse_rate_limit_headers_zero_values_preserved() -> None:
    status = parse_rate_limit_headers(
        {"X-RateLimit-Remaining": "0", "Retry-After": "0"}
    )
    assert status.remaining == 0
    assert status.retry_after_seconds == 0


def test_parse_rate_limit_headers_only_retry_after() -> None:
    status = parse_rate_limit_headers({"Retry-After": "60"})
    assert status.retry_after_seconds == 60
    assert status.limit is None
    assert status.remaining is None
    assert status.reset_at is None


def test_rate_limit_status_is_frozen() -> None:
    status = RateLimitStatus(limit=10)
    with pytest.raises(Exception):
        status.limit = 20  # type: ignore[misc]


# ---------------------------------------------------------------------------
# §5 — Priority resolution
# ---------------------------------------------------------------------------


def test_resolve_priority_default_when_absent() -> None:
    assert resolve_priority(_envelope()) == DEFAULT_PRIORITY


def test_resolve_priority_from_envelope_context() -> None:
    assert resolve_priority(_envelope(context={"priority": 8})) == 8


def test_resolve_priority_out_of_range_in_context_falls_back_to_default() -> None:
    assert resolve_priority(_envelope(context={"priority": 15})) == DEFAULT_PRIORITY


def test_resolve_priority_override_wins() -> None:
    assert resolve_priority(_envelope(context={"priority": 3}), override=9) == 9


def test_resolve_priority_override_out_of_range_raises() -> None:
    with pytest.raises(ValueError):
        resolve_priority(_envelope(), override=11)


def test_resolve_priority_override_negative_raises() -> None:
    with pytest.raises(ValueError):
        resolve_priority(_envelope(), override=-1)


def test_resolve_priority_ignores_boolean_priority() -> None:
    assert (
        resolve_priority(_envelope(context={"priority": True}))
        == DEFAULT_PRIORITY
    )


def test_resolve_priority_zero_is_valid() -> None:
    assert resolve_priority(_envelope(context={"priority": 0})) == 0


def test_default_priority_is_five() -> None:
    assert DEFAULT_PRIORITY == 5


# ---------------------------------------------------------------------------
# Core §11.3 — Retry policy
# ---------------------------------------------------------------------------


def test_retry_base_delay_is_1s() -> None:
    assert RETRY_BASE_DELAY_S == 1.0


def test_retry_multiplier_is_2x() -> None:
    assert RETRY_MULTIPLIER == 2.0


def test_max_retry_delay_is_32s() -> None:
    assert MAX_RETRY_DELAY_S == 32.0


def test_max_retries_recommended_is_3() -> None:
    assert MAX_RETRIES_RECOMMENDED == 3


@pytest.mark.parametrize(
    "attempt,expected",
    [(1, 1.0), (2, 2.0), (3, 4.0), (4, 8.0), (5, 16.0), (6, 32.0)],
)
def test_compute_retry_delay_schedule(attempt: int, expected: float) -> None:
    assert compute_retry_delay(attempt) == expected


def test_compute_retry_delay_caps_at_max() -> None:
    assert compute_retry_delay(10) == MAX_RETRY_DELAY_S
    assert compute_retry_delay(100) == MAX_RETRY_DELAY_S


def test_compute_retry_delay_beyond_recommended_budget_does_not_raise() -> None:
    value = compute_retry_delay(MAX_RETRIES_RECOMMENDED + 5)
    assert value == MAX_RETRY_DELAY_S


def test_compute_retry_delay_zero_raises() -> None:
    with pytest.raises(ValueError):
        compute_retry_delay(0)


def test_compute_retry_delay_negative_raises() -> None:
    with pytest.raises(ValueError):
        compute_retry_delay(-1)


# ---------------------------------------------------------------------------
# §4.1.8 — Non-retryable HTTP codes (ROUTE-§4.1.8-01)
# ---------------------------------------------------------------------------


def test_non_retryable_http_codes_contains_spec_codes() -> None:
    """All §4.1.8 codes are present in the frozenset."""
    expected = {400, 401, 403, 404, 409, 413, 501}
    assert expected <= NON_RETRYABLE_HTTP_CODES


def test_is_retryable_http_status_400_returns_false() -> None:
    assert is_retryable_http_status(400) is False


def test_is_retryable_http_status_500_returns_true() -> None:
    assert is_retryable_http_status(500) is True


def test_is_retryable_http_status_501_returns_false() -> None:
    assert is_retryable_http_status(501) is False


def test_is_retryable_http_status_200_returns_false() -> None:
    assert is_retryable_http_status(200) is False


# ---------------------------------------------------------------------------
# §5.1 — Zone pattern extension (ROUTE-§5.1-05)
# ---------------------------------------------------------------------------


def test_broker_entry_accepts_2_char_zone() -> None:
    """Standard 2-char zone codes (e.g. 'EU') are still accepted."""
    entry = BrokerEntry(
        agent_id="agent:broker.eu",
        inbox="https://broker.example.com/inbox",
        jurisdiction="DE",
        residency_zones=["EU"],
        health="healthy",
        last_health_check="2026-05-01T12:00:00.000Z",
    )
    assert entry.residency_zones == ["EU"]


def test_broker_entry_accepts_4_char_zone() -> None:
    """4-char zone codes (e.g. 'APAC') are now accepted."""
    entry = BrokerEntry(
        agent_id="agent:broker.apac",
        inbox="https://broker.example.com/inbox",
        jurisdiction="SG",
        residency_zones=["APAC"],
        health="healthy",
        last_health_check="2026-05-01T12:00:00.000Z",
    )
    assert entry.residency_zones == ["APAC"]


def test_broker_entry_rejects_5_char_zone() -> None:
    """5-char zones exceed the spec limit and MUST be rejected."""
    with pytest.raises(Exception):
        BrokerEntry(
            agent_id="agent:broker.test",
            inbox="https://broker.example.com/inbox",
            jurisdiction="US",
            residency_zones=["USCAN1"],
            health="healthy",
            last_health_check="2026-05-01T12:00:00.000Z",
        )


def test_broker_entry_rejects_lowercase_zone() -> None:
    """Lowercase zone codes MUST be rejected."""
    with pytest.raises(Exception):
        BrokerEntry(
            agent_id="agent:broker.test",
            inbox="https://broker.example.com/inbox",
            jurisdiction="US",
            residency_zones=["us"],
            health="healthy",
            last_health_check="2026-05-01T12:00:00.000Z",
        )
