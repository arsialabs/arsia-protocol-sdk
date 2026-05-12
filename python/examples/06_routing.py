# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Routing, broker discovery, and delivery lifecycle.

The Routing primitive (ARSIA-Routing.md) governs how envelopes reach
their destination when data-residency constraints apply. The SDK
provides topology selection, broker validation, relay precondition
checks, a delivery lifecycle state machine, and audit record builders.

This example shows:
  1. Direct topology — no residency constraint
  2. Broker construction and validation
  3. Brokered topology — cross-zone routing via a compliance broker
  4. Broker selection strategies (priority vs. random)
  5. Relay precondition validation
  6. Delivery lifecycle FSM
  7. Broker relay audit records
  8. Priority resolution

Run:  cd python && python examples/06_routing.py
"""

import json
from datetime import datetime, timedelta, timezone

from arsia_protocol import (
    create_request,
    sign_message,
    generate_ed25519_keypair,
    compute_payload_hash,
    # Topology
    select_topology,
    # Broker operations
    validate_broker_entry,
    broker_serves_zone,
    select_broker_by_priority,
    select_broker_random,
    # Relay
    validate_relay_preconditions,
    # Lifecycle
    is_valid_lifecycle_transition,
    is_terminal_lifecycle_state,
    is_retryable_lifecycle_state,
    # Audit
    build_broker_relay_audit_record,
    validate_broker_relay_audit_record,
    # Priority
    resolve_priority,
    # Rate limiting
    parse_rate_limit_headers,
)

SENDER = "agent:acme.trade-bot"
RECEIVER = "agent:bank.settlement"

private_key, _ = generate_ed25519_keypair()

# ── Section 1: Setup ───────────────────────────────────────────────
print("=== Section 1: Setup ===")

envelope_no_residency = create_request(
    from_agent=SENDER,
    to_agent=RECEIVER,
    payload_type="com.bank.settlement.initiate",
    capabilities=["com.bank.settlement.initiate"],
    args={"amount": 50_000, "currency": "EUR"},
)
signed_envelope = sign_message(
    envelope_no_residency, private_key, f"{SENDER}#key-1"
)
print(f"  Built envelope: id={signed_envelope['id'][:8]}...")
print(f"  intent={signed_envelope['intent']}, from={signed_envelope['from']}")
print()


# ── Section 2: Direct Topology ─────────────────────────────────────
print("=== Section 2: Direct Topology (no residency constraint) ===")

decision = select_topology(signed_envelope)
print(f"  topology:       {decision.topology}")
print(f"  data_residency: {decision.data_residency}")
print(f"  reason:         {decision.reason}")
print(f"  broker:         {decision.broker}")
assert decision.topology == "direct"
print()


# ── Section 3: Broker Construction and Validation ──────────────────
print("=== Section 3: Broker Construction and Validation ===")

now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

broker_eu = {
    "agent_id": "agent:clearstream.relay",
    "inbox": "https://relay.clearstream.example/arsia/inbox",
    "jurisdiction": "DE",
    "residency_zones": ["EU", "DE"],
    "health": "healthy",
    "last_health_check": now_ts,
}

broker_us = {
    "agent_id": "agent:dtcc.relay",
    "inbox": "https://relay.dtcc.example/arsia/inbox",
    "jurisdiction": "US",
    "residency_zones": ["US"],
    "health": "healthy",
    "last_health_check": now_ts,
}

broker_degraded = {
    "agent_id": "agent:euronext.relay",
    "inbox": "https://relay.euronext.example/arsia/inbox",
    "jurisdiction": "FR",
    "residency_zones": ["EU", "FR"],
    "health": "degraded",
    "last_health_check": now_ts,
}

# Valid broker
errors = validate_broker_entry(broker_eu)
print(f"  broker_eu valid:  {len(errors) == 0} ({len(errors)} errors)")

# Invalid broker (missing required field)
broker_invalid = {
    "agent_id": "agent:bad.broker",
    "jurisdiction": "XX",
    "residency_zones": ["EU"],
    "health": "healthy",
    "last_health_check": now_ts,
}
errors = validate_broker_entry(broker_invalid)
print(f"  broker_invalid:   {len(errors)} error(s)")
for err in errors:
    print(f"    [{err.code}] {err.message}")

# Zone membership check
print(f"  broker_eu serves EU:  {broker_serves_zone(broker_eu, 'EU')}")
print(f"  broker_us serves EU:  {broker_serves_zone(broker_us, 'EU')}")
print()


# ── Section 4: Brokered Topology (cross-zone) ─────────────────────
print("=== Section 4: Brokered Topology (EU residency) ===")

envelope_eu = create_request(
    from_agent=SENDER,
    to_agent=RECEIVER,
    payload_type="com.bank.settlement.initiate",
    capabilities=["com.bank.settlement.initiate"],
    args={"amount": 200_000, "currency": "EUR"},
    compliance={"data_residency": "EU", "profile": "mifid2"},
)
signed_eu = sign_message(envelope_eu, private_key, f"{SENDER}#key-1")

brokers = [broker_eu, broker_us, broker_degraded]

decision = select_topology(signed_eu, brokers=brokers)
print(f"  topology:       {decision.topology}")
print(f"  data_residency: {decision.data_residency}")
print(f"  reason:         {decision.reason}")
print(f"  broker:         {decision.broker['agent_id'] if decision.broker else None}")
assert decision.topology == "brokered"
assert decision.broker is not None
print()

# Error topology — residency declared but no matching broker
print("--- Error case: no broker for zone 'JP' ---")
envelope_jp = create_request(
    from_agent=SENDER,
    to_agent=RECEIVER,
    payload_type="com.bank.settlement.initiate",
    capabilities=["com.bank.settlement.initiate"],
    compliance={"data_residency": "JP"},
)
signed_jp = sign_message(envelope_jp, private_key, f"{SENDER}#key-1")

decision_err = select_topology(signed_jp, brokers=brokers)
print(f"  topology:       {decision_err.topology}")
print(f"  error code:     {decision_err.error['code'] if decision_err.error else None}")
assert decision_err.topology == "error"
print()


# ── Section 5: Broker Selection Strategies ─────────────────────────
print("=== Section 5: Broker Selection Strategies ===")

eu_brokers = [broker_eu, broker_degraded]

by_priority = select_broker_by_priority(eu_brokers, zone="EU")
print(f"  By priority: {by_priority['agent_id']} (health={by_priority['health']})")

by_random = select_broker_random(eu_brokers, zone="EU")
print(f"  By random:   {by_random['agent_id']} (health={by_random['health']})")

# Healthy brokers are always preferred over degraded
only_degraded = [broker_degraded]
fallback = select_broker_by_priority(only_degraded, zone="EU")
print(f"  Fallback:    {fallback['agent_id']} (health={fallback['health']})")
print()


# ── Section 6: Relay Precondition Validation ───────────────────────
print("=== Section 6: Relay Precondition Validation ===")

errors = validate_relay_preconditions(signed_eu, broker_eu)
print(f"  Valid relay:   {len(errors)} errors")
assert len(errors) == 0

# Expired envelope — fails Rule 9
expired_env = dict(signed_eu)
expired_env["expires_at"] = "2020-01-01T00:00:00.000Z"
errors = validate_relay_preconditions(expired_env, broker_eu)
print(f"  Expired relay: {len(errors)} error(s)")
for err in errors:
    print(f"    [{err.code}] {err.message[:80]}")
assert len(errors) > 0

# Wrong zone — fails Rule 2
errors = validate_relay_preconditions(signed_eu, broker_us)
print(f"  Wrong zone:    {len(errors)} error(s)")
for err in errors:
    print(f"    [{err.code}] {err.message[:80]}")
print()


# ── Section 7: Delivery Lifecycle FSM ──────────────────────────────
print("=== Section 7: Delivery Lifecycle FSM ===")

# Walk through a brokered delivery
path = [
    ("created", "signed"),
    ("signed", "dispatched"),
    ("dispatched", "broker_relayed"),
    ("broker_relayed", "delivered"),
    ("delivered", "responded"),
]
print("  Brokered delivery path:")
for from_s, to_s in path:
    valid = is_valid_lifecycle_transition(from_s, to_s)
    print(f"    {from_s:20s} → {to_s:20s}  valid={valid}")
    assert valid

# Invalid transition
invalid = is_valid_lifecycle_transition("created", "delivered")
print(f"\n  Invalid skip:  created → delivered  valid={invalid}")
assert not invalid

# Terminal states
print(f"\n  Terminal states:")
for state in ["responded", "expired", "dispatched", "dispatch_failed"]:
    terminal = is_terminal_lifecycle_state(state)
    retryable = is_retryable_lifecycle_state(state)
    print(f"    {state:20s}  terminal={terminal}  retryable={retryable}")
print()


# ── Section 8: Broker Relay Audit Record ───────────────────────────
print("=== Section 8: Broker Relay Audit Record ===")

payload_hash = compute_payload_hash(signed_eu["payload"])

audit_record = build_broker_relay_audit_record(
    signed_eu,
    broker_agent_id="agent:clearstream.relay",
    payload_hash=payload_hash,
    forwarding_result="success",
    relay_latency_ms=42,
)
print(f"  audit_type:       {audit_record.audit_type}")
print(f"  relay_id:         {audit_record.relay_id[:8]}...")
print(f"  message_id:       {audit_record.message_id[:8]}...")
print(f"  broker_agent_id:  {audit_record.broker_agent_id}")
print(f"  forwarding:       {audit_record.forwarding_result}")
print(f"  latency:          {audit_record.relay_latency_ms}ms")

# Validate the audit record
errors = validate_broker_relay_audit_record(audit_record.model_dump())
print(f"  validation:       {len(errors)} errors")
assert len(errors) == 0
print()


# ── Section 9: Priority Resolution ────────────────────────────────
print("=== Section 9: Priority Resolution ===")

# From envelope context
envelope_with_priority = create_request(
    from_agent=SENDER,
    to_agent=RECEIVER,
    payload_type="com.bank.settlement.initiate",
    capabilities=["com.bank.settlement.initiate"],
    context={"priority": 8},
)
p = resolve_priority(envelope_with_priority)
print(f"  From context:  priority={p}")
assert p == 8

# Default when no priority set
p = resolve_priority(signed_envelope)
print(f"  Default:       priority={p}")
assert p == 5

# Caller override wins
p = resolve_priority(envelope_with_priority, override=2)
print(f"  Override:      priority={p}")
assert p == 2
print()


# ── Section 10: Rate-Limit Header Parsing ─────────────────────────
print("=== Section 10: Rate-Limit Header Parsing ===")

headers = {
    "X-RateLimit-Limit": "100",
    "X-RateLimit-Remaining": "3",
    "X-RateLimit-Reset": "1747094400",
}
status = parse_rate_limit_headers(headers)
print(f"  limit:         {status.limit}")
print(f"  remaining:     {status.remaining}")
print(f"  reset_at:      {status.reset_at}")
print(f"  retry_after:   {status.retry_after_seconds}")

# Malformed headers are silently dropped
bad_headers = {"X-RateLimit-Limit": "not-a-number", "Retry-After": "-5"}
status = parse_rate_limit_headers(bad_headers)
print(f"  bad limit:     {status.limit} (silently None)")
print(f"  bad retry:     {status.retry_after_seconds} (silently None)")
print()

print("=== All routing checks passed ===")
