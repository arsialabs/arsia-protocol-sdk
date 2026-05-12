# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Escrow lifecycle: create, hold, release, return, and dispute.

The Assets primitive (ARSIA-Assets.md §4) models escrow as a four-state
machine: ESCROWED → RELEASED | RETURNED | DISPUTED, where DISPUTED
can itself resolve to RELEASED or RETURNED. The SDK provides state-
machine helpers, condition validators, and audit record builders for
every transition.

This example walks through a €50,000 trade escrow:
  1. Setup — three agents and trade context
  2. Building and validating escrow conditions
  3. Escrow FSM basics (valid/invalid transitions)
  4. Escrow created audit record
  5. Release path (ESCROWED → RELEASED)
  6. Return path (ESCROWED → RETURNED via timeout)
  7. Dispute path (ESCROWED → DISPUTED → RELEASED)
  8. Cancellation (ESCROWED → RETURNED via cancel)
  9. Invalid transitions

Run:  cd python && python examples/07_escrow.py
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

from arsia_protocol import (
    format_timestamp,
    # Escrow FSM
    is_valid_escrow_transition,
    is_terminal_escrow_state,
    can_reach_disputed,
    ESCROW_TRANSITIONS,
    # Escrow validation
    validate_escrow_conditions,
    validate_escrow_release,
    validate_escrow_dispute,
    validate_escrow_cancel,
    # Escrow audit records
    build_escrow_created_audit,
    build_escrow_released_audit,
    build_escrow_returned_audit,
    build_escrow_disputed_audit,
)

# ── Section 1: Setup ───────────────────────────────────────────────
print("=== Section 1: Setup ===")

PAYER = "agent:acme.treasury"
PAYEE = "agent:vendor.receivables"
RELEASE_AGENT = "agent:escrow-svc.verifier"
ARBITRATOR = "agent:disputes.arbiter"

AMOUNT = 50_000
CURRENCY = "EUR"
PAYMENT_REF = "PAY-2026-05-11-0042"

now = datetime.now(timezone.utc)
timeout = now + timedelta(hours=72)
timeout_ts = format_timestamp(timeout)
now_ts = format_timestamp(now)

print(f"  Payer:         {PAYER}")
print(f"  Payee:         {PAYEE}")
print(f"  Release agent: {RELEASE_AGENT}")
print(f"  Amount:        {AMOUNT:,} {CURRENCY}")
print(f"  Payment ref:   {PAYMENT_REF}")
print(f"  Timeout:       {timeout_ts}")
print()


# ── Section 2: Build and Validate Escrow Conditions ────────────────
print("=== Section 2: Escrow Conditions ===")

conditions = {
    "release_condition": "Vendor delivers signed proof-of-shipment document",
    "release_trigger": "com.acme.procurement/shipment-confirmed",
    "release_agent": RELEASE_AGENT,
    "timeout_at": timeout_ts,
}

errors = validate_escrow_conditions(conditions, envelope_ts=now_ts)
print(f"  Valid conditions: {len(errors) == 0} ({len(errors)} errors)")

# With arbitration agent
conditions_with_arb = {**conditions, "arbitration_agent": ARBITRATOR}
errors = validate_escrow_conditions(conditions_with_arb, envelope_ts=now_ts)
print(f"  With arbitrator: {len(errors) == 0} ({len(errors)} errors)")

# Invalid: timeout_at in the past
past_ts = format_timestamp(now - timedelta(hours=1))
bad_conditions = {**conditions, "timeout_at": past_ts}
errors = validate_escrow_conditions(bad_conditions, envelope_ts=now_ts)
print(f"  Past timeout:    {len(errors)} error(s)")
for err in errors:
    print(f"    [{err.code}] {err.message[:80]}")
print()


# ── Section 3: Escrow FSM Basics ──────────────────────────────────
print("=== Section 3: Escrow FSM ===")

print("  Transition table:")
for state, targets in sorted(ESCROW_TRANSITIONS.items()):
    targets_str = ", ".join(sorted(targets)) if targets else "(terminal)"
    print(f"    {state:10s} → {targets_str}")

print()
print("  Key transitions:")
transitions = [
    ("ESCROWED", "RELEASED", True),
    ("ESCROWED", "RETURNED", True),
    ("ESCROWED", "DISPUTED", True),
    ("DISPUTED", "RELEASED", True),
    ("DISPUTED", "RETURNED", True),
    ("RELEASED", "ESCROWED", False),
    ("RETURNED", "DISPUTED", False),
]
for from_s, to_s, expected in transitions:
    valid = is_valid_escrow_transition(from_s, to_s)
    assert valid == expected, f"{from_s}→{to_s}: expected {expected}, got {valid}"
    marker = "✓" if valid else "✗"
    print(f"    {from_s:10s} → {to_s:10s}  {marker}")
print()


# ── Section 4: Escrow Created Audit Record ─────────────────────────
print("=== Section 4: Escrow Created Audit ===")

created_audit_id = str(uuid.uuid4())

created_audit = build_escrow_created_audit(
    audit_id=created_audit_id,
    timestamp=now_ts,
    payment_reference=PAYMENT_REF,
    amount=AMOUNT,
    currency_or_unit=CURRENCY,
    from_agent=PAYER,
    to_agent=PAYEE,
    release_agent=RELEASE_AGENT,
    timeout_at=timeout_ts,
)

print(f"  event_type:       {created_audit['event_type']}")
print(f"  sub_type:         {created_audit['sub_type']}")
print(f"  payment_ref:      {created_audit['payment_reference']}")
print(f"  amount:           {created_audit['amount']:,} {created_audit['currency_or_unit']}")
print(f"  from:             {created_audit['from_agent']}")
print(f"  to:               {created_audit['to_agent']}")
print(f"  release_agent:    {created_audit['release_agent']}")
print(f"  audit_id:         {created_audit['audit_id'][:8]}...")
print()


# ── Section 5: Release Path (ESCROWED → RELEASED) ─────────────────
print("=== Section 5: Release Path ===")

# Validate release args
release_args = {"payment_reference": PAYMENT_REF}
errors = validate_escrow_release(release_args)
print(f"  Release args valid: {len(errors) == 0} ({len(errors)} errors)")

# Invalid release (missing payment_reference)
errors = validate_escrow_release({})
print(f"  Empty args:         {len(errors)} error(s)")
for err in errors:
    print(f"    [{err.code}] {err.message[:70]}")

# Transition check
assert is_valid_escrow_transition("ESCROWED", "RELEASED")

# Build audit record
release_ts = format_timestamp(now + timedelta(hours=24))
released_audit = build_escrow_released_audit(
    audit_id=str(uuid.uuid4()),
    timestamp=release_ts,
    payment_reference=PAYMENT_REF,
    released_by=RELEASE_AGENT,
    release_trigger="com.acme.procurement/shipment-confirmed",
    original_audit_id=created_audit_id,
)

print(f"  sub_type:           {released_audit['sub_type']}")
print(f"  released_by:        {released_audit['released_by']}")
print(f"  release_trigger:    {released_audit['release_trigger']}")
print(f"  chains to:          {released_audit['original_audit_id'][:8]}...")

# RELEASED is terminal
assert is_terminal_escrow_state("RELEASED")
print(f"  RELEASED terminal:  {is_terminal_escrow_state('RELEASED')}")
print()


# ── Section 6: Return Path (ESCROWED → RETURNED via timeout) ──────
print("=== Section 6: Return Path (timeout) ===")

assert is_valid_escrow_transition("ESCROWED", "RETURNED")

actual_timeout_ts = format_timestamp(timeout + timedelta(seconds=1))
returned_audit = build_escrow_returned_audit(
    audit_id=str(uuid.uuid4()),
    timestamp=actual_timeout_ts,
    payment_reference=PAYMENT_REF,
    timeout_at=timeout_ts,
    actual_timeout=actual_timeout_ts,
    original_audit_id=created_audit_id,
)

print(f"  sub_type:           {returned_audit['sub_type']}")
print(f"  timeout_at:         {returned_audit['timeout_at']}")
print(f"  actual_timeout:     {returned_audit['actual_timeout']}")
print(f"  chains to:          {returned_audit['original_audit_id'][:8]}...")

assert is_terminal_escrow_state("RETURNED")
print(f"  RETURNED terminal:  {is_terminal_escrow_state('RETURNED')}")
print()


# ── Section 7: Dispute Path (ESCROWED → DISPUTED → RELEASED) ──────
print("=== Section 7: Dispute Path ===")

# DISPUTED is only reachable when arbitration_agent is present
print(f"  Can dispute (no arb):   {can_reach_disputed(conditions)}")
print(f"  Can dispute (with arb): {can_reach_disputed(conditions_with_arb)}")
assert not can_reach_disputed(conditions)
assert can_reach_disputed(conditions_with_arb)

# Validate dispute args
dispute_args = {
    "payment_reference": PAYMENT_REF,
    "dispute_reason": "Shipment received but goods damaged in transit",
    "disputed_by": PAYEE,
}
errors = validate_escrow_dispute(dispute_args)
print(f"  Dispute args valid:     {len(errors) == 0} ({len(errors)} errors)")

# Validate with party check
errors = validate_escrow_dispute(
    dispute_args,
    sender_agent_id=PAYEE,
    escrow_parties=(PAYER, PAYEE),
)
print(f"  Party check (payee):    {len(errors) == 0} ({len(errors)} errors)")

# Outsider cannot dispute
errors = validate_escrow_dispute(
    {**dispute_args, "disputed_by": "agent:outsider.evil"},
    sender_agent_id="agent:outsider.evil",
    escrow_parties=(PAYER, PAYEE),
)
print(f"  Party check (outsider): {len(errors)} error(s)")
for err in errors:
    print(f"    [{err.code}] {err.message[:70]}")

# ESCROWED → DISPUTED
assert is_valid_escrow_transition("ESCROWED", "DISPUTED")

dispute_ts = format_timestamp(now + timedelta(hours=48))
disputed_audit = build_escrow_disputed_audit(
    audit_id=str(uuid.uuid4()),
    timestamp=dispute_ts,
    payment_reference=PAYMENT_REF,
    disputed_by=PAYEE,
    dispute_reason="Shipment received but goods damaged in transit",
    arbitration_agent=ARBITRATOR,
    original_audit_id=created_audit_id,
)

print(f"  sub_type:               {disputed_audit['sub_type']}")
print(f"  disputed_by:            {disputed_audit['disputed_by']}")
print(f"  arbitration_agent:      {disputed_audit['arbitration_agent']}")

# DISPUTED is NOT terminal — it resolves to RELEASED or RETURNED
assert not is_terminal_escrow_state("DISPUTED")
print(f"  DISPUTED terminal:      {is_terminal_escrow_state('DISPUTED')}")

# Arbitrator resolves in favor of payee: DISPUTED → RELEASED
assert is_valid_escrow_transition("DISPUTED", "RELEASED")
assert is_valid_escrow_transition("DISPUTED", "RETURNED")
print(f"  DISPUTED → RELEASED:    {is_valid_escrow_transition('DISPUTED', 'RELEASED')}")
print(f"  DISPUTED → RETURNED:    {is_valid_escrow_transition('DISPUTED', 'RETURNED')}")
print()


# ── Section 8: Cancellation (ESCROWED → RETURNED via cancel) ──────
print("=== Section 8: Cancellation ===")

cancel_args = {
    "payment_reference": PAYMENT_REF,
    "cancellation_reason": "Trade cancelled by mutual agreement before shipment",
}
errors = validate_escrow_cancel(cancel_args)
print(f"  Cancel args valid:    {len(errors) == 0} ({len(errors)} errors)")

# Only the escrow creator (payer) can cancel
errors = validate_escrow_cancel(
    cancel_args,
    sender_agent_id=PAYER,
    from_agent=PAYER,
)
print(f"  Creator cancels:      {len(errors) == 0} ({len(errors)} errors)")

errors = validate_escrow_cancel(
    cancel_args,
    sender_agent_id=PAYEE,
    from_agent=PAYER,
)
print(f"  Non-creator cancels:  {len(errors)} error(s)")
for err in errors:
    print(f"    [{err.code}] {err.message[:70]}")

# Cancellation produces a returned audit with a cancellation_reason
cancel_ts = format_timestamp(now + timedelta(hours=2))
cancel_returned_audit = build_escrow_returned_audit(
    audit_id=str(uuid.uuid4()),
    timestamp=cancel_ts,
    payment_reference=PAYMENT_REF,
    timeout_at=timeout_ts,
    actual_timeout=cancel_ts,
    original_audit_id=created_audit_id,
    cancellation_reason="Trade cancelled by mutual agreement before shipment",
)

print(f"  sub_type:             {cancel_returned_audit['sub_type']}")
print(f"  cancellation_reason:  {cancel_returned_audit['cancellation_reason'][:50]}...")
print()


# ── Section 9: Invalid Transitions ────────────────────────────────
print("=== Section 9: Invalid Transitions ===")

invalid_transitions = [
    ("RELEASED", "ESCROWED", "terminal — cannot reverse a release"),
    ("RETURNED", "ESCROWED", "terminal — cannot re-escrow after return"),
    ("RELEASED", "DISPUTED", "terminal — cannot dispute after release"),
    ("RETURNED", "DISPUTED", "terminal — cannot dispute after return"),
    ("DISPUTED", "ESCROWED", "can only resolve to RELEASED or RETURNED"),
]

for from_s, to_s, reason in invalid_transitions:
    valid = is_valid_escrow_transition(from_s, to_s)
    assert not valid, f"Expected invalid: {from_s} → {to_s}"
    print(f"  {from_s:10s} → {to_s:10s}  ✗ ({reason})")
print()

print("=== All escrow checks passed ===")
