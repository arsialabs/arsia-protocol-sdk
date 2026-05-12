# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Human oversight workflow for high-risk actions.

The ARSIA Protocol requires human approval for high-risk actions
(Actions §3). This example demonstrates the full oversight lifecycle:

  1. Create a request that triggers oversight
  2. Check risk classification
  3. Create a pending_approval envelope (with spec-required args)
  4. Create an approval_decision envelope
  5. Validate state transitions

Run:  cd python && python examples/04_oversight_flow.py
"""

from arsia_protocol import (
    create_request,
    create_pending_approval,
    create_approval_decision,
    format_timestamp,
    generate_ed25519_keypair,
    sign_message,
    validate_envelope,
    get_risk_classification,
    is_valid_transition,
    is_terminal_state,
    is_explanation_required,
)
from datetime import datetime, timedelta, timezone

# --- Setup: Generate keys for two agents ---
agent_key, agent_pub = generate_ed25519_keypair()
reviewer_key, reviewer_pub = generate_ed25519_keypair()

AGENT = "agent:acme.assistant"
REVIEWER = "agent:acme.human-reviewer"

# --- Step 1: Create the original request ---
request = create_request(
    from_agent=AGENT,
    to_agent=REVIEWER,
    payload_type="com.acme.financial.transfer",
    capabilities=["com.acme.financial.transfer"],
    args={"amount": 50000, "currency": "EUR", "recipient": "vendor-42"},
)
signed_request = sign_message(request, agent_key, f"{AGENT}#key-1")

print("=== Step 1: Original request ===")
print(f"  id:           {signed_request['id']}")
print(f"  intent:       {signed_request['intent']}")
print(f"  payload_type: {signed_request['payload']['type']}")
print()

# --- Step 2: Check risk classification ---
# The EU AI Act defines five risk bands (Actions §2.2).
for level in [1, 3, 5, 7, 9]:
    classification = get_risk_classification(level)
    print(f"  Risk level {level:2d} -> {classification}")
print()

# --- Step 3: Check if explanation is required ---
needs_explanation = is_explanation_required(
    compliance={"explainability_required": True},
)
print(f"=== Explanation required: {needs_explanation} ===")
print()

# --- Step 4: Create pending_approval envelope ---
# The schema requires specific args for pending_approval (Actions §3.2):
#   action_id, original_request_id, approval_deadline,
#   approver_capability, context, risk_level
approval_deadline = format_timestamp(
    datetime.now(timezone.utc) + timedelta(hours=1)
)
pending = create_pending_approval(
    from_agent=REVIEWER,
    to_agent=AGENT,
    correlation_id=signed_request["id"],
    payload_type="arsiaprotocol.oversight/pending",
    args={
        "action_id": "com.acme.financial.transfer",
        "original_request_id": signed_request["id"],
        "approval_deadline": approval_deadline,
        "approver_capability": "arsiaprotocol.oversight.approve",
        "context": "EUR 50,000 transfer to vendor-42 exceeds automated threshold",
        "risk_level": 7,
    },
    expires_in_seconds=3600,
)
signed_pending = sign_message(pending, reviewer_key, f"{REVIEWER}#key-1")

print("=== Step 4: Pending approval ===")
print(f"  intent:         {signed_pending['intent']}")
print(f"  correlation_id: {signed_pending['correlation_id']}")
print(f"  expires_at:     {signed_pending['expires_at']}")
print()

# --- Step 5: Create approval decision ---
# The approval_decision payload type must be "arsiaprotocol.oversight/decision"
# and result must include decision + approver_id (Actions §3.3).
decision = create_approval_decision(
    from_agent=REVIEWER,
    to_agent=AGENT,
    correlation_id=signed_pending["id"],
    payload_type="arsiaprotocol.oversight/decision",
    capabilities=["com.acme.financial.transfer"],
    result={
        "decision": "approved",
        "approver_id": REVIEWER,
        "reason": "Amount verified against quarterly budget",
    },
)
signed_decision = sign_message(decision, reviewer_key, f"{REVIEWER}#key-1")

print("=== Step 5: Approval decision ===")
print(f"  intent:         {signed_decision['intent']}")
print(f"  correlation_id: {signed_decision['correlation_id']}")
print(f"  decision:       {signed_decision['payload']['result']['decision']}")
print()

# --- Step 6: Validate state transitions ---
# The action lifecycle defines which transitions are legal (Actions §4.1).
print("=== State transitions ===")
transitions_to_check = [
    ("requested", "pending_approval"),
    ("pending_approval", "executing"),
    ("executing", "completed"),
    ("completed", "rolled_back"),
    ("completed", "executing"),
]
for from_state, to_state in transitions_to_check:
    valid = is_valid_transition(from_state, to_state)
    symbol = "OK" if valid else "INVALID"
    print(f"  {from_state:20s} -> {to_state:20s}  [{symbol}]")
print()

# Terminal states have no outgoing transitions.
print("=== Terminal states ===")
for state in ["completed", "failed", "rolled_back"]:
    print(f"  {state:15s}  terminal: {is_terminal_state(state)}")
print()

# --- Step 7: Validate all envelopes ---
print("=== Validation ===")
for name, env in [("request", signed_request), ("pending", signed_pending), ("decision", signed_decision)]:
    errors = validate_envelope(env)
    status = "valid" if not errors else f"{len(errors)} error(s)"
    if errors:
        for err in errors:
            status += f"\n    [{err.code}] {err.message}"
    print(f"  {name:10s}  {status}")
