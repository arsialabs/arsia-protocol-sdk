# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Build ARSIA state operation payloads.

The State primitive (ARSIA-State.md) lets agents store, retrieve, query,
and delete key-value state with built-in PII classification, data
residency, and retention rules. The SDK provides builder functions that
produce the correct payload.args shape for each operation.

This example shows:
  1. Building SET args (with scope and PII classification)
  2. Building GET args
  3. Building DELETE args (with optimistic concurrency)
  4. Building QUERY args (with filters)
  5. Wrapping state args in a full envelope

Run:  cd python && python examples/05_state_operations.py
"""

import json

from arsia_protocol import (
    StateEntry,
    build_set_args,
    build_get_args,
    build_delete_args,
    build_query_args,
    create_request,
    sign_message,
    validate_envelope,
    PAYLOAD_TYPE_SET,
    PAYLOAD_TYPE_GET,
    PAYLOAD_TYPE_DELETE,
    PAYLOAD_TYPE_QUERY,
)
from arsia_protocol import format_timestamp, generate_ed25519_keypair
from datetime import datetime, timedelta, timezone

AGENT = "agent:acme.assistant"
STORE = "agent:acme.state-store"

# --- Step 1: Build SET args ---
# StateEntry requires all fields including server-managed ones for
# validation. For a SET request, build_set_args extracts only the
# agent-supplied fields (State §3.1.2).
entry = StateEntry(
    key="agent:acme.assistant/agent/user-preferences",
    value={"theme": "dark", "language": "en"},
    owner_agent_id=AGENT,
    scope="agent",
    pii_classification="pseudonymised",
    created_at=format_timestamp(),
    updated_at=format_timestamp(),
    version=1,
)

set_args = build_set_args(entry)
print("=== SET args ===")
print(json.dumps(set_args, indent=2))
print()

# --- Step 2: Build GET args ---
get_args = build_get_args("agent:acme.assistant/agent/user-preferences")
print("=== GET args ===")
print(json.dumps(get_args, indent=2))
print()

# --- Step 3: Build DELETE args ---
# expected_version enables optimistic concurrency — the store rejects
# the delete if the entry has been modified since you last read it.
delete_args = build_delete_args(
    "agent:acme.assistant/agent/user-preferences",
    expected_version=1,
)
print("=== DELETE args (with optimistic concurrency) ===")
print(json.dumps(delete_args, indent=2))
print()

# --- Step 4: Build QUERY args ---
# QUERY supports multiple filters combined with AND logic (State §3.1.4).
query_args = build_query_args(
    scope="agent",
    key_prefix="agent:acme.assistant/agent/",
    pii_classification="pseudonymised",
    limit=50,
)
print("=== QUERY args ===")
print(json.dumps(query_args, indent=2))
print()

# --- Step 5: Wrap in a full envelope ---
# State operations are transported as normal ARSIA request envelopes.
# The payload_type indicates the operation (SET, GET, DELETE, QUERY).
private_key, _ = generate_ed25519_keypair()

envelope = create_request(
    from_agent=AGENT,
    to_agent=STORE,
    payload_type=PAYLOAD_TYPE_SET,
    capabilities=["arsiaprotocol.state.write"],
    args=set_args,
)
signed = sign_message(envelope, private_key, f"{AGENT}#key-1")

print(f"=== Full SET envelope ===")
print(f"  intent:       {signed['intent']}")
print(f"  payload_type: {signed['payload']['type']}")
print(f"  args.key:     {signed['payload']['args']['key']}")
print(f"  args.scope:   {signed['payload']['args']['scope']}")
print()

# Validate the complete envelope
errors = validate_envelope(signed)
if errors:
    print("Validation errors:")
    for err in errors:
        print(f"  [{err.code}] {err.message}")
else:
    print("=== Envelope is valid (0 errors) ===")
print()

# --- Payload type constants ---
print("=== State payload types ===")
for label, pt in [("SET", PAYLOAD_TYPE_SET), ("GET", PAYLOAD_TYPE_GET),
                  ("DELETE", PAYLOAD_TYPE_DELETE), ("QUERY", PAYLOAD_TYPE_QUERY)]:
    print(f"  {label:6s}  {pt}")
