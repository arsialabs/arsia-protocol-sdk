# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Sign, verify, and validate an ARSIA envelope.

This is the golden path — the workflow every developer does first:

  1. Generate an Ed25519 keypair
  2. Build a request envelope
  3. Sign it
  4. Verify the signature
  5. Validate the envelope structure (L1 schema + L2 semantic rules)

Run:  cd python && python examples/01_sign_verify_validate.py
"""

from arsia_protocol import (
    create_request,
    generate_ed25519_keypair,
    sign_message,
    verify_message,
    validate_envelope,
)

# --- Step 1: Generate an Ed25519 keypair ---
# In production you'd load keys from a secure store. For this example
# we generate a fresh pair.
private_key, public_key = generate_ed25519_keypair()

# --- Step 2: Build a request envelope ---
# Agent IDs follow the pattern "agent:{org}.{name}" (Core §3.3).
# capabilities lists the actions the sender wants to perform.
envelope = create_request(
    from_agent="agent:example.sender",
    to_agent="agent:example.receiver",
    payload_type="com.example.greeting",
    capabilities=["com.example.greeting.send"],
)

print("=== Unsigned envelope ===")
print(f"  id:      {envelope['id']}")
print(f"  intent:  {envelope['intent']}")
print(f"  from:    {envelope['from']}")
print(f"  to:      {envelope['to']}")
print()

# --- Step 3: Sign the envelope ---
# The kid (key identifier) MUST start with "{from}#" (Core §5.1 Step 6).
kid = f"{envelope['from']}#signing-key-1"
signed = sign_message(envelope, private_key, kid)

print("=== Signed ===")
print(f"  security.alg: {signed['security']['alg']}")
print(f"  security.kid: {signed['security']['kid']}")
print(f"  security.sig: {signed['security']['sig'][:40]}...")
print()

# --- Step 4: Verify the signature ---
# verify_message returns True if the signature is valid.
valid = verify_message(signed, public_key)
print(f"=== Signature valid: {valid} ===")
print()

# --- Step 5: Validate the envelope ---
# validate_envelope runs L1 (JSON Schema) then L2 (semantic rules).
# An empty list means the envelope is valid.
errors = validate_envelope(signed)
if errors:
    print("Validation errors:")
    for err in errors:
        print(f"  [{err.code}] {err.message}")
else:
    print("=== Envelope is valid (0 errors) ===")
