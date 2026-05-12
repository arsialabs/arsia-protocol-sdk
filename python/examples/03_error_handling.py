# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Build spec-compliant ARSIA error responses.

When an agent cannot process a request, it sends back an error envelope.
The ARSIA Protocol defines 14 standard error codes (Core §11.2, Identity
§6.4.3), each with an assigned HTTP status and retry policy.

This example shows:
  1. Building an error envelope with build_error_envelope
  2. Inspecting the error registry for metadata
  3. Checking retry policy for error codes
  4. Signing error responses (errors are envelopes too)
  5. Validating error envelopes

Run:  cd python && python examples/03_error_handling.py
"""

import json

from arsia_protocol import (
    ERROR_REGISTRY,
    build_error_envelope,
    generate_ed25519_keypair,
    get_error_info,
    is_retryable,
    create_request,
    sign_message,
    validate_envelope,
)

# --- Step 1: Explore the error registry ---
# The registry maps each standard code to its HTTP status and retry flag.
print("=== Standard ARSIA error codes ===")
for code, info in sorted(ERROR_REGISTRY.items()):
    retry = "retryable" if info.retryable else "non-retryable"
    print(f"  {code:25s}  HTTP {info.http_status}  ({retry})")
print()

# --- Step 2: Simulate receiving a request ---
# We create a request so we have a correlation_id to reference in our error.
request = create_request(
    from_agent="agent:acme.client",
    to_agent="agent:acme.server",
    payload_type="com.acme.billing.create-invoice",
    capabilities=["com.acme.billing.create-invoice"],
)
print(f"=== Incoming request ===")
print(f"  id: {request['id']}")
print()

# --- Step 3: Build an error response ---
# build_error_envelope validates the code against the registry and
# creates a proper error envelope with correlation_id linking back
# to the original request.
error_envelope = build_error_envelope(
    from_agent="agent:acme.server",
    to_agent="agent:acme.client",
    correlation_id=request["id"],
    code="forbidden",
    description="Caller lacks the com.acme.billing.create-invoice capability.",
    details={"required_capability": "com.acme.billing.create-invoice"},
)

print("=== Error envelope ===")
print(f"  intent:         {error_envelope['intent']}")
print(f"  correlation_id: {error_envelope['correlation_id']}")
print(f"  error code:     {error_envelope['payload']['error']['code']}")
print(f"  description:    {error_envelope['payload']['error']['description']}")
print(f"  details:        {json.dumps(error_envelope['payload']['error'].get('details'))}")
print()

# --- Step 4: Check retry policy ---
info = get_error_info("forbidden")
print(f"=== Error code metadata: 'forbidden' ===")
print(f"  HTTP status: {info.http_status}")
print(f"  Retryable:   {info.retryable}")
print()

# Compare with a retryable error
print(f"  is_retryable('forbidden'):          {is_retryable('forbidden')}")
print(f"  is_retryable('service_unavailable'): {is_retryable('service_unavailable')}")
print()

# --- Step 5: Sign and validate the error envelope ---
# Error envelopes are full ARSIA envelopes — they get signed and
# validated just like requests and responses.
private_key, public_key = generate_ed25519_keypair()
kid = f"{error_envelope['from']}#signing-key-1"
signed_error = sign_message(error_envelope, private_key, kid)

errors = validate_envelope(signed_error)
if errors:
    print("Validation errors:")
    for err in errors:
        print(f"  [{err.code}] {err.message}")
else:
    print("=== Signed error envelope is valid (0 errors) ===")
