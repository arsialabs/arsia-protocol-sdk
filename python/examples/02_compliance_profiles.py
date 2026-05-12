# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Apply compliance profiles to ARSIA envelopes.

Compliance profiles (e.g. GDPR-STANDARD, HIPAA-STANDARD) define default
values for retention, data residency, and explainability. When a sender
declares a profile on an envelope, apply_profile() fills in inherited
defaults so the wire message carries the fully resolved compliance state.

This example shows:
  1. Listing available profiles
  2. Building an envelope with a compliance profile
  3. Applying the profile to inherit default fields
  4. Comparing before/after to see what changed
  5. Strict vs non-strict mode for unknown profiles

Run:  cd python && python examples/02_compliance_profiles.py
"""

import json

from arsia_protocol import (
    apply_profile,
    create_request,
    get_profile,
    get_profile_names,
)

# --- Step 1: List available profiles ---
print("=== Available compliance profiles ===")
for name in get_profile_names():
    print(f"  - {name}")
print()

# --- Step 2: Inspect a profile's defaults ---
profile = get_profile("GDPR-STANDARD")
print("=== GDPR-STANDARD profile defaults ===")
print(json.dumps(profile, indent=2))
print()

# --- Step 3: Build an envelope with a compliance profile ---
# When you set compliance.profile, apply_profile() will inherit the
# profile's defaults for any field you don't explicitly set.
envelope = create_request(
    from_agent="agent:example.sender",
    to_agent="agent:example.receiver",
    payload_type="com.example.user-data",
    capabilities=["com.example.user-data.read"],
    compliance={
        "profile": "GDPR-STANDARD",
        "data_residency": "DE",
    },
)

print("=== Before apply_profile ===")
print(json.dumps(envelope["compliance"], indent=2))
print()

# --- Step 4: Apply the profile ---
# apply_profile() returns a new envelope (the original is not mutated).
# Fields from the profile fill in gaps; explicit per-message values
# take priority (Core §4.3.7).
resolved = apply_profile(envelope)

print("=== After apply_profile ===")
print(json.dumps(resolved["compliance"], indent=2))
print()

# --- Step 5: Strict mode ---
# With strict=True, an unknown profile name raises ValueError.
# With strict=False (default), it logs a warning and falls back
# to GDPR-STANDARD defaults.
bad_envelope = create_request(
    from_agent="agent:example.sender",
    to_agent="agent:example.receiver",
    payload_type="com.example.test",
    capabilities=["com.example.test.run"],
    compliance={"profile": "NONEXISTENT-PROFILE"},
)

# Non-strict: falls back gracefully
resolved_lenient = apply_profile(bad_envelope, strict=False)
print("=== Unknown profile (non-strict) — falls back to GDPR-STANDARD ===")
print(json.dumps(resolved_lenient["compliance"], indent=2))
print()

# Strict: raises ValueError
try:
    apply_profile(bad_envelope, strict=True)
except ValueError as exc:
    print(f"=== Unknown profile (strict) — error ===")
    print(f"  {exc}")
