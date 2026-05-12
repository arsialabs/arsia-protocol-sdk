# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Authorization: JWT construction, DPoP proofs, scope checking, token binding.

ARSIA-Core.md section 6 defines the OAuth 2.0 access-token layer that agents use to
authenticate to each other.  The SDK provides helpers for every step of the
flow: building and signing JWTs (section 6.1), validating token claims (section 6.4),
parsing and checking scopes (section 6.4 step 5), constructing DPoP proofs
(Identity section 3.3), and verifying the cnf.jkt binding between tokens and proofs.

This example walks through the full client-authentication story:
  1. Setup -- keypairs and claim definitions
  2. Build and sign a JWT
  3. Verify JWT signatures
  4. Validate token claims (valid, expired, wrong audience)
  5. Scope checking (sufficient and insufficient)
  6. Build a token request
  7. DPoP proof construction
  8. DPoP proof validation (valid and invalid)
  9. DPoP binding verification

Run:  cd python && python examples/08_authorization.py
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

from arsia_protocol import (
    DPoPValidationResult,
    TokenValidationResult,
    build_dpop_proof,
    build_jwt,
    build_token_request,
    check_scope_coverage,
    compute_jwk_thumbprint,
    decode_jwt,
    generate_ed25519_keypair,
    parse_scope,
    validate_dpop_proof,
    validate_token_claims,
    verify_dpop_binding,
    verify_jwt_signature,
)
from arsia_protocol.hazmat.primitives.ed25519 import base64url_encode

# ============================================================================
# Section 1 -- Setup
# ============================================================================

print("=== Section 1: Setup ===")
print()

# Authorization Server keypair (signs access tokens)
as_private, as_public = generate_ed25519_keypair()
print("  Authorization Server keypair generated")

# Client agent keypair (signs DPoP proofs)
client_private, client_public = generate_ed25519_keypair()
print("  Client agent keypair generated")

# An unrelated keypair for negative tests
wrong_private, wrong_public = generate_ed25519_keypair()
print("  Wrong keypair generated (for negative tests)")

now = datetime.now(timezone.utc)
now_ts = int(now.timestamp())

CLIENT_ID = "agent:acme.trade-bot"
SERVER_ID = "agent:acme.api-server"
SCOPE = "notes.read notes.write transfers.initiate"
TOKEN_ENDPOINT = "https://auth.acme.example/token"
INBOX_URL = "https://api.acme.example/arsia/inbox"

print(f"  Client:   {CLIENT_ID}")
print(f"  Server:   {SERVER_ID}")
print(f"  Scope:    {SCOPE}")
print()

# ============================================================================
# Section 2 -- Build and Sign a JWT
# ============================================================================

print("=== Section 2: Build and Sign a JWT ===")
print()

# Build a JWK thumbprint for the client's DPoP key -- this goes into cnf.jkt
client_jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": base64url_encode(client_public.public_bytes_raw()),
}
client_thumbprint = compute_jwk_thumbprint(client_jwk)

claims = {
    "iss": TOKEN_ENDPOINT,
    "sub": CLIENT_ID,
    "aud": SERVER_ID,
    "exp": now_ts + 3600,
    "iat": now_ts,
    "jti": str(uuid.uuid4()),
    "scope": SCOPE,
    "cnf": {"jkt": client_thumbprint},
}

token = build_jwt(claims, as_private)
print(f"  JWT (truncated): {token[:60]}...")
print(f"  Length: {len(token)} characters")
print()

# Decode it to inspect header and payload
header, payload, sig_bytes = decode_jwt(token)
print(f"  Header:  {json.dumps(header)}")
print(f"  Payload: iss={payload['iss']}, sub={payload['sub']}, aud={payload['aud']}")
print(f"           scope={payload['scope']!r}")
print(f"           exp={payload['exp']}, iat={payload['iat']}")
print(f"           cnf.jkt={payload['cnf']['jkt'][:20]}...")
print()

# ============================================================================
# Section 3 -- Verify JWT Signature
# ============================================================================

print("=== Section 3: Verify JWT Signature ===")
print()

# Valid signature
valid = verify_jwt_signature(token, as_public)
assert valid, "Expected valid signature"
print(f"  Correct key:  {valid}")

# Wrong key
invalid = verify_jwt_signature(token, wrong_public)
assert not invalid, "Expected invalid signature with wrong key"
print(f"  Wrong key:    {invalid}")
print()

# ============================================================================
# Section 4 -- Validate Token Claims
# ============================================================================

print("=== Section 4: Validate Token Claims ===")
print()

# 4a. Valid token
result = validate_token_claims(
    token,
    as_public,
    expected_sub=CLIENT_ID,
    expected_aud=SERVER_ID,
    required_capabilities=["notes.read", "notes.write"],
    now=now,
)
assert result.is_valid, f"Expected valid token, got errors: {result.errors}"
assert result.claims is not None
print(f"  4a. Valid token:       is_valid={result.is_valid}, errors={len(result.errors)}")
print(f"      Claims sub={result.claims['sub']}, aud={result.claims['aud']}")
print()

# 4b. Expired token
expired_claims = {**claims, "exp": now_ts - 7200, "iat": now_ts - 7200}
expired_token = build_jwt(expired_claims, as_private)

result_expired = validate_token_claims(
    expired_token,
    as_public,
    expected_sub=CLIENT_ID,
    expected_aud=SERVER_ID,
    now=now,
)
assert not result_expired.is_valid, "Expected expired token to be invalid"
error_codes = [e.code for e in result_expired.errors]
assert "token_expired" in error_codes
print(f"  4b. Expired token:     is_valid={result_expired.is_valid}")
print(f"      Errors: {[e.code for e in result_expired.errors]}")
print()

# 4c. Wrong audience
result_aud = validate_token_claims(
    token,
    as_public,
    expected_sub=CLIENT_ID,
    expected_aud="agent:other.service",
    now=now,
)
assert not result_aud.is_valid, "Expected wrong-audience token to be invalid"
error_codes_aud = [e.code for e in result_aud.errors]
assert "token_aud_mismatch" in error_codes_aud
print(f"  4c. Wrong audience:    is_valid={result_aud.is_valid}")
print(f"      Errors: {[e.code for e in result_aud.errors]}")
print()

# 4d. Wrong signature (signed with wrong key)
bad_sig_token = build_jwt(claims, wrong_private)
result_sig = validate_token_claims(
    bad_sig_token,
    as_public,
    now=now,
)
assert not result_sig.is_valid, "Expected bad-signature token to be invalid"
error_codes_sig = [e.code for e in result_sig.errors]
assert "token_signature_invalid" in error_codes_sig
print(f"  4d. Wrong signature:   is_valid={result_sig.is_valid}")
print(f"      Errors: {[e.code for e in result_sig.errors]}")
print()

# ============================================================================
# Section 5 -- Scope Checking
# ============================================================================

print("=== Section 5: Scope Checking ===")
print()

granted = parse_scope(SCOPE)
print(f"  Parsed scope: {sorted(granted)}")

# Sufficient scope
covered, missing = check_scope_coverage(granted, ["notes.read", "notes.write"])
assert covered, "Expected sufficient scope"
print(f"  Required [notes.read, notes.write]: covered={covered}, missing={missing}")

# Insufficient scope
covered2, missing2 = check_scope_coverage(granted, ["notes.read", "admin.delete"])
assert not covered2, "Expected insufficient scope"
assert "admin.delete" in missing2
print(f"  Required [notes.read, admin.delete]: covered={covered2}, missing={missing2}")

# Exact match -- no wildcards
covered3, missing3 = check_scope_coverage(granted, ["notes.*"])
assert not covered3, "Expected no wildcard expansion"
print(f"  Required [notes.*]: covered={covered3}, missing={missing3}  (no wildcard expansion)")
print()

# ============================================================================
# Section 6 -- Build a Token Request
# ============================================================================

print("=== Section 6: Build a Token Request ===")
print()

request = build_token_request(
    client_id=CLIENT_ID,
    scope=SCOPE,
    audience=SERVER_ID,
)
print(f"  Token request:")
for k, v in request.items():
    print(f"    {k}: {v}")
assert request["grant_type"] == "client_credentials"
assert request["client_id"] == CLIENT_ID
assert request["scope"] == SCOPE
assert request["audience"] == SERVER_ID
print()

# ============================================================================
# Section 7 -- DPoP Proof Construction
# ============================================================================

print("=== Section 7: DPoP Proof Construction ===")
print()

print(f"  Client JWK thumbprint: {client_thumbprint}")

dpop_proof = build_dpop_proof(
    client_private,
    client_public,
    htm="POST",
    htu=INBOX_URL,
    access_token=token,
)
print(f"  DPoP proof (truncated): {dpop_proof[:60]}...")
print(f"  Length: {len(dpop_proof)} characters")

# Decode to inspect
dpop_header, dpop_payload, _ = decode_jwt(dpop_proof)
print(f"  Header typ: {dpop_header['typ']}")
print(f"  Header alg: {dpop_header['alg']}")
print(f"  Header jwk.kty: {dpop_header['jwk']['kty']}")
print(f"  Payload htm: {dpop_payload['htm']}")
print(f"  Payload htu: {dpop_payload['htu']}")
print(f"  Payload ath: {dpop_payload['ath'][:20]}...")
print()

# ============================================================================
# Section 8 -- DPoP Proof Validation
# ============================================================================

print("=== Section 8: DPoP Proof Validation ===")
print()

# 8a. Valid proof
dpop_result = validate_dpop_proof(
    dpop_proof,
    token,
    expected_htm="POST",
    expected_htu=INBOX_URL,
)
assert dpop_result.is_valid, f"Expected valid DPoP proof, got: {dpop_result.errors}"
print(f"  8a. Valid proof:       is_valid={dpop_result.is_valid}, errors={len(dpop_result.errors)}")

# 8b. Wrong HTTP method
dpop_result_htm = validate_dpop_proof(
    dpop_proof,
    token,
    expected_htm="GET",
    expected_htu=INBOX_URL,
)
assert not dpop_result_htm.is_valid, "Expected invalid DPoP proof (wrong htm)"
error_codes_htm = [e.code for e in dpop_result_htm.errors]
assert "dpop_htm_mismatch" in error_codes_htm
print(f"  8b. Wrong htm (GET):   is_valid={dpop_result_htm.is_valid}")
print(f"      Errors: {[e.code for e in dpop_result_htm.errors]}")

# 8c. Wrong URI
dpop_result_htu = validate_dpop_proof(
    dpop_proof,
    token,
    expected_htm="POST",
    expected_htu="https://other.example/inbox",
)
assert not dpop_result_htu.is_valid, "Expected invalid DPoP proof (wrong htu)"
error_codes_htu = [e.code for e in dpop_result_htu.errors]
assert "dpop_htu_mismatch" in error_codes_htu
print(f"  8c. Wrong htu:         is_valid={dpop_result_htu.is_valid}")
print(f"      Errors: {[e.code for e in dpop_result_htu.errors]}")

# 8d. Replay detection
seen: set[str] = set()
seen.add(dpop_payload["jti"])
dpop_result_replay = validate_dpop_proof(
    dpop_proof,
    token,
    expected_htm="POST",
    expected_htu=INBOX_URL,
    seen_jti=seen,
)
assert not dpop_result_replay.is_valid, "Expected invalid DPoP proof (replay)"
error_codes_replay = [e.code for e in dpop_result_replay.errors]
assert "dpop_jti_replay" in error_codes_replay
print(f"  8d. Replay:            is_valid={dpop_result_replay.is_valid}")
print(f"      Errors: {[e.code for e in dpop_result_replay.errors]}")
print()

# ============================================================================
# Section 9 -- DPoP Binding Verification
# ============================================================================

print("=== Section 9: DPoP Binding Verification ===")
print()

# The token's cnf.jkt should match the DPoP proof's embedded JWK
bound = verify_dpop_binding(payload, dpop_header)
assert bound, "Expected DPoP binding to succeed"
print(f"  9a. Correct binding:   {bound}")

# A DPoP proof signed by a different key should NOT bind
wrong_dpop = build_dpop_proof(
    wrong_private,
    wrong_public,
    htm="POST",
    htu=INBOX_URL,
    access_token=token,
)
wrong_dpop_header, _, _ = decode_jwt(wrong_dpop)
unbound = verify_dpop_binding(payload, wrong_dpop_header)
assert not unbound, "Expected DPoP binding to fail with wrong key"
print(f"  9b. Wrong key binding: {unbound}")

# A token without cnf claim should not bind
claims_no_cnf = {k: v for k, v in claims.items() if k != "cnf"}
token_no_cnf = build_jwt(claims_no_cnf, as_private)
_, payload_no_cnf, _ = decode_jwt(token_no_cnf)
no_cnf = verify_dpop_binding(payload_no_cnf, dpop_header)
assert not no_cnf, "Expected DPoP binding to fail without cnf"
print(f"  9c. No cnf claim:      {no_cnf}")
print()

print("=== All authorization checks passed ===")
