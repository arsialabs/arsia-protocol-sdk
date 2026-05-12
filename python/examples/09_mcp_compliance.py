# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA as a compliance layer for MCP tool calls.

ARSIA Protocol sits above MCP as a compliance layer — it doesn't replace
MCP, it makes it audit-ready.  This example demonstrates wrapping an MCP
tools/call JSON-RPC message inside a signed, GDPR-compliant ARSIA
envelope.

Scenario: An LLM assistant (Agent A) calls a CRM tool on Agent B via MCP
to fetch customer data that contains PII.  Without ARSIA the call has no
identity, no compliance tagging, and no audit trail.  With ARSIA, the
same MCP call gains cryptographic identity, GDPR compliance fields, and
an automatic audit record.

  1. Setup — keypairs and agent identifiers
  2. The raw MCP tool call (before ARSIA)
  3. Wrap with ARSIA + GDPR compliance
  4. Receiver: verify + validate
  5. Extract the inner MCP message
  6. MCP tool result (response path)
  7. Audit record generation
  8. The contrast — with vs. without ARSIA

Spec references: ARSIA-Core.md §1.3, §4.4, Appendix B.1.

Run:  cd python && python examples/09_mcp_compliance.py
"""

import copy
import json

from arsia_protocol import (
    apply_profile,
    build_audit_record,
    compute_payload_hash,
    create_request,
    create_response,
    generate_ed25519_keypair,
    get_effective_retention,
    sign_message,
    validate_compliance,
    validate_envelope,
    verify_message,
    validate_audit_record,
)

# ── Section 1: Setup ──────────────────────────────────────────────────

print("=" * 65)
print("Section 1: Setup")
print("=" * 65)

agent_a_priv, agent_a_pub = generate_ed25519_keypair()
agent_b_priv, agent_b_pub = generate_ed25519_keypair()

AGENT_A = "agent:acme.assistant"
AGENT_B = "agent:acme.crmService"
KID_A = f"{AGENT_A}#signing-key-1"
KID_B = f"{AGENT_B}#signing-key-1"

print(f"  Agent A (LLM assistant): {AGENT_A}")
print(f"  Agent B (CRM service):   {AGENT_B}")
print(f"  kid A: {KID_A}")
print(f"  kid B: {KID_B}")

# ── Section 2: The raw MCP tool call (before ARSIA) ──────────────────

print()
print("=" * 65)
print("Section 2: The raw MCP tool call (before ARSIA)")
print("=" * 65)

mcp_tool_call = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "getCustomerData",
        "arguments": {"customer_id": "C-12345"},
    },
    "id": 1,
}

print("  MCP JSON-RPC message:")
print(f"    {json.dumps(mcp_tool_call, indent=4)}")
print()
print("  This is what goes over the wire without ARSIA:")
print("    - No sender identity")
print("    - No compliance tagging")
print("    - No audit trail")
print("    - No data residency constraint")
print("    - No human oversight signal")

# ── Section 3: Wrap with ARSIA + GDPR compliance ─────────────────────

print()
print("=" * 65)
print("Section 3: Wrap with ARSIA + GDPR compliance")
print("=" * 65)

envelope = create_request(
    from_agent=AGENT_A,
    to_agent=AGENT_B,
    payload_type="arsiaprotocol.mcp/tool-call",
    capabilities=["acme.crm.getCustomerData"],
    args=mcp_tool_call,
    compliance={
        "profile": "GDPR-STANDARD",
        "pii_involved": True,
        "legal_basis": "contract",
        "data_residency": "DE",
        "audit_required": True,
        "retention_days": 90,
    },
)

enriched = apply_profile(envelope)
signed_request = sign_message(enriched, agent_a_priv, KID_A)

print(f"  Envelope ID:      {signed_request['id']}")
print(f"  From -> To:       {signed_request['from']} -> {signed_request['to']}")
print(f"  payload.type:     {signed_request['payload']['type']}")
print(f"  intent:           {signed_request['intent']}")
print(f"  Profile:          {signed_request['compliance']['profile']}")
print(f"  PII involved:     {signed_request['compliance']['pii_involved']}")
print(f"  Legal basis:      {signed_request['compliance']['legal_basis']}")
print(f"  Data residency:   {signed_request['compliance']['data_residency']}")
print(f"  Audit required:   {signed_request['compliance']['audit_required']}")
print(f"  Retention:        {signed_request['compliance']['retention_days']} days")
print(f"  Signature (alg):  {signed_request['security']['alg']}")
print(f"  Signature (kid):  {signed_request['security']['kid']}")
print(f"  Signature (sig):  {signed_request['security']['sig'][:40]}...")
print()
print("  The MCP JSON-RPC is now inside a signed, compliance-tagged envelope.")

# ── Section 4: Receiver — verify + validate ───────────────────────────

print()
print("=" * 65)
print("Section 4: Receiver — verify + validate")
print("=" * 65)

valid_sig = verify_message(signed_request, agent_a_pub)
print(f"  Signature valid:     {valid_sig}")
assert valid_sig, "Signature verification failed"

errors = validate_envelope(signed_request)
print(f"  Envelope valid:      {len(errors) == 0} ({len(errors)} errors)")
assert not errors, f"Envelope validation failed: {errors}"

errors = validate_compliance(signed_request)
print(f"  Compliance valid:    {len(errors) == 0} ({len(errors)} errors)")
assert not errors, f"Compliance validation failed: {errors}"

# Tamper detection: flip one byte in the payload and re-verify
tampered = copy.deepcopy(signed_request)
tampered["payload"]["args"]["params"]["arguments"]["customer_id"] = "C-99999"
tampered_valid = verify_message(tampered, agent_a_pub)
print(f"  Tampered sig valid:  {tampered_valid}")
assert not tampered_valid, "Tampered envelope should fail verification"
print("  Tamper detected — signature invalidated by payload change.")

# ── Section 5: Extract the inner MCP message ──────────────────────────

print()
print("=" * 65)
print("Section 5: Extract the inner MCP message")
print("=" * 65)

inner_mcp = signed_request["payload"]["args"]
print(f"  Inner MCP method:    {inner_mcp['method']}")
print(f"  Inner MCP tool:      {inner_mcp['params']['name']}")
print(f"  Inner MCP arguments: {json.dumps(inner_mcp['params']['arguments'])}")
print(f"  Inner MCP id:        {inner_mcp['id']}")
print()
assert inner_mcp == mcp_tool_call, "Inner MCP message should be untouched"
print("  The original MCP JSON-RPC is preserved byte-for-byte.")
print("  Forward this to the actual MCP server for execution.")

# ── Section 6: MCP tool result (response path) ───────────────────────

print()
print("=" * 65)
print("Section 6: MCP tool result (response path)")
print("=" * 65)

mcp_tool_result = {
    "jsonrpc": "2.0",
    "result": {
        "content": [
            {
                "type": "text",
                "text": "Customer: Jane Doe, email: jane@example.com, "
                "plan: Enterprise, region: EU-DE",
            }
        ],
    },
    "id": 1,
}

response = create_response(
    from_agent=AGENT_B,
    to_agent=AGENT_A,
    correlation_id=signed_request["id"],
    payload_type="arsiaprotocol.mcp/tool-result",
    result=mcp_tool_result,
    compliance={
        "profile": "GDPR-STANDARD",
        "pii_involved": True,
        "legal_basis": "contract",
        "data_residency": "DE",
        "retention_days": 90,
    },
)

enriched_response = apply_profile(response)
signed_response = sign_message(enriched_response, agent_b_priv, KID_B)

valid_sig = verify_message(signed_response, agent_b_pub)
assert valid_sig, "Response signature failed"

errors = validate_envelope(signed_response)
assert not errors, f"Response validation failed: {errors}"

errors = validate_compliance(signed_response)
assert not errors, f"Response compliance failed: {errors}"

print(f"  Response envelope ID:  {signed_response['id']}")
print(f"  Correlation ID:        {signed_response['correlation_id']}")
print(f"  payload.type:          {signed_response['payload']['type']}")
print(f"  Signature valid:       {valid_sig}")
print(f"  Envelope valid:        True (0 errors)")
print(f"  Compliance valid:      True (0 errors)")
print()

inner_result = signed_response["payload"]["result"]
print(f"  Inner MCP result:      {inner_result['result']['content'][0]['text'][:50]}...")
assert inner_result == mcp_tool_result, "Inner MCP result should be untouched"
print("  The MCP tool result passes through the ARSIA envelope untouched.")

# ── Section 7: Audit record generation ────────────────────────────────

print()
print("=" * 65)
print("Section 7: Audit record generation")
print("=" * 65)

effective_retention = get_effective_retention(signed_request)
print(f"  Effective retention:   {effective_retention} days")

request_record = build_audit_record(
    signed_request,
    event_type="request",
    operator_id="LEI:529900T8BM49AURSDO55",
    effective_retention_days=effective_retention or 90,
)

response_record = build_audit_record(
    signed_response,
    event_type="response",
    operator_id="LEI:529900T8BM49AURSDO55",
    effective_retention_days=effective_retention or 90,
)

request_dict = request_record.model_dump(mode="json", exclude_none=True)
response_dict = response_record.model_dump(mode="json", exclude_none=True)

req_errors = validate_audit_record(request_dict)
resp_errors = validate_audit_record(response_dict)
assert not req_errors, f"Request audit record invalid: {req_errors}"
assert not resp_errors, f"Response audit record invalid: {resp_errors}"

payload_hash = compute_payload_hash(signed_request["payload"])

print(f"  Request audit record:")
print(f"    record_id:         {request_record.record_id}")
print(f"    event_type:        {request_record.event_type}")
print(f"    from -> to:        {request_record.from_agent} -> {request_record.to_agent}")
print(f"    payload_type:      {request_record.payload_type}")
print(f"    compliance_profile:{request_record.compliance_profile}")
print(f"    retained_until:    {request_record.retained_until}")
print(f"    valid:             True (0 errors)")
print(f"  Response audit record:")
print(f"    record_id:         {response_record.record_id}")
print(f"    event_type:        {response_record.event_type}")
print(f"    valid:             True (0 errors)")
print(f"  Payload hash:        {payload_hash[:32]}...")
print()
print("  GDPR Art. 30 requires records of processing activities.")
print("  These audit records are generated automatically from the ARSIA envelope.")

# ── Section 8: The contrast — with vs. without ARSIA ─────────────────

print()
print("=" * 65)
print("Section 8: The contrast")
print("=" * 65)

print()
print("  WITHOUT ARSIA (raw MCP):")
print("    - No sender identity — anyone can call the tool")
print("    - No compliance tagging — no GDPR signals")
print("    - No audit trail — no record of data access")
print("    - No data residency — PII may cross borders")
print("    - No tamper detection — payload can be modified in transit")
print()
print("  WITH ARSIA (MCP wrapped in ARSIA envelope):")
print(f"    - Sender identity: {signed_request['from']} (Ed25519 signed)")
print(f"    - GDPR compliance: profile={signed_request['compliance']['profile']}")
print(f"    - PII flagged: legal_basis={signed_request['compliance']['legal_basis']}")
print(f"    - Data residency: {signed_request['compliance']['data_residency']}")
print(f"    - Audit trail: {request_record.record_id[:20]}...")
print(f"    - Retention: {effective_retention} days")
print(f"    - Tamper detection: signature invalidated on any change")
print()
print("  The MCP server processes the tool call normally — it does not")
print("  need to understand ARSIA.  Compliance is enforced by the ARSIA")
print("  layer, not by MCP.  (Core §1.3, Appendix B.1)")
