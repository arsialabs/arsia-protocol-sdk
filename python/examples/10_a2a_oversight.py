# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA as a compliance layer for A2A tasks — EU AI Act oversight.

ARSIA Protocol wraps A2A (Agent-to-Agent) tasks with compliance,
identity, and audit — without modifying the A2A protocol itself.  This
example demonstrates the full lifecycle when an A2A task triggers EU AI
Act human oversight requirements.

Scenario: A hiring platform (Agent A) sends a resume screening task to
an AI agent (Agent B) via A2A.  Resume screening by AI is classified as
high-risk under the EU AI Act (Art. 6, Annex III §4).  ARSIA enforces:

  - Human approval before execution (Art. 14 — human oversight)
  - Explainability in the AI's response (Art. 13 — transparency)
  - Full audit trail (Art. 12 — record-keeping)

Sections:
  1. Setup — keypairs and agent identifiers
  2. The raw A2A task (before ARSIA)
  3. Wrap with ARSIA + EU AI Act compliance
  4. Receiver: detect oversight requirement
  5. Create pending_approval
  6. Human review and approval
  7. Execute and respond with explainability
  8. Audit record generation
  9. The contrast — without vs. with ARSIA

Spec references: ARSIA-Core.md §1.3, §4.3.6; ARSIA-Actions.md §3, §5.

Run:  cd python && python examples/10_a2a_oversight.py
"""

import json

from arsia_protocol import (
    apply_profile,
    build_audit_record,
    create_approval_decision,
    create_pending_approval,
    create_request,
    create_response,
    format_timestamp,
    generate_ed25519_keypair,
    is_approval_expired,
    is_explanation_required,
    sign_message,
    validate_audit_record,
    validate_compliance,
    validate_envelope,
    validate_explainability,
    verify_message,
)
from datetime import datetime, timedelta, timezone

# ── Section 1: Setup ──────────────────────────────────────────────────

print("=" * 65)
print("Section 1: Setup")
print("=" * 65)

agent_a_priv, agent_a_pub = generate_ed25519_keypair()
agent_b_priv, agent_b_pub = generate_ed25519_keypair()
reviewer_priv, reviewer_pub = generate_ed25519_keypair()

AGENT_A = "agent:hiringco.platform"
AGENT_B = "agent:hiringco.screener"
REVIEWER = "agent:hiringco.humanReviewer"
KID_A = f"{AGENT_A}#signing-key-1"
KID_B = f"{AGENT_B}#signing-key-1"
KID_R = f"{REVIEWER}#signing-key-1"

print(f"  Agent A (hiring platform):  {AGENT_A}")
print(f"  Agent B (AI screener):      {AGENT_B}")
print(f"  Human Reviewer:             {REVIEWER}")
print(f"  kid A: {KID_A}")
print(f"  kid B: {KID_B}")
print(f"  kid R: {KID_R}")

# ── Section 2: The raw A2A task (before ARSIA) ────────────────────────

print()
print("=" * 65)
print("Section 2: The raw A2A task (before ARSIA)")
print("=" * 65)

a2a_task = {
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
        "id": "task-resume-screen-001",
        "message": {
            "role": "user",
            "parts": [
                {"type": "text", "text": "Screen 50 resumes for senior engineer role"}
            ],
        },
    },
}

print("  A2A JSON-RPC message:")
print(f"    {json.dumps(a2a_task, indent=4)}")
print()
print("  This is what goes over the wire without ARSIA:")
print("    - No sender identity")
print("    - No human oversight before AI processes resumes")
print("    - No explainability requirement on the AI's decision")
print("    - No audit trail for regulatory inspection")
print("    - No EU AI Act Art. 14 compliance")

# ── Section 3: Wrap with ARSIA + EU AI Act compliance ─────────────────

print()
print("=" * 65)
print("Section 3: Wrap with ARSIA + EU AI Act compliance")
print("=" * 65)

envelope = create_request(
    from_agent=AGENT_A,
    to_agent=AGENT_B,
    payload_type="arsiaprotocol.a2a/task",
    capabilities=["hiringco.recruitment.screen"],
    args=a2a_task,
    compliance={
        "profile": "EU-AI-ACT-HIGH-RISK",
        "ai_system_classification": "high-risk",
        "human_oversight": "required_before_execution",
        "explainability_required": True,
        "audit_required": True,
        "data_residency": "PT",
    },
)

enriched = apply_profile(envelope)
signed_request = sign_message(enriched, agent_a_priv, KID_A)

print(f"  Envelope ID:          {signed_request['id']}")
print(f"  From -> To:           {signed_request['from']} -> {signed_request['to']}")
print(f"  payload.type:         {signed_request['payload']['type']}")
print(f"  intent:               {signed_request['intent']}")
print(f"  Profile:              {signed_request['compliance']['profile']}")
print(f"  AI classification:    {signed_request['compliance']['ai_system_classification']}")
print(f"  Human oversight:      {signed_request['compliance']['human_oversight']}")
print(f"  Explainability req:   {signed_request['compliance']['explainability_required']}")
print(f"  Audit required:       {signed_request['compliance']['audit_required']}")
print(f"  Data residency:       {signed_request['compliance']['data_residency']}")
print(f"  Signature (alg):      {signed_request['security']['alg']}")
print(f"  Signature (kid):      {signed_request['security']['kid']}")
print()
print("  The A2A JSON-RPC is now inside a signed, EU AI Act-compliant envelope.")

# ── Section 4: Receiver — detect oversight requirement ────────────────

print()
print("=" * 65)
print("Section 4: Receiver — detect oversight requirement")
print("=" * 65)

valid_sig = verify_message(signed_request, agent_a_pub)
print(f"  Signature valid:       {valid_sig}")
assert valid_sig, "Signature verification failed"

errors = validate_envelope(signed_request)
print(f"  Envelope valid:        {len(errors) == 0} ({len(errors)} errors)")
assert not errors, f"Envelope validation failed: {errors}"

errors = validate_compliance(signed_request)
print(f"  Compliance valid:      {len(errors) == 0} ({len(errors)} errors)")
assert not errors, f"Compliance validation failed: {errors}"

oversight = signed_request["compliance"]["human_oversight"]
print(f"  human_oversight:       {oversight}")
assert oversight == "required_before_execution"
print()
print("  ARSIA layer detects oversight requirement — holding A2A task.")
print("  Agent B MUST NOT process the resumes until a human approves.")

# ── Section 5: Create pending_approval ────────────────────────────────

print()
print("=" * 65)
print("Section 5: Create pending_approval")
print("=" * 65)

approval_deadline = format_timestamp(
    datetime.now(timezone.utc) + timedelta(hours=4)
)

pending = create_pending_approval(
    from_agent=AGENT_B,
    to_agent=REVIEWER,
    correlation_id=signed_request["id"],
    payload_type="arsiaprotocol.oversight/pending",
    args={
        "action_id": "hiringco.recruitment.screen",
        "original_request_id": signed_request["id"],
        "approval_deadline": approval_deadline,
        "approver_capability": "arsiaprotocol.oversight.approve",
        "context": "AI resume screening for 50 candidates — EU AI Act "
        "high-risk (Annex III §4: employment, recruitment AI)",
        "risk_level": 8,
    },
    expires_in_seconds=14400,
)
signed_pending = sign_message(pending, agent_b_priv, KID_B)

errors = validate_envelope(signed_pending)
assert not errors, f"Pending approval validation failed: {errors}"

print(f"  Envelope ID:           {signed_pending['id']}")
print(f"  intent:                {signed_pending['intent']}")
print(f"  correlation_id:        {signed_pending['correlation_id']}")
print(f"  expires_at:            {signed_pending['expires_at']}")
print(f"  risk_level:            {signed_pending['payload']['args']['risk_level']}")
print(f"  context:               {signed_pending['payload']['args']['context'][:60]}...")
print()
print("  The pending_approval is sent to the human reviewer.")
print("  The A2A task remains held until a decision is made.")

# ── Section 6: Human review and approval ──────────────────────────────

print()
print("=" * 65)
print("Section 6: Human review and approval")
print("=" * 65)

expired = is_approval_expired(approval_deadline)
print(f"  Approval expired:      {expired}")
assert not expired, "Approval deadline has passed — cannot proceed"

decision = create_approval_decision(
    from_agent=REVIEWER,
    to_agent=AGENT_B,
    correlation_id=signed_pending["id"],
    payload_type="arsiaprotocol.oversight/decision",
    capabilities=["hiringco.recruitment.screen"],
    result={
        "decision": "approved",
        "approver_id": REVIEWER,
        "reason": "Reviewed screening criteria — no discriminatory filters, "
        "bias mitigation active, candidate data handled per GDPR",
    },
)
signed_decision = sign_message(decision, reviewer_priv, KID_R)

errors = validate_envelope(signed_decision)
assert not errors, f"Decision validation failed: {errors}"

print(f"  Decision:              {signed_decision['payload']['result']['decision']}")
print(f"  Approver:              {signed_decision['payload']['result']['approver_id']}")
print(f"  Reason:                {signed_decision['payload']['result']['reason'][:60]}...")
print(f"  Envelope valid:        True (0 errors)")
print()
print("  Human has approved. Agent B may now execute the A2A task.")

# ── Section 7: Execute and respond with explainability ────────────────

print()
print("=" * 65)
print("Section 7: Execute and respond with explainability")
print("=" * 65)

a2a_result = {
    "jsonrpc": "2.0",
    "result": {
        "id": "task-resume-screen-001",
        "status": {"state": "completed"},
        "artifacts": [
            {
                "type": "text",
                "text": "Top 5 candidates: #12 (9.2), #7 (8.8), #31 (8.5), "
                "#3 (8.1), #44 (7.9). Criteria: technical skills (40%), "
                "experience (30%), education (20%), cultural fit (10%).",
            }
        ],
    },
}

response = create_response(
    from_agent=AGENT_B,
    to_agent=AGENT_A,
    correlation_id=signed_request["id"],
    payload_type="arsiaprotocol.a2a/task-result",
    result=a2a_result,
    explanation={
        "model_version": "screening-v3.1",
        "reasoning": "Ranked candidates using weighted multi-criteria scoring. "
        "Technical skills assessed via keyword extraction and project "
        "complexity analysis. Experience weighted by relevance to senior "
        "engineer role. Bias mitigation: name/age/gender fields excluded "
        "from scoring pipeline.",
        "confidence": 0.87,
        "alternatives_considered": [
            {
                "option": "Binary pass/fail classification",
                "reason_rejected": "Loses ranking granularity — hiring managers "
                "need relative ordering, not just yes/no",
                "confidence": 0.42,
            },
            {
                "option": "Unweighted equal-criteria scoring",
                "reason_rejected": "Treats all criteria equally — technical skills "
                "should dominate for a senior engineer role",
                "confidence": 0.61,
            },
        ],
        "inputs_used": [
            "resume_text",
            "job_description",
            "scoring_rubric_v3",
        ],
        "decision_timestamp": format_timestamp(),
    },
    compliance={
        "profile": "EU-AI-ACT-HIGH-RISK",
        "ai_system_classification": "high-risk",
        "explainability_required": True,
        "audit_required": True,
        "data_residency": "PT",
    },
)

enriched_response = apply_profile(response)
signed_response = sign_message(enriched_response, agent_b_priv, KID_B)

needs_explanation = is_explanation_required(
    compliance=signed_request.get("compliance"),
)
print(f"  Explanation required:  {needs_explanation}")
assert needs_explanation, "EU AI Act high-risk tasks require explanations"

explainability_error = validate_explainability(signed_request, signed_response)
print(f"  Explainability valid:  {explainability_error is None}")
assert explainability_error is None, f"Explainability failed: {explainability_error}"

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

explanation = signed_response["payload"]["explanation"]
print("  Explanation (EU AI Act Art. 13 — transparency):")
print(f"    model_version:       {explanation['model_version']}")
print(f"    confidence:          {explanation['confidence']}")
print(f"    reasoning:           {explanation['reasoning'][:60]}...")
print(f"    alternatives:        {len(explanation['alternatives_considered'])} considered")
print(f"    inputs_used:         {explanation['inputs_used']}")
print()

inner_result = signed_response["payload"]["result"]
print(f"  Inner A2A result:      {inner_result['result']['artifacts'][0]['text'][:60]}...")
print("  The A2A task result passes through the ARSIA envelope untouched.")

# ── Section 8: Audit record generation ────────────────────────────────

print()
print("=" * 65)
print("Section 8: Audit record generation")
print("=" * 65)

audit_record = build_audit_record(
    signed_request,
    event_type="request",
    operator_id="LEI:529900T8BM49AURSDO55",
    effective_retention_days=2555,
    oversight_status="approved",
    approver_id=REVIEWER,
)

record_dict = audit_record.model_dump(mode="json", exclude_none=True)
audit_errors = validate_audit_record(record_dict)
assert not audit_errors, f"Audit record invalid: {audit_errors}"

print("  Audit record (EU AI Act Art. 12 — record-keeping):")
print(f"    record_id:           {audit_record.record_id}")
print(f"    event_type:          {audit_record.event_type}")
print(f"    from -> to:          {audit_record.from_agent} -> {audit_record.to_agent}")
print(f"    payload_type:        {audit_record.payload_type}")
print(f"    compliance_profile:  {audit_record.compliance_profile}")
print(f"    oversight_status:    {audit_record.human_oversight_status}")
print(f"    approver_id:         {audit_record.approver_id}")
print(f"    retained_until:      {audit_record.retained_until}")
print(f"    valid:               True (0 errors)")
print()
print("  The audit record captures the full oversight lifecycle:")
print("    request -> pending_approval -> approved -> executed -> response")
print("  Stored for 7 years per EU AI Act Art. 12(2) retention requirement.")

# ── Section 9: The contrast — without vs. with ARSIA ─────────────────

print()
print("=" * 65)
print("Section 9: The contrast")
print("=" * 65)

print()
print("  WITHOUT ARSIA (raw A2A):")
print("    - A2A task runs immediately — no human review")
print("    - AI screens 50 resumes with no oversight")
print("    - No explanation of how candidates were ranked")
print("    - No audit trail for labour inspectors")
print("    - EU AI Act Art. 14 violation (no human oversight)")
print("    - EU AI Act Art. 13 violation (no transparency)")
print("    - EU AI Act Art. 12 violation (no record-keeping)")
print()
print("  WITH ARSIA (A2A wrapped in ARSIA envelope):")
print(f"    - Sender identity: {signed_request['from']} (Ed25519 signed)")
print(f"    - Human oversight: {signed_request['compliance']['human_oversight']}")
print(f"    - Approved by:     {REVIEWER}")
print(f"    - AI classification: {signed_request['compliance']['ai_system_classification']}")
print(f"    - Explainability:  model={explanation['model_version']}, "
      f"confidence={explanation['confidence']}")
print(f"    - Audit trail:     {audit_record.record_id[:20]}...")
print(f"    - Data residency:  {signed_request['compliance']['data_residency']}")
print()
print("  The A2A protocol is unchanged — ARSIA wraps it, not replaces it.")
print("  Compliance is enforced by the ARSIA layer, not by A2A.")
print("  (Core §1.3, Actions §3, §5)")
