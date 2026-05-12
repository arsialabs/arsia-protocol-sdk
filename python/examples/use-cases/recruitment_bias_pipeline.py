# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Recruitment bias pipeline -- iterative bias detection with EU AI Act compliance.

Demonstrates a multinational company screening 2,000 applications for a
senior engineering role. Under the EU AI Act, employment AI is high-risk
(Annex III, point 4). Three agents handle CV screening, bias auditing,
and decision preparation -- structured so that discriminatory outcomes
are caught before any human sees a ranking.

Agents:
    A -- CV Screener       (agent:hiringco.cv-screener)
        Capabilities: screening.score, screening.result
        Sees: anonymized CVs + scoring criteria
        Does NOT see: candidate names, photos, age, nationality

    B -- Bias Auditor      (agent:hiringco.bias-auditor)
        Capabilities: bias.audit
        Sees: scores + protected group flags
        Does NOT see: CV content, scoring criteria, weights

    C -- Decision Packager (agent:hiringco.decision-packager)
        Capabilities: decision.prepare
        Sees: anonymized shortlist + audit certificate
        Does NOT see: protected group data, CV content, bias metrics

Pipeline steps:
    1. A->B (iter 1): ranked shortlist (50/2000), request bias audit
    2. B->A (iter 1): FAIL -- gender 0.41, age 0.42 (threshold 0.80)
    3. A->B (iter 2): adjusted shortlist after scoring weight changes
    4. B->A (iter 2): PASS -- gender 0.83, age 0.83, nationality 0.89
    5. A->C: audited shortlist + certificate (no protected group data)
    6. C->A: decision package with audit summary
    7. Oversight hold: pending_approval for hiring manager
    8. Oversight approve: manager approves with documented reason
    9. Denial #1: B requests screening.score -> 403
   10. Denial #2: C requests bias.audit -> 403
   11. Audit trail: 10 records, 180-day retention

Regulatory references:
    - EU AI Act Art. 9: risk management for high-risk AI
    - EU AI Act Art. 10: data governance and bias mitigation
    - EU AI Act Art. 13: transparency obligations
    - EU AI Act Art. 14: human oversight requirements
    - EU AI Act Art. 26(6): deployer obligations
    - Directive 2006/54/EC: equal treatment in employment

Uses only SDK functions -- no HTTP, no server, no database.
"""

from datetime import datetime, timedelta, timezone

from arsia_protocol import (
    apply_profile,
    build_audit_record,
    build_forbidden_error,
    build_jwk,
    compute_payload_hash,
    create_approval_decision,
    create_pending_approval,
    create_request,
    create_response,
    find_unsatisfied_capabilities,
    format_timestamp,
    get_effective_retention,
    match_capabilities,
    sign_message,
    validate_compliance,
    validate_correlation,
    validate_envelope,
    validate_eu_ai_act_response,
    validate_explainability,
    generate_ed25519_keypair,
    verify_message,
)


def main() -> None:
    # -- Setup: generate keypairs and define agents -----------------------

    priv_a, pub_a = generate_ed25519_keypair()
    priv_b, pub_b = generate_ed25519_keypair()
    priv_c, pub_c = generate_ed25519_keypair()

    agent_a = "agent:hiringco.cv-screener"
    agent_b = "agent:hiringco.bias-auditor"
    agent_c = "agent:hiringco.decision-packager"

    kid_a = f"{agent_a}#key-1"
    kid_b = f"{agent_b}#key-1"
    kid_c = f"{agent_c}#key-1"

    scope_a = ["screening.score", "screening.result"]
    scope_b = ["bias.audit"]
    scope_c = ["decision.prepare"]

    jwk_a = build_jwk(pub_a, kid_a)
    jwk_b = build_jwk(pub_b, kid_b)
    jwk_c = build_jwk(pub_c, kid_c)

    print("ARSIA Protocol -- Recruitment Bias Pipeline (EU AI Act High-Risk)")
    print("=" * 70)
    print(f"  Agent A (CV Screener):       {agent_a}  scope={scope_a}")
    print(f"  Agent B (Bias Auditor):      {agent_b}  scope={scope_b}")
    print(f"  Agent C (Decision Packager): {agent_c}  scope={scope_c}")
    print(f"  JWK A kid: {jwk_a['kid']}")
    print(f"  JWK B kid: {jwk_b['kid']}")
    print(f"  JWK C kid: {jwk_c['kid']}")

    signed_envelopes: list[dict] = []
    eu_ai_retention = 180

    # -- Step 1: A->B iter 1 -- ranked shortlist for bias audit ----------

    print("\n" + "=" * 70)
    print("Step 1: A->B (iter 1) -- Ranked shortlist for bias audit")
    print("=" * 70)

    shortlist_iter1 = [
        {"candidate_id": f"ANON-{i:04d}", "score": round(0.55 + (i % 17) * 0.025, 3)}
        for i in range(1, 51)
    ]

    env_1 = create_request(
        from_agent=agent_a,
        to_agent=agent_b,
        payload_type="org.hiringco.bias.audit",
        capabilities=["bias.audit"],
        args={
            "audit_iteration": 1,
            "total_applicants": 2000,
            "shortlist_size": 50,
            "role": "senior-engineer",
            "shortlist": shortlist_iter1,
            "scoring_criteria": "withheld",
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_1 = apply_profile(env_1)
    signed_1 = sign_message(env_1, priv_a, kid_a)

    assert verify_message(signed_1, pub_a), "Step 1: signature verification failed"

    errors = validate_envelope(signed_1)
    assert not errors, f"Step 1: validation errors: {errors}"

    comp_errors = validate_compliance(signed_1)
    assert not comp_errors, f"Step 1: compliance errors: {comp_errors}"

    signed_envelopes.append(signed_1)

    print(f"  Envelope ID:   {signed_1['id']}")
    print(f"  From -> To:    {signed_1['from']} -> {signed_1['to']}")
    print(f"  Profile:       {signed_1['compliance']['profile']}")
    print(f"  Total screened:{signed_1['payload']['args']['total_applicants']}")
    print(f"  Shortlist:     {signed_1['payload']['args']['shortlist_size']} candidates")
    print("  No CV content sent to B -- only anonymized IDs + scores")
    print("  Signed, verified, validated, EU-AI-ACT-HIGH-RISK applied")

    # -- Step 2: B->A iter 1 -- FAIL (disparate impact detected) ---------

    print("\n" + "=" * 70)
    print("Step 2: B->A (iter 1) -- FAIL: disparate impact detected")
    print("=" * 70)

    env_2 = create_response(
        from_agent=agent_b,
        to_agent=agent_a,
        correlation_id=signed_1["id"],
        payload_type="org.hiringco.bias.audit.result",
        result={
            "audit_result": "FAIL",
            "iteration": 1,
            "methodology": "EEOC_four_fifths_rule",
            "threshold": 0.80,
            "disparate_impact": {
                "gender": {"ratio": 0.41, "pass": False, "p_value": 0.0003},
                "age": {"ratio": 0.42, "pass": False, "p_value": 0.0008},
                "nationality": {"ratio": 0.78, "pass": False, "p_value": 0.042},
            },
            "recommendation": "Adjust scoring weights to reduce correlation "
            "with protected characteristics. Re-submit adjusted shortlist.",
        },
        explanation={
            "reasoning": (
                "Applied EEOC four-fifths rule (80% threshold) to shortlist "
                "composition. Gender selection rate 0.41 indicates women selected "
                "at 41% the rate of men. Age selection rate 0.42 indicates "
                "candidates over 40 selected at 42% the rate of younger candidates. "
                "Both ratios fall below the 0.80 adverse impact threshold with "
                "statistical significance (p < 0.001)."
            ),
            "confidence": 0.97,
            "inputs_used": [
                "candidate_scores",
                "protected_group_flags_gender",
                "protected_group_flags_age",
                "protected_group_flags_nationality",
                "selection_threshold",
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_2 = apply_profile(env_2)
    signed_2 = sign_message(env_2, priv_b, kid_b)

    assert verify_message(signed_2, pub_b), "Step 2: signature verification failed"

    errors = validate_envelope(signed_2)
    assert not errors, f"Step 2: validation errors: {errors}"

    corr_errors = validate_correlation(signed_1, signed_2)
    assert not corr_errors, f"Step 2: correlation errors: {corr_errors}"

    explain_error = validate_explainability(signed_1, signed_2)
    assert explain_error is None, f"Step 2: explainability error: {explain_error}"

    eu_errors = validate_eu_ai_act_response(signed_2)
    assert not eu_errors, f"Step 2: EU AI Act response errors: {eu_errors}"

    signed_envelopes.append(signed_2)

    result_2 = signed_2["payload"]["result"]
    di = result_2["disparate_impact"]
    print(f"  Correlation:   {signed_2['correlation_id']}")
    print(f"  Audit result:  {result_2['audit_result']}")
    print(f"  Gender ratio:  {di['gender']['ratio']} (threshold: 0.80) -- FAIL")
    print(f"  Age ratio:     {di['age']['ratio']} (threshold: 0.80) -- FAIL")
    print(f"  Nationality:   {di['nationality']['ratio']} (threshold: 0.80) -- FAIL")
    print(f"  Methodology:   {result_2['methodology']}")
    print(f"  Recommendation:{result_2['recommendation'][:60]}...")
    print("  Directive 2006/54/EC: disparate impact on protected groups detected")
    print("  Signed, verified, validated, correlation + explainability confirmed")

    # -- Step 3: A->B iter 2 -- adjusted shortlist after weight changes ---

    print("\n" + "=" * 70)
    print("Step 3: A->B (iter 2) -- Adjusted shortlist after weight changes")
    print("=" * 70)

    shortlist_iter2 = [
        {"candidate_id": f"ANON-{i:04d}", "score": round(0.60 + (i % 13) * 0.028, 3)}
        for i in range(1, 51)
    ]

    env_3 = create_request(
        from_agent=agent_a,
        to_agent=agent_b,
        payload_type="org.hiringco.bias.audit",
        capabilities=["bias.audit"],
        args={
            "audit_iteration": 2,
            "total_applicants": 2000,
            "shortlist_size": 50,
            "role": "senior-engineer",
            "shortlist": shortlist_iter2,
            "scoring_weights_adjusted": True,
            "adjustments_made": [
                "reduced years_experience weight from 0.35 to 0.20",
                "removed university_ranking as factor",
                "added skills_assessment weight 0.30",
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_3 = apply_profile(env_3)
    signed_3 = sign_message(env_3, priv_a, kid_a)

    assert verify_message(signed_3, pub_a), "Step 3: signature verification failed"

    errors = validate_envelope(signed_3)
    assert not errors, f"Step 3: validation errors: {errors}"

    signed_envelopes.append(signed_3)

    print(f"  Envelope ID:   {signed_3['id']}")
    print(f"  Iteration:     {signed_3['payload']['args']['audit_iteration']}")
    print(f"  Weights adj:   {signed_3['payload']['args']['scoring_weights_adjusted']}")
    print(f"  Adjustments:   {signed_3['payload']['args']['adjustments_made']}")
    print("  New correlation chain (independent request-response pair)")
    print("  Signed, verified, validated, re-submitted for bias audit")

    # -- Step 4: B->A iter 2 -- PASS + certificate issued ----------------

    print("\n" + "=" * 70)
    print("Step 4: B->A (iter 2) -- PASS: bias thresholds met, certificate issued")
    print("=" * 70)

    certificate_id = "CERT-BIAS-2026-05-10-001"
    certificate_hash = compute_payload_hash({
        "certificate_id": certificate_id,
        "audit_result": "PASS",
        "iterations_required": 2,
        "gender_ratio": 0.83,
        "age_ratio": 0.83,
        "nationality_ratio": 0.89,
    })

    env_4 = create_response(
        from_agent=agent_b,
        to_agent=agent_a,
        correlation_id=signed_3["id"],
        payload_type="org.hiringco.bias.audit.result",
        result={
            "audit_result": "PASS",
            "iteration": 2,
            "iterations_required": 2,
            "methodology": "EEOC_four_fifths_rule",
            "threshold": 0.80,
            "disparate_impact": {
                "gender": {"ratio": 0.83, "pass": True, "p_value": 0.31},
                "age": {"ratio": 0.83, "pass": True, "p_value": 0.28},
                "nationality": {"ratio": 0.89, "pass": True, "p_value": 0.52},
            },
            "certificate_id": certificate_id,
            "certificate_hash": certificate_hash,
        },
        explanation={
            "reasoning": (
                "Re-applied EEOC four-fifths rule after scoring weight adjustments. "
                "Gender selection rate improved from 0.41 to 0.83. Age selection "
                "rate improved from 0.42 to 0.83. Nationality ratio improved from "
                "0.78 to 0.89. All three protected groups now exceed the 0.80 "
                "adverse impact threshold. No statistically significant disparate "
                "impact remains (all p-values > 0.05)."
            ),
            "confidence": 0.95,
            "inputs_used": [
                "adjusted_candidate_scores",
                "protected_group_flags_gender",
                "protected_group_flags_age",
                "protected_group_flags_nationality",
                "selection_threshold",
                "prior_iteration_results",
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_4 = apply_profile(env_4)
    signed_4 = sign_message(env_4, priv_b, kid_b)

    assert verify_message(signed_4, pub_b), "Step 4: signature verification failed"

    errors = validate_envelope(signed_4)
    assert not errors, f"Step 4: validation errors: {errors}"

    corr_errors = validate_correlation(signed_3, signed_4)
    assert not corr_errors, f"Step 4: correlation errors: {corr_errors}"

    explain_error = validate_explainability(signed_3, signed_4)
    assert explain_error is None, f"Step 4: explainability error: {explain_error}"

    eu_errors = validate_eu_ai_act_response(signed_4)
    assert not eu_errors, f"Step 4: EU AI Act response errors: {eu_errors}"

    signed_envelopes.append(signed_4)

    result_4 = signed_4["payload"]["result"]
    di4 = result_4["disparate_impact"]
    print(f"  Correlation:   {signed_4['correlation_id']}")
    print(f"  Audit result:  {result_4['audit_result']}")
    print(f"  Gender ratio:  {di4['gender']['ratio']} (>= 0.80) -- PASS")
    print(f"  Age ratio:     {di4['age']['ratio']} (>= 0.80) -- PASS")
    print(f"  Nationality:   {di4['nationality']['ratio']} (>= 0.80) -- PASS")
    print(f"  Iterations:    {result_4['iterations_required']}")
    print(f"  Certificate:   {result_4['certificate_id']}")
    print(f"  Cert hash:     {result_4['certificate_hash'][:32]}...")
    print("  EU AI Act Art. 10: bias mitigation through iterative correction")
    print("  Signed, verified, validated, correlation + explainability confirmed")

    # -- Step 5: A->C -- audited shortlist + certificate -----------------

    print("\n" + "=" * 70)
    print("Step 5: A->C -- Audited shortlist + certificate (no protected data)")
    print("=" * 70)

    shortlist_for_c = [
        {"candidate_id": c["candidate_id"], "score": c["score"]}
        for c in shortlist_iter2[:10]
    ]

    env_5 = create_request(
        from_agent=agent_a,
        to_agent=agent_c,
        payload_type="org.hiringco.decision.prepare",
        capabilities=["decision.prepare"],
        args={
            "shortlist": shortlist_for_c,
            "certificate_id": certificate_id,
            "certificate_hash": certificate_hash,
            "audit_iterations": 2,
            "audit_result": "PASS",
            "role": "senior-engineer",
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_5 = apply_profile(env_5)
    signed_5 = sign_message(env_5, priv_a, kid_a)

    assert verify_message(signed_5, pub_a), "Step 5: signature verification failed"

    errors = validate_envelope(signed_5)
    assert not errors, f"Step 5: validation errors: {errors}"

    signed_envelopes.append(signed_5)

    args_5 = signed_5["payload"]["args"]
    assert "certificate_id" in args_5, "Step 5: certificate_id missing"
    assert "certificate_hash" in args_5, "Step 5: certificate_hash missing"
    assert all(
        "gender" not in str(c) and "age" not in str(c) and "nationality" not in str(c)
        for c in args_5["shortlist"]
    ), "Step 5: protected group data leaked to Agent C"

    print(f"  Envelope ID:   {signed_5['id']}")
    print(f"  From -> To:    {signed_5['from']} -> {signed_5['to']}")
    print(f"  Certificate:   {args_5['certificate_id']}")
    print(f"  Cert hash:     {args_5['certificate_hash'][:32]}...")
    print(f"  Shortlist:     {len(args_5['shortlist'])} candidates (top 10)")
    print("  DATA ISOLATION: No protected group data, no CV content, no bias metrics")
    print("  Only: anonymized IDs + scores + audit certificate")
    print("  Signed, verified, validated")

    # -- Step 6: C->A -- decision package --------------------------------

    print("\n" + "=" * 70)
    print("Step 6: C->A -- Decision package ready for human review")
    print("=" * 70)

    env_6 = create_response(
        from_agent=agent_c,
        to_agent=agent_a,
        correlation_id=signed_5["id"],
        payload_type="org.hiringco.decision.package",
        result={
            "package_id": "PKG-2026-05-10-SR-ENG-001",
            "shortlist_count": 10,
            "top_candidates": [
                {"candidate_id": "ANON-0010", "score": 0.852, "rank": 1},
                {"candidate_id": "ANON-0023", "score": 0.844, "rank": 2},
                {"candidate_id": "ANON-0036", "score": 0.836, "rank": 3},
            ],
            "audit_summary": {
                "certificate_id": certificate_id,
                "bias_audit_passed": True,
                "iterations_required": 2,
                "methodology": "EEOC_four_fifths_rule",
            },
            "recommendation": "Proceed to structured interview phase",
        },
        explanation={
            "reasoning": (
                "Prepared decision package from audited shortlist. Verified "
                "bias audit certificate hash matches. Ranked candidates by "
                "adjusted score. Top 3 candidates presented with scores. "
                "All candidates passed bias-corrected screening. Package "
                "ready for hiring manager review under Art. 14 oversight."
            ),
            "confidence": 0.92,
            "inputs_used": [
                "audited_shortlist_scores",
                "certificate_id",
                "certificate_hash",
                "role_requirements",
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_6 = apply_profile(env_6)
    signed_6 = sign_message(env_6, priv_c, kid_c)

    assert verify_message(signed_6, pub_c), "Step 6: signature verification failed"

    errors = validate_envelope(signed_6)
    assert not errors, f"Step 6: validation errors: {errors}"

    corr_errors = validate_correlation(signed_5, signed_6)
    assert not corr_errors, f"Step 6: correlation errors: {corr_errors}"

    explain_error = validate_explainability(signed_5, signed_6)
    assert explain_error is None, f"Step 6: explainability error: {explain_error}"

    eu_errors = validate_eu_ai_act_response(signed_6)
    assert not eu_errors, f"Step 6: EU AI Act response errors: {eu_errors}"

    signed_envelopes.append(signed_6)

    result_6 = signed_6["payload"]["result"]
    print(f"  Correlation:   {signed_6['correlation_id']}")
    print(f"  Package ID:    {result_6['package_id']}")
    print(f"  Shortlist:     {result_6['shortlist_count']} candidates")
    print(f"  Top candidate: {result_6['top_candidates'][0]['candidate_id']} "
          f"(score {result_6['top_candidates'][0]['score']})")
    print(f"  Audit cert:    {result_6['audit_summary']['certificate_id']}")
    print(f"  Recommendation:{result_6['recommendation']}")
    print("  EU AI Act Art. 13: transparent decision package for human review")
    print("  Signed, verified, validated, correlation + explainability confirmed")

    # -- Step 7: Oversight hold -- pending hiring manager review ----------

    print("\n" + "=" * 70)
    print("Step 7: Oversight hold -- pending hiring manager review")
    print("=" * 70)

    approval_deadline = format_timestamp(
        datetime.now(timezone.utc) + timedelta(hours=4)
    )

    env_7 = create_pending_approval(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_5["id"],
        payload_type="arsiaprotocol.oversight/pending",
        args={
            "action_id": "org.hiringco.decision.prepare",
            "original_request_id": signed_5["id"],
            "approval_deadline": approval_deadline,
            "approver_capability": "arsiaprotocol.oversight.approve",
            "context": (
                "AI-screened shortlist of 10 candidates for senior-engineer role. "
                "Bias audit PASSED after 2 iterations (gender 0.83, age 0.83, "
                "nationality 0.89). Hiring manager review required."
            ),
            "risk_level": 9,
        },
        expires_in_seconds=14400,
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        },
    )

    env_7 = apply_profile(env_7)
    signed_7 = sign_message(env_7, priv_a, kid_a)

    assert verify_message(signed_7, pub_a), "Step 7: signature verification failed"

    errors = validate_envelope(signed_7)
    assert not errors, f"Step 7: validation errors: {errors}"

    signed_envelopes.append(signed_7)

    print(f"  Hold ID:       {signed_7['id']}")
    print(f"  Correlation:   {signed_7['correlation_id']}")
    print(f"  Expires at:    {signed_7['expires_at']}")
    print(f"  Intent:        {signed_7['intent']}")
    print(f"  Risk level:    {signed_7['payload']['args']['risk_level']}")
    print("  Awaiting hiring manager review:")
    print(f"    - Shortlist: 10 candidates")
    print(f"    - Audit:     PASS (2 iterations)")
    print(f"    - Ratios:    gender 0.83, age 0.83, nationality 0.89")
    print("  EU AI Act Art. 14: human oversight before employment decision")
    print("  Signed, verified, validated -- hold active")

    # -- Step 8: Oversight approve -- manager decision -------------------

    print("\n" + "=" * 70)
    print("Step 8: Oversight approve -- hiring manager decision")
    print("=" * 70)

    env_8 = create_approval_decision(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_7["id"],
        payload_type="arsiaprotocol.oversight/decision",
        capabilities=["screening.result"],
        result={
            "decision": "approved",
            "approver_id": "agent:hiringco.hiring-manager-js",
            "reason": (
                "Bias audit passed with adequate margins (all ratios > 0.80). "
                "Iterative correction demonstrates due diligence under Art. 9. "
                "Shortlist composition appears balanced. Approved for structured "
                "interview scheduling."
            ),
            "conditions": [
                "Schedule interviews within 10 business days",
                "Maintain anonymization until interview stage",
                "Record interview panel composition for Art. 26(6) compliance",
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        },
    )

    env_8 = apply_profile(env_8)
    signed_8 = sign_message(env_8, priv_a, kid_a)

    assert verify_message(signed_8, pub_a), "Step 8: signature verification failed"

    errors = validate_envelope(signed_8)
    assert not errors, f"Step 8: validation errors: {errors}"

    signed_envelopes.append(signed_8)

    decision_result = signed_8["payload"]["result"]
    print(f"  Decision:      {decision_result['decision']}")
    print(f"  Approver:      {decision_result['approver_id']}")
    print(f"  Reason:        {decision_result['reason'][:70]}...")
    print(f"  Conditions:    {decision_result['conditions']}")
    print("  EU AI Act Art. 14: human oversight completed")
    print("  Signed, verified, validated -- shortlist approved for interviews")

    # -- Step 9: Capability denial #1 -- B requests screening.score ------

    print("\n" + "=" * 70)
    print("Step 9: Capability denial #1 -- B requests screening.score")
    print("=" * 70)

    requested_caps_b = ["screening.score"]
    can_access_b = match_capabilities(scope_b, requested_caps_b)
    missing_b = find_unsatisfied_capabilities(scope_b, requested_caps_b)

    print(f"  Agent B scope:     {scope_b}")
    print(f"  Requested:         {requested_caps_b}")
    print(f"  match_capabilities -> {can_access_b}")
    print(f"  Missing:           {missing_b}")

    assert not can_access_b, "Step 9: Agent B should NOT have screening.score"
    assert missing_b == ["screening.score"], f"Step 9: unexpected missing: {missing_b}"

    env_9 = build_forbidden_error(
        from_agent=agent_a,
        to_agent=agent_b,
        correlation_id=signed_1["id"],
        required_capabilities=["screening.score"],
        provided_capabilities=scope_b,
    )

    signed_9 = sign_message(env_9, priv_a, kid_a)
    assert verify_message(signed_9, pub_a), "Step 9: signature verification failed"

    signed_envelopes.append(signed_9)

    error_obj_9 = signed_9["payload"]["error"]
    print(f"  Error code:    {error_obj_9['code']}")
    print(f"  Description:   {error_obj_9['description']}")
    print(f"  Required:      {error_obj_9['details']['required_capabilities']}")
    print(f"  Provided:      {error_obj_9['details']['provided_capabilities']}")
    print("  B cannot see scoring criteria or weights. 403 Forbidden.")
    print("  Separation of concerns: auditor audits, not scores")

    # -- Step 10: Capability denial #2 -- C requests bias.audit ----------

    print("\n" + "=" * 70)
    print("Step 10: Capability denial #2 -- C requests bias.audit")
    print("=" * 70)

    requested_caps_c = ["bias.audit"]
    can_access_c = match_capabilities(scope_c, requested_caps_c)
    missing_c = find_unsatisfied_capabilities(scope_c, requested_caps_c)

    print(f"  Agent C scope:     {scope_c}")
    print(f"  Requested:         {requested_caps_c}")
    print(f"  match_capabilities -> {can_access_c}")
    print(f"  Missing:           {missing_c}")

    assert not can_access_c, "Step 10: Agent C should NOT have bias.audit"
    assert missing_c == ["bias.audit"], f"Step 10: unexpected missing: {missing_c}"

    env_10 = build_forbidden_error(
        from_agent=agent_a,
        to_agent=agent_c,
        correlation_id=signed_5["id"],
        required_capabilities=["bias.audit"],
        provided_capabilities=scope_c,
    )

    signed_10 = sign_message(env_10, priv_a, kid_a)
    assert verify_message(signed_10, pub_a), "Step 10: signature verification failed"

    signed_envelopes.append(signed_10)

    error_obj_10 = signed_10["payload"]["error"]
    print(f"  Error code:    {error_obj_10['code']}")
    print(f"  Description:   {error_obj_10['description']}")
    print(f"  Required:      {error_obj_10['details']['required_capabilities']}")
    print(f"  Provided:      {error_obj_10['details']['provided_capabilities']}")
    print("  C cannot see protected group data or bias metrics. 403 Forbidden.")
    print("  Data isolation: packager never sees what auditor sees")

    # -- Step 11: Audit trail -- 10 records, 180-day retention -----------

    print("\n" + "=" * 70)
    print("Step 11: Audit trail -- 10 records, 180-day retention")
    print("=" * 70)

    operator_id = "org:hiringco-talent-acquisition"

    audit_entries = [
        ("A->B iter1 request",  signed_envelopes[0], "request"),
        ("B->A iter1 FAIL",     signed_envelopes[1], "response"),
        ("A->B iter2 request",  signed_envelopes[2], "request"),
        ("B->A iter2 PASS",     signed_envelopes[3], "response"),
        ("A->C shortlist",      signed_envelopes[4], "request"),
        ("C->A package",        signed_envelopes[5], "response"),
        ("Oversight hold",      signed_envelopes[6], "pending_approval"),
        ("Oversight approve",   signed_envelopes[7], "approval_decision"),
        ("403 B->score",        signed_envelopes[8], "error"),
        ("403 C->audit",        signed_envelopes[9], "error"),
    ]

    records = []
    for label, env, event_type in audit_entries:
        record = build_audit_record(
            env,
            event_type=event_type,
            operator_id=operator_id,
            effective_retention_days=eu_ai_retention,
        )
        records.append((label, record))

    eff_ret = get_effective_retention(signed_envelopes[0])

    print(f"  {'Label':<22} {'Event Type':<20} {'Retention':<10} {'From -> To'}")
    print(f"  {'-' * 22} {'-' * 20} {'-' * 10} {'-' * 50}")
    for label, record in records:
        print(
            f"  {label:<22} {record.event_type:<20} "
            f"{eu_ai_retention:>4} days  "
            f"{record.from_agent} -> {record.to_agent}"
        )

    payload_hash = compute_payload_hash(signed_envelopes[0]["payload"])

    print(f"\n  Total records:       {len(records)}")
    print(f"  Operator:            {operator_id}")
    print(f"  Retention:           {eu_ai_retention} days (all envelopes)")
    print(f"  Effective (profile): {eff_ret} days")
    print(f"  Sample hash:         {payload_hash[:32]}...")
    print()
    print("  Regulatory basis for 180-day retention:")
    print("    - EU AI Act Art. 9:  risk management system records")
    print("    - EU AI Act Art. 10: data governance (bias audit trail)")
    print("    - EU AI Act Art. 13: transparency (explanation records)")
    print("    - EU AI Act Art. 14: human oversight (approval records)")
    print("    - EU AI Act Art. 26(6): deployer obligation to retain logs")
    print("    - Directive 2006/54/EC: equal treatment evidence preservation")

    # -- Summary ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("Pipeline complete")
    print("=" * 70)
    print(f"  Envelopes created: {len(signed_envelopes)}")
    print(f"  Audit records:     {len(records)}")
    print(f"  Bias iterations:   2 (FAIL -> weight adjustment -> PASS)")
    print("  All signatures verified")
    print("  All validations passed")
    print("  EU-AI-ACT-HIGH-RISK compliance enforced on all envelopes")
    print("  Disparate impact detected and corrected before human review")
    print("  Data isolation maintained:")
    print("    - B never sees CV content or scoring criteria")
    print("    - C never sees protected group data or bias metrics")
    print("    - Hiring manager sees only audited, anonymized shortlist")
    print("  EU AI Act Art. 9:  risk management (iterative bias correction)")
    print("  EU AI Act Art. 10: data governance (protected group isolation)")
    print("  EU AI Act Art. 13: transparency (explainability on all responses)")
    print("  EU AI Act Art. 14: human oversight (manager approval)")


if __name__ == "__main__":
    main()
