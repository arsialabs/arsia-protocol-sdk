# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Healthcare PII pipeline -- clinical lab results with PII isolation.

Demonstrates a clinical research organization processing patient lab
results using three specialized AI agents. Each agent sees only what it
needs -- enforced at the protocol level via ARSIA compliance profiles
and the capability model, not by application logic.

Agents:
    A -- Data Collector   (agent:meddata.data-collector)
        Capabilities: patient.collect, patient.result
        Sees: PII + clinical data + diagnosis
        Does NOT see: --

    B -- Anonymizer       (agent:meddata.anonymizer)
        Capabilities: pii.strip
        Sees: PII + lab values
        Does NOT see: diagnosis

    C -- Clinical Analyzer (agent:meddata.clinical-analyzer)
        Capabilities: analysis.interpret
        Sees: anonymized lab values ONLY
        Does NOT see: patient identity

Pipeline steps:
    1. A->B: patient data with PII (GDPR-STANDARD, legal_basis=consent)
    2. B->A: anonymized data (opaque token + lab values, PII stripped)
    3. A->C: anonymized lab values (EU-AI-ACT-HIGH-RISK, no PII)
    4. C->A: diagnosis with explanation (reasoning, confidence, inputs)
    5. Oversight hold: pending_approval for clinician review
    6. Oversight approve: clinician approves diagnosis
    7. Capability denial: Agent C requests patient.collect -> 403
    8. Negative demo: pii_involved=true without legal_basis -> R2
    9. Audit trail: GDPR 90 days vs EU AI Act 180 days

Regulatory references:
    - GDPR Art. 5(1)(c): data minimization
    - GDPR Art. 6(1)(a): consent as legal basis
    - GDPR Art. 17: right to erasure (retention limits)
    - EU AI Act Art. 13: transparency obligations for high-risk AI
    - EU AI Act Art. 14: human oversight requirements

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
    # -- Setup: generate keypairs and define agents ---------------------

    priv_a, pub_a = generate_ed25519_keypair()
    priv_b, pub_b = generate_ed25519_keypair()
    priv_c, pub_c = generate_ed25519_keypair()

    agent_a = "agent:meddata.data-collector"
    agent_b = "agent:meddata.anonymizer"
    agent_c = "agent:meddata.clinical-analyzer"

    kid_a = f"{agent_a}#key-1"
    kid_b = f"{agent_b}#key-1"
    kid_c = f"{agent_c}#key-1"

    scope_a = ["patient.collect", "patient.result"]
    scope_b = ["pii.strip"]
    scope_c = ["analysis.interpret"]

    jwk_a = build_jwk(pub_a, kid_a)
    jwk_b = build_jwk(pub_b, kid_b)
    jwk_c = build_jwk(pub_c, kid_c)

    print("ARSIA Protocol -- Healthcare PII Pipeline (GDPR + EU AI Act)")
    print("=" * 65)
    print(f"  Agent A (Data Collector):    {agent_a}  scope={scope_a}")
    print(f"  Agent B (Anonymizer):        {agent_b}  scope={scope_b}")
    print(f"  Agent C (Clinical Analyzer): {agent_c}  scope={scope_c}")
    print(f"  JWK A kid: {jwk_a['kid']}")
    print(f"  JWK B kid: {jwk_b['kid']}")
    print(f"  JWK C kid: {jwk_c['kid']}")

    signed_envelopes: list[dict] = []

    # -- Step 1: A->B patient data with PII (GDPR-STANDARD) -----------

    print("\n" + "=" * 65)
    print("Step 1: A->B -- Patient data with PII (GDPR-STANDARD)")
    print("=" * 65)

    env_1 = create_request(
        from_agent=agent_a,
        to_agent=agent_b,
        payload_type="org.meddata.patient.anonymize",
        capabilities=["pii.strip"],
        args={
            "patient_id": "PT-2026-08341",
            "patient_name": "Maria Kovacs",
            "date_of_birth": "1987-03-14",
            "health_number": "HU-TAJ-123456789",
            "lab_results": {
                "test_date": "2026-05-08",
                "panel": "comprehensive_metabolic",
                "values": {
                    "glucose_fasting_mg_dl": 142,
                    "hba1c_percent": 7.1,
                    "creatinine_mg_dl": 1.2,
                    "alt_u_l": 35,
                    "ldl_mg_dl": 145,
                },
            },
        },
        compliance={
            "profile": "GDPR-STANDARD",
            "pii_involved": True,
            "legal_basis": "consent",
            "retention_days": 90,
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
    print(f"  PII present:   name, DOB, health number")
    print(f"  Legal basis:   {signed_1['compliance']['legal_basis']}")
    print(f"  Retention:     {signed_1['compliance']['retention_days']} days")
    print(f"  Audit req'd:   {signed_1['compliance']['audit_required']}")
    print("  GDPR Art. 6(1)(a): legal_basis=consent authorizes PII processing")
    print("  Signed, verified, validated, GDPR-STANDARD profile applied")

    # -- Step 2: B->A anonymized data (PII stripped) -------------------

    print("\n" + "=" * 65)
    print("Step 2: B->A -- Anonymized data (PII stripped)")
    print("=" * 65)

    env_2 = create_response(
        from_agent=agent_b,
        to_agent=agent_a,
        correlation_id=signed_1["id"],
        payload_type="org.meddata.patient.anonymize.result",
        result={
            "anonymized_token": "ANON-b7e4d2f1-9a3c-4e8b-a1d6-5f2c7e8b9d0a",
            "lab_results": {
                "test_date": "2026-05-08",
                "panel": "comprehensive_metabolic",
                "values": {
                    "glucose_fasting_mg_dl": 142,
                    "hba1c_percent": 7.1,
                    "creatinine_mg_dl": 1.2,
                    "alt_u_l": 35,
                    "ldl_mg_dl": 145,
                },
            },
            "pii_fields_removed": [
                "patient_name",
                "date_of_birth",
                "health_number",
            ],
            "anonymization_method": "k-anonymity-5",
        },
        compliance={
            "profile": "GDPR-STANDARD",
            "pii_involved": False,
            "retention_days": 90,
        },
    )

    env_2 = apply_profile(env_2)
    signed_2 = sign_message(env_2, priv_b, kid_b)

    assert verify_message(signed_2, pub_b), "Step 2: signature verification failed"

    errors = validate_envelope(signed_2)
    assert not errors, f"Step 2: validation errors: {errors}"

    corr_errors = validate_correlation(signed_1, signed_2)
    assert not corr_errors, f"Step 2: correlation errors: {corr_errors}"

    signed_envelopes.append(signed_2)

    result_2 = signed_2["payload"]["result"]
    print(f"  Correlation:   {signed_2['correlation_id']}")
    print(f"  Anon token:    {result_2['anonymized_token']}")
    print(f"  PII removed:   {result_2['pii_fields_removed']}")
    print(f"  Method:        {result_2['anonymization_method']}")
    print("  PII stripped. Only opaque token + lab values remain.")
    print("  Signed, verified, validated, correlation confirmed")

    # -- Step 3: A->C anonymized lab values (EU-AI-ACT-HIGH-RISK) ------

    print("\n" + "=" * 65)
    print("Step 3: A->C -- Anonymized lab values (EU-AI-ACT-HIGH-RISK)")
    print("=" * 65)

    env_3 = create_request(
        from_agent=agent_a,
        to_agent=agent_c,
        payload_type="org.meddata.analysis.interpret",
        capabilities=["analysis.interpret"],
        args={
            "anonymized_token": "ANON-b7e4d2f1-9a3c-4e8b-a1d6-5f2c7e8b9d0a",
            "lab_results": {
                "test_date": "2026-05-08",
                "panel": "comprehensive_metabolic",
                "values": {
                    "glucose_fasting_mg_dl": 142,
                    "hba1c_percent": 7.1,
                    "creatinine_mg_dl": 1.2,
                    "alt_u_l": 35,
                    "ldl_mg_dl": 145,
                },
            },
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "pii_involved": False,
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_3 = apply_profile(env_3)
    signed_3 = sign_message(env_3, priv_a, kid_a)

    assert verify_message(signed_3, pub_a), "Step 3: signature verification failed"

    errors = validate_envelope(signed_3)
    assert not errors, f"Step 3: validation errors: {errors}"

    comp_errors = validate_compliance(signed_3)
    assert not comp_errors, f"Step 3: compliance errors: {comp_errors}"

    signed_envelopes.append(signed_3)

    print(f"  Envelope ID:   {signed_3['id']}")
    print(f"  From -> To:    {signed_3['from']} -> {signed_3['to']}")
    print(f"  Profile:       {signed_3['compliance']['profile']}")
    print(f"  PII involved:  {signed_3['compliance']['pii_involved']}")
    print(f"  Classification:{signed_3['compliance']['ai_system_classification']}")
    print(f"  Oversight:     {signed_3['compliance']['human_oversight']}")
    print(f"  Explainability:{signed_3['compliance']['explainability_required']}")
    print(f"  Retention:     {signed_3['compliance']['retention_days']} days")
    print("  ZERO PII in this envelope. Profile switched to EU-AI-ACT-HIGH-RISK.")
    print("  GDPR Art. 5(1)(c): data minimization by design.")
    print("  Signed, verified, validated, EU AI Act profile applied")

    # -- Step 4: C->A diagnosis with explanation -----------------------

    print("\n" + "=" * 65)
    print("Step 4: C->A -- Diagnosis with explanation")
    print("=" * 65)

    env_4 = create_response(
        from_agent=agent_c,
        to_agent=agent_a,
        correlation_id=signed_3["id"],
        payload_type="org.meddata.analysis.interpret.result",
        result={
            "diagnosis": "pre_diabetic_with_dyslipidemia",
            "icd10_codes": ["R73.03", "E78.5"],
            "severity": "moderate",
            "recommendations": [
                "Repeat fasting glucose in 4 weeks",
                "Consider statin therapy for LDL > 130 mg/dL",
                "Dietary counseling referral",
            ],
        },
        explanation={
            "model_version": "MedAnalyzer-v4.2-EU",
            "reasoning": (
                "Fasting glucose 142 mg/dL exceeds 126 mg/dL threshold "
                "(ADA criteria). HbA1c 7.1% confirms sustained hyperglycemia. "
                "LDL 145 mg/dL above treatment target. Creatinine and ALT within "
                "normal range, ruling out hepatic or renal confounders."
            ),
            "confidence": 0.89,
            "inputs_used": [
                "glucose_fasting_mg_dl",
                "hba1c_percent",
                "creatinine_mg_dl",
                "alt_u_l",
                "ldl_mg_dl",
            ],
            "alternatives_considered": [
                {
                    "option": "type_2_diabetes",
                    "reason_rejected": "HbA1c 7.1% is above pre-diabetic range but fasting glucose below 6.5% diagnostic threshold",
                    "confidence": 0.35,
                },
                {
                    "option": "isolated_hyperlipidemia",
                    "reason_rejected": "Glucose also elevated, indicating systemic metabolic dysfunction",
                    "confidence": 0.20,
                },
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "pii_involved": False,
            "human_oversight": "required_before_execution",
            "explainability_required": True,
        },
    )

    env_4 = apply_profile(env_4)
    signed_4 = sign_message(env_4, priv_c, kid_c)

    assert verify_message(signed_4, pub_c), "Step 4: signature verification failed"

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
    explanation = signed_4["payload"]["explanation"]
    print(f"  Correlation:   {signed_4['correlation_id']}")
    print(f"  Diagnosis:     {result_4['diagnosis']}")
    print(f"  ICD-10:        {result_4['icd10_codes']}")
    print(f"  Severity:      {result_4['severity']}")
    print(f"  Model:         {explanation['model_version']}")
    print(f"  Confidence:    {explanation['confidence']}")
    print(f"  Inputs used:   {explanation['inputs_used']}")
    print(f"  Reasoning:     {explanation['reasoning'][:80]}...")
    print("  Explanation satisfies EU AI Act Art. 13 transparency.")
    print("  Signed, verified, validated, correlation + explainability confirmed")

    # -- Step 5: Oversight hold (pending clinician review) --------------

    print("\n" + "=" * 65)
    print("Step 5: Oversight hold -- pending clinician review")
    print("=" * 65)

    approval_deadline = format_timestamp(
        datetime.now(timezone.utc) + timedelta(hours=1)
    )

    env_5 = create_pending_approval(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_3["id"],
        payload_type="arsiaprotocol.oversight/pending",
        args={
            "action_id": "org.meddata.analysis.interpret",
            "original_request_id": signed_3["id"],
            "approval_deadline": approval_deadline,
            "approver_capability": "arsiaprotocol.oversight.approve",
            "context": (
                "AI diagnosis: pre_diabetic_with_dyslipidemia (confidence 0.89). "
                "Clinician review required before results delivered to patient."
            ),
            "risk_level": 8,
        },
        expires_in_seconds=3600,
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        },
    )

    env_5 = apply_profile(env_5)
    signed_5 = sign_message(env_5, priv_a, kid_a)

    assert verify_message(signed_5, pub_a), "Step 5: signature verification failed"

    errors = validate_envelope(signed_5)
    assert not errors, f"Step 5: validation errors: {errors}"

    signed_envelopes.append(signed_5)

    print(f"  Hold ID:       {signed_5['id']}")
    print(f"  Correlation:   {signed_5['correlation_id']}")
    print(f"  Expires at:    {signed_5['expires_at']}")
    print(f"  Intent:        {signed_5['intent']}")
    print(f"  Risk level:    {signed_5['payload']['args']['risk_level']}")
    print("  EU AI Act Art. 14: human oversight before high-risk output delivered.")
    print("  Signed, verified, validated -- awaiting clinician decision")

    # -- Step 6: Oversight approve (clinician decision) ----------------

    print("\n" + "=" * 65)
    print("Step 6: Oversight approve -- clinician decision")
    print("=" * 65)

    env_6 = create_approval_decision(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_5["id"],
        payload_type="arsiaprotocol.oversight/decision",
        capabilities=["patient.result"],
        result={
            "decision": "approved",
            "approver_id": "agent:meddata.dr-chen",
            "reason": (
                "Diagnosis consistent with lab values. HbA1c 7.1% and fasting "
                "glucose 142 mg/dL support pre-diabetic classification. "
                "Approved for patient communication."
            ),
            "conditions": [
                "include dietary counseling referral",
                "schedule follow-up glucose test in 4 weeks",
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
            "human_oversight": "required_before_execution",
        },
    )

    env_6 = apply_profile(env_6)
    signed_6 = sign_message(env_6, priv_a, kid_a)

    assert verify_message(signed_6, pub_a), "Step 6: signature verification failed"

    errors = validate_envelope(signed_6)
    assert not errors, f"Step 6: validation errors: {errors}"

    signed_envelopes.append(signed_6)

    decision_result = signed_6["payload"]["result"]
    print(f"  Decision:      {decision_result['decision']}")
    print(f"  Approver:      {decision_result['approver_id']}")
    print(f"  Reason:        {decision_result['reason'][:80]}...")
    print(f"  Conditions:    {decision_result['conditions']}")
    print("  EU AI Act Art. 14: human oversight before high-risk output delivered.")
    print("  Signed, verified, validated -- diagnosis approved for delivery")

    # -- Step 7: Capability denial -- Agent C requests patient.collect --

    print("\n" + "=" * 65)
    print("Step 7: Capability denial -- Agent C requests patient.collect")
    print("=" * 65)

    requested_caps = ["patient.collect"]
    can_access = match_capabilities(scope_c, requested_caps)
    missing = find_unsatisfied_capabilities(scope_c, requested_caps)

    print(f"  Agent C scope:     {scope_c}")
    print(f"  Requested:         {requested_caps}")
    print(f"  match_capabilities -> {can_access}")
    print(f"  Missing:           {missing}")

    assert not can_access, "Step 7: Agent C should NOT have patient.collect"
    assert missing == ["patient.collect"], f"Step 7: unexpected missing: {missing}"

    env_7 = build_forbidden_error(
        from_agent=agent_a,
        to_agent=agent_c,
        correlation_id=signed_3["id"],
        required_capabilities=["patient.collect"],
        provided_capabilities=scope_c,
    )

    signed_7 = sign_message(env_7, priv_a, kid_a)
    assert verify_message(signed_7, pub_a), "Step 7: signature verification failed"

    signed_envelopes.append(signed_7)

    error_obj = signed_7["payload"]["error"]
    print(f"  Error code:    {error_obj['code']}")
    print(f"  Description:   {error_obj['description']}")
    print(f"  Required:      {error_obj['details']['required_capabilities']}")
    print(f"  Provided:      {error_obj['details']['provided_capabilities']}")
    print("  Agent C has analysis.interpret, not patient.collect. 403 Forbidden.")
    print("  Data isolation enforced by capability model")

    # -- Step 8: Negative demo -- pii_involved=true without legal_basis -

    print("\n" + "=" * 65)
    print("Step 8: Negative demo -- pii_involved=true without legal_basis")
    print("=" * 65)

    env_bad = create_request(
        from_agent=agent_a,
        to_agent=agent_b,
        payload_type="org.meddata.patient.anonymize",
        capabilities=["pii.strip"],
        args={"patient_id": "PT-2026-99999", "patient_name": "Test Patient"},
        compliance={
            "profile": "GDPR-STANDARD",
            "pii_involved": True,
        },
    )

    env_bad = apply_profile(env_bad)

    r2_errors = validate_compliance(env_bad)
    assert len(r2_errors) > 0, "Step 8: expected R2 violation"
    r2 = r2_errors[0]
    assert r2.code == "missing_legal_basis", f"Step 8: unexpected code: {r2.code}"

    print(f"  Envelope PII:  {env_bad['compliance']['pii_involved']}")
    print(f"  Legal basis:   (missing)")
    print(f"  Error code:    {r2.code}")
    print(f"  Error message: {r2.message}")
    print(f"  Spec ref:      {r2.spec_ref}")
    print("  SDK catches missing legal_basis -- R2 violation (Core 4.3.8 Rule 2).")
    print("  GDPR Art. 6: no lawful basis for processing PII")

    # -- Step 9: Audit trail -- GDPR 90d vs EU AI Act 180d -------------

    print("\n" + "=" * 65)
    print("Step 9: Audit trail -- differentiated retention")
    print("=" * 65)

    operator_id = "org:meddata-clinical-research"
    gdpr_retention = 90
    eu_ai_act_retention = 180

    audit_entries = [
        ("A->B PII request",     signed_envelopes[0], "request",           gdpr_retention),
        ("B->A anonymized",      signed_envelopes[1], "response",          gdpr_retention),
        ("A->C analysis req",    signed_envelopes[2], "request",           eu_ai_act_retention),
        ("C->A diagnosis",       signed_envelopes[3], "response",          eu_ai_act_retention),
        ("Oversight hold",       signed_envelopes[4], "pending_approval",  eu_ai_act_retention),
        ("Oversight approve",    signed_envelopes[5], "approval_decision", eu_ai_act_retention),
        ("403 forbidden",        signed_envelopes[6], "error",             gdpr_retention),
    ]

    records = []
    for label, env, event_type, retention in audit_entries:
        record = build_audit_record(
            env,
            event_type=event_type,
            operator_id=operator_id,
            effective_retention_days=retention,
        )
        records.append((label, record, retention))

    eff_ret_gdpr = get_effective_retention(signed_envelopes[0])
    eff_ret_euai = get_effective_retention(signed_envelopes[2])

    print(f"  {'Label':<22} {'Event Type':<20} {'Retention':<12} {'From -> To'}")
    print(f"  {'-' * 22} {'-' * 20} {'-' * 12} {'-' * 45}")
    for label, record, retention in records:
        print(
            f"  {label:<22} {record.event_type:<20} "
            f"{retention:>4} days    "
            f"{record.from_agent} -> {record.to_agent}"
        )

    print(f"\n  Total records:       {len(records)}")
    print(f"  Operator:            {operator_id}")
    print(f"  GDPR retention:      {gdpr_retention} days (Art. 17 right to erasure)")
    print(f"  EU AI Act retention: {eu_ai_act_retention} days (Art. 13 traceability)")
    print(f"  Effective (GDPR):    {eff_ret_gdpr} days")
    print(f"  Effective (EU AI):   {eff_ret_euai} days")

    payload_hash = compute_payload_hash(signed_envelopes[0]["payload"])
    print(f"  Sample hash:         {payload_hash[:32]}...")
    print("  GDPR records: 90 days. EU AI Act records: 180 days.")

    # -- Summary -------------------------------------------------------

    print("\n" + "=" * 65)
    print("Pipeline complete")
    print("=" * 65)
    print(f"  Envelopes created: {len(signed_envelopes)}")
    print(f"  Audit records:     {len(records)}")
    print("  All signatures verified")
    print("  All validations passed")
    print("  GDPR-STANDARD + EU-AI-ACT-HIGH-RISK compliance enforced")
    print("  PII isolation maintained across agents")
    print("  EU AI Act Art. 13 transparency satisfied (explainability)")
    print("  EU AI Act Art. 14 human oversight completed (clinician)")
    print("  Capability model enforced data minimization (403 on patient.collect)")


if __name__ == "__main__":
    main()
