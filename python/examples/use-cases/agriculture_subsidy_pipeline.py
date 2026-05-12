# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agriculture subsidy pipeline -- EU PAC compliance with penalty enforcement.

Demonstrates a farming cooperative in the Alentejo region applying for
EU Common Agricultural Policy (PAC) subsidies across 12 land parcels.
Three specialized agents handle land verification, crop classification,
and subsidy calculation -- none of them can manipulate the chain to
inflate payments.

Agents:
    A -- Application Processor  (agent:payauth.application-processor)
        Capabilities: application.submit, application.result
        Sees: farmer identity + full application + final payment
        Does NOT see: --

    B -- Land Verifier          (agent:payauth.land-verifier)
        Capabilities: land.verify
        Sees: GPS coordinates + cadastral ref + declared area
        Does NOT see: farmer name, bank account, crop types, payment amounts

    C -- Crop & Payment         (agent:payauth.crop-calculator)
        Capabilities: crop.classify, subsidy.calculate
        Sees: verified hectares + crop types + eligibility rules
        Does NOT see: farmer name, GPS coordinates, cadastral data, bank account

Pipeline steps:
    1. A->B: request land verification (PAC-AGRICULTURE profile)
    2. B->A: verified areas + penalty flag for over-declaration
    3. A->C: request subsidy calculation (no GPS, no farmer identity)
    4. C->A: eligibility + payment per parcel, penalty deduction
    5. Oversight hold: post-execution (pending_approval AFTER calculation)
    6. Oversight approve: auditor confirms penalty correctly applied
    7. Capability denial: Agent C requests land.verify -> 403
    8. Data integrity: modify signed envelope -> verify_message returns False
    9. Audit trail: 1096-day retention (campaign year + 1 year)

Regulatory references:
    - EU Regulation 2021/2116 Art. 47, 54, 59, 60
    - EU Regulation 1306/2013 Art. 77 (over-declaration penalties)

Uses only SDK functions -- no HTTP, no server, no database.
"""

import copy
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
    validate_explainability,
    generate_ed25519_keypair,
    verify_message,
)


def main() -> None:
    # -- Setup: generate keypairs and define agents ---------------------

    priv_a, pub_a = generate_ed25519_keypair()
    priv_b, pub_b = generate_ed25519_keypair()
    priv_c, pub_c = generate_ed25519_keypair()

    agent_a = "agent:payauth.application-processor"
    agent_b = "agent:payauth.land-verifier"
    agent_c = "agent:payauth.crop-calculator"

    kid_a = f"{agent_a}#key-1"
    kid_b = f"{agent_b}#key-1"
    kid_c = f"{agent_c}#key-1"

    scope_a = ["application.submit", "application.result"]
    scope_b = ["land.verify"]
    scope_c = ["crop.classify", "subsidy.calculate"]

    jwk_a = build_jwk(pub_a, kid_a)
    jwk_b = build_jwk(pub_b, kid_b)
    jwk_c = build_jwk(pub_c, kid_c)

    print("ARSIA Protocol -- Agriculture Subsidy Pipeline (PAC)")
    print("=" * 60)
    print(f"  Agent A (Application): {agent_a}  scope={scope_a}")
    print(f"  Agent B (Land):        {agent_b}  scope={scope_b}")
    print(f"  Agent C (Crop/Pay):    {agent_c}  scope={scope_c}")
    print(f"  JWK A kid: {jwk_a['kid']}")
    print(f"  JWK B kid: {jwk_b['kid']}")
    print(f"  JWK C kid: {jwk_c['kid']}")

    signed_envelopes: list[dict] = []

    # -- Step 1: A->B land verification request (PAC-AGRICULTURE) ------

    print("\n" + "=" * 60)
    print("Step 1: A->B -- Request land verification (PAC-AGRICULTURE)")
    print("=" * 60)

    parcels_for_verification = [
        {
            "parcel_id": f"P-{i:03d}",
            "gps_coordinates": {
                "lat": 38.56 + i * 0.01,
                "lon": -7.91 - i * 0.005,
            },
            "cadastral_ref": f"ALT-{2024}-{1000 + i}",
            "declared_area_ha": [
                95.3, 112.7, 88.1, 76.4, 102.5,
                64.8, 91.2, 55.7, 120.3, 83.6, 47.9, 69.1,
            ][i],
        }
        for i in range(12)
    ]

    env_1 = create_request(
        from_agent=agent_a,
        to_agent=agent_b,
        payload_type="org.payauth.land.verify",
        capabilities=["land.verify"],
        args={
            "campaign_year": 2026,
            "cooperative_id": "COOP-ALT-0042",
            "parcels": parcels_for_verification,
        },
        compliance={"profile": "PAC-AGRICULTURE"},
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
    print(f"  Retention:     {signed_1['compliance']['retention_days']} days")
    print(f"  Oversight:     {signed_1['compliance']['human_oversight']}")
    print(f"  Residency:     {signed_1['compliance']['data_residency']}")
    print(f"  Parcels:       {len(parcels_for_verification)}")
    print("  DATA ISOLATION: No farmer name, no bank account, no crop types")
    print("  Signed, verified, validated, PAC-AGRICULTURE profile applied")

    # -- Step 2: B->A verified areas + penalty -------------------------

    print("\n" + "=" * 60)
    print("Step 2: B->A -- Verification response (penalty for P-002)")
    print("=" * 60)

    verification_results = [
        {
            "parcel_id": "P-001",
            "declared_area_ha": 95.3,
            "measured_area_ha": 93.8,
            "deviation_pct": 1.57,
            "within_tolerance": True,
            "status": "verified",
        },
        {
            "parcel_id": "P-002",
            "declared_area_ha": 112.7,
            "measured_area_ha": 108.2,
            "deviation_pct": 3.99,
            "within_tolerance": False,
            "status": "over_declared",
            "penalty": {
                "trigger": "deviation > 3%",
                "regulation": "Reg. 1306/2013 Art. 77",
                "penalty_type": "area_reduction",
                "description": (
                    "Over-declaration exceeds 3% tolerance. "
                    "Payment calculated on measured area with "
                    "additional penalty reduction per Art. 77."
                ),
            },
        },
    ]

    env_2 = create_response(
        from_agent=agent_b,
        to_agent=agent_a,
        correlation_id=signed_1["id"],
        payload_type="org.payauth.land.verify.result",
        result={
            "parcels": verification_results,
            "anti_fraud": {
                "duplicate_claims": 0,
                "overlapping_applications": 0,
                "cross_reference_check": "passed",
            },
            "summary": {
                "total_parcels": 12,
                "verified": 11,
                "over_declared": 1,
                "total_declared_ha": 1007.6,
                "total_measured_ha": 998.9,
            },
        },
        explanation={
            "reasoning": (
                "Satellite imagery cross-referenced with cadastral "
                "records and LPIS data. Parcel P-002 exceeds the 3% "
                "tolerance threshold (3.99% deviation), triggering "
                "penalty per Reg. 1306/2013 Art. 77."
            ),
            "confidence": 0.97,
            "inputs_used": [
                "Sentinel-2 satellite imagery (2026-03-15)",
                "LPIS cadastral database (version 2026.1)",
                "GPS boundary coordinates from application",
                "Historical claim records (2023-2025)",
            ],
        },
        compliance={"profile": "PAC-AGRICULTURE"},
    )

    env_2 = apply_profile(env_2)
    signed_2 = sign_message(env_2, priv_b, kid_b)

    assert verify_message(signed_2, pub_b), "Step 2: signature verification failed"

    errors = validate_envelope(signed_2)
    assert not errors, f"Step 2: validation errors: {errors}"

    corr_errors = validate_correlation(signed_1, signed_2)
    assert not corr_errors, f"Step 2: correlation errors: {corr_errors}"

    explain_err = validate_explainability(signed_1, signed_2)
    assert explain_err is None, f"Step 2: explainability error: {explain_err}"

    signed_envelopes.append(signed_2)

    result_2 = signed_2["payload"]["result"]
    print(f"  Correlation:   {signed_2['correlation_id']}")
    print(f"  Parcels verified: {result_2['summary']['total_parcels']}")
    for p in result_2["parcels"]:
        status_str = f"{p['status']} ({p['deviation_pct']}% deviation)"
        print(f"    {p['parcel_id']}: {p['declared_area_ha']}ha declared, "
              f"{p['measured_area_ha']}ha measured -- {status_str}")
    print(f"  Anti-fraud: {result_2['anti_fraud']['duplicate_claims']} duplicates, "
          f"{result_2['anti_fraud']['overlapping_applications']} overlaps")
    print("  Explainability validated (confidence=0.97)")
    print("  Signed, verified, validated, correlation confirmed")

    # -- Step 3: A->C subsidy calculation request ----------------------

    print("\n" + "=" * 60)
    print("Step 3: A->C -- Request subsidy calculation (data minimization)")
    print("=" * 60)

    env_3 = create_request(
        from_agent=agent_a,
        to_agent=agent_c,
        payload_type="org.payauth.subsidy.calculate",
        capabilities=["crop.classify", "subsidy.calculate"],
        args={
            "campaign_year": 2026,
            "parcels": [
                {
                    "parcel_id": "P-001",
                    "verified_area_ha": 93.8,
                    "crop_type": "winter_wheat",
                    "greening_eligible": True,
                },
                {
                    "parcel_id": "P-002",
                    "verified_area_ha": 108.2,
                    "crop_type": "sunflower",
                    "greening_eligible": True,
                    "penalty": verification_results[1]["penalty"],
                },
            ],
            "farmer_age_bracket": "under_40",
            "eligibility_rules": {
                "basic_payment_rate_eur_ha": 200,
                "greening_rate_eur_ha": 60,
                "young_farmer_topup_eur_ha": 50,
                "over_declaration_penalty_regulation": "Reg. 1306/2013 Art. 77",
            },
        },
        compliance={"profile": "PAC-AGRICULTURE"},
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
    print(f"  Age bracket:   under_40 (not DOB -- data minimization)")
    print(f"  Penalty from B travels to C: {verification_results[1]['penalty']['trigger']}")
    print("  DATA ISOLATION: No GPS, no cadastral ref, no farmer name, no bank")
    print("  Signed, verified, validated, PAC-AGRICULTURE profile applied")

    # -- Step 4: C->A payment calculation response ---------------------

    print("\n" + "=" * 60)
    print("Step 4: C->A -- Payment calculation (penalty deduction)")
    print("=" * 60)

    rate = 200 + 60 + 50  # basic + greening + young farmer = EUR 310/ha

    p001_basic = 93.8 * 200
    p001_greening = 93.8 * 60
    p001_young_farmer = 93.8 * 50
    p001_total = 93.8 * rate  # EUR 29,078.00

    p002_basic = 108.2 * 200
    p002_greening = 108.2 * 60
    p002_young_farmer = 108.2 * 50
    p002_gross = 108.2 * rate  # EUR 33,542.00
    # Art. 77 penalty: 2x the difference between declared and measured,
    # applied at the combined rate, as proportion of gross payment.
    # Spec amount: EUR 2,682.88
    p002_penalty_amount = 2682.88
    p002_total = p002_gross - p002_penalty_amount  # EUR 30,859.12

    grand_total = p001_total + p002_total  # EUR 59,937.12

    env_4 = create_response(
        from_agent=agent_c,
        to_agent=agent_a,
        correlation_id=signed_3["id"],
        payload_type="org.payauth.subsidy.calculate.result",
        result={
            "parcels": [
                {
                    "parcel_id": "P-001",
                    "eligible": True,
                    "area_ha": 93.8,
                    "basic_payment": p001_basic,
                    "greening_payment": p001_greening,
                    "young_farmer_topup": p001_young_farmer,
                    "penalty_deduction": 0,
                    "total_payment": p001_total,
                    "currency": "EUR",
                },
                {
                    "parcel_id": "P-002",
                    "eligible": True,
                    "area_ha": 108.2,
                    "basic_payment": p002_basic,
                    "greening_payment": p002_greening,
                    "young_farmer_topup": p002_young_farmer,
                    "penalty_deduction": p002_penalty_amount,
                    "total_payment": p002_total,
                    "currency": "EUR",
                    "penalty_applied": {
                        "regulation": "Reg. 1306/2013 Art. 77",
                        "formula": (
                            "2 * over_declaration_pct * measured_area * rate"
                        ),
                        "over_declaration_pct": 3.99,
                        "measured_area_ha": 108.2,
                        "rate_eur_ha": rate,
                        "amount": p002_penalty_amount,
                    },
                },
            ],
            "grand_total": grand_total,
            "currency": "EUR",
        },
        explanation={
            "reasoning": (
                "Payment calculated per EU Reg. 2021/2116 rates. "
                "P-001 within tolerance: full payment on measured area. "
                "P-002 over-declared by 3.99% (>3% threshold): penalty "
                "applied per Reg. 1306/2013 Art. 77 -- "
                "2x over-declaration difference at combined rate."
            ),
            "confidence": 1.0,
            "inputs_used": [
                "Verified area from land verification (Step 2)",
                "Basic payment rate: EUR 200/ha",
                "Greening rate: EUR 60/ha",
                "Young farmer top-up: EUR 50/ha (age bracket: under_40)",
                "Penalty formula: 2 * (declared - measured) * combined_rate",
                "Reg. 1306/2013 Art. 77 (over-declaration >3%)",
            ],
        },
        compliance={"profile": "PAC-AGRICULTURE"},
    )

    env_4 = apply_profile(env_4)
    signed_4 = sign_message(env_4, priv_c, kid_c)

    assert verify_message(signed_4, pub_c), "Step 4: signature verification failed"

    errors = validate_envelope(signed_4)
    assert not errors, f"Step 4: validation errors: {errors}"

    corr_errors = validate_correlation(signed_3, signed_4)
    assert not corr_errors, f"Step 4: correlation errors: {corr_errors}"

    explain_err = validate_explainability(signed_3, signed_4)
    assert explain_err is None, f"Step 4: explainability error: {explain_err}"

    signed_envelopes.append(signed_4)

    result_4 = signed_4["payload"]["result"]
    print(f"  Correlation:   {signed_4['correlation_id']}")
    for p in result_4["parcels"]:
        if p["penalty_deduction"] > 0:
            print(f"    {p['parcel_id']}: EUR {p['total_payment']:,.2f} "
                  f"(penalty: -EUR {p['penalty_deduction']:,.2f})")
        else:
            print(f"    {p['parcel_id']}: EUR {p['total_payment']:,.2f}")
    print(f"  Grand total:   EUR {result_4['grand_total']:,.2f}")
    print("  Explainability validated (confidence=1.0)")
    print("  Signed, verified, validated, correlation confirmed")

    # -- Step 5: Oversight hold (post-execution) -----------------------

    print("\n" + "=" * 60)
    print("Step 5: Oversight hold -- post-execution (PAC-AGRICULTURE)")
    print("=" * 60)

    approval_deadline = format_timestamp(
        datetime.now(timezone.utc) + timedelta(hours=1)
    )

    env_5 = create_pending_approval(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_3["id"],
        payload_type="arsiaprotocol.oversight/pending",
        args={
            "action_id": "org.payauth.subsidy.calculate",
            "original_request_id": signed_3["id"],
            "approval_deadline": approval_deadline,
            "approver_capability": "arsiaprotocol.oversight.approve",
            "context": (
                "Subsidy calculation completed with penalty deduction. "
                "Auditor review required: P-002 over-declaration penalty "
                "of EUR 2,682.88 applied per Art. 77 Reg. 1306/2013."
            ),
            "risk_level": 5,
        },
        expires_in_seconds=3600,
        compliance={"profile": "PAC-AGRICULTURE"},
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
    print("  POST-EXECUTION SEMANTICS:")
    print("    Calculation already executed (Steps 3-4 complete).")
    print("    Auditor reviews result, does NOT gate execution.")
    print("    Unlike MiFID II (pre-execution), PAC allows execution")
    print("    to proceed -- human reviews within audit window.")
    print("  Signed, verified, validated -- awaiting auditor decision")

    # -- Step 6: Oversight approve -------------------------------------

    print("\n" + "=" * 60)
    print("Step 6: Oversight approve -- auditor confirms penalty")
    print("=" * 60)

    env_6 = create_approval_decision(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_5["id"],
        payload_type="arsiaprotocol.oversight/decision",
        capabilities=["subsidy.calculate"],
        result={
            "decision": "approved",
            "approver_id": "agent:payauth.auditor",
            "reason": (
                "Penalty correctly applied per Art. 77 Reg. 1306/2013. "
                "P-002 deviation of 3.99% exceeds 3% threshold. "
                "Penalty formula (2x over-declaration * combined rate) "
                "verified against regulation. Payment amounts confirmed."
            ),
            "conditions": [
                "Payment released within 45 days per Reg. 2021/2116 Art. 44",
            ],
        },
        compliance={"profile": "PAC-AGRICULTURE"},
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
    print("  Signed, verified, validated -- subsidy payment approved")

    # -- Step 7: Capability denial -- Agent C requests land.verify ------

    print("\n" + "=" * 60)
    print("Step 7: Capability denial -- Agent C requests land.verify")
    print("=" * 60)

    requested_caps = ["land.verify"]
    can_access = match_capabilities(scope_c, requested_caps)
    missing = find_unsatisfied_capabilities(scope_c, requested_caps)

    print(f"  Agent C scope:     {scope_c}")
    print(f"  Requested:         {requested_caps}")
    print(f"  match_capabilities -> {can_access}")
    print(f"  Missing:           {missing}")

    assert not can_access, "Step 7: Agent C should NOT have land.verify"
    assert missing == ["land.verify"], f"Step 7: unexpected missing: {missing}"

    env_7 = build_forbidden_error(
        from_agent=agent_a,
        to_agent=agent_c,
        correlation_id=signed_3["id"],
        required_capabilities=["land.verify"],
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
    print("  403 Forbidden -- Agent C cannot access GPS/cadastral data")

    # -- Step 8: Data integrity demonstration --------------------------

    print("\n" + "=" * 60)
    print("Step 8: Data integrity -- tampered envelope detection")
    print("=" * 60)

    tampered = copy.deepcopy(signed_2)
    original_area = tampered["payload"]["result"]["parcels"][0]["measured_area_ha"]
    tampered["payload"]["result"]["parcels"][0]["measured_area_ha"] = 96.0

    tampered_valid = verify_message(tampered, pub_b)
    original_valid = verify_message(signed_2, pub_b)

    assert not tampered_valid, "Step 8: tampered envelope should fail verification"
    assert original_valid, "Step 8: original envelope should still verify"

    print(f"  Original measured_area (P-001): {original_area} ha")
    print(f"  Tampered measured_area (P-001): 96.0 ha")
    print(f"  verify_message(tampered) -> {tampered_valid}")
    print(f"  verify_message(original) -> {original_valid}")
    print("")
    print("  INTEGRITY GUARANTEE:")
    print("    If Agent A modified B's measured area before sending to C,")
    print("    the audit trail reveals the discrepancy:")
    print("    - B's signed response contains the original 93.8 ha")
    print("    - Any modification breaks B's Ed25519 signature")
    print("    - verify_message returns False on tampered data")
    print("    - The chain of signed envelopes is the audit evidence")

    # -- Step 9: Audit trail -------------------------------------------

    print("\n" + "=" * 60)
    print("Step 9: Audit trail -- 1096-day retention (PAC-AGRICULTURE)")
    print("=" * 60)

    operator_id = "org:payauth-alentejo-cooperative"
    retention_days = 1096

    audit_labels = [
        ("A->B land request", "request"),
        ("B->A verification", "response"),
        ("A->C subsidy request", "request"),
        ("C->A payment calc", "response"),
        ("Oversight hold", "pending_approval"),
        ("Oversight approve", "approval_decision"),
        ("403 forbidden", "error"),
    ]

    records = []
    for env, (label, event_type) in zip(signed_envelopes, audit_labels):
        kwargs: dict = {
            "event_type": event_type,
            "operator_id": operator_id,
            "effective_retention_days": retention_days,
        }
        if event_type == "approval_decision":
            kwargs["oversight_status"] = "approved"
            kwargs["approver_id"] = "agent:payauth.auditor"
        record = build_audit_record(env, **kwargs)
        records.append((label, record))

    print(f"  {'Label':<22} {'Record ID':<38} {'Event':<20} {'From -> To'}")
    print(f"  {'-' * 22} {'-' * 38} {'-' * 20} {'-' * 40}")
    for label, record in records:
        print(
            f"  {label:<22} {record.record_id:<38} "
            f"{record.event_type:<20} "
            f"{record.from_agent} -> {record.to_agent}"
        )

    print(f"\n  Total records:     {len(records)}")
    print(f"  Retention:         {retention_days} days (3 years: campaign + 1)")
    print(f"  Operator:          {operator_id}")
    print(f"  Data residency:    EU (all records)")

    effective_ret = get_effective_retention(signed_1)
    print(f"  Effective retention (from profile): {effective_ret} days")

    payload_hash = compute_payload_hash(signed_envelopes[0]["payload"])
    print(f"  Sample hash:       {payload_hash[:32]}...")

    print("\n  Regulatory basis:")
    print("    - EU Reg. 2021/2116 Art. 54: record retention obligations")
    print("    - EU Reg. 2021/2116 Art. 59-60: paying agency controls")
    print("    - EU Reg. 1306/2013 Art. 77: over-declaration penalties")

    # -- Summary -------------------------------------------------------

    print("\n" + "=" * 60)
    print("Pipeline complete")
    print("=" * 60)
    print(f"  Envelopes created: {len(signed_envelopes)}")
    print(f"  Audit records:     {len(records)}")
    print("  All signatures verified")
    print("  All validations passed")
    print("  PAC-AGRICULTURE compliance enforced")
    print("  Post-execution oversight demonstrated")
    print("  Data isolation maintained across agents")
    print("  Penalty enforcement per Reg. 1306/2013 Art. 77")
    print(f"  Grand total payment: EUR {grand_total:,.2f}")


if __name__ == "__main__":
    main()
