# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Fintech trade pipeline — MiFID II-compliant €200K investment trade.

Demonstrates a wealth management firm processing a client's request to
invest €200,000 using three specialized agents, each with strict data
isolation enforced by the ARSIA Protocol.

Agents:
    A — Client Advisor  (agent:acme.advisor)
        Capabilities: client.profile, trade.request
        Sees: risk profile + final confirmation
        Does NOT see: —

    B — Risk Assessor   (agent:acme.risk-assessor)
        Capabilities: risk.assess
        Sees: risk profile + portfolio
        Does NOT see: client name, account, trade details

    C — Trade Executor  (agent:acme.trade-executor)
        Capabilities: trade.execute
        Sees: instrument + amount + venue
        Does NOT see: client name, risk profile, suitability

Pipeline steps:
    1. A→B: request risk assessment (MiFID II profile applied)
    2. B→A: response with suitability score 0.72
    3. Oversight hold: pending_approval for human review
    4. Oversight approve: compliance officer approves
    5. A→C: trade execution request (data isolation — no PII)
    6. C→A: execution report (4 × €50K orders)
    7. Capability denial: Agent C requests client.profile → 403
    8. Audit trail: build audit records for all envelopes

Uses only SDK functions — no HTTP, no server, no database.
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
    match_capabilities,
    sign_message,
    validate_compliance,
    validate_correlation,
    validate_envelope,
    generate_ed25519_keypair,
    verify_message,
)


def main() -> None:
    # ── Setup: generate keypairs and define agents ──────────────────

    priv_a, pub_a = generate_ed25519_keypair()
    priv_b, pub_b = generate_ed25519_keypair()
    priv_c, pub_c = generate_ed25519_keypair()

    agent_a = "agent:acme.advisor"
    agent_b = "agent:acme.risk-assessor"
    agent_c = "agent:acme.trade-executor"

    kid_a = f"{agent_a}#key-1"
    kid_b = f"{agent_b}#key-1"
    kid_c = f"{agent_c}#key-1"

    scope_a = ["client.profile", "trade.request"]
    scope_b = ["risk.assess"]
    scope_c = ["trade.execute"]

    jwk_a = build_jwk(pub_a, kid_a)
    jwk_b = build_jwk(pub_b, kid_b)
    jwk_c = build_jwk(pub_c, kid_c)

    print("ARSIA Protocol — Fintech Trade Pipeline (MiFID II)")
    print("=" * 60)
    print(f"  Agent A (Advisor):  {agent_a}  scope={scope_a}")
    print(f"  Agent B (Risk):     {agent_b}  scope={scope_b}")
    print(f"  Agent C (Executor): {agent_c}  scope={scope_c}")
    print(f"  JWK A kid: {jwk_a['kid']}")
    print(f"  JWK B kid: {jwk_b['kid']}")
    print(f"  JWK C kid: {jwk_c['kid']}")

    signed_envelopes: list[dict] = []

    # ── Step 1: A→B risk assessment request (MiFID II) ─────────────

    print("\n" + "=" * 60)
    print("Step 1: A→B — Request risk assessment (MiFID II)")
    print("=" * 60)

    env_1 = create_request(
        from_agent=agent_a,
        to_agent=agent_b,
        payload_type="com.acme.risk.assess",
        capabilities=["risk.assess"],
        args={
            "portfolio_id": "PF-2026-0042",
            "investment_amount": 200_000,
            "currency": "EUR",
            "instrument": "UCITS-EU-BLEND-50",
            "client_risk_tolerance": "moderate",
        },
        compliance={"profile": "MIFID-II"},
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
    print(f"  From → To:     {signed_1['from']} → {signed_1['to']}")
    print(f"  Profile:       {signed_1['compliance']['profile']}")
    print(f"  Retention:     {signed_1['compliance']['retention_days']} days")
    print(f"  Oversight:     {signed_1['compliance']['human_oversight']}")
    print(f"  Residency:     {signed_1['compliance']['data_residency']}")
    print(f"  Audit req'd:   {signed_1['compliance']['audit_required']}")
    print("  ✓ Signed, verified, validated, MiFID II profile applied")

    # ── Step 2: B→A suitability response ───────────────────────────

    print("\n" + "=" * 60)
    print("Step 2: B→A — Suitability assessment response")
    print("=" * 60)

    env_2 = create_response(
        from_agent=agent_b,
        to_agent=agent_a,
        correlation_id=signed_1["id"],
        payload_type="com.acme.risk.assess.result",
        result={
            "suitability_score": 0.72,
            "risk_category": "moderate",
            "warnings": [
                "Concentration risk: 40% single-sector exposure",
                "Currency risk: EUR-denominated in non-EUR portfolio",
            ],
            "explanation": {
                "method": "MiFID II suitability matrix v3.1",
                "factors": [
                    "client risk tolerance: moderate",
                    "investment horizon: 5+ years",
                    "portfolio diversification: adequate",
                ],
                "recommendation": "suitable_with_warnings",
            },
        },
        compliance={"profile": "MIFID-II"},
    )

    env_2 = apply_profile(env_2)
    signed_2 = sign_message(env_2, priv_b, kid_b)

    assert verify_message(signed_2, pub_b), "Step 2: signature verification failed"

    errors = validate_envelope(signed_2)
    assert not errors, f"Step 2: validation errors: {errors}"

    corr_errors = validate_correlation(signed_1, signed_2)
    assert not corr_errors, f"Step 2: correlation errors: {corr_errors}"

    signed_envelopes.append(signed_2)

    result = signed_2["payload"]["result"]
    print(f"  Correlation:   {signed_2['correlation_id']}")
    print(f"  Suitability:   {result['suitability_score']}")
    print(f"  Risk category: {result['risk_category']}")
    print(f"  Warnings:      {len(result['warnings'])}")
    for w in result["warnings"]:
        print(f"    - {w}")
    print("  ✓ Signed, verified, validated, correlation confirmed")

    # ── Step 3: Oversight hold (pending human approval) ────────────

    print("\n" + "=" * 60)
    print("Step 3: Oversight hold — pending human approval")
    print("=" * 60)

    approval_deadline = format_timestamp(
        datetime.now(timezone.utc) + timedelta(hours=1)
    )

    env_3 = create_pending_approval(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_1["id"],
        payload_type="arsiaprotocol.oversight/pending",
        args={
            "action_id": "com.acme.trade.execute",
            "original_request_id": signed_1["id"],
            "approval_deadline": approval_deadline,
            "approver_capability": "arsiaprotocol.oversight.approve",
            "context": "EUR 200,000 UCITS investment requires compliance officer sign-off",
            "risk_level": 7,
        },
        expires_in_seconds=3600,
        compliance={"profile": "MIFID-II"},
    )

    env_3 = apply_profile(env_3)
    signed_3 = sign_message(env_3, priv_a, kid_a)

    assert verify_message(signed_3, pub_a), "Step 3: signature verification failed"

    errors = validate_envelope(signed_3)
    assert not errors, f"Step 3: validation errors: {errors}"

    signed_envelopes.append(signed_3)

    print(f"  Hold ID:       {signed_3['id']}")
    print(f"  Correlation:   {signed_3['correlation_id']}")
    print(f"  Expires at:    {signed_3['expires_at']}")
    print(f"  Intent:        {signed_3['intent']}")
    print("  ✓ Signed, verified, validated — awaiting human decision")

    # ── Step 4: Oversight approve ──────────────────────────────────

    print("\n" + "=" * 60)
    print("Step 4: Oversight approve — compliance officer decision")
    print("=" * 60)

    env_4 = create_approval_decision(
        from_agent=agent_a,
        to_agent=agent_a,
        correlation_id=signed_3["id"],
        payload_type="arsiaprotocol.oversight/decision",
        capabilities=["trade.request"],
        result={
            "decision": "approved",
            "approver_id": "agent:acme.compliance-officer",
            "reason": "Suitability score 0.72 meets threshold (0.60). "
            "Concentration warning acknowledged.",
            "conditions": ["execution within 24h", "best-execution venue required"],
        },
        compliance={"profile": "MIFID-II"},
    )

    env_4 = apply_profile(env_4)
    signed_4 = sign_message(env_4, priv_a, kid_a)

    assert verify_message(signed_4, pub_a), "Step 4: signature verification failed"

    errors = validate_envelope(signed_4)
    assert not errors, f"Step 4: validation errors: {errors}"

    signed_envelopes.append(signed_4)

    decision_result = signed_4["payload"]["result"]
    print(f"  Decision:      {decision_result['decision']}")
    print(f"  Approver:      {decision_result['approver_id']}")
    print(f"  Reason:        {decision_result['reason'][:80]}...")
    print(f"  Conditions:    {decision_result['conditions']}")
    print("  ✓ Signed, verified, validated — trade approved")

    # ── Step 5: A→C trade execution request (data isolation) ──────

    print("\n" + "=" * 60)
    print("Step 5: A→C — Trade execution request (data isolation)")
    print("=" * 60)

    env_5 = create_request(
        from_agent=agent_a,
        to_agent=agent_c,
        payload_type="com.acme.trade.execute",
        capabilities=["trade.execute"],
        args={
            "instrument": "UCITS-EU-BLEND-50",
            "amount": 200_000,
            "currency": "EUR",
            "venue": "XETRA",
            "order_type": "limit",
            "limit_price": 50.00,
            "execution_strategy": "TWAP-4",
            "time_in_force": "day",
        },
        compliance={"profile": "MIFID-II"},
    )

    env_5 = apply_profile(env_5)
    signed_5 = sign_message(env_5, priv_a, kid_a)

    assert verify_message(signed_5, pub_a), "Step 5: signature verification failed"

    errors = validate_envelope(signed_5)
    assert not errors, f"Step 5: validation errors: {errors}"

    signed_envelopes.append(signed_5)

    trade_args = signed_5["payload"]["args"]
    print(f"  Envelope ID:   {signed_5['id']}")
    print(f"  From → To:     {signed_5['from']} → {signed_5['to']}")
    print(f"  Instrument:    {trade_args['instrument']}")
    print(f"  Amount:        €{trade_args['amount']:,}")
    print(f"  Venue:         {trade_args['venue']}")
    print(f"  Strategy:      {trade_args['execution_strategy']}")
    print("  ✓ DATA ISOLATION: No client name, no risk profile, no suitability")
    print("  ✓ Signed, verified, validated, MiFID II profile applied")

    # ── Step 6: C→A execution report ──────────────────────────────

    print("\n" + "=" * 60)
    print("Step 6: C→A — Execution report (4 × €50K orders)")
    print("=" * 60)

    orders = [
        {
            "order_id": f"ORD-2026-{i:04d}",
            "instrument": "UCITS-EU-BLEND-50",
            "quantity": 1000,
            "price": 50.00,
            "amount": 50_000,
            "currency": "EUR",
            "venue": "XETRA",
            "status": "filled",
            "fill_time": f"2026-05-10T14:{15 + i * 5:02d}:00.000Z",
        }
        for i in range(4)
    ]

    env_6 = create_response(
        from_agent=agent_c,
        to_agent=agent_a,
        correlation_id=signed_5["id"],
        payload_type="com.acme.trade.execute.result",
        result={
            "execution_status": "completed",
            "orders": orders,
            "total_amount": 200_000,
            "currency": "EUR",
            "average_price": 50.00,
            "venue": "XETRA",
            "strategy_used": "TWAP-4",
        },
        compliance={"profile": "MIFID-II"},
    )

    env_6 = apply_profile(env_6)
    signed_6 = sign_message(env_6, priv_c, kid_c)

    assert verify_message(signed_6, pub_c), "Step 6: signature verification failed"

    errors = validate_envelope(signed_6)
    assert not errors, f"Step 6: validation errors: {errors}"

    corr_errors = validate_correlation(signed_5, signed_6)
    assert not corr_errors, f"Step 6: correlation errors: {corr_errors}"

    signed_envelopes.append(signed_6)

    exec_result = signed_6["payload"]["result"]
    print(f"  Correlation:   {signed_6['correlation_id']}")
    print(f"  Status:        {exec_result['execution_status']}")
    print(f"  Orders:        {len(exec_result['orders'])}")
    for order in exec_result["orders"]:
        print(
            f"    {order['order_id']}: {order['quantity']} units "
            f"@ €{order['price']:.2f} = €{order['amount']:,} [{order['status']}]"
        )
    print(f"  Total:         €{exec_result['total_amount']:,}")
    print("  ✓ Signed, verified, validated, correlation confirmed")

    # ── Step 7: Capability denial — Agent C requests client.profile ─

    print("\n" + "=" * 60)
    print("Step 7: Capability denial — Agent C requests client.profile")
    print("=" * 60)

    requested_caps = ["client.profile"]
    can_access = match_capabilities(scope_c, requested_caps)
    missing = find_unsatisfied_capabilities(scope_c, requested_caps)

    print(f"  Agent C scope:     {scope_c}")
    print(f"  Requested:         {requested_caps}")
    print(f"  match_capabilities → {can_access}")
    print(f"  Missing:           {missing}")

    assert not can_access, "Step 7: Agent C should NOT have client.profile"
    assert missing == ["client.profile"], f"Step 7: unexpected missing: {missing}"

    env_7 = build_forbidden_error(
        from_agent=agent_a,
        to_agent=agent_c,
        correlation_id=signed_5["id"],
        required_capabilities=["client.profile"],
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
    print("  ✓ 403 Forbidden — data isolation enforced by capability model")

    # ── Step 8: Audit trail ────────────────────────────────────────

    print("\n" + "=" * 60)
    print("Step 8: Audit trail — build audit records")
    print("=" * 60)

    operator_id = "org:acme-wealth-management"
    retention_days = 1827

    audit_labels = [
        ("A→B risk request", "request"),
        ("B→A suitability", "response"),
        ("Oversight hold", "pending_approval"),
        ("Oversight approve", "approval_decision"),
        ("A→C trade request", "request"),
        ("C→A execution", "response"),
        ("403 forbidden", "error"),
    ]

    records = []
    for env, (label, event_type) in zip(signed_envelopes, audit_labels):
        record = build_audit_record(
            env,
            event_type=event_type,
            operator_id=operator_id,
            effective_retention_days=retention_days,
        )
        records.append((label, record))

    print(f"  {'Label':<22} {'Record ID':<38} {'Event Type':<20} {'From → To'}")
    print(f"  {'─' * 22} {'─' * 38} {'─' * 20} {'─' * 40}")
    for label, record in records:
        print(
            f"  {label:<22} {record.record_id:<38} "
            f"{record.event_type:<20} "
            f"{record.from_agent} → {record.to_agent}"
        )

    print(f"\n  Total records:     {len(records)}")
    print(f"  Retention:         {retention_days} days (MiFID II: 5 years)")
    print(f"  Operator:          {operator_id}")

    payload_hash = compute_payload_hash(signed_envelopes[0]["payload"])
    print(f"  Sample hash:       {payload_hash[:32]}...")

    # ── Summary ────────────────────────────────────────────────────

    print("\n" + "=" * 60)
    print("Pipeline complete")
    print("=" * 60)
    print(f"  Envelopes created: {len(signed_envelopes)}")
    print(f"  Audit records:     {len(records)}")
    print("  All signatures verified")
    print("  All validations passed")
    print("  MiFID II compliance enforced")
    print("  Data isolation maintained across agents")


if __name__ == "__main__":
    main()
