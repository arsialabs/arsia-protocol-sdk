# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent A — Client Advisor (pipeline orchestrator).

Orchestrates the 7-step MiFID-II trade pipeline:
1. Receive client request
2. Send risk profile to Agent B (no client PII)
3. Receive suitability assessment from Agent B
4. Create pending_approval for human oversight — STOP
5. On approval: send trade to Agent C (no identity, no risk data)
6. Receive execution report from Agent C
7. Complete audit trail

Holds full client context; enforces data isolation by constructing
envelopes that exclude unauthorized fields for each peer agent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arsia_protocol import (
    apply_profile,
    build_forbidden_error,
    build_oversight_denied_error,
    build_oversight_expired_error,
    create_approval_decision,
    create_pending_approval,
    create_request,
    create_response,
    format_timestamp,
    is_approval_expired,
    sign_message,
    validate_correlation,
    validate_explainability,
)

from audit_store import AuditStore
from config import load_agent_config
from flow_state import FlowState, PipelineStatus
from keys import KeyStore, exchange_keys
from transport import send_envelope

logger = logging.getLogger(__name__)

cfg = load_agent_config("AGENT_A", {
    "id": "agent:acme.advisor",
    "port": "8001",
    "ollama_url": "http://localhost:11434",
    "ollama_model": "gemma4:e2b",
    "capabilities": "client.profile,trade.request",
})

key_store = KeyStore(cfg.agent_id)
client_portal_keys = KeyStore("agent:acme.client-portal")
compliance_officer_keys = KeyStore("agent:acme.compliance-officer")
audit_store = AuditStore()
flow = FlowState()

PEER_B_URL = ""
PEER_C_URL = ""
AGENT_B_ID = ""
AGENT_C_ID = ""

_pipeline_state: dict[str, Any] = {
    "client_data": None,
    "risk_request_env": None,
    "risk_response_env": None,
    "pending_approval_env": None,
    "trade_request_env": None,
    "trade_response_env": None,
    "original_request_id": None,
}


def _reset_pipeline_state() -> None:
    for k in _pipeline_state:
        _pipeline_state[k] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global PEER_B_URL, PEER_C_URL, AGENT_B_ID, AGENT_C_ID

    key_store.generate()
    client_portal_keys.generate()
    compliance_officer_keys.generate()

    AGENT_B_ID = os.environ.get("AGENT_B_ID", "agent:acme.risk-assessor")
    AGENT_C_ID = os.environ.get("AGENT_C_ID", "agent:acme.trade-executor")
    PEER_B_URL = os.environ.get("PEER_B_URL", f"http://localhost:{os.environ.get('AGENT_B_PORT', '8002')}")
    PEER_C_URL = os.environ.get("PEER_C_URL", f"http://localhost:{os.environ.get('AGENT_C_PORT', '8003')}")

    task = asyncio.create_task(exchange_keys(key_store, {
        AGENT_B_ID: PEER_B_URL,
        AGENT_C_ID: PEER_C_URL,
    }))

    logger.info("Agent A (Client Advisor) ready — %s on port %s", cfg.agent_id, cfg.port)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Agent A — Client Advisor", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/keys")
async def get_keys():
    return key_store.jwks


@app.get("/health")
async def health():
    return {
        "agent_id": cfg.agent_id,
        "status": "healthy",
        "pipeline_status": flow.status.value,
        "capabilities": cfg.capabilities,
    }


@app.get("/state")
async def get_state():
    return await flow.snapshot()


@app.get("/state/stream")
async def state_stream(request: Request):
    queue = await flow.subscribe()

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    parsed = json.loads(message)
                    yield {
                        "event": parsed.get("event", "update"),
                        "data": json.dumps(parsed.get("data", {})),
                    }
                except asyncio.TimeoutError:
                    yield {"event": "keepalive", "data": "{}"}
        finally:
            await flow.unsubscribe(queue)

    return EventSourceResponse(event_generator())


@app.post("/llm-stream")
async def receive_llm_stream(request: Request):
    """Receive LLM streaming tokens from Agents B/C and broadcast to dashboard."""
    body = await request.json()
    await flow.broadcast_llm_event(body)
    return {"ok": True}


@app.post("/trigger")
async def trigger_pipeline(request: Request, demo_denial: bool = False):
    """Start the trade pipeline.

    Query param ?demo_denial=true triggers the capability denial
    demonstration path (Agent C asked for risk.assess → 403).
    """
    if flow.status not in (PipelineStatus.IDLE, PipelineStatus.COMPLETED, PipelineStatus.ERROR):
        return JSONResponse(
            status_code=409,
            content={"error": f"Pipeline already active (status={flow.status.value})"},
        )

    body = await request.json()
    _reset_pipeline_state()
    await audit_store.clear()

    asyncio.create_task(_run_pipeline(body, demo_denial=demo_denial))

    return {"status": "started", "message": "Pipeline triggered"}


@app.post("/envelope")
async def receive_envelope(request: Request):
    """Receive approval decisions from the dashboard."""
    body = await request.json()

    intent = body.get("intent", "")
    if intent != "approval_decision":
        return JSONResponse(
            status_code=400,
            content={"error": f"Agent A /envelope expects approval_decision, got {intent}"},
        )

    if flow.status != PipelineStatus.AWAITING_APPROVAL:
        return JSONResponse(
            status_code=409,
            content={"error": f"Not awaiting approval (status={flow.status.value})"},
        )

    asyncio.create_task(_handle_approval(body))

    return {"status": "received", "message": "Approval decision processing"}


@app.post("/reset")
async def reset_pipeline():
    _reset_pipeline_state()
    await audit_store.clear()
    await flow.reset()
    return {"status": "reset"}


@app.get("/audit")
async def get_audit():
    records = await audit_store.list_all()
    return {"records": [r.model_dump() for r in records]}


async def _run_pipeline(client_request: dict[str, Any], *, demo_denial: bool = False) -> None:
    """Execute steps 1-4 of the pipeline, then wait for approval."""
    try:
        await flow.start()

        # ── Step 1: Record client request ──────────────────────
        _pipeline_state["client_data"] = client_request
        client_ref = client_request.get("client_ref", "CLT-UNKNOWN")

        client_record_env = create_request(
            from_agent="agent:acme.client-portal",
            to_agent=cfg.agent_id,
            payload_type="org.arsiaprotocol.finance/client-request",
            capabilities=["client.profile"],
            args=client_request,
            compliance={"profile": "MIFID-II"},
        )
        profiled = apply_profile(client_record_env)
        signed_client = sign_message(profiled, client_portal_keys.private_key, client_portal_keys.kid)
        _pipeline_state["original_request_id"] = signed_client["id"]

        await audit_store.add_from_envelope(signed_client, event_type="request")
        await flow.advance(1, signed_client)
        logger.info("Step 1 complete: client request recorded (ref=%s)", client_ref)

        # ── Step 2: Send risk profile to Agent B ───────────────
        risk_request = create_request(
            from_agent=cfg.agent_id,
            to_agent=AGENT_B_ID,
            payload_type="org.arsiaprotocol.finance/assess-suitability",
            capabilities=["risk.assess"],
            args={
                "client_ref": client_ref,
                "risk_tolerance": client_request.get("risk_tolerance", "moderate"),
                "investment_horizon": client_request.get("investment_horizon", "5-10 years"),
                "current_portfolio": client_request.get("current_portfolio", {}),
                "proposed_trade": client_request.get("proposed_trade", {}),
            },
            compliance={"profile": "MIFID-II"},
        )

        signed_risk_req = sign_message(apply_profile(risk_request), key_store.private_key, key_store.kid)
        await audit_store.add_from_envelope(signed_risk_req, event_type="request")

        risk_response = await send_envelope(risk_request, key_store, PEER_B_URL, timeout=360.0)
        _pipeline_state["risk_request_env"] = signed_risk_req
        _pipeline_state["risk_response_env"] = risk_response
        await flow.advance(2, signed_risk_req)
        logger.info("Step 2 complete: risk request sent to Agent B")

        # ── Step 3: Process suitability response ───────────────
        corr_errors = validate_correlation(signed_risk_req, risk_response)
        if corr_errors:
            logger.warning("Correlation errors with risk response: %s", corr_errors)

        explain_error = validate_explainability(signed_risk_req, risk_response)
        if explain_error:
            logger.warning("Explainability validation: %s", explain_error)

        await audit_store.add_from_envelope(risk_response, event_type="response")
        await flow.advance(3, risk_response)

        suitability = risk_response.get("payload", {}).get("result", {})
        logger.info(
            "Step 3 complete: suitability score=%.2f, classification=%s",
            suitability.get("suitability_score", 0),
            suitability.get("suitability_classification", "unknown"),
        )

        # ── Step 4: Human oversight gate ───────────────────────
        pending_env = create_pending_approval(
            from_agent=cfg.agent_id,
            to_agent="agent:acme.compliance-officer",
            correlation_id=_pipeline_state["original_request_id"],
            payload_type="arsiaprotocol.oversight/pending",
            args={
                "action_id": "org.arsiaprotocol.finance/execute-trade",
                "original_request_id": _pipeline_state["original_request_id"],
                "context": (
                    f"EUR {client_request.get('proposed_trade', {}).get('amount_eur', 200000):,} "
                    f"investment requires compliance officer sign-off. "
                    f"Suitability score: {suitability.get('suitability_score', 'N/A')}. "
                    f"Warnings: {len(suitability.get('warnings', []))}."
                ),
                "suitability_score": suitability.get("suitability_score"),
                "suitability_classification": suitability.get("suitability_classification"),
                "warnings_count": len(suitability.get("warnings", [])),
                "amount_eur": client_request.get("proposed_trade", {}).get("amount_eur", 200000),
                "approver_capability": "arsiaprotocol.oversight.approve",
            },
            expires_in_seconds=3600,
            compliance={"profile": "MIFID-II"},
        )

        profiled_pending = apply_profile(pending_env)
        signed_pending = sign_message(profiled_pending, key_store.private_key, key_store.kid)
        _pipeline_state["pending_approval_env"] = signed_pending

        await audit_store.add_from_envelope(signed_pending, event_type="pending_approval")
        await flow.advance(4, signed_pending)
        await flow.set_pending_approval(signed_pending)

        logger.info("Step 4 complete: awaiting human approval (expires_at=%s)", signed_pending.get("expires_at"))

        if demo_denial:
            await _demo_capability_denial()

    except Exception as exc:
        logger.exception("Pipeline error: %s", exc)
        await flow.set_error(str(exc))


async def _handle_approval(decision_body: dict[str, Any]) -> None:
    """Process an approval decision and continue the pipeline (steps 5-7)."""
    try:
        pending = _pipeline_state.get("pending_approval_env")
        if pending is None:
            await flow.set_error("No pending approval to decide on")
            return

        decision = decision_body.get("decision", "denied")
        approver_id = decision_body.get("approver_id", "agent:acme.compliance-officer")
        reason = decision_body.get("reason", "")

        approval_env = create_approval_decision(
            from_agent=approver_id,
            to_agent=cfg.agent_id,
            correlation_id=pending["id"],
            payload_type="arsiaprotocol.oversight/decision",
            capabilities=["trade.request"],
            result={
                "decision": decision,
                "approver_id": approver_id,
                "reason": reason,
            },
            compliance={"profile": "MIFID-II"},
        )

        profiled_decision = apply_profile(approval_env)
        signed_decision = sign_message(profiled_decision, compliance_officer_keys.private_key, compliance_officer_keys.kid)

        if is_approval_expired(pending.get("expires_at", "")):
            expired_error = build_oversight_expired_error(
                from_agent=cfg.agent_id,
                to_agent="agent:acme.compliance-officer",
                correlation_id=_pipeline_state["original_request_id"],
                deadline=pending.get("expires_at", ""),
            )
            signed_expired = sign_message(expired_error, key_store.private_key, key_store.kid)
            await audit_store.add_from_envelope(signed_expired, event_type="error")
            await flow.set_error("Approval deadline expired")
            return

        await audit_store.add_from_envelope(
            signed_decision,
            event_type="approval_decision",
            oversight_status="approved" if decision == "approved" else "denied",
            approver_id=approver_id,
        )

        if decision != "approved":
            denied_error = build_oversight_denied_error(
                from_agent=approver_id,
                to_agent=cfg.agent_id,
                correlation_id=_pipeline_state["original_request_id"],
                approver_id=approver_id,
                reason=reason or None,
            )
            denied_error["compliance"] = {
                "profile": "MIFID-II",
                "audit_required": True,
                "retention_days": 1827,
            }
            profiled_denied = apply_profile(denied_error)
            signed_denied = sign_message(profiled_denied, compliance_officer_keys.private_key, compliance_officer_keys.kid)
            await audit_store.add_from_envelope(
                signed_denied,
                event_type="error",
                oversight_status="denied",
                approver_id=approver_id,
            )
            await flow.set_approval_decision("denied", signed_decision)
            logger.info("Pipeline denied by %s: %s", approver_id, reason)
            return

        await flow.set_approval_decision("approved", signed_decision)
        logger.info("Approval granted by %s", approver_id)

        # ── Step 5: Send trade to Agent C ──────────────────────
        client_data = _pipeline_state["client_data"]
        proposed = client_data.get("proposed_trade", {})

        trade_request = create_request(
            from_agent=cfg.agent_id,
            to_agent=AGENT_C_ID,
            payload_type="org.arsiaprotocol.finance/execute-trade",
            capabilities=["trade.execute"],
            args={
                "trade_ref": f"TRD-2026-{pending['id'][:8]}",
                "instrument": "UCITS-EU-BLEND-50",
                "amount": proposed.get("amount_eur", 200_000),
                "currency": "EUR",
                "venue": "XETRA",
                "order_type": "limit",
                "limit_price": 50.00,
                "execution_strategy": "TWAP",
                "time_in_force": "day",
            },
            compliance={"profile": "MIFID-II"},
        )

        signed_trade_req = sign_message(apply_profile(trade_request), key_store.private_key, key_store.kid)
        await audit_store.add_from_envelope(signed_trade_req, event_type="request")

        trade_response = await send_envelope(trade_request, key_store, PEER_C_URL, timeout=360.0)
        _pipeline_state["trade_request_env"] = signed_trade_req
        _pipeline_state["trade_response_env"] = trade_response
        await flow.advance(5, signed_trade_req)
        logger.info("Step 5 complete: trade request sent to Agent C")

        # ── Step 6: Process execution report ───────────────────
        corr_errors = validate_correlation(signed_trade_req, trade_response)
        if corr_errors:
            logger.warning("Correlation errors with trade response: %s", corr_errors)

        await audit_store.add_from_envelope(trade_response, event_type="response")
        await flow.advance(6, trade_response)

        exec_result = trade_response.get("payload", {}).get("result", {})
        logger.info(
            "Step 6 complete: %d orders executed, total EUR %s",
            len(exec_result.get("orders", [])),
            exec_result.get("total_amount", "?"),
        )

        # ── Step 7: Audit trail complete ───────────────────────
        audit_count = await audit_store.count()
        await flow.advance(7)
        await flow.complete()

        logger.info("Step 7 complete: pipeline finished with %d audit records", audit_count)

    except Exception as exc:
        logger.exception("Pipeline error during approval handling: %s", exc)
        await flow.set_error(str(exc))


async def _demo_capability_denial() -> None:
    """Demonstrate capability denial: ask Agent C for risk.assess."""
    logger.info("Demo: triggering capability denial (Agent C asked for risk.assess)")

    denial_request = create_request(
        from_agent=cfg.agent_id,
        to_agent=AGENT_C_ID,
        payload_type="org.arsiaprotocol.finance/assess-suitability",
        capabilities=["risk.assess"],
        args={"demo": True, "note": "This request will be denied — Agent C lacks risk.assess"},
        compliance={"profile": "MIFID-II"},
    )

    try:
        response = await send_envelope(denial_request, key_store, PEER_C_URL, timeout=360.0)
        logger.info("Capability denial response: intent=%s", response.get("intent"))
    except Exception as exc:
        logger.info("Capability denial triggered expected error: %s", exc)
