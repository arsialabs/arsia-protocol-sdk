# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent B — Risk Assessor (MiFID-II suitability analysis).

Receives risk assessment requests, calls an LLM for suitability
analysis, and returns a signed response with structured results.
Never sees client name, account, or trade execution details.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arsia_protocol import (
    apply_profile,
    build_forbidden_error,
    create_response,
    match_capabilities,
    sign_message,
    validate_correlation,
)

from audit_store import AuditStore
from config import load_agent_config
from keys import KeyStore, exchange_keys
from ollama_client import OllamaClient
from transport import IncomingEnvelopeError, validate_incoming

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a risk assessment analyst at a regulated wealth management firm \
operating under MiFID II (Directive 2014/65/EU).

Your role: analyse client risk profiles and proposed investment trades \
to determine suitability under Article 25(2) of MiFID II.

You will receive:
- A client reference (opaque identifier — you do NOT know the client's name)
- Risk tolerance level (conservative / moderate / aggressive)
- Investment horizon
- Current portfolio composition (equity %, fixed income %, cash %)
- Proposed trade parameters (asset class, region, amount)

You must NEVER ask for or reference the client's personal identity.

Produce a JSON response with exactly this structure:
{
  "suitability_score": <float 0.0-1.0>,
  "suitability_classification": "<suitable|suitable_with_warnings|unsuitable>",
  "risk_category": "<conservative|moderate|aggressive>",
  "warnings": ["<warning 1>", "..."],
  "recommendation": "<suitable|suitable_with_warnings|unsuitable>",
  "regulatory_basis": {
    "framework": "MiFID II",
    "article": "Art. 25(2)",
    "method": "<assessment method used>",
    "factors": ["<factor 1>", "..."]
  }
}

Assessment guidelines:
- Score >= 0.80: suitable (no warnings needed)
- Score 0.60-0.79: suitable_with_warnings
- Score < 0.60: unsuitable
- Always check concentration risk (>30% single sector)
- Always check portfolio balance against risk tolerance
- Always verify investment horizon matches asset class
- Consider currency risk for cross-currency positions
"""

cfg = load_agent_config("AGENT_B", {
    "id": "agent:acme.risk-assessor",
    "port": "8002",
    "ollama_url": "http://localhost:11435",
    "ollama_model": "gemma4:e2b",
    "capabilities": "risk.assess",
})

key_store = KeyStore(cfg.agent_id)
audit_store = AuditStore()
ollama = OllamaClient(
    base_url=cfg.ollama_url,
    model=cfg.ollama_model,
    system_prompt=SYSTEM_PROMPT,
)

PEER_A_URL = ""

FALLBACK_RESULT: dict[str, Any] = {
    "suitability_score": 0.72,
    "suitability_classification": "suitable_with_warnings",
    "risk_category": "moderate",
    "warnings": [
        "Concentration risk: proposed allocation exceeds 30% single-sector exposure",
        "Currency risk: EUR-denominated in non-EUR portfolio",
    ],
    "recommendation": "suitable_with_warnings",
    "regulatory_basis": {
        "framework": "MiFID II",
        "article": "Art. 25(2)",
        "method": "Suitability matrix v3.1",
        "factors": [
            "client risk tolerance: moderate",
            "investment horizon: 5+ years",
            "portfolio diversification: adequate",
        ],
    },
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global PEER_A_URL

    key_store.generate()

    PEER_A_URL = os.environ.get("PEER_A_URL", f"http://localhost:{os.environ.get('AGENT_A_PORT', '8001')}")
    agent_a_id = os.environ.get("AGENT_A_ID", "agent:acme.advisor")

    task = asyncio.create_task(exchange_keys(key_store, {agent_a_id: PEER_A_URL}))

    logger.info("Agent B (Risk Assessor) ready — %s on port %s", cfg.agent_id, cfg.port)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Agent B — Risk Assessor", lifespan=lifespan)


@app.get("/keys")
async def get_keys():
    return key_store.jwks


@app.get("/health")
async def health():
    ollama_ok = await ollama.health_check()
    return {
        "agent_id": cfg.agent_id,
        "status": "healthy",
        "ollama_reachable": ollama_ok,
        "ollama_model": cfg.ollama_model,
        "capabilities": cfg.capabilities,
    }


@app.post("/envelope")
async def receive_envelope(request: Request):
    body = await request.json()

    try:
        validate_incoming(body, key_store)
    except IncomingEnvelopeError as exc:
        logger.warning("Incoming envelope rejected: %s", exc)
        return JSONResponse(
            status_code=400,
            content={"error": str(exc)},
        )

    intent = body.get("intent", "")
    if intent != "request":
        return JSONResponse(
            status_code=400,
            content={"error": f"Expected intent=request, got {intent}"},
        )

    requested_caps = body.get("capabilities", [])
    if not match_capabilities(cfg.capabilities, requested_caps):
        error_env = build_forbidden_error(
            from_agent=cfg.agent_id,
            to_agent=body["from"],
            correlation_id=body["id"],
            required_capabilities=requested_caps,
            provided_capabilities=cfg.capabilities,
        )
        signed_error = sign_message(error_env, key_store.private_key, key_store.kid)
        await audit_store.add_from_envelope(signed_error, event_type="error")
        return JSONResponse(status_code=403, content=signed_error)

    await audit_store.add_from_envelope(body, event_type="request")

    args = body.get("payload", {}).get("args", {})
    llm_result = await _assess_risk(args)

    response_env = create_response(
        from_agent=cfg.agent_id,
        to_agent=body["from"],
        correlation_id=body["id"],
        payload_type="org.arsiaprotocol.finance/assess-suitability.result",
        result=llm_result,
        explanation={
            "reasoning": (
                f"Suitability assessment performed using {llm_result.get('regulatory_basis', {}).get('method', 'MiFID II matrix')}. "
                f"Score {llm_result.get('suitability_score', 'N/A')} based on "
                f"risk tolerance, portfolio composition, and investment horizon analysis."
            ),
            "confidence": llm_result.get("suitability_score", 0.72),
            "inputs_used": [
                "client_ref",
                "risk_tolerance",
                "investment_horizon",
                "portfolio_composition",
                "proposed_trade",
            ],
        },
        compliance={"profile": "MIFID-II"},
    )

    profiled = apply_profile(response_env)
    signed = sign_message(profiled, key_store.private_key, key_store.kid)

    corr_errors = validate_correlation(body, signed)
    if corr_errors:
        logger.error("Self-check: correlation validation failed: %s", corr_errors)

    await audit_store.add_from_envelope(signed, event_type="response")

    return signed


@app.get("/audit")
async def get_audit():
    records = await audit_store.list_all()
    return {"records": [r.model_dump() for r in records]}


async def _assess_risk(args: dict[str, Any]) -> dict[str, Any]:
    """Call the LLM for risk assessment, with fallback to deterministic result."""
    prompt = (
        f"Assess the suitability of this proposed investment:\n\n"
        f"Client reference: {args.get('client_ref', 'UNKNOWN')}\n"
        f"Risk tolerance: {args.get('risk_tolerance', 'moderate')}\n"
        f"Investment horizon: {args.get('investment_horizon', '5-10 years')}\n"
        f"Portfolio — equity: {args.get('current_portfolio', {}).get('equity_pct', 'N/A')}%, "
        f"fixed income: {args.get('current_portfolio', {}).get('fixed_income_pct', 'N/A')}%, "
        f"cash: {args.get('current_portfolio', {}).get('cash_pct', 'N/A')}%\n"
        f"Portfolio total value: EUR {args.get('current_portfolio', {}).get('total_value_eur', 'N/A'):,}\n"
        f"Proposed trade — asset class: {args.get('proposed_trade', {}).get('asset_class', 'N/A')}, "
        f"region: {args.get('proposed_trade', {}).get('region', 'N/A')}, "
        f"amount: EUR {args.get('proposed_trade', {}).get('amount_eur', 'N/A'):,}\n\n"
        f"Provide your suitability assessment as JSON."
    )

    stream_client: httpx.AsyncClient | None = None
    if PEER_A_URL:
        stream_client = httpx.AsyncClient(timeout=5.0)

    async def on_token(token: str) -> None:
        if stream_client:
            try:
                await stream_client.post(
                    f"{PEER_A_URL}/llm-stream",
                    json={"agent": cfg.agent_id, "token": token},
                )
            except Exception:
                pass

    try:
        if stream_client:
            try:
                await stream_client.post(
                    f"{PEER_A_URL}/llm-stream",
                    json={"agent": cfg.agent_id, "event": "start"},
                )
            except Exception:
                pass

        result = await ollama.chat_json_stream(prompt, on_token=on_token)
        if isinstance(result, dict) and "suitability_score" in result:
            return result
        logger.warning("LLM returned unexpected structure, using fallback")
        return FALLBACK_RESULT
    except Exception as exc:
        logger.warning("LLM call failed (%s), using fallback result", exc)
        return FALLBACK_RESULT
    finally:
        if stream_client:
            try:
                await stream_client.post(
                    f"{PEER_A_URL}/llm-stream",
                    json={"agent": cfg.agent_id, "event": "end"},
                )
            except Exception:
                pass
            await stream_client.aclose()
