# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent C — Trade Executor (order splitting and execution).

Receives trade execution requests, calls an LLM to plan the execution
strategy (applying the EUR 50,000 per-execution monetary limit),
and returns a signed response with the execution report.
Never sees client name, risk profile, or suitability reasoning.
"""

from __future__ import annotations

import asyncio
import logging
import math
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
You are a trade execution engine at a regulated wealth management firm.

Your role: execute investment trades by splitting them into orders \
that comply with the EUR 50,000 per-execution monetary limit.

You will receive:
- A trade reference (opaque identifier)
- Instrument identifier (e.g. UCITS-EU-BLEND-50)
- Total amount in EUR
- Order type (market / limit)
- Venue (e.g. XETRA)
- Settlement terms

You must NEVER ask for or reference:
- The client's personal identity or name
- Risk profiles or suitability assessments
- Why this trade was approved

Rules:
- Each individual order MUST NOT exceed EUR 50,000
- Use TWAP (Time-Weighted Average Price) strategy for splitting
- Space orders at regular intervals (e.g. 5 minutes apart)
- All orders must target the same venue
- Estimate a realistic price per unit

Produce a JSON response with exactly this structure:
{
  "execution_status": "completed",
  "strategy": "TWAP",
  "orders": [
    {
      "order_id": "ORD-2026-0001",
      "instrument": "<instrument>",
      "quantity": <units>,
      "price": <price per unit>,
      "amount": <total for this order, max 50000>,
      "currency": "EUR",
      "venue": "<venue>",
      "status": "filled",
      "fill_time": "<ISO 8601 timestamp>"
    }
  ],
  "total_amount": <sum of all order amounts>,
  "total_units": <sum of all units>,
  "average_price": <weighted average price>,
  "currency": "EUR",
  "venue": "<venue>",
  "settlement_date": "<T+2 business day ISO date>"
}
"""

cfg = load_agent_config("AGENT_C", {
    "id": "agent:acme.trade-executor",
    "port": "8003",
    "ollama_url": "http://localhost:11436",
    "ollama_model": "gemma4:e2b",
    "capabilities": "trade.execute",
})

key_store = KeyStore(cfg.agent_id)
audit_store = AuditStore()
ollama = OllamaClient(
    base_url=cfg.ollama_url,
    model=cfg.ollama_model,
    system_prompt=SYSTEM_PROMPT,
)

PEER_A_URL = ""


def _build_fallback_result(args: dict[str, Any]) -> dict[str, Any]:
    """Deterministic fallback: split into EUR 50K orders."""
    instrument = args.get("instrument", "UCITS-EU-BLEND-50")
    total_amount = args.get("amount", 200_000)
    venue = args.get("venue", "XETRA")
    price_per_unit = args.get("limit_price", 50.00)
    currency = args.get("currency", "EUR")

    num_orders = (total_amount + 49_999) // 50_000
    order_amount = total_amount // num_orders
    units_per_order = int(order_amount / price_per_unit)

    orders = []
    for i in range(num_orders):
        amt = order_amount if i < num_orders - 1 else total_amount - order_amount * (num_orders - 1)
        qty = int(amt / price_per_unit)
        orders.append({
            "order_id": f"ORD-2026-{i + 1:04d}",
            "instrument": instrument,
            "quantity": qty,
            "price": price_per_unit,
            "amount": amt,
            "currency": currency,
            "venue": venue,
            "status": "filled",
            "fill_time": f"2026-05-12T14:{15 + i * 5:02d}:00.000Z",
        })

    return {
        "execution_status": "completed",
        "strategy": "TWAP",
        "orders": orders,
        "total_amount": total_amount,
        "total_units": sum(o["quantity"] for o in orders),
        "average_price": price_per_unit,
        "currency": currency,
        "venue": venue,
        "settlement_date": "2026-05-14",
    }


def _validate_execution(result: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    """Validate and correct LLM execution math. The LLM reasons; the code enforces."""
    total_amount = float(args.get("amount", 200_000))
    limit_price = float(args.get("limit_price", 50.00))
    instrument = args.get("instrument", "UCITS-EU-BLEND-50")
    venue = args.get("venue", "XETRA")
    currency = args.get("currency", "EUR")
    max_per_order = 50_000.0

    num_orders = math.ceil(total_amount / max_per_order)
    llm_orders = result.get("orders", [])
    corrections: list[str] = []

    if len(llm_orders) != num_orders:
        corrections.append(
            f"order count: LLM={len(llm_orders)}, expected={num_orders}"
        )

    price = limit_price
    for o in llm_orders:
        p = o.get("price")
        if isinstance(p, (int, float)) and p > 0:
            price = float(p)
            break

    orders: list[dict[str, Any]] = []
    remaining = total_amount
    for i in range(num_orders):
        order_amount = min(max_per_order, remaining)
        remaining -= order_amount
        quantity = int(order_amount / price)

        llm_order = llm_orders[i] if i < len(llm_orders) else {}

        llm_qty = llm_order.get("quantity")
        llm_amt = llm_order.get("amount")
        if llm_qty is not None and llm_amt is not None:
            if abs(float(llm_qty) * price - float(llm_amt)) > 1.0:
                corrections.append(
                    f"order {i + 1}: qty*price={llm_qty}*{price}="
                    f"{float(llm_qty) * price} != amount={llm_amt}"
                )

        orders.append({
            "order_id": llm_order.get("order_id", f"ORD-2026-{i + 1:04d}"),
            "instrument": instrument,
            "quantity": quantity,
            "price": price,
            "amount": order_amount,
            "currency": currency,
            "venue": venue,
            "status": "filled",
            "fill_time": llm_order.get(
                "fill_time", f"2026-05-12T14:{15 + i * 5:02d}:00.000Z"
            ),
        })

    computed_total = sum(o["amount"] for o in orders)
    computed_units = sum(o["quantity"] for o in orders)
    computed_avg = round(computed_total / computed_units, 2) if computed_units else price

    llm_total = result.get("total_amount")
    if llm_total is not None and abs(float(llm_total) - computed_total) > 0.01:
        corrections.append(f"total_amount: LLM={llm_total}, computed={computed_total}")

    llm_units = result.get("total_units")
    if llm_units is not None and llm_units != computed_units:
        corrections.append(f"total_units: LLM={llm_units}, computed={computed_units}")

    if corrections:
        logger.warning("Math corrections applied: %s", "; ".join(corrections))

    return {
        "execution_status": result.get("execution_status", "completed"),
        "strategy": result.get("strategy", "TWAP"),
        "orders": orders,
        "total_amount": computed_total,
        "total_units": computed_units,
        "average_price": computed_avg,
        "currency": currency,
        "venue": venue,
        "settlement_date": result.get("settlement_date", "2026-05-14"),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    global PEER_A_URL

    key_store.generate()

    PEER_A_URL = os.environ.get("PEER_A_URL", f"http://localhost:{os.environ.get('AGENT_A_PORT', '8001')}")
    agent_a_id = os.environ.get("AGENT_A_ID", "agent:acme.advisor")

    task = asyncio.create_task(exchange_keys(key_store, {agent_a_id: PEER_A_URL}))

    logger.info("Agent C (Trade Executor) ready — %s on port %s", cfg.agent_id, cfg.port)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Agent C — Trade Executor", lifespan=lifespan)


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
    llm_result = await _execute_trade(args)

    response_env = create_response(
        from_agent=cfg.agent_id,
        to_agent=body["from"],
        correlation_id=body["id"],
        payload_type="org.arsiaprotocol.finance/execute-trade.result",
        result=llm_result,
        explanation={
            "reasoning": (
                f"Trade split into {len(llm_result.get('orders', []))} orders "
                f"using {llm_result.get('strategy', 'TWAP')} strategy to comply "
                f"with EUR 50,000 per-execution monetary limit."
            ),
            "confidence": 0.95,
            "inputs_used": [
                "instrument",
                "amount",
                "venue",
                "order_type",
                "limit_price",
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


async def _execute_trade(args: dict[str, Any]) -> dict[str, Any]:
    """Call the LLM for trade execution planning, with fallback."""
    prompt = (
        f"Execute this trade:\n\n"
        f"Trade reference: {args.get('trade_ref', 'TRD-UNKNOWN')}\n"
        f"Instrument: {args.get('instrument', 'UNKNOWN')}\n"
        f"Total amount: EUR {args.get('amount', 0):,}\n"
        f"Order type: {args.get('order_type', 'limit')}\n"
        f"Limit price: EUR {args.get('limit_price', 50.00)}\n"
        f"Venue: {args.get('venue', 'XETRA')}\n"
        f"Currency: {args.get('currency', 'EUR')}\n"
        f"Time in force: {args.get('time_in_force', 'day')}\n\n"
        f"Remember: each order must not exceed EUR 50,000. "
        f"Split the trade accordingly and provide the execution report as JSON."
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
        if isinstance(result, dict) and "orders" in result:
            return _validate_execution(result, args)
        logger.warning("LLM returned unexpected structure, using fallback")
        return _build_fallback_result(args)
    except Exception as exc:
        logger.warning("LLM call failed (%s), using fallback result", exc)
        return _build_fallback_result(args)
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
