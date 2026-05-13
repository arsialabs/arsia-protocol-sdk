# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent B — Anonymizer (PII stripping with structural isolation).

Receives patient records containing PII + lab values, strips all
personally identifiable information, generates an opaque anonymization
token, and returns the anonymized dataset. Never sees diagnosis data.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
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
You are a data anonymization agent operating under GDPR Article 9 \
(processing of special categories of personal data — health data).

Your role: receive a patient record containing both personally \
identifiable information (PII) and clinical lab values, strip ALL \
PII fields, and return only the anonymized clinical data.

You will receive a JSON object with:
- patient_name: full name (PII — MUST be stripped)
- date_of_birth: date of birth (PII — MUST be stripped)
- health_number: national health service number (PII — MUST be stripped)
- lab_values: clinical measurements (NOT PII — MUST be preserved)
- Any other fields that may contain PII

PII identification rules:
- Names, dates of birth, health/insurance numbers are ALWAYS PII
- Addresses, phone numbers, email addresses are PII
- Any field that could identify a specific individual is PII
- Lab values (cholesterol, glucose, hemoglobin, etc.) are NOT PII
- Clinical measurements and reference ranges are NOT PII

You must NEVER include any PII in your output.

Produce a JSON response with exactly this structure:
{
  "anonymization_token": "<provided token>",
  "method": "field_redaction",
  "lab_values": {
    <preserved lab values exactly as received>
  },
  "fields_stripped": ["<field_name_1>", "<field_name_2>", ...],
  "pii_leak_check": {
    "passed": true,
    "details": "No PII detected in output"
  }
}

CRITICAL: Double-check your output contains NO patient names, \
dates of birth, or health numbers. The output must be safe to \
send to a clinical analyzer that has no authorization to see PII.\
"""

PII_FIELDS = {"patient_name", "date_of_birth", "health_number"}

cfg = load_agent_config("AGENT_B", {
    "id": "agent:meddata.anonymizer",
    "port": "8002",
    "ollama_url": "http://localhost:11435",
    "ollama_model": "gemma4:e2b",
    "capabilities": "pii.strip",
})

key_store = KeyStore(cfg.agent_id)
audit_store = AuditStore()
ollama = OllamaClient(
    base_url=cfg.ollama_url,
    model=cfg.ollama_model,
    system_prompt=SYSTEM_PROMPT,
)

PEER_A_URL = ""


def _build_fallback_result(args: dict[str, Any], token: str) -> dict[str, Any]:
    """Deterministic fallback: strip known PII fields by name."""
    lab_values = args.get("lab_values", {})
    stripped = [f for f in PII_FIELDS if f in args]
    return {
        "anonymization_token": token,
        "method": "field_redaction",
        "lab_values": lab_values,
        "fields_stripped": sorted(stripped),
        "pii_leak_check": {
            "passed": True,
            "details": "Deterministic fallback — known PII fields stripped by name",
        },
    }


def _validate_anonymization(result: dict[str, Any], original_args: dict[str, Any]) -> dict[str, Any]:
    """Verify no PII leaked into the LLM result."""
    pii_values = set()
    for field in PII_FIELDS:
        val = original_args.get(field)
        if val:
            pii_values.add(str(val).lower())

    result_str = str(result).lower()
    leaked = [v for v in pii_values if v in result_str and v not in ("", "n/a")]

    if leaked:
        logger.warning("PII leak detected in LLM output, falling back to deterministic")
        token = result.get("anonymization_token", f"anonymized-{uuid.uuid4().hex[:12]}")
        return _build_fallback_result(original_args, token)

    return result


@asynccontextmanager
async def lifespan(app: FastAPI):
    global PEER_A_URL

    key_store.generate()

    PEER_A_URL = os.environ.get("PEER_A_URL", f"http://localhost:{os.environ.get('AGENT_A_PORT', '8001')}")
    agent_a_id = os.environ.get("AGENT_A_ID", "agent:meddata.data-collector")

    task = asyncio.create_task(exchange_keys(key_store, {agent_a_id: PEER_A_URL}))

    logger.info("Agent B (Anonymizer) ready — %s on port %s", cfg.agent_id, cfg.port)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Agent B — Anonymizer", lifespan=lifespan)


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
    llm_result = await _anonymize(args)

    response_env = create_response(
        from_agent=cfg.agent_id,
        to_agent=body["from"],
        correlation_id=body["id"],
        payload_type="org.arsiaprotocol.health/anonymize.result",
        result=llm_result,
        compliance={
            "profile": "GDPR-STANDARD",
            "pii_involved": False,
            "audit_required": True,
        },
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


async def _anonymize(args: dict[str, Any]) -> dict[str, Any]:
    """Call LLM to anonymize patient data, with deterministic fallback."""
    token = f"anonymized-{uuid.uuid4().hex[:12]}"

    prompt = (
        f"Anonymize this patient record. Strip ALL PII and preserve "
        f"only the lab values.\n\n"
        f"Use this anonymization token: {token}\n\n"
        f"Patient record:\n{_safe_json_dump(args)}\n\n"
        f"Return the anonymized result as JSON. Remember: NO patient "
        f"names, dates of birth, or health numbers in the output."
    )

    stream_client: httpx.AsyncClient | None = None
    if PEER_A_URL:
        stream_client = httpx.AsyncClient(timeout=5.0)

    async def on_token(tok: str) -> None:
        if stream_client:
            try:
                await stream_client.post(
                    f"{PEER_A_URL}/llm-stream",
                    json={"agent": cfg.agent_id, "token": tok},
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
        if isinstance(result, dict) and "lab_values" in result:
            result.setdefault("anonymization_token", token)
            return _validate_anonymization(result, args)
        logger.warning("LLM returned unexpected structure, using fallback")
        return _build_fallback_result(args, token)
    except Exception as exc:
        logger.warning("LLM call failed (%s), using fallback result", exc)
        return _build_fallback_result(args, token)
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


def _safe_json_dump(obj: Any) -> str:
    """JSON-serialize for LLM prompt, handling non-serializable types."""
    import json
    try:
        return json.dumps(obj, indent=2, default=str)
    except Exception:
        return str(obj)
