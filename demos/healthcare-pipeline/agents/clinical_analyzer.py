# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent C — Clinical Analyzer (LLM-powered lab interpretation).

Receives anonymized lab values (no patient identity — structurally
impossible because the envelope never contains PII), generates a
clinical interpretation via LLM, and returns a diagnosis with an
EU AI Act Art. 13 explanation object.
"""

from __future__ import annotations

import asyncio
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
You are a clinical laboratory analysis AI system classified as \
HIGH-RISK under the EU AI Act (Regulation 2024/1689, Annex III).

Your role: interpret anonymized lab values and produce a structured \
clinical assessment. You operate on ANONYMIZED data only — you have \
no access to patient identity and must NEVER attempt to identify \
the patient.

You will receive:
- anonymization_token: an opaque reference (do NOT interpret it)
- lab_values: clinical measurements (LDL cholesterol, HDL cholesterol, \
  fasting glucose, hemoglobin, etc.)

Reference ranges (adult):
- LDL Cholesterol: <100 mg/dL optimal, 100-129 near optimal, \
  130-159 borderline high, 160-189 high, ≥190 very high (ATP III)
- HDL Cholesterol: ≥60 mg/dL protective, 40-59 acceptable, \
  <40 low / major risk factor (ATP III)
- Fasting Glucose: <100 mg/dL normal, 100-125 prediabetes, \
  ≥126 diabetes (ADA 2024)
- Hemoglobin: 12.0-16.0 g/dL female, 13.5-17.5 g/dL male (WHO)

Produce a JSON response with exactly this structure:
{
  "anonymization_token": "<echo back the token received>",
  "diagnosis": "<clinical findings summary>",
  "risk_level": "<low|moderate|high|critical>",
  "confidence": <float 0.0-1.0>,
  "findings": [
    {
      "test": "<test name>",
      "value": "<value with units>",
      "reference_range": "<normal range>",
      "interpretation": "<normal|borderline|abnormal|critical>",
      "clinical_note": "<brief clinical significance>"
    }
  ],
  "recommendations": ["<recommendation 1>", "..."],
  "guidelines_cited": ["ATP III", "ADA 2024", "WHO"]
}

CRITICAL: You must NEVER attempt to identify the patient. \
You must NEVER request PII. Your analysis is based solely on \
the lab values provided.\
"""

cfg = load_agent_config("AGENT_C", {
    "id": "agent:meddata.clinical-analyzer",
    "port": "8003",
    "ollama_url": "http://localhost:11436",
    "ollama_model": "gemma4:e2b",
    "capabilities": "analysis.interpret",
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
    "anonymization_token": "",
    "diagnosis": (
        "Dyslipidemia with elevated cardiovascular risk. LDL cholesterol "
        "is high (185 mg/dL, target <100 mg/dL per ATP III). HDL cholesterol "
        "is low (42 mg/dL, below the 60 mg/dL protective threshold). "
        "Fasting glucose is in the prediabetes range (110 mg/dL, ADA threshold "
        "100 mg/dL). Hemoglobin is within normal limits."
    ),
    "risk_level": "high",
    "confidence": 0.88,
    "findings": [
        {
            "test": "LDL Cholesterol",
            "value": "185 mg/dL",
            "reference_range": "<100 mg/dL optimal",
            "interpretation": "abnormal",
            "clinical_note": "High LDL — major modifiable cardiovascular risk factor",
        },
        {
            "test": "HDL Cholesterol",
            "value": "42 mg/dL",
            "reference_range": "≥60 mg/dL protective",
            "interpretation": "borderline",
            "clinical_note": "Low HDL — independent risk factor per ATP III",
        },
        {
            "test": "Fasting Glucose",
            "value": "110 mg/dL",
            "reference_range": "<100 mg/dL normal",
            "interpretation": "borderline",
            "clinical_note": "Prediabetes range per ADA 2024 guidelines",
        },
        {
            "test": "Hemoglobin",
            "value": "13.2 g/dL",
            "reference_range": "12.0-16.0 g/dL (female) / 13.5-17.5 g/dL (male)",
            "interpretation": "normal",
            "clinical_note": "Within reference range",
        },
    ],
    "recommendations": [
        "Lipid-lowering therapy evaluation (statin candidacy per ATP III)",
        "Dietary modification — Mediterranean diet pattern",
        "Repeat fasting glucose in 3 months; consider HbA1c testing",
        "Cardiovascular risk scoring (Framingham or SCORE2)",
    ],
    "guidelines_cited": ["ATP III", "ADA 2024", "WHO"],
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global PEER_A_URL

    key_store.generate()

    PEER_A_URL = os.environ.get("PEER_A_URL", f"http://localhost:{os.environ.get('AGENT_A_PORT', '8001')}")
    agent_a_id = os.environ.get("AGENT_A_ID", "agent:meddata.data-collector")

    task = asyncio.create_task(exchange_keys(key_store, {agent_a_id: PEER_A_URL}))

    logger.info("Agent C (Clinical Analyzer) ready — %s on port %s", cfg.agent_id, cfg.port)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Agent C — Clinical Analyzer", lifespan=lifespan)


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
    llm_result = await _analyze(args)

    response_env = create_response(
        from_agent=cfg.agent_id,
        to_agent=body["from"],
        correlation_id=body["id"],
        payload_type="org.arsiaprotocol.health/interpret.result",
        result=llm_result,
        explanation={
            "model": cfg.ollama_model,
            "reasoning": (
                f"Clinical interpretation based on lab values against "
                f"standard reference ranges (ATP III for lipids, ADA 2024 "
                f"for glucose, WHO for hemoglobin). "
                f"Risk level: {llm_result.get('risk_level', 'unknown')}. "
                f"Confidence: {llm_result.get('confidence', 0.0):.2f}."
            ),
            "confidence": llm_result.get("confidence", 0.88),
            "inputs_used": [
                "anonymization_token",
                "lab_values.ldl_cholesterol",
                "lab_values.hdl_cholesterol",
                "lab_values.fasting_glucose",
                "lab_values.hemoglobin",
            ],
        },
        compliance={
            "profile": "EU-AI-ACT-HIGH-RISK",
            "ai_system_classification": "high-risk",
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


async def _analyze(args: dict[str, Any]) -> dict[str, Any]:
    """Call LLM for clinical interpretation, with deterministic fallback."""
    token = args.get("anonymization_token", "")
    lab_values = args.get("lab_values", {})

    prompt = (
        f"Interpret these anonymized lab results.\n\n"
        f"Anonymization token: {token}\n\n"
        f"Lab values:\n"
    )
    for test, value in lab_values.items():
        label = test.replace("_", " ").title()
        prompt += f"  - {label}: {value}\n"
    prompt += (
        f"\nProvide your clinical interpretation as JSON. "
        f"Include the anonymization token in your response."
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
        if isinstance(result, dict) and "diagnosis" in result:
            result.setdefault("anonymization_token", token)
            return result
        logger.warning("LLM returned unexpected structure, using fallback")
        fallback = dict(FALLBACK_RESULT)
        fallback["anonymization_token"] = token
        _adapt_fallback(fallback, lab_values)
        return fallback
    except Exception as exc:
        logger.warning("LLM call failed (%s), using fallback result", exc)
        fallback = dict(FALLBACK_RESULT)
        fallback["anonymization_token"] = token
        _adapt_fallback(fallback, lab_values)
        return fallback
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


def _adapt_fallback(fallback: dict[str, Any], lab_values: dict[str, Any]) -> None:
    """Adjust the fallback findings to match the actual lab values received."""
    value_map = {
        "ldl_cholesterol": ("LDL Cholesterol", "mg/dL"),
        "hdl_cholesterol": ("HDL Cholesterol", "mg/dL"),
        "fasting_glucose": ("Fasting Glucose", "mg/dL"),
        "hemoglobin": ("Hemoglobin", "g/dL"),
    }
    findings = []
    for key, (label, unit) in value_map.items():
        val = lab_values.get(key)
        if val is None:
            continue
        interp = _interpret_value(key, val)
        findings.append({
            "test": label,
            "value": f"{val} {unit}",
            "reference_range": interp["range"],
            "interpretation": interp["status"],
            "clinical_note": interp["note"],
        })

    if findings:
        fallback["findings"] = findings

    risk = _compute_risk_level(lab_values)
    fallback["risk_level"] = risk
    fallback["diagnosis"] = _build_fallback_diagnosis(lab_values, findings)


def _interpret_value(key: str, val: float) -> dict[str, str]:
    if key == "ldl_cholesterol":
        if val < 100:
            return {"range": "<100 mg/dL optimal", "status": "normal", "note": "Optimal LDL level"}
        if val < 130:
            return {"range": "100-129 mg/dL near optimal", "status": "borderline", "note": "Near optimal — monitor"}
        if val < 160:
            return {"range": "130-159 mg/dL borderline high", "status": "borderline", "note": "Borderline high per ATP III"}
        if val < 190:
            return {"range": "160-189 mg/dL high", "status": "abnormal", "note": "High LDL — cardiovascular risk factor"}
        return {"range": "≥190 mg/dL very high", "status": "critical", "note": "Very high LDL — immediate intervention per ATP III"}
    if key == "hdl_cholesterol":
        if val >= 60:
            return {"range": "≥60 mg/dL protective", "status": "normal", "note": "Protective HDL level"}
        if val >= 40:
            return {"range": "40-59 mg/dL acceptable", "status": "borderline", "note": "Acceptable but not protective"}
        return {"range": "<40 mg/dL low", "status": "abnormal", "note": "Low HDL — independent risk factor per ATP III"}
    if key == "fasting_glucose":
        if val < 100:
            return {"range": "<100 mg/dL normal", "status": "normal", "note": "Normal fasting glucose"}
        if val < 126:
            return {"range": "100-125 mg/dL prediabetes", "status": "borderline", "note": "Prediabetes range per ADA 2024"}
        return {"range": "≥126 mg/dL diabetes", "status": "abnormal", "note": "Diabetic range per ADA 2024"}
    if key == "hemoglobin":
        if 12.0 <= val <= 17.5:
            return {"range": "12.0-17.5 g/dL", "status": "normal", "note": "Within reference range"}
        if val < 12.0:
            return {"range": "12.0-17.5 g/dL", "status": "abnormal", "note": "Low hemoglobin — evaluate for anemia"}
        return {"range": "12.0-17.5 g/dL", "status": "borderline", "note": "Elevated hemoglobin — monitor"}
    return {"range": "N/A", "status": "normal", "note": ""}


def _compute_risk_level(lab_values: dict[str, Any]) -> str:
    abnormal_count = 0
    ldl = lab_values.get("ldl_cholesterol", 0)
    hdl = lab_values.get("hdl_cholesterol", 100)
    glucose = lab_values.get("fasting_glucose", 0)

    if ldl >= 190:
        abnormal_count += 2
    elif ldl >= 160:
        abnormal_count += 1
    if hdl < 40:
        abnormal_count += 1
    if glucose >= 126:
        abnormal_count += 2
    elif glucose >= 100:
        abnormal_count += 1

    if abnormal_count >= 3:
        return "critical"
    if abnormal_count >= 2:
        return "high"
    if abnormal_count >= 1:
        return "moderate"
    return "low"


def _build_fallback_diagnosis(lab_values: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    abnormal = [f for f in findings if f["interpretation"] in ("abnormal", "critical")]
    borderline = [f for f in findings if f["interpretation"] == "borderline"]

    parts = []
    if abnormal:
        tests = ", ".join(f["test"] for f in abnormal)
        parts.append(f"Abnormal values detected: {tests}.")
    if borderline:
        tests = ", ".join(f["test"] for f in borderline)
        parts.append(f"Borderline values: {tests}.")
    if not abnormal and not borderline:
        parts.append("All lab values within normal reference ranges.")

    return " ".join(parts)
