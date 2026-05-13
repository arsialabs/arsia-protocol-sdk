# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent A — Data Collector (pipeline orchestrator).

Orchestrates the 7-step healthcare data pipeline with PII isolation:
1. Receive patient record (PII + lab values)
2. Send PII + lab values to Agent B for anonymization
3. Receive anonymized dataset with opaque token from Agent B
4. Send anonymized lab values to Agent C for clinical analysis
5. Receive diagnosis + explanation from Agent C
6. Human oversight gate — clinician approves/denies diagnosis
7. Reassociate diagnosis with patient identity via token

Holds full patient context; enforces data isolation by constructing
envelopes that exclude PII for Agent C (structurally impossible for
the clinical analyzer to see patient identity).
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
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from arsia_protocol import (
    apply_profile,
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
from ollama_client import OllamaClient
from transport import send_envelope

logger = logging.getLogger(__name__)

PATIENT_PROFILES: list[dict[str, Any]] = [
    {
        "patient_name": "Maria Silva",
        "date_of_birth": "1985-03-14",
        "health_number": "PT-SNS-123456789",
        "lab_values": {
            "ldl_cholesterol": 185,
            "hdl_cholesterol": 42,
            "fasting_glucose": 110,
            "hemoglobin": 13.2,
        },
    },
    {
        "patient_name": "João Mendes",
        "date_of_birth": "1972-08-22",
        "health_number": "PT-SNS-987654321",
        "lab_values": {
            "ldl_cholesterol": 145,
            "hdl_cholesterol": 55,
            "fasting_glucose": 95,
            "hemoglobin": 15.1,
        },
    },
    {
        "patient_name": "Ana Costa",
        "date_of_birth": "1990-11-03",
        "health_number": "PT-SNS-456789123",
        "lab_values": {
            "ldl_cholesterol": 220,
            "hdl_cholesterol": 38,
            "fasting_glucose": 135,
            "hemoglobin": 11.8,
        },
    },
    {
        "patient_name": "Pedro Lopes",
        "date_of_birth": "1968-05-30",
        "health_number": "PT-SNS-321654987",
        "lab_values": {
            "ldl_cholesterol": 160,
            "hdl_cholesterol": 48,
            "fasting_glucose": 102,
            "hemoglobin": 14.5,
        },
    },
    {
        "patient_name": "Sofia Rodrigues",
        "date_of_birth": "2001-01-17",
        "health_number": "PT-SNS-654321789",
        "lab_values": {
            "ldl_cholesterol": 110,
            "hdl_cholesterol": 65,
            "fasting_glucose": 88,
            "hemoglobin": 12.9,
        },
    },
]

SYSTEM_PROMPT = """\
You are a clinical data coordinator at a research organization. \
Your role is to format the final clinical report that reassociates \
a diagnosis (from an anonymized analysis) with patient identity.

You will receive:
- Patient identity (name, date of birth, health number)
- Diagnosis and clinical findings (from an anonymized analysis)
- Risk level and recommendations

Produce a JSON response with exactly this structure:
{
  "report_title": "Clinical Lab Report",
  "patient": {
    "name": "<patient name>",
    "date_of_birth": "<DOB>",
    "health_number": "<health number>"
  },
  "summary": "<1-2 sentence clinical summary>",
  "risk_level": "<risk level>",
  "findings": [<findings array>],
  "recommendations": [<recommendations array>],
  "report_date": "<current date>",
  "disclaimer": "This report was generated with AI assistance and \
requires clinician review before clinical action."
}
"""

cfg = load_agent_config("AGENT_A", {
    "id": "agent:meddata.data-collector",
    "port": "8001",
    "ollama_url": "http://localhost:11434",
    "ollama_model": "gemma4:e2b",
    "capabilities": "patient.collect,patient.result",
})

key_store = KeyStore(cfg.agent_id)
intake_keys = KeyStore("agent:meddata.intake-system")
clinician_keys = KeyStore("agent:meddata.clinician")
audit_store = AuditStore()
flow = FlowState()
ollama = OllamaClient(
    base_url=cfg.ollama_url,
    model=cfg.ollama_model,
    system_prompt=SYSTEM_PROMPT,
)

PEER_B_URL = ""
PEER_C_URL = ""
AGENT_B_ID = ""
AGENT_C_ID = ""

_patient_index: int = 0

_pipeline_state: dict[str, Any] = {
    "patient_data": None,
    "anonymize_request_env": None,
    "anonymize_response_env": None,
    "anonymization_token": None,
    "analyze_request_env": None,
    "analyze_response_env": None,
    "pending_approval_env": None,
    "original_request_id": None,
    "diagnosis": None,
    "final_result": None,
}


def _reset_pipeline_state() -> None:
    for k in _pipeline_state:
        _pipeline_state[k] = None


def _next_patient() -> dict[str, Any]:
    global _patient_index
    patient = PATIENT_PROFILES[_patient_index % len(PATIENT_PROFILES)]
    _patient_index += 1
    return dict(patient)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global PEER_B_URL, PEER_C_URL, AGENT_B_ID, AGENT_C_ID

    key_store.generate()
    intake_keys.generate()
    clinician_keys.generate()

    AGENT_B_ID = os.environ.get("AGENT_B_ID", "agent:meddata.anonymizer")
    AGENT_C_ID = os.environ.get("AGENT_C_ID", "agent:meddata.clinical-analyzer")
    PEER_B_URL = os.environ.get("PEER_B_URL", f"http://localhost:{os.environ.get('AGENT_B_PORT', '8002')}")
    PEER_C_URL = os.environ.get("PEER_C_URL", f"http://localhost:{os.environ.get('AGENT_C_PORT', '8003')}")

    task = asyncio.create_task(exchange_keys(key_store, {
        AGENT_B_ID: PEER_B_URL,
        AGENT_C_ID: PEER_C_URL,
    }))

    logger.info("Agent A (Data Collector) ready — %s on port %s", cfg.agent_id, cfg.port)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Agent A — Data Collector", lifespan=lifespan)
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
    snapshot = await flow.snapshot()
    snapshot["patient_data"] = _redact_patient_for_dashboard(_pipeline_state.get("patient_data"))
    snapshot["final_result"] = _pipeline_state.get("final_result")
    return snapshot


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
    body = await request.json()
    await flow.broadcast_llm_event(body)
    return {"ok": True}


@app.post("/trigger")
async def trigger_pipeline(request: Request, demo_denial: bool = False):
    if flow.status not in (PipelineStatus.IDLE, PipelineStatus.COMPLETED, PipelineStatus.ERROR):
        return JSONResponse(
            status_code=409,
            content={"error": f"Pipeline already active (status={flow.status.value})"},
        )

    body: dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        pass

    patient = body if body.get("patient_name") else _next_patient()

    _reset_pipeline_state()
    await audit_store.clear()

    asyncio.create_task(_run_pipeline(patient, demo_denial=demo_denial))

    return {
        "status": "started",
        "patient_name": patient.get("patient_name", "Unknown"),
    }


@app.post("/envelope")
async def receive_envelope(request: Request):
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


async def _run_pipeline(patient_data: dict[str, Any], *, demo_denial: bool = False) -> None:
    """Execute steps 1-6 of the pipeline, then wait for approval."""
    try:
        await flow.start()

        # ── Step 1: Record patient data ───────────────────────
        _pipeline_state["patient_data"] = patient_data
        patient_name = patient_data.get("patient_name", "Unknown")

        intake_env = create_request(
            from_agent="agent:meddata.intake-system",
            to_agent=cfg.agent_id,
            payload_type="org.arsiaprotocol.health/patient-intake",
            capabilities=["patient.collect"],
            args=patient_data,
            compliance={
                "profile": "GDPR-STANDARD",
                "pii_involved": True,
                "legal_basis": "health_medicine",
                "audit_required": True,
                "retention_days": 3650,
                "data_residency": "EU",
            },
        )
        profiled_intake = apply_profile(intake_env)
        signed_intake = sign_message(profiled_intake, intake_keys.private_key, intake_keys.kid)
        _pipeline_state["original_request_id"] = signed_intake["id"]

        await audit_store.add_from_envelope(signed_intake, event_type="request")
        await flow.advance(1, signed_intake)
        logger.info("Step 1: patient record received (%s)", patient_name)

        # ── Step 2: Send to Agent B for anonymization ─────────
        anonymize_request = create_request(
            from_agent=cfg.agent_id,
            to_agent=AGENT_B_ID,
            payload_type="org.arsiaprotocol.health/anonymize",
            capabilities=["pii.strip"],
            args=patient_data,
            compliance={
                "profile": "GDPR-STANDARD",
                "pii_involved": True,
                "legal_basis": "health_medicine",
                "audit_required": True,
                "retention_days": 3650,
                "data_residency": "EU",
            },
        )

        signed_anon_req = sign_message(apply_profile(anonymize_request), key_store.private_key, key_store.kid)
        await audit_store.add_from_envelope(signed_anon_req, event_type="request")

        anonymize_response = await send_envelope(anonymize_request, key_store, PEER_B_URL, timeout=360.0)
        _pipeline_state["anonymize_request_env"] = signed_anon_req
        _pipeline_state["anonymize_response_env"] = anonymize_response
        await flow.advance(2, signed_anon_req)
        logger.info("Step 2: anonymization request sent to Agent B")

        # ── Step 3: Process anonymized response ───────────────
        corr_errors = validate_correlation(signed_anon_req, anonymize_response)
        if corr_errors:
            logger.warning("Correlation errors with anonymize response: %s", corr_errors)

        anon_result = anonymize_response.get("payload", {}).get("result", {})
        anon_token = anon_result.get("anonymization_token", "")
        lab_values = anon_result.get("lab_values", {})
        fields_stripped = anon_result.get("fields_stripped", [])

        _pipeline_state["anonymization_token"] = anon_token

        pii_in_result = _check_pii_leak(anon_result, patient_data)
        if pii_in_result:
            logger.error("PII leak detected in anonymized response: %s", pii_in_result)
            await flow.set_error(f"PII leak detected in anonymized data: {pii_in_result}")
            return

        await audit_store.add_from_envelope(anonymize_response, event_type="response")
        await flow.advance(3, anonymize_response)
        logger.info(
            "Step 3: anonymized data received (token=%s, stripped=%s)",
            anon_token[:20], fields_stripped,
        )

        # ── Step 4: Send anonymized data to Agent C ───────────
        analyze_request = create_request(
            from_agent=cfg.agent_id,
            to_agent=AGENT_C_ID,
            payload_type="org.arsiaprotocol.health/interpret",
            capabilities=["analysis.interpret"],
            args={
                "anonymization_token": anon_token,
                "lab_values": lab_values,
            },
            compliance={
                "profile": "GDPR-STANDARD",
                "pii_involved": False,
                "audit_required": True,
            },
        )

        signed_analyze_req = sign_message(apply_profile(analyze_request), key_store.private_key, key_store.kid)
        await audit_store.add_from_envelope(signed_analyze_req, event_type="request")

        analyze_response = await send_envelope(analyze_request, key_store, PEER_C_URL, timeout=360.0)
        _pipeline_state["analyze_request_env"] = signed_analyze_req
        _pipeline_state["analyze_response_env"] = analyze_response
        await flow.advance(4, signed_analyze_req)
        logger.info("Step 4: analysis request sent to Agent C")

        # ── Step 5: Process diagnosis ─────────────────────────
        corr_errors = validate_correlation(signed_analyze_req, analyze_response)
        if corr_errors:
            logger.warning("Correlation errors with analyze response: %s", corr_errors)

        explain_error = validate_explainability(signed_analyze_req, analyze_response)
        if explain_error:
            logger.warning("Explainability validation: %s", explain_error)

        diagnosis = analyze_response.get("payload", {}).get("result", {})
        _pipeline_state["diagnosis"] = diagnosis

        await audit_store.add_from_envelope(analyze_response, event_type="response")
        await flow.advance(5, analyze_response)
        logger.info(
            "Step 5: diagnosis received (risk=%s, confidence=%.2f)",
            diagnosis.get("risk_level", "unknown"),
            diagnosis.get("confidence", 0.0),
        )

        # ── Step 6: Human oversight gate ──────────────────────
        pending_env = create_pending_approval(
            from_agent=cfg.agent_id,
            to_agent="agent:meddata.clinician",
            correlation_id=_pipeline_state["original_request_id"],
            payload_type="arsiaprotocol.oversight/pending",
            args={
                "action_id": "org.arsiaprotocol.health/reassociate-diagnosis",
                "original_request_id": _pipeline_state["original_request_id"],
                "anonymization_token": anon_token,
                "diagnosis_summary": diagnosis.get("diagnosis", ""),
                "risk_level": diagnosis.get("risk_level", "unknown"),
                "confidence": diagnosis.get("confidence", 0.0),
                "findings_count": len(diagnosis.get("findings", [])),
                "recommendations_count": len(diagnosis.get("recommendations", [])),
                "approver_capability": "arsiaprotocol.oversight.approve",
            },
            explanation=analyze_response.get("payload", {}).get("explanation"),
            expires_in_seconds=3600,
            compliance={
                "profile": "EU-AI-ACT-HIGH-RISK",
                "ai_system_classification": "high-risk",
                "audit_required": True,
            },
        )

        profiled_pending = apply_profile(pending_env)
        signed_pending = sign_message(profiled_pending, key_store.private_key, key_store.kid)
        _pipeline_state["pending_approval_env"] = signed_pending

        await audit_store.add_from_envelope(signed_pending, event_type="pending_approval")
        await flow.advance(6, signed_pending)
        await flow.set_pending_approval(signed_pending)

        logger.info("Step 6: awaiting clinician approval (expires_at=%s)", signed_pending.get("expires_at"))

        if demo_denial:
            await _demo_capability_denial()

    except Exception as exc:
        logger.exception("Pipeline error: %s", exc)
        await flow.set_error(str(exc))


async def _handle_approval(decision_body: dict[str, Any]) -> None:
    """Process an approval decision and complete the pipeline (step 7)."""
    try:
        pending = _pipeline_state.get("pending_approval_env")
        if pending is None:
            await flow.set_error("No pending approval to decide on")
            return

        decision = decision_body.get("decision", "denied")
        approver_id = decision_body.get("approver_id", "agent:meddata.clinician")
        reason = decision_body.get("reason", "")

        approval_env = create_approval_decision(
            from_agent=approver_id,
            to_agent=cfg.agent_id,
            correlation_id=pending["id"],
            payload_type="arsiaprotocol.oversight/decision",
            capabilities=["patient.result"],
            result={
                "decision": decision,
                "approver_id": approver_id,
                "reason": reason,
            },
            compliance={
                "profile": "EU-AI-ACT-HIGH-RISK",
                "ai_system_classification": "high-risk",
                "audit_required": True,
            },
        )

        profiled_decision = apply_profile(approval_env)
        signed_decision = sign_message(profiled_decision, clinician_keys.private_key, clinician_keys.kid)

        if is_approval_expired(pending.get("expires_at", "")):
            expired_error = build_oversight_expired_error(
                from_agent=cfg.agent_id,
                to_agent="agent:meddata.clinician",
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
                "profile": "EU-AI-ACT-HIGH-RISK",
                "audit_required": True,
                "retention_days": 3650,
            }
            profiled_denied = apply_profile(denied_error)
            signed_denied = sign_message(profiled_denied, clinician_keys.private_key, clinician_keys.kid)
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

        # ── Step 7: Reassociate diagnosis with patient identity ─
        patient_data = _pipeline_state["patient_data"]
        diagnosis = _pipeline_state["diagnosis"]
        anon_token = _pipeline_state["anonymization_token"]

        final_result = await _reassociate(patient_data, diagnosis, anon_token)
        _pipeline_state["final_result"] = final_result

        completion_env = create_response(
            from_agent=cfg.agent_id,
            to_agent="agent:meddata.intake-system",
            correlation_id=_pipeline_state["original_request_id"],
            payload_type="org.arsiaprotocol.health/patient-result",
            result=final_result,
            compliance={
                "profile": "GDPR-STANDARD",
                "pii_involved": True,
                "legal_basis": "health_medicine",
                "audit_required": True,
                "retention_days": 3650,
                "data_residency": "EU",
            },
        )
        profiled_completion = apply_profile(completion_env)
        signed_completion = sign_message(profiled_completion, key_store.private_key, key_store.kid)

        await audit_store.add_from_envelope(signed_completion, event_type="response")
        await flow.advance(7, signed_completion)
        await flow.complete()

        audit_count = await audit_store.count()
        logger.info("Step 7: pipeline complete — %d audit records", audit_count)

    except Exception as exc:
        logger.exception("Pipeline error during approval handling: %s", exc)
        await flow.set_error(str(exc))


async def _reassociate(
    patient_data: dict[str, Any],
    diagnosis: dict[str, Any],
    anon_token: str,
) -> dict[str, Any]:
    """Reassociate diagnosis with patient identity. LLM formats the report."""
    prompt = (
        f"Format a clinical lab report reassociating these results.\n\n"
        f"Patient: {patient_data.get('patient_name', 'Unknown')}\n"
        f"DOB: {patient_data.get('date_of_birth', 'Unknown')}\n"
        f"Health Number: {patient_data.get('health_number', 'Unknown')}\n"
        f"Anonymization Token: {anon_token}\n\n"
        f"Diagnosis: {diagnosis.get('diagnosis', 'N/A')}\n"
        f"Risk Level: {diagnosis.get('risk_level', 'N/A')}\n"
        f"Confidence: {diagnosis.get('confidence', 'N/A')}\n"
        f"Findings: {json.dumps(diagnosis.get('findings', []), indent=2)}\n"
        f"Recommendations: {json.dumps(diagnosis.get('recommendations', []), indent=2)}\n\n"
        f"Format as a structured clinical report JSON."
    )

    await flow.broadcast_llm_event({
        "agent": cfg.agent_id, "event": "start",
    })

    async def on_token(token: str) -> None:
        await flow.broadcast_llm_event({
            "agent": cfg.agent_id, "event": "token", "token": token,
        })

    try:
        result = await ollama.chat_json_stream(prompt, on_token=on_token)
        await flow.broadcast_llm_event({
            "agent": cfg.agent_id, "event": "end",
        })
        if isinstance(result, dict) and "patient" in result:
            return result
    except Exception as exc:
        await flow.broadcast_llm_event({
            "agent": cfg.agent_id, "event": "end",
        })
        logger.warning("LLM reassociation failed (%s), using template", exc)

    return _build_fallback_report(patient_data, diagnosis, anon_token)


def _build_fallback_report(
    patient_data: dict[str, Any],
    diagnosis: dict[str, Any],
    anon_token: str,
) -> dict[str, Any]:
    return {
        "report_title": "Clinical Lab Report",
        "patient": {
            "name": patient_data.get("patient_name", "Unknown"),
            "date_of_birth": patient_data.get("date_of_birth", "Unknown"),
            "health_number": patient_data.get("health_number", "Unknown"),
        },
        "anonymization_token": anon_token,
        "summary": diagnosis.get("diagnosis", "No diagnosis available"),
        "risk_level": diagnosis.get("risk_level", "unknown"),
        "confidence": diagnosis.get("confidence", 0.0),
        "findings": diagnosis.get("findings", []),
        "recommendations": diagnosis.get("recommendations", []),
        "guidelines_cited": diagnosis.get("guidelines_cited", []),
        "report_date": format_timestamp(),
        "disclaimer": (
            "This report was generated with AI assistance and "
            "requires clinician review before clinical action."
        ),
    }


async def _demo_capability_denial() -> None:
    """Demonstrate capability denial: ask Agent C for pii.read."""
    logger.info("Demo: triggering capability denial (Agent C asked for pii.read)")

    denial_request = create_request(
        from_agent=cfg.agent_id,
        to_agent=AGENT_C_ID,
        payload_type="org.arsiaprotocol.health/read-pii",
        capabilities=["pii.read"],
        args={"demo": True, "note": "This request will be denied — Agent C lacks pii.read"},
        compliance={
            "profile": "GDPR-STANDARD",
            "legal_basis": "health_medicine",
            "pii_involved": True,
            "audit_required": True,
        },
    )

    signed_denial_req = sign_message(apply_profile(denial_request), key_store.private_key, key_store.kid)
    await audit_store.add_from_envelope(signed_denial_req, event_type="request")
    await flow.add_envelope("denial_req", signed_denial_req)

    try:
        response = await send_envelope(denial_request, key_store, PEER_C_URL, timeout=30.0)
        logger.info("Capability denial response: intent=%s", response.get("intent"))
        await audit_store.add_from_envelope(response, event_type="error")
        await flow.add_envelope("denial_resp", response)
    except httpx.HTTPStatusError as exc:
        try:
            error_envelope = exc.response.json()
            await audit_store.add_from_envelope(error_envelope, event_type="error")
            await flow.add_envelope("denial_resp", error_envelope)
        except Exception:
            pass
        logger.info("Capability denial triggered expected error: %s", exc)
    except Exception as exc:
        logger.info("Capability denial triggered expected error: %s", exc)


def _check_pii_leak(anon_result: dict[str, Any], patient_data: dict[str, Any]) -> list[str]:
    """Check if any PII from the original patient data leaked into the anonymized result."""
    pii_checks = {
        "patient_name": patient_data.get("patient_name", ""),
        "date_of_birth": patient_data.get("date_of_birth", ""),
        "health_number": patient_data.get("health_number", ""),
    }
    result_str = json.dumps(anon_result).lower()
    leaked = []
    for field, value in pii_checks.items():
        if value and str(value).lower() in result_str:
            leaked.append(field)
    return leaked


def _redact_patient_for_dashboard(patient_data: dict[str, Any] | None) -> dict[str, Any] | None:
    """Include patient data for the dashboard (it shows both PII + diagnosis
    because the clinician needs to see the full picture for oversight)."""
    if patient_data is None:
        return None
    return {
        "patient_name": patient_data.get("patient_name", "Unknown"),
        "date_of_birth": patient_data.get("date_of_birth", "Unknown"),
        "health_number": patient_data.get("health_number", "Unknown"),
        "lab_values": patient_data.get("lab_values", {}),
    }
