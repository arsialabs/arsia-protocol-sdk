# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Clinician Dashboard — FastAPI service serving static UI.

Proxies requests to Agent A and serves the single-page dashboard
for real-time pipeline monitoring, PII isolation visualization,
human oversight, and audit trail inspection.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load_demo_config

logger = logging.getLogger(__name__)

demo_cfg = load_demo_config()
AGENT_A_URL = demo_cfg.dashboard_agent_a_url

app = FastAPI(title="ARSIA Clinician Dashboard")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "dashboard", "agent_a_url": AGENT_A_URL}


@app.post("/api/trigger")
async def proxy_trigger(request: Request):
    params = dict(request.query_params)
    body: dict = {}
    try:
        body = await request.json()
    except Exception:
        pass
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(f"{AGENT_A_URL}/trigger", json=body, params=params)
        return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/envelope")
async def proxy_envelope(request: Request):
    body = await request.json()
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(f"{AGENT_A_URL}/envelope", json=body)
        return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.post("/api/reset")
async def proxy_reset():
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{AGENT_A_URL}/reset")
        return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.get("/api/state")
async def proxy_state():
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{AGENT_A_URL}/state")
        return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.get("/api/audit")
async def proxy_audit():
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{AGENT_A_URL}/audit")
        return JSONResponse(status_code=resp.status_code, content=resp.json())


@app.get("/api/state/stream-url")
async def stream_url():
    return {"url": f"{AGENT_A_URL}/state/stream"}


app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
