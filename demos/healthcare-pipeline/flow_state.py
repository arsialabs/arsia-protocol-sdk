# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pipeline flow state tracking with SSE support for the dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class PipelineStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    DENIED = "denied"
    COMPLETED = "completed"
    ERROR = "error"


STEP_DESCRIPTIONS = {
    1: "Patient record arrives at Data Collector (PII + lab values)",
    2: "Data Collector → Anonymizer: PII + lab values for anonymization",
    3: "Anonymizer → Data Collector: anonymized dataset with opaque token",
    4: "Data Collector → Clinical Analyzer: anonymized lab values for analysis",
    5: "Clinical Analyzer → Data Collector: diagnosis + explanation",
    6: "Human oversight gate: clinician approves/denies diagnosis",
    7: "Data Collector reassociates diagnosis with patient identity via token",
}


class FlowState:
    """Tracks pipeline progress and provides SSE events for the dashboard.

    Holds envelopes at each step so the dashboard can inspect them.
    Manages pending approvals and decisions.
    """

    def __init__(self) -> None:
        self._status: PipelineStatus = PipelineStatus.IDLE
        self._current_step: int = 0
        self._step_envelopes: dict[str, dict[str, Any]] = {}
        self._pending_approval: dict[str, Any] | None = None
        self._approval_decision: dict[str, Any] | None = None
        self._error: str | None = None
        self._started_at: str | None = None
        self._completed_at: str | None = None
        self._lock = asyncio.Lock()
        self._subscribers: list[asyncio.Queue[str]] = []

    def _now_ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
            f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"

    async def subscribe(self) -> asyncio.Queue[str]:
        """Create a new SSE subscriber queue."""
        queue: asyncio.Queue[str] = asyncio.Queue()
        async with self._lock:
            self._subscribers.append(queue)
        initial = await self.snapshot()
        await queue.put(json.dumps({"event": "snapshot", "data": initial}))
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        """Remove an SSE subscriber queue."""
        async with self._lock:
            try:
                self._subscribers.remove(queue)
            except ValueError:
                pass

    async def _broadcast(self, event: str, data: dict[str, Any]) -> None:
        """Send an SSE event to all subscribers."""
        message = json.dumps({"event": event, "data": data})
        async with self._lock:
            dead: list[asyncio.Queue[str]] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    async def broadcast_llm_event(self, data: dict[str, Any]) -> None:
        """Broadcast an LLM streaming event (start/token/end) to SSE subscribers."""
        await self._broadcast("llm_stream", data)

    async def start(self) -> None:
        """Begin a new pipeline run."""
        async with self._lock:
            self._status = PipelineStatus.RUNNING
            self._current_step = 1
            self._step_envelopes.clear()
            self._pending_approval = None
            self._approval_decision = None
            self._error = None
            self._started_at = self._now_ts()
            self._completed_at = None

        await self._broadcast("pipeline_started", {
            "status": PipelineStatus.RUNNING.value,
            "step": 1,
            "started_at": self._started_at,
        })

    async def add_envelope(self, key: str, envelope: dict[str, Any]) -> None:
        """Store an extra envelope (e.g. denial demo) visible in the inspector."""
        async with self._lock:
            self._step_envelopes[key] = envelope

    async def advance(self, step: int, envelope: dict[str, Any] | None = None) -> None:
        """Move the pipeline to the given step, optionally recording an envelope."""
        async with self._lock:
            self._current_step = step
            if envelope is not None:
                self._step_envelopes[str(step)] = envelope

        await self._broadcast("step_advanced", {
            "step": step,
            "description": STEP_DESCRIPTIONS.get(step, ""),
            "has_envelope": envelope is not None,
            "envelope_id": envelope.get("id", "") if envelope else "",
        })

    async def set_pending_approval(self, envelope: dict[str, Any]) -> None:
        """Record a pending approval envelope and move to awaiting_approval status."""
        async with self._lock:
            self._status = PipelineStatus.AWAITING_APPROVAL
            self._pending_approval = envelope

        await self._broadcast("awaiting_approval", {
            "status": PipelineStatus.AWAITING_APPROVAL.value,
            "envelope_id": envelope.get("id", ""),
            "expires_at": envelope.get("expires_at", ""),
        })

    async def set_approval_decision(self, decision: str, envelope: dict[str, Any]) -> None:
        """Record the approval decision."""
        async with self._lock:
            self._status = PipelineStatus.APPROVED if decision == "approved" else PipelineStatus.DENIED
            self._approval_decision = envelope

        await self._broadcast("approval_decision", {
            "status": self._status.value,
            "decision": decision,
            "envelope_id": envelope.get("id", ""),
        })

    async def complete(self) -> None:
        """Mark the pipeline as completed."""
        async with self._lock:
            self._status = PipelineStatus.COMPLETED
            self._completed_at = self._now_ts()

        await self._broadcast("pipeline_completed", {
            "status": PipelineStatus.COMPLETED.value,
            "completed_at": self._completed_at,
        })

    async def set_error(self, error: str) -> None:
        """Mark the pipeline as errored."""
        async with self._lock:
            self._status = PipelineStatus.ERROR
            self._error = error

        await self._broadcast("pipeline_error", {
            "status": PipelineStatus.ERROR.value,
            "error": error,
        })

    async def reset(self) -> None:
        """Reset to idle state for a new run."""
        async with self._lock:
            self._status = PipelineStatus.IDLE
            self._current_step = 0
            self._step_envelopes.clear()
            self._pending_approval = None
            self._approval_decision = None
            self._error = None
            self._started_at = None
            self._completed_at = None

        await self._broadcast("pipeline_reset", {
            "status": PipelineStatus.IDLE.value,
        })

    async def snapshot(self) -> dict[str, Any]:
        """Return the full current state for initial SSE payload or API queries."""
        async with self._lock:
            return {
                "status": self._status.value,
                "current_step": self._current_step,
                "total_steps": 7,
                "step_descriptions": STEP_DESCRIPTIONS,
                "step_envelopes": {
                    k: _envelope_summary(v)
                    for k, v in self._step_envelopes.items()
                },
                "pending_approval": _envelope_summary(self._pending_approval) if self._pending_approval else None,
                "approval_decision": _envelope_summary(self._approval_decision) if self._approval_decision else None,
                "error": self._error,
                "started_at": self._started_at,
                "completed_at": self._completed_at,
            }

    @property
    def status(self) -> PipelineStatus:
        return self._status

    def get_step_envelope(self, step: int) -> dict[str, Any] | None:
        return self._step_envelopes.get(str(step))


def _envelope_summary(env: dict[str, Any]) -> dict[str, Any]:
    """Extract display fields from an envelope for the dashboard.

    Includes the full payload so the dashboard can render clinical
    analysis results and anonymization details. The ``security``
    object (signature material) is replaced with a boolean flag.
    """
    return {
        "id": env.get("id", ""),
        "v": env.get("v", ""),
        "from": env.get("from", ""),
        "to": env.get("to", ""),
        "intent": env.get("intent", ""),
        "ts": env.get("ts", ""),
        "correlation_id": env.get("correlation_id"),
        "expires_at": env.get("expires_at"),
        "capabilities": env.get("capabilities"),
        "payload": env.get("payload"),
        "compliance": env.get("compliance"),
        "has_security": "security" in env,
    }
