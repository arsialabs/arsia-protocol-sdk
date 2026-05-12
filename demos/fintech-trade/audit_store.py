# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""In-memory audit record store for the fintech trade demo."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from arsia_protocol import ArsiaAuditRecord, build_audit_record, compute_payload_hash

logger = logging.getLogger(__name__)


class AuditStore:
    """Thread-safe (asyncio) in-memory store for ARSIA audit records.

    Not persistent — records live only for the duration of the demo process.
    """

    def __init__(self) -> None:
        self._records: list[ArsiaAuditRecord] = []
        self._lock = asyncio.Lock()

    async def add(self, record: ArsiaAuditRecord) -> None:
        """Append an audit record to the store."""
        async with self._lock:
            self._records.append(record)
            logger.info(
                "Audit record added: %s (event=%s, from=%s → to=%s)",
                record.record_id[:12],
                record.event_type,
                record.from_agent,
                record.to_agent,
            )

    async def add_from_envelope(
        self,
        envelope: dict[str, Any],
        *,
        event_type: str,
        operator_id: str = "org:acme-wealth-management",
        effective_retention_days: int = 1827,
        **kwargs: Any,
    ) -> ArsiaAuditRecord:
        """Build an audit record from an envelope and add it to the store."""
        record = build_audit_record(
            envelope,
            event_type=event_type,
            operator_id=operator_id,
            effective_retention_days=effective_retention_days,
            **kwargs,
        )
        await self.add(record)
        return record

    async def list_all(self) -> list[ArsiaAuditRecord]:
        """Return all audit records in insertion order."""
        async with self._lock:
            return list(self._records)

    async def filter_by_event_type(self, event_type: str) -> list[ArsiaAuditRecord]:
        """Return records matching the given event type."""
        async with self._lock:
            return [r for r in self._records if r.event_type == event_type]

    async def filter_by_correlation(self, correlation_id: str) -> list[ArsiaAuditRecord]:
        """Return records whose originating envelope had the given correlation_id.

        Uses message_id matching against the correlation chain — callers
        should pass envelope IDs that participate in the correlation.
        """
        async with self._lock:
            return [r for r in self._records if r.correlation_id == correlation_id]

    async def count(self) -> int:
        """Return the total number of records."""
        async with self._lock:
            return len(self._records)

    async def clear(self) -> None:
        """Remove all records (for demo reset)."""
        async with self._lock:
            self._records.clear()
            logger.info("Audit store cleared")
