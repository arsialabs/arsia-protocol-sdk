# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Test fixture — InMemoryIdempotencyStore. Not part of the SDK public API."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from arsia_protocol.core.idempotency import (
    DuplicateIdempotencyKey,
    IdempotencyRecord,
    IdempotencyScope,
    IdempotencyStatus,
    is_idempotency_record_expired,
)


@dataclass
class _Entry:
    """Internal store slot: completed record or pending reservation."""

    status: Literal["new", "pending", "completed"]
    record: IdempotencyRecord | None
    pending_since: datetime | None


class InMemoryIdempotencyStore:
    """Thread-safe in-memory IdempotencyStore implementation.

    Intended for unit tests, conformance runs, and single-process
    deployments. Not suitable for production: the store is lost on
    process restart and is not visible across processes. Expired
    records are purged lazily on access; no background reaper runs.

    Implements the Core §10.3 lifecycle: ``new → pending → completed``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str, str, str], _Entry] = {}
        self._responses: dict[tuple[str, str, str, str], bytes] = {}

    @staticmethod
    def _index(scope: IdempotencyScope, key: str) -> tuple[str, str, str, str]:
        return (scope.from_agent, scope.to_agent, scope.payload_type, key)

    @staticmethod
    def _scope_of(record: IdempotencyRecord) -> IdempotencyScope:
        return IdempotencyScope(
            from_agent=record.from_agent,
            to_agent=record.to_agent,
            payload_type=record.payload_type,
        )

    def _purge_if_expired(
        self, idx: tuple[str, str, str, str], entry: _Entry
    ) -> _Entry | None:
        if entry.status == "completed":
            assert entry.record is not None
            if is_idempotency_record_expired(entry.record.expires_at):
                del self._entries[idx]
                self._responses.pop(idx, None)
                return None
        return entry

    def get(
        self, scope: IdempotencyScope, key: str
    ) -> IdempotencyRecord | None:
        idx = self._index(scope, key)
        with self._lock:
            entry = self._entries.get(idx)
            if entry is None:
                return None
            entry = self._purge_if_expired(idx, entry)
            if entry is None or entry.status != "completed":
                return None
            return entry.record

    def put(self, record: IdempotencyRecord) -> None:
        scope = self._scope_of(record)
        idx = self._index(scope, record.key)
        with self._lock:
            entry = self._entries.get(idx)
            if entry is not None:
                entry = self._purge_if_expired(idx, entry)
            if entry is not None and entry.status == "completed":
                raise DuplicateIdempotencyKey(scope, record.key)
            self._entries[idx] = _Entry(
                status="completed", record=record, pending_since=None
            )

    def mark_pending(self, scope: IdempotencyScope, key: str) -> bool:
        idx = self._index(scope, key)
        with self._lock:
            entry = self._entries.get(idx)
            if entry is not None:
                entry = self._purge_if_expired(idx, entry)
            if entry is not None:
                return False
            self._entries[idx] = _Entry(
                status="pending",
                record=None,
                pending_since=datetime.now(timezone.utc),
            )
            return True

    def mark_complete(self, record: IdempotencyRecord) -> None:
        scope = self._scope_of(record)
        idx = self._index(scope, record.key)
        with self._lock:
            entry = self._entries.get(idx)
            if entry is not None:
                entry = self._purge_if_expired(idx, entry)
            if entry is not None and entry.status == "completed":
                raise DuplicateIdempotencyKey(scope, record.key)
            self._entries[idx] = _Entry(
                status="completed", record=record, pending_since=None
            )

    def check_status(
        self, scope: IdempotencyScope, key: str
    ) -> IdempotencyStatus:
        idx = self._index(scope, key)
        with self._lock:
            entry = self._entries.get(idx)
            if entry is None:
                return "new"
            entry = self._purge_if_expired(idx, entry)
            if entry is None:
                return "new"
            return entry.status

    def store_response(
        self, scope: IdempotencyScope, key: str, response_bytes: bytes
    ) -> None:
        idx = self._index(scope, key)
        with self._lock:
            self._responses[idx] = response_bytes

    def get_response(
        self, scope: IdempotencyScope, key: str
    ) -> bytes | None:
        idx = self._index(scope, key)
        with self._lock:
            entry = self._entries.get(idx)
            if entry is None:
                return None
            entry = self._purge_if_expired(idx, entry)
            if entry is None or entry.status != "completed":
                return None
            return self._responses.get(idx)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._responses.clear()
