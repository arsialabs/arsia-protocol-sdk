# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""In-memory idempotency store for conformance test execution."""

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
    status: Literal["new", "pending", "completed"]
    record: IdempotencyRecord | None
    pending_since: datetime | None


class InMemoryIdempotencyStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str, str, str], _Entry] = {}

    @staticmethod
    def _index(scope: IdempotencyScope, key: str) -> tuple[str, str, str, str]:
        return (scope.from_agent, scope.to_agent, scope.payload_type, key)

    def _purge_if_expired(
        self, idx: tuple[str, str, str, str], entry: _Entry
    ) -> _Entry | None:
        if entry.status == "completed":
            assert entry.record is not None
            if is_idempotency_record_expired(entry.record.expires_at):
                del self._entries[idx]
                return None
        return entry

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
