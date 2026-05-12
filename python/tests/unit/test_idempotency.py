# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for :mod:`arsia_protocol.idempotency`.

Covers ARSIA-Core.md §10: key grammar, scope tuple, header vs
envelope precedence, expiry, and the InMemoryIdempotencyStore
test fixture.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

import pytest

from arsia_protocol.core.idempotency import (
    HEADER_ONLY_RETENTION_HOURS,
    IDEMPOTENCY_KEY_MAX_LENGTH,
    IDEMPOTENCY_KEY_MIN_LENGTH,
    DuplicateIdempotencyKey,
    DuplicateRequestInProgress,
    IdempotencyRecord,
    IdempotencyScope,
    IdempotencyStore,
    compute_idempotency_expiry,
    extract_envelope_idempotency,
    is_idempotency_record_expired,
    is_valid_idempotency_key,
    resolve_idempotency_key,
    resolve_idempotency_source,
    scope_tuple,
    validate_idempotency_key,
)
from tests.fixtures.in_memory_idempotency_store import InMemoryIdempotencyStore

_SENDER = "agent:acme.alpha"
_RECIPIENT = "agent:acme.beta"
_PAYLOAD_TYPE = "arsiaprotocol.state/set"
_MSG_ID = "11111111-1111-4111-9111-111111111111"
_TS = "2026-04-14T12:00:00.000Z"
_FUTURE_TS = "2099-12-31T23:59:59.999Z"
_PAST_TS = "2020-01-01T00:00:00.000Z"


def _envelope(
    *,
    idempotency: dict | None = None,
    payload_type: str = _PAYLOAD_TYPE,
) -> dict:
    env: dict = {
        "v": "1.0",
        "id": _MSG_ID,
        "ts": _TS,
        "from": _SENDER,
        "to": _RECIPIENT,
        "intent": "request",
        "payload": {"type": payload_type},
    }
    if idempotency is not None:
        env["idempotency"] = idempotency
    return env


def _record(
    *,
    key: str = "k1",
    from_agent: str = _SENDER,
    to_agent: str = _RECIPIENT,
    payload_type: str = _PAYLOAD_TYPE,
    expires_at: str = _FUTURE_TS,
    fingerprint: str | None = None,
) -> IdempotencyRecord:
    return IdempotencyRecord(
        key=key,
        from_agent=from_agent,
        to_agent=to_agent,
        payload_type=payload_type,
        message_id=_MSG_ID,
        response_fingerprint=fingerprint,
        stored_at=_TS,
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# §10.2 — Key grammar
# ---------------------------------------------------------------------------


def test_key_bounds_constants() -> None:
    assert IDEMPOTENCY_KEY_MIN_LENGTH == 1
    assert IDEMPOTENCY_KEY_MAX_LENGTH == 128


def test_validate_key_happy_path() -> None:
    assert validate_idempotency_key("abc-123_XYZ") == []


def test_validate_key_rejects_empty() -> None:
    errors = validate_idempotency_key("")
    assert any(e.code == "idempotency_key_too_short" for e in errors)


def test_validate_key_accepts_single_char() -> None:
    assert validate_idempotency_key("a") == []


def test_validate_key_accepts_128_chars() -> None:
    assert validate_idempotency_key("a" * 128) == []


def test_validate_key_rejects_129_chars() -> None:
    errors = validate_idempotency_key("a" * 129)
    assert any(e.code == "idempotency_key_too_long" for e in errors)


def test_validate_key_rejects_control_character() -> None:
    errors = validate_idempotency_key("ab\x01cd")
    assert any(e.code == "idempotency_key_invalid_char" for e in errors)


def test_validate_key_rejects_tab() -> None:
    errors = validate_idempotency_key("ab\tcd")
    assert any(e.code == "idempotency_key_invalid_char" for e in errors)


def test_validate_key_rejects_newline() -> None:
    errors = validate_idempotency_key("ab\ncd")
    assert errors


def test_validate_key_rejects_non_ascii() -> None:
    errors = validate_idempotency_key("café")
    assert any(e.code == "idempotency_key_invalid_char" for e in errors)


def test_validate_key_accepts_space() -> None:
    assert validate_idempotency_key("a b") == []


def test_validate_key_accepts_tilde() -> None:
    assert validate_idempotency_key("a~b") == []


def test_validate_key_rejects_non_string() -> None:
    errors = validate_idempotency_key(123)  # type: ignore[arg-type]
    assert any(e.code == "idempotency_key_type" for e in errors)


def test_is_valid_idempotency_key_true() -> None:
    assert is_valid_idempotency_key("abc123") is True


def test_is_valid_idempotency_key_false() -> None:
    assert is_valid_idempotency_key("") is False
    assert is_valid_idempotency_key("a" * 200) is False


# ---------------------------------------------------------------------------
# §10.1 — Scope tuple
# ---------------------------------------------------------------------------


def test_scope_tuple_from_envelope() -> None:
    scope = scope_tuple(_envelope())
    assert scope.from_agent == _SENDER
    assert scope.to_agent == _RECIPIENT
    assert scope.payload_type == _PAYLOAD_TYPE


def test_scope_tuple_is_hashable() -> None:
    s1 = scope_tuple(_envelope())
    s2 = scope_tuple(_envelope())
    assert hash(s1) == hash(s2)
    assert s1 == s2


def test_scope_tuple_frozen() -> None:
    scope = scope_tuple(_envelope())
    with pytest.raises(Exception):
        scope.from_agent = "other"  # type: ignore[misc]


def test_scope_tuple_missing_from_raises() -> None:
    env = _envelope()
    del env["from"]
    with pytest.raises(ValueError):
        scope_tuple(env)


def test_scope_tuple_missing_to_raises() -> None:
    env = _envelope()
    del env["to"]
    with pytest.raises(ValueError):
        scope_tuple(env)


def test_scope_tuple_missing_payload_type_raises() -> None:
    env = _envelope()
    del env["payload"]["type"]
    with pytest.raises(ValueError):
        scope_tuple(env)


def test_scope_tuple_distinguishes_different_payload_types() -> None:
    s1 = scope_tuple(_envelope(payload_type="a.b"))
    s2 = scope_tuple(_envelope(payload_type="a.c"))
    assert s1 != s2


# ---------------------------------------------------------------------------
# §10.4 — Header vs envelope precedence
# ---------------------------------------------------------------------------


def test_resolve_idempotency_key_header_wins() -> None:
    envelope = _envelope(idempotency={"key": "env-key", "expires_at": _FUTURE_TS})
    assert resolve_idempotency_key(envelope, header_key="hdr-key") == "hdr-key"


def test_resolve_idempotency_key_empty_header_falls_back_to_envelope() -> None:
    envelope = _envelope(idempotency={"key": "env-key", "expires_at": _FUTURE_TS})
    assert resolve_idempotency_key(envelope, header_key="") == "env-key"


def test_resolve_idempotency_key_envelope_only() -> None:
    envelope = _envelope(idempotency={"key": "env-key", "expires_at": _FUTURE_TS})
    assert resolve_idempotency_key(envelope) == "env-key"


def test_resolve_idempotency_key_header_only() -> None:
    envelope = _envelope()
    assert resolve_idempotency_key(envelope, header_key="hdr-key") == "hdr-key"


def test_resolve_idempotency_key_neither_returns_none() -> None:
    assert resolve_idempotency_key(_envelope()) is None


def test_resolve_idempotency_key_malformed_envelope_returns_none() -> None:
    envelope = _envelope()
    envelope["idempotency"] = "malformed"  # type: ignore[assignment]
    assert resolve_idempotency_key(envelope) is None


# ---------------------------------------------------------------------------
# §10.3 — Expiry
# ---------------------------------------------------------------------------


def test_is_idempotency_record_expired_future_false() -> None:
    assert is_idempotency_record_expired(_FUTURE_TS) is False


def test_is_idempotency_record_expired_past_true() -> None:
    assert is_idempotency_record_expired(_PAST_TS) is True


def test_is_idempotency_record_expired_with_injected_now() -> None:
    now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    assert (
        is_idempotency_record_expired("2026-04-14T11:59:59.000Z", now=now)
        is True
    )
    assert (
        is_idempotency_record_expired("2026-04-14T12:00:01.000Z", now=now)
        is False
    )


def test_is_idempotency_record_expired_malformed_returns_true() -> None:
    assert is_idempotency_record_expired("not-a-timestamp") is True


def test_is_idempotency_record_expired_naive_now_treated_as_utc() -> None:
    now = datetime(2026, 4, 14, 12, 0, 0)
    assert is_idempotency_record_expired(_FUTURE_TS, now=now) is False


# ---------------------------------------------------------------------------
# IdempotencyRecord model
# ---------------------------------------------------------------------------


def test_idempotency_record_accepts_valid_input() -> None:
    record = _record()
    assert record.key == "k1"
    assert record.expires_at == _FUTURE_TS


def test_idempotency_record_rejects_bad_key() -> None:
    with pytest.raises(ValueError):
        IdempotencyRecord(
            key="bad\tkey",
            from_agent=_SENDER,
            to_agent=_RECIPIENT,
            payload_type=_PAYLOAD_TYPE,
            message_id=_MSG_ID,
            stored_at=_TS,
            expires_at=_FUTURE_TS,
        )


def test_idempotency_record_rejects_bad_timestamp_pattern() -> None:
    with pytest.raises(ValueError):
        IdempotencyRecord(
            key="k1",
            from_agent=_SENDER,
            to_agent=_RECIPIENT,
            payload_type=_PAYLOAD_TYPE,
            message_id=_MSG_ID,
            stored_at=_TS,
            expires_at="2026-04-14",
        )


def test_idempotency_record_fingerprint_optional() -> None:
    record = _record(fingerprint=None)
    assert record.response_fingerprint is None


def test_idempotency_record_fingerprint_stored() -> None:
    record = _record(fingerprint="sha256:abc")
    assert record.response_fingerprint == "sha256:abc"


def test_idempotency_record_extra_fields_rejected() -> None:
    with pytest.raises(ValueError):
        IdempotencyRecord(
            key="k1",
            from_agent=_SENDER,
            to_agent=_RECIPIENT,
            payload_type=_PAYLOAD_TYPE,
            message_id=_MSG_ID,
            stored_at=_TS,
            expires_at=_FUTURE_TS,
            extra="x",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# InMemoryIdempotencyStore
# ---------------------------------------------------------------------------


def test_store_starts_empty() -> None:
    store = InMemoryIdempotencyStore()
    assert len(store) == 0


def test_store_put_then_get() -> None:
    store = InMemoryIdempotencyStore()
    record = _record(key="k1")
    store.put(record)
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    fetched = store.get(scope, "k1")
    assert fetched is not None
    assert fetched.key == "k1"


def test_store_get_missing_returns_none() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    assert store.get(scope, "missing") is None


def test_store_duplicate_put_raises() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1"))
    with pytest.raises(DuplicateIdempotencyKey):
        store.put(_record(key="k1"))


def test_store_different_scope_no_collision() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1", to_agent="agent:acme.beta"))
    store.put(_record(key="k1", to_agent="agent:acme.gamma"))
    assert len(store) == 2


def test_store_different_payload_type_no_collision() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1", payload_type="a.b"))
    store.put(_record(key="k1", payload_type="a.c"))
    assert len(store) == 2


def test_store_expired_record_purged_on_get() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1", expires_at=_PAST_TS))
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    assert store.get(scope, "k1") is None
    assert len(store) == 0


def test_store_put_allowed_after_expired_record_purged() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1", expires_at=_PAST_TS))
    # Access triggers purge; subsequent put with same key succeeds.
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.get(scope, "k1")
    store.put(_record(key="k1"))
    assert store.get(scope, "k1") is not None


def test_store_put_over_expired_record_succeeds() -> None:
    """put() treats an expired existing record as absent."""
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1", expires_at=_PAST_TS))
    # Do not call get() — put() itself should accept the new record.
    store.put(_record(key="k1"))
    assert len(store) == 1


def test_store_clear() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1"))
    store.put(_record(key="k2"))
    store.clear()
    assert len(store) == 0


def test_store_implements_protocol() -> None:
    store = InMemoryIdempotencyStore()
    assert isinstance(store, IdempotencyStore)


def test_store_is_thread_safe_under_contention() -> None:
    store = InMemoryIdempotencyStore()
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            store.put(_record(key=f"k{i}"))
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(store) == 50


def test_duplicate_error_exposes_scope_and_key() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1"))
    with pytest.raises(DuplicateIdempotencyKey) as exc_info:
        store.put(_record(key="k1"))
    err = exc_info.value
    assert err.key == "k1"
    assert err.scope.from_agent == _SENDER


# ---------------------------------------------------------------------------
# extract_envelope_idempotency
# ---------------------------------------------------------------------------


def test_extract_envelope_idempotency_present() -> None:
    envelope = _envelope(idempotency={"key": "k1", "expires_at": _FUTURE_TS})
    obj = extract_envelope_idempotency(envelope)
    assert obj is not None
    assert obj.key == "k1"
    assert obj.expires_at == _FUTURE_TS


def test_extract_envelope_idempotency_absent() -> None:
    assert extract_envelope_idempotency(_envelope()) is None


def test_extract_envelope_idempotency_malformed_raises() -> None:
    envelope = _envelope()
    envelope["idempotency"] = "not-a-mapping"  # type: ignore[assignment]
    with pytest.raises(ValueError):
        extract_envelope_idempotency(envelope)


def test_extract_envelope_idempotency_returns_pydantic_model() -> None:
    from arsia_protocol.types.envelope import ArsiaIdempotency

    envelope = _envelope(idempotency={"key": "k1", "expires_at": _FUTURE_TS})
    obj = extract_envelope_idempotency(envelope)
    assert isinstance(obj, ArsiaIdempotency)


# ---------------------------------------------------------------------------
# §10.2(2) — Header-only 24-hour retention floor (G-4)
# ---------------------------------------------------------------------------


def test_header_only_retention_hours_is_24() -> None:
    assert HEADER_ONLY_RETENTION_HOURS == 24


def test_resolve_idempotency_source_header_only() -> None:
    envelope = _envelope()
    key, source = resolve_idempotency_source(envelope, header_key="hdr-key")
    assert key == "hdr-key"
    assert source == "header"


def test_resolve_idempotency_source_envelope_only() -> None:
    envelope = _envelope(idempotency={"key": "env-key", "expires_at": _FUTURE_TS})
    key, source = resolve_idempotency_source(envelope)
    assert key == "env-key"
    assert source == "envelope"


def test_resolve_idempotency_source_both_present_source_is_envelope() -> None:
    """Header wins for key detection but envelope authorises retention."""
    envelope = _envelope(idempotency={"key": "env-key", "expires_at": _FUTURE_TS})
    key, source = resolve_idempotency_source(envelope, header_key="hdr-key")
    assert key == "hdr-key"
    assert source == "envelope"


def test_resolve_idempotency_source_neither() -> None:
    key, source = resolve_idempotency_source(_envelope())
    assert key is None
    assert source is None


def test_compute_idempotency_expiry_uses_envelope_when_present() -> None:
    out = compute_idempotency_expiry(_FUTURE_TS, header_only=False)
    assert out == _FUTURE_TS


def test_compute_idempotency_expiry_uses_envelope_even_when_header_only() -> None:
    """§10.4(3): envelope expires_at is authoritative regardless of source."""
    out = compute_idempotency_expiry(_FUTURE_TS, header_only=True)
    assert out == _FUTURE_TS


def test_compute_idempotency_expiry_header_only_applies_24h_floor() -> None:
    now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    out = compute_idempotency_expiry(None, header_only=True, now=now)
    assert out == "2026-04-15T12:00:00.000Z"


def test_compute_idempotency_expiry_default_applies_24h_floor() -> None:
    now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    out = compute_idempotency_expiry(None, header_only=False, now=now)
    assert out == "2026-04-15T12:00:00.000Z"


def test_compute_idempotency_expiry_format_is_rfc3339_ms() -> None:
    out = compute_idempotency_expiry(None, header_only=True)
    assert out.endswith("Z")
    assert len(out) == len("YYYY-MM-DDTHH:MM:SS.mmmZ")


# ---------------------------------------------------------------------------
# §10.3 — In-progress lifecycle (G-3)
# ---------------------------------------------------------------------------


def test_store_mark_pending_new_key_returns_true() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    assert store.mark_pending(scope, "k1") is True


def test_store_mark_pending_duplicate_returns_false() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_pending(scope, "k1")
    assert store.mark_pending(scope, "k1") is False


def test_store_mark_pending_over_completed_returns_false() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.put(_record(key="k1"))
    assert store.mark_pending(scope, "k1") is False


def test_store_mark_pending_over_expired_completed_succeeds() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.put(_record(key="k1", expires_at=_PAST_TS))
    assert store.mark_pending(scope, "k1") is True


def test_store_get_returns_none_while_pending() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_pending(scope, "k1")
    assert store.get(scope, "k1") is None


def test_store_mark_complete_transitions_pending_to_completed() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_pending(scope, "k1")
    store.mark_complete(_record(key="k1"))
    fetched = store.get(scope, "k1")
    assert fetched is not None
    assert fetched.key == "k1"


def test_store_mark_complete_without_prior_pending_stores_completed() -> None:
    """Back-compat: mark_complete behaves like put when no entry exists."""
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_complete(_record(key="k1"))
    assert store.check_status(scope, "k1") == "completed"


def test_store_mark_complete_over_completed_raises() -> None:
    store = InMemoryIdempotencyStore()
    store.put(_record(key="k1"))
    with pytest.raises(DuplicateIdempotencyKey):
        store.mark_complete(_record(key="k1"))


def test_store_check_status_new() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    assert store.check_status(scope, "k1") == "new"


def test_store_check_status_pending() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_pending(scope, "k1")
    assert store.check_status(scope, "k1") == "pending"


def test_store_check_status_completed() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.put(_record(key="k1"))
    assert store.check_status(scope, "k1") == "completed"


def test_store_check_status_lifecycle_transitions() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    assert store.check_status(scope, "k1") == "new"
    store.mark_pending(scope, "k1")
    assert store.check_status(scope, "k1") == "pending"
    store.mark_complete(_record(key="k1"))
    assert store.check_status(scope, "k1") == "completed"


def test_store_check_status_expired_completed_reports_new() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.put(_record(key="k1", expires_at=_PAST_TS))
    assert store.check_status(scope, "k1") == "new"


def test_store_put_over_pending_transitions_to_completed() -> None:
    """put() is the legacy completion path; it must accept a pending entry."""
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_pending(scope, "k1")
    store.put(_record(key="k1"))
    assert store.check_status(scope, "k1") == "completed"


def test_duplicate_request_in_progress_carries_scope_and_key() -> None:
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    err = DuplicateRequestInProgress(scope, "k1")
    assert err.scope == scope
    assert err.key == "k1"
    assert "k1" in str(err)
    assert "in-progress" in str(err)


def test_idempotency_store_protocol_default_mark_pending_raises() -> None:
    """Protocol default bodies signal missing implementations clearly."""
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    with pytest.raises(NotImplementedError):
        IdempotencyStore.mark_pending(None, scope, "k1")  # type: ignore[arg-type]


def test_idempotency_store_protocol_default_check_status_raises() -> None:
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    with pytest.raises(NotImplementedError):
        IdempotencyStore.check_status(None, scope, "k1")  # type: ignore[arg-type]


def test_idempotency_store_protocol_default_mark_complete_raises() -> None:
    with pytest.raises(NotImplementedError):
        IdempotencyStore.mark_complete(None, _record(key="k1"))  # type: ignore[arg-type]


def test_idempotency_store_protocol_default_store_response_raises() -> None:
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    with pytest.raises(NotImplementedError):
        IdempotencyStore.store_response(  # type: ignore[arg-type]
            None, scope, "k1", b"bytes"
        )


def test_idempotency_store_protocol_default_get_response_raises() -> None:
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    with pytest.raises(NotImplementedError):
        IdempotencyStore.get_response(None, scope, "k1")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §10.3 — Response replay (store_response / get_response)
# ---------------------------------------------------------------------------


def test_store_response_returned_after_mark_complete() -> None:
    """Spec: ARSIA-Core.md §10.3 Rule 3 — replay stored response bytes."""
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    assert store.mark_pending(scope, "k1") is True
    store.store_response(scope, "k1", b"signed-envelope-bytes")
    store.mark_complete(_record(key="k1"))
    assert store.get_response(scope, "k1") == b"signed-envelope-bytes"


def test_store_response_none_when_no_entry() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    assert store.get_response(scope, "k1") is None


def test_store_response_none_while_pending() -> None:
    """Pending entries do not surface their stored bytes (§10.3 Rule 4)."""
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_pending(scope, "k1")
    store.store_response(scope, "k1", b"premature")
    assert store.get_response(scope, "k1") is None


def test_store_response_purged_when_record_expires() -> None:
    """Expired entries purge response bytes alongside the record (§10.2(4))."""
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_complete(_record(key="k1", expires_at=_PAST_TS))
    store.store_response(scope, "k1", b"stale")
    assert store.get_response(scope, "k1") is None
    # And the record itself is purged on the same access.
    assert store.check_status(scope, "k1") == "new"


def test_store_response_replaced_by_subsequent_call() -> None:
    """Last-write-wins for the same scope+key while still completed."""
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_complete(_record(key="k1"))
    store.store_response(scope, "k1", b"first")
    store.store_response(scope, "k1", b"second")
    assert store.get_response(scope, "k1") == b"second"


def test_store_response_scope_isolation() -> None:
    """Different payload_type scopes do not share response bytes."""
    store = InMemoryIdempotencyStore()
    scope_a = IdempotencyScope(_SENDER, _RECIPIENT, "arsiaprotocol.state/set")
    scope_b = IdempotencyScope(_SENDER, _RECIPIENT, "arsiaprotocol.state/query")
    store.mark_complete(_record(key="k1", payload_type="arsiaprotocol.state/set"))
    store.mark_complete(_record(key="k1", payload_type="arsiaprotocol.state/query"))
    store.store_response(scope_a, "k1", b"set-response")
    store.store_response(scope_b, "k1", b"query-response")
    assert store.get_response(scope_a, "k1") == b"set-response"
    assert store.get_response(scope_b, "k1") == b"query-response"


def test_store_clear_drops_responses() -> None:
    store = InMemoryIdempotencyStore()
    scope = IdempotencyScope(_SENDER, _RECIPIENT, _PAYLOAD_TYPE)
    store.mark_complete(_record(key="k1"))
    store.store_response(scope, "k1", b"bytes")
    store.clear()
    assert store.get_response(scope, "k1") is None
    assert len(store) == 0


# ---------------------------------------------------------------------------
# §10.4 — Idempotency discrepancy logging (CORE-§10.4-02)
# ---------------------------------------------------------------------------


def test_resolve_idempotency_key_discrepancy_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Header vs envelope key mismatch MUST log a warning."""
    env = _envelope(idempotency={"key": "envelope-key-1"})
    with caplog.at_level(logging.WARNING, logger="arsia_protocol.core.idempotency"):
        result = resolve_idempotency_key(env, header_key="header-key-2")
    assert result == "header-key-2"
    assert any("Idempotency key discrepancy" in r.message for r in caplog.records)


def test_resolve_idempotency_key_matching_no_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Matching header and envelope keys MUST NOT log."""
    env = _envelope(idempotency={"key": "same-key"})
    with caplog.at_level(logging.WARNING, logger="arsia_protocol.core.idempotency"):
        result = resolve_idempotency_key(env, header_key="same-key")
    assert result == "same-key"
    assert not any("Idempotency key discrepancy" in r.message for r in caplog.records)
