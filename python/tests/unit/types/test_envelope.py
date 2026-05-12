# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.envelope``.

Spec: ARSIA-Core.md §4 and ``shared/schemas/arsia-message.schema.json``.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from arsia_protocol.types.envelope import (
    ArsiaContext,
    ArsiaIdempotency,
    ArsiaMessage,
    ArsiaPayload,
)


def _base_request_kwargs() -> dict[str, Any]:
    return {
        "v": "1.0",
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "ts": "2026-03-24T10:15:30.000Z",
        "from": "agent:acme.billing",
        "to": "agent:acme.payments",
        "intent": "request",
        "expires_at": "2026-03-24T10:16:00.000Z",
        "capabilities": ["payments.charge"],
    }


def test_arsia_message_required_fields() -> None:
    """A minimal valid request envelope constructs successfully.

    Spec: ARSIA-Core.md §4.1-§4.2.
    """
    msg = ArsiaMessage(**_base_request_kwargs())
    assert msg.v == "1.0"
    assert msg.intent == "request"
    assert msg.from_ == "agent:acme.billing"


def test_arsia_message_from_alias_in_json() -> None:
    """``from_`` serialises as ``"from"`` with ``by_alias=True``.

    Spec: ARSIA-Core.md §4.1.4.
    """
    msg = ArsiaMessage(**_base_request_kwargs())
    dumped = msg.model_dump(by_alias=True, exclude_none=True)
    assert "from" in dumped
    assert "from_" not in dumped
    assert dumped["from"] == "agent:acme.billing"


def test_arsia_message_populate_by_name() -> None:
    """``from_`` can also be passed by attribute name.

    Spec: ARSIA-Core.md §4.1.4 (with Pydantic populate_by_name).
    """
    kwargs = _base_request_kwargs()
    del kwargs["from"]
    kwargs["from_"] = "agent:acme.billing"
    msg = ArsiaMessage(**kwargs)
    assert msg.from_ == "agent:acme.billing"


def test_arsia_message_rejects_invalid_version() -> None:
    """``v`` must match ``^\\d+\\.\\d+$``.

    Spec: ARSIA-Core.md §4.1.1.
    """
    kwargs = _base_request_kwargs()
    kwargs["v"] = "abc"
    with pytest.raises(ValidationError):
        ArsiaMessage(**kwargs)


def test_arsia_message_rejects_invalid_uuid() -> None:
    """``id`` must be a valid UUID v4.

    Spec: ARSIA-Core.md §4.1.2.
    """
    kwargs = _base_request_kwargs()
    kwargs["id"] = "not-a-uuid"
    with pytest.raises(ValidationError):
        ArsiaMessage(**kwargs)


def test_arsia_message_rejects_bad_timestamp() -> None:
    """``ts`` must match RFC 3339 with millisecond precision.

    Spec: ARSIA-Core.md §4.1.3.
    """
    kwargs = _base_request_kwargs()
    kwargs["ts"] = "2026-03-24 10:15:30"
    with pytest.raises(ValidationError):
        ArsiaMessage(**kwargs)


def test_arsia_message_rejects_invalid_from_agent_id() -> None:
    """``from`` must be a valid agent identifier.

    Spec: ARSIA-Core.md §3.3, §4.1.4.
    """
    kwargs = _base_request_kwargs()
    kwargs["from"] = "not-an-agent-id"
    with pytest.raises(ValidationError):
        ArsiaMessage(**kwargs)


def test_arsia_message_rejects_invalid_to_agent_id() -> None:
    """``to`` must be a valid agent identifier.

    Spec: ARSIA-Core.md §3.3, §4.1.5.
    """
    kwargs = _base_request_kwargs()
    kwargs["to"] = "user:acme.payments"
    with pytest.raises(ValidationError):
        ArsiaMessage(**kwargs)


def test_arsia_message_request_requires_expires_at() -> None:
    """An envelope with intent='request' must include expires_at.

    Spec: ARSIA-Core.md §4.2.2.
    """
    kwargs = _base_request_kwargs()
    del kwargs["expires_at"]
    with pytest.raises(ValidationError, match="expires_at is required"):
        ArsiaMessage(**kwargs)


def test_arsia_message_request_requires_capabilities() -> None:
    """An envelope with intent='request' must include capabilities.

    Spec: ARSIA-Core.md §4.2.3.
    """
    kwargs = _base_request_kwargs()
    del kwargs["capabilities"]
    with pytest.raises(ValidationError, match="capabilities is required"):
        ArsiaMessage(**kwargs)


def test_arsia_message_response_requires_correlation_id() -> None:
    """An envelope with intent='response' must include correlation_id.

    Spec: ARSIA-Core.md §4.2.1.
    """
    kwargs = _base_request_kwargs()
    del kwargs["expires_at"]
    del kwargs["capabilities"]
    kwargs["intent"] = "response"
    with pytest.raises(ValidationError, match="correlation_id is required"):
        ArsiaMessage(**kwargs)


def test_arsia_message_error_requires_correlation_id() -> None:
    """An envelope with intent='error' must include correlation_id.

    Spec: ARSIA-Core.md §4.2.1.
    """
    kwargs = _base_request_kwargs()
    del kwargs["expires_at"]
    del kwargs["capabilities"]
    kwargs["intent"] = "error"
    with pytest.raises(ValidationError, match="correlation_id is required"):
        ArsiaMessage(**kwargs)


def test_arsia_message_pending_approval_requires_expires_at() -> None:
    """An envelope with intent='pending_approval' must include expires_at.

    Spec: ARSIA-Core.md §4.2.2.
    """
    kwargs = _base_request_kwargs()
    del kwargs["expires_at"]
    del kwargs["capabilities"]
    kwargs["intent"] = "pending_approval"
    with pytest.raises(ValidationError, match="expires_at is required"):
        ArsiaMessage(**kwargs)


def test_arsia_message_event_no_conditionals() -> None:
    """An envelope with intent='event' has no conditional-required fields.

    Spec: ARSIA-Core.md §4.1.6.
    """
    kwargs = _base_request_kwargs()
    del kwargs["expires_at"]
    del kwargs["capabilities"]
    kwargs["intent"] = "event"
    msg = ArsiaMessage(**kwargs)
    assert msg.intent == "event"


def test_arsia_message_all_six_intents_accepted() -> None:
    """Each of the six intent values is a valid Literal member.

    Spec: ARSIA-Core.md §4.1.6.
    """
    intents: list[tuple[str, dict[str, Any]]] = [
        ("request", {"expires_at": "2026-03-24T10:16:00.000Z", "capabilities": ["x.y"]}),
        ("response", {"correlation_id": "550e8400-e29b-41d4-a716-446655440000"}),
        ("event", {}),
        ("error", {"correlation_id": "550e8400-e29b-41d4-a716-446655440000"}),
        ("pending_approval", {"expires_at": "2026-03-24T10:16:00.000Z"}),
        ("approval_decision", {"correlation_id": "550e8400-e29b-41d4-a716-446655440000"}),
    ]
    for intent, extras in intents:
        kwargs = _base_request_kwargs()
        del kwargs["expires_at"]
        del kwargs["capabilities"]
        kwargs["intent"] = intent
        kwargs.update(extras)
        msg = ArsiaMessage(**kwargs)
        assert msg.intent == intent


def test_arsia_message_rejects_unknown_intent() -> None:
    """Unknown intent values are rejected by the Literal type.

    Spec: ARSIA-Core.md §4.1.6.
    """
    kwargs = _base_request_kwargs()
    kwargs["intent"] = "ping"
    with pytest.raises(ValidationError):
        ArsiaMessage(**kwargs)


def test_arsia_message_rejects_duplicate_capabilities() -> None:
    """Duplicate capability strings are rejected.

    Spec: ARSIA-Core.md §4.2.3.
    """
    kwargs = _base_request_kwargs()
    kwargs["capabilities"] = ["payments.charge", "payments.charge"]
    with pytest.raises(ValidationError, match="unique"):
        ArsiaMessage(**kwargs)


def test_arsia_message_rejects_empty_capabilities() -> None:
    """Empty capabilities array is rejected.

    Spec: ARSIA-Core.md §4.2.3.
    """
    kwargs = _base_request_kwargs()
    kwargs["capabilities"] = []
    with pytest.raises(ValidationError):
        ArsiaMessage(**kwargs)


def test_arsia_message_ignores_unknown_top_level_fields() -> None:
    """Forward compatibility: unknown top-level fields are ignored.

    Minor version differences within the same major version MUST be handled
    gracefully — unknown fields introduced in a later minor version are
    silently ignored by the envelope model, so a v="1.0" implementation
    still accepts a message that adds a new optional field.

    Spec: ARSIA-Core.md §4.1.1, §7.4.
    """
    kwargs = _base_request_kwargs()
    kwargs["future_field"] = "value"
    msg = ArsiaMessage(**kwargs)
    dumped = msg.model_dump(by_alias=True, exclude_none=True)
    assert "future_field" not in dumped


def test_arsia_message_sub_models_still_forbid_extra_fields() -> None:
    """Forward compat applies to the top-level envelope only.

    Sub-models retain ``extra="forbid"`` because unknown fields inside
    a sub-model would change the semantics of a known structure rather
    than add a new optional field.

    Spec: ARSIA-Core.md §4.1.1 (scope of graceful handling).
    """
    with pytest.raises(ValidationError):
        ArsiaIdempotency(
            key="k1",
            expires_at="2026-03-24T10:16:00.000Z",
            unknown="x",  # type: ignore[call-arg]
        )


def test_arsia_payload_type_required() -> None:
    """``ArsiaPayload`` requires ``type``.

    Spec: ARSIA-Core.md §4.4.1.
    """
    with pytest.raises(ValidationError):
        ArsiaPayload()  # type: ignore[call-arg]


def test_arsia_payload_type_pattern_enforced() -> None:
    """Payload types not matching the reverse-domain pattern are rejected.

    Spec: ARSIA-Core.md §4.4.1.
    """
    with pytest.raises(ValidationError):
        ArsiaPayload(type="NOT A TYPE")


def test_arsia_context_accepts_all_optional_fields() -> None:
    """``ArsiaContext`` accepts trace/span/flags/locale/priority.

    Spec: ARSIA-Core.md §4.3.3.
    """
    ctx = ArsiaContext(
        trace_id="0af7651916cd43dd8448eb211c80319c",
        span_id="b7ad6b7169203331",
        flags=1,
        locale="pt-PT",
        priority=8,
    )
    assert ctx.priority == 8


def test_arsia_idempotency_key_length() -> None:
    """Idempotency key must be 1-128 characters.

    Spec: ARSIA-Core.md §4.3.2.
    """
    with pytest.raises(ValidationError):
        ArsiaIdempotency(key="", expires_at="2026-03-24T10:16:00.000Z")
    with pytest.raises(ValidationError):
        ArsiaIdempotency(key="x" * 129, expires_at="2026-03-24T10:16:00.000Z")
    ok = ArsiaIdempotency(key="k", expires_at="2026-03-24T10:16:00.000Z")
    assert ok.key == "k"


def test_arsia_message_schema_example_request_roundtrip() -> None:
    """The first schema example constructs and dumps to the same shape.

    Spec: ``shared/schemas/arsia-message.schema.json`` examples[0].
    """
    example = {
        "v": "1.0",
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "ts": "2026-03-24T10:15:30.000Z",
        "from": "agent:acme.billing",
        "to": "agent:acme.payments",
        "intent": "request",
        "expires_at": "2026-03-24T10:16:00.000Z",
        "capabilities": ["payments.charge"],
        "payload": {
            "type": "com.acme.payments/charge",
            "args": {"amount": 100.00, "currency": "EUR"},
        },
        "security": {
            "alg": "EdDSA",
            "kid": "agent:acme.billing#key1",
            "sig": "base64url-encoded-signature-placeholder",
        },
    }
    msg = ArsiaMessage(**example)
    round = msg.model_dump(by_alias=True, exclude_none=True)
    assert round["from"] == example["from"]
    assert round["payload"]["type"] == "com.acme.payments/charge"
