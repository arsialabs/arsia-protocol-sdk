# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.message``.

Covers the envelope factory functions (Core §4), the timestamp and
expiration helpers (Core §4.1.3, §8.3), and the high-level
signing/verification workflow (Core §5.1, §5.2).
"""

from __future__ import annotations

import copy
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair
from arsia_protocol.core.message import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    DEFAULT_MAX_MESSAGE_BYTES,
    PENDING_APPROVAL_CONTEXT_MAX_LENGTH,
    PROTOCOL_VERSION,
    check_envelope_size,
    create_approval_decision,
    create_error,
    create_event,
    create_pending_approval,
    create_request,
    create_response,
    format_timestamp,
    is_expired,
    sign_message,
    verify_message,
)

_TS_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_UUID_V4_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

_ACME = "agent:acme.echo-client"
_RISK = "agent:arsialabs.demo.risk-assessor"


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


# ---------------------------------------------------------------------------
# create_request
# ---------------------------------------------------------------------------


def test_create_request_required_fields() -> None:
    """create_request populates every required envelope field.

    Spec: ARSIA-Core.md §4.1, §4.2.2, §4.2.3.
    """
    env = create_request(_ACME, _RISK, "com.example.notes/get", ["notes.read"])
    assert env["v"] == PROTOCOL_VERSION
    assert env["from"] == _ACME
    assert env["to"] == _RISK
    assert env["intent"] == "request"
    assert env["payload"]["type"] == "com.example.notes/get"
    assert env["capabilities"] == ["notes.read"]
    assert "id" in env and "ts" in env and "expires_at" in env


def test_create_request_auto_uuid() -> None:
    """The generated ``id`` is a valid UUID v4.

    Spec: ARSIA-Core.md §4.1.2.
    """
    env = create_request(_ACME, _RISK, "com.example.ping", ["ping.call"])
    assert _UUID_V4_PATTERN.match(env["id"])
    parsed = uuid.UUID(env["id"])
    assert parsed.version == 4


def test_create_request_auto_timestamp() -> None:
    """``ts`` matches the RFC 3339 millisecond pattern with ``Z``.

    Spec: ARSIA-Core.md §4.1.3.
    """
    env = create_request(_ACME, _RISK, "com.example.ping", ["ping.call"])
    assert _TS_PATTERN.match(env["ts"]) is not None


def test_create_request_expires_at_default() -> None:
    """Default expiry is ~300 s after ``ts``.

    Spec: ARSIA-Core.md §4.2.2.
    """
    env = create_request(_ACME, _RISK, "com.example.ping", ["ping.call"])
    ts = _parse_ts(env["ts"])
    expires_at = _parse_ts(env["expires_at"])
    delta = (expires_at - ts).total_seconds()
    assert delta == pytest.approx(300.0, abs=0.01)


def test_create_request_expires_at_custom() -> None:
    """Custom ``expires_in_seconds`` produces the correct offset.

    Spec: ARSIA-Core.md §4.2.2.
    """
    env = create_request(
        _ACME,
        _RISK,
        "com.example.ping",
        ["ping.call"],
        expires_in_seconds=600,
    )
    ts = _parse_ts(env["ts"])
    expires_at = _parse_ts(env["expires_at"])
    delta = (expires_at - ts).total_seconds()
    assert delta == pytest.approx(600.0, abs=0.01)


def test_create_request_with_args() -> None:
    """``payload.args`` is populated when supplied.

    Spec: ARSIA-Core.md §4.4.3.
    """
    env = create_request(
        _ACME,
        _RISK,
        "com.example.notes/get",
        ["notes.read"],
        args={"note_id": "abc"},
    )
    assert env["payload"]["args"] == {"note_id": "abc"}


def test_create_request_with_compliance() -> None:
    """``compliance`` is attached at the envelope root when supplied.

    Spec: ARSIA-Core.md §4.3.6.
    """
    env = create_request(
        _ACME,
        _RISK,
        "com.example.ping",
        ["ping.call"],
        compliance={"profile": "GDPR-STANDARD"},
    )
    assert env["compliance"] == {"profile": "GDPR-STANDARD"}


def test_create_request_with_context() -> None:
    """``context`` is attached when supplied.

    Spec: ARSIA-Core.md §4.3.3.
    """
    env = create_request(
        _ACME,
        _RISK,
        "com.example.ping",
        ["ping.call"],
        context={"locale": "pt-PT"},
    )
    assert env["context"] == {"locale": "pt-PT"}


def test_create_request_with_idempotency() -> None:
    """``idempotency`` is attached when supplied.

    Spec: ARSIA-Core.md §4.3.2.
    """
    idem = {"key": "abc-123", "expires_at": "2026-05-01T00:00:00.000Z"}
    env = create_request(
        _ACME,
        _RISK,
        "com.example.ping",
        ["ping.call"],
        idempotency=idem,
    )
    assert env["idempotency"] == idem


def test_create_request_with_min_v() -> None:
    """``min_v`` is attached when supplied.

    Spec: ARSIA-Core.md §4.3.1.
    """
    env = create_request(
        _ACME,
        _RISK,
        "com.example.ping",
        ["ping.call"],
        min_v="1.0",
    )
    assert env["min_v"] == "1.0"


def test_create_request_invalid_from() -> None:
    """An invalid ``from`` agent identifier raises ValueError.

    Spec: ARSIA-Core.md §3.3, §4.1.4.
    """
    with pytest.raises(ValueError, match="'from'"):
        create_request("not-an-agent", _RISK, "com.x.y", ["cap"])


def test_create_request_invalid_to() -> None:
    """An invalid ``to`` agent identifier raises ValueError.

    Spec: ARSIA-Core.md §3.3, §4.1.5.
    """
    with pytest.raises(ValueError, match="'to'"):
        create_request(_ACME, "not-an-agent", "com.x.y", ["cap"])


def test_create_request_capabilities_in_envelope_root() -> None:
    """``capabilities`` lives at the envelope root, not inside context.

    Spec: ARSIA-Core.md §4.2.3.
    """
    env = create_request(_ACME, _RISK, "com.example.ping", ["ping.call", "ping.admin"])
    assert "capabilities" in env
    assert env.get("context") is None or "capabilities" not in env["context"]


# ---------------------------------------------------------------------------
# create_response
# ---------------------------------------------------------------------------


def test_create_response_required_fields() -> None:
    """Responses have correlation_id and intent='response'.

    Spec: ARSIA-Core.md §4.1, §4.2.1.
    """
    corr = str(uuid.uuid4())
    env = create_response(_RISK, _ACME, corr, "com.example.notes/get")
    assert env["intent"] == "response"
    assert env["correlation_id"] == corr


def test_create_response_with_result() -> None:
    """``payload.result`` is populated when supplied.

    Spec: ARSIA-Core.md §4.4.4.
    """
    env = create_response(
        _RISK,
        _ACME,
        str(uuid.uuid4()),
        "com.example.notes/get",
        result={"note": "hi"},
    )
    assert env["payload"]["result"] == {"note": "hi"}


def test_create_response_no_expires_at() -> None:
    """Responses never carry an ``expires_at``.

    Spec: ARSIA-Core.md §4.2.2.
    """
    env = create_response(_RISK, _ACME, str(uuid.uuid4()), "com.example.notes/get")
    assert "expires_at" not in env


# ---------------------------------------------------------------------------
# create_error
# ---------------------------------------------------------------------------


def test_create_error_required_fields() -> None:
    """Error envelopes have correlation_id, intent='error', payload.error.

    Spec: ARSIA-Core.md §4.1, §4.2.1, §4.4.6, §11.1.
    """
    corr = str(uuid.uuid4())
    env = create_error(_RISK, _ACME, corr, "invalid_request", "bad input")
    assert env["intent"] == "error"
    assert env["correlation_id"] == corr
    assert "error" in env["payload"]


def test_create_error_payload_error_structure() -> None:
    """``payload.error`` contains code and description.

    Spec: ARSIA-Core.md §4.4.6.
    """
    env = create_error(_RISK, _ACME, str(uuid.uuid4()), "unauthorized", "bad sig")
    err = env["payload"]["error"]
    assert err["code"] == "unauthorized"
    assert err["description"] == "bad sig"


def test_create_error_with_details() -> None:
    """``payload.error.details`` is populated when supplied.

    Spec: ARSIA-Core.md §4.4.6, §11.2.
    """
    env = create_error(
        _RISK,
        _ACME,
        str(uuid.uuid4()),
        "forbidden",
        "missing capability",
        details={
            "required_capabilities": ["notes.read"],
            "provided_capabilities": [],
        },
    )
    assert env["payload"]["error"]["details"]["required_capabilities"] == ["notes.read"]


def test_create_error_default_payload_type() -> None:
    """The default payload.type is ``org.arsiaprotocol.error``.

    Spec: ARSIA-Core.md §11.1.
    """
    env = create_error(_RISK, _ACME, str(uuid.uuid4()), "internal_error", "boom")
    assert env["payload"]["type"] == "org.arsiaprotocol.error"


# ---------------------------------------------------------------------------
# create_event
# ---------------------------------------------------------------------------


def test_create_event_required_fields() -> None:
    """Events have intent='event', no correlation_id, no expires_at.

    Spec: ARSIA-Core.md §4.1.
    """
    env = create_event(_ACME, _RISK, "com.example.notification")
    assert env["intent"] == "event"
    assert "correlation_id" not in env
    assert "expires_at" not in env


def test_create_event_with_data() -> None:
    """``payload.data`` is populated when supplied.

    Spec: ARSIA-Core.md §4.4.5.
    """
    env = create_event(
        _ACME,
        _RISK,
        "com.example.notification",
        data={"kind": "status_update"},
    )
    assert env["payload"]["data"] == {"kind": "status_update"}


# ---------------------------------------------------------------------------
# create_pending_approval
# ---------------------------------------------------------------------------


def test_create_pending_approval_fields() -> None:
    """pending_approval has correlation_id and expires_at, intent matches.

    Spec: ARSIA-Core.md §4.1, §4.2.1, §4.2.2.
    """
    corr = str(uuid.uuid4())
    env = create_pending_approval(_RISK, _ACME, corr, "com.example.notes/create")
    assert env["intent"] == "pending_approval"
    assert env["correlation_id"] == corr
    assert "expires_at" in env


def test_create_pending_approval_uses_args_not_result() -> None:
    """pending_approval content field is ``args``, per §4.4.7.

    Spec: ARSIA-Core.md §4.4.7.
    """
    env = create_pending_approval(
        _RISK,
        _ACME,
        str(uuid.uuid4()),
        "com.example.notes/create",
        args={"note": "hi"},
    )
    assert env["payload"]["args"] == {"note": "hi"}
    assert "result" not in env["payload"]


def test_create_pending_approval_context_at_1024_ok() -> None:
    """Spec: ARSIA-Actions.md §3.2 — context ≤ 1024 chars is accepted."""
    env = create_pending_approval(
        _RISK,
        _ACME,
        str(uuid.uuid4()),
        "com.example.notes/create",
        args={"context": "a" * 1024},
    )
    assert env["payload"]["args"]["context"] == "a" * 1024


def test_create_pending_approval_context_exceeds_1024_raises() -> None:
    """Spec: ARSIA-Actions.md §3.2 — context > 1024 chars raises."""
    with pytest.raises(ValueError, match="1024 characters"):
        create_pending_approval(
            _RISK,
            _ACME,
            str(uuid.uuid4()),
            "com.example.notes/create",
            args={"context": "a" * 1025},
        )


def test_create_pending_approval_with_explanation() -> None:
    """Spec: ARSIA-Actions.md §3.2 — explanation at payload level, not in args."""
    explanation = {
        "reasoning": "Preliminary risk assessment.",
        "confidence": 0.85,
        "inputs_used": ["state:risk/model-v2"],
    }
    env = create_pending_approval(
        _RISK,
        _ACME,
        str(uuid.uuid4()),
        "com.example.notes/create",
        args={"action_id": "test-action"},
        explanation=explanation,
    )
    assert env["payload"]["explanation"] == explanation
    assert "explanation" not in env["payload"].get("args", {})


def test_create_pending_approval_without_explanation() -> None:
    """Spec: ARSIA-Actions.md §3.2 — explanation omitted when None."""
    env = create_pending_approval(
        _RISK,
        _ACME,
        str(uuid.uuid4()),
        "com.example.notes/create",
        args={"action_id": "test-action"},
    )
    assert "explanation" not in env["payload"]


# ---------------------------------------------------------------------------
# create_approval_decision
# ---------------------------------------------------------------------------


def test_create_approval_decision_fields() -> None:
    """approval_decision has correlation_id, no expires_at.

    Spec: ARSIA-Core.md §4.1, §4.2.1.
    """
    corr = str(uuid.uuid4())
    env = create_approval_decision(
        _RISK, _ACME, corr, "com.example.notes/create",
        ["arsiaprotocol.oversight.approve"],
    )
    assert env["intent"] == "approval_decision"
    assert env["correlation_id"] == corr
    assert "expires_at" not in env
    assert env["capabilities"] == ["arsiaprotocol.oversight.approve"]


def test_create_approval_decision_uses_result() -> None:
    """approval_decision content field is ``result``, per §4.4.7.

    Spec: ARSIA-Core.md §4.4.7.
    """
    env = create_approval_decision(
        _RISK,
        _ACME,
        str(uuid.uuid4()),
        "com.example.notes/create",
        ["arsiaprotocol.oversight.approve"],
        result={"decision": "approve"},
    )
    assert env["payload"]["result"] == {"decision": "approve"}


# ---------------------------------------------------------------------------
# format_timestamp
# ---------------------------------------------------------------------------


def test_format_timestamp_matches_pattern() -> None:
    """format_timestamp output matches the §4.1.3 pattern.

    Spec: ARSIA-Core.md §4.1.3.
    """
    ts = format_timestamp()
    assert _TS_PATTERN.match(ts) is not None


def test_format_timestamp_is_utc() -> None:
    """format_timestamp output is in UTC and ends with ``Z``.

    Spec: ARSIA-Core.md §4.1.3.
    """
    ts = format_timestamp()
    assert ts.endswith("Z")
    now = datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(ts)
    assert abs((now - parsed).total_seconds()) < 5


def test_format_timestamp_millisecond_precision() -> None:
    """format_timestamp produces exactly three fractional digits.

    Spec: ARSIA-Core.md §4.1.3.
    """
    moment = datetime(2026, 4, 11, 12, 34, 56, 789123, tzinfo=timezone.utc)
    ts = format_timestamp(moment)
    assert ts == "2026-04-11T12:34:56.789Z"


# ---------------------------------------------------------------------------
# is_expired
# ---------------------------------------------------------------------------


def test_is_expired_past() -> None:
    """Envelope with expires_at deep in the past is expired.

    Spec: ARSIA-Core.md §4.2.2, §8.3.
    """
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {"expires_at": format_timestamp(now - timedelta(hours=1))}
    assert is_expired(env, now=now) is True


def test_is_expired_future() -> None:
    """Envelope with expires_at in the future is not expired.

    Spec: ARSIA-Core.md §4.2.2.
    """
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {"expires_at": format_timestamp(now + timedelta(seconds=60))}
    assert is_expired(env, now=now) is False


def test_is_expired_no_field() -> None:
    """Envelope without expires_at is never expired.

    Spec: ARSIA-Core.md §4.2.2.
    """
    assert is_expired({"v": "1.0"}) is False


def test_is_expired_within_clock_skew_tolerance() -> None:
    """expires_at 100 s ago is within the 300 s tolerance.

    Spec: ARSIA-Core.md §8.3.
    """
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {"expires_at": format_timestamp(now - timedelta(seconds=100))}
    assert is_expired(env, now=now) is False


def test_is_expired_beyond_clock_skew_tolerance() -> None:
    """expires_at 400 s ago is beyond the 300 s tolerance.

    Spec: ARSIA-Core.md §8.3.
    """
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {"expires_at": format_timestamp(now - timedelta(seconds=400))}
    assert is_expired(env, now=now) is True


def test_is_expired_custom_skew_zero() -> None:
    """With ``clock_skew_seconds=0`` even a 1 s stale message is expired."""
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {"expires_at": format_timestamp(now - timedelta(seconds=1))}
    assert is_expired(env, now=now, clock_skew_seconds=0) is True


def test_clock_skew_constant_matches_spec() -> None:
    """The exported constant equals the §8.3 value of 300 seconds."""
    assert CLOCK_SKEW_TOLERANCE_SECONDS == 300


# ---------------------------------------------------------------------------
# sign_message
# ---------------------------------------------------------------------------


def _fresh_request(from_agent: str = _ACME, to_agent: str = _RISK) -> dict[str, Any]:
    return create_request(
        from_agent,
        to_agent,
        "com.example.ping",
        ["ping.call"],
        args={"value": 1},
    )


def test_sign_message_adds_security_object(
    keypair_acme: dict[str, Any],
) -> None:
    """sign_message populates security.alg/kid/sig.

    Spec: ARSIA-Core.md §5.1 Step 6.
    """
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    assert "security" in signed
    assert signed["security"]["alg"] == "EdDSA"
    assert signed["security"]["kid"] == keypair_acme["kid"]
    assert isinstance(signed["security"]["sig"], str)


def test_sign_message_does_not_mutate_input(
    keypair_acme: dict[str, Any],
) -> None:
    """sign_message returns a new dict and leaves the input untouched.

    Spec: ARSIA-Core.md §5.1 Step 1.
    """
    env = _fresh_request()
    original = copy.deepcopy(env)
    sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    assert env == original
    assert "security" not in env


def test_sign_message_alg_is_eddsa(keypair_acme: dict[str, Any]) -> None:
    """Signed envelopes always use the EdDSA algorithm.

    Spec: ARSIA-Core.md §5.1 (Ed25519 is the primary algorithm).
    """
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    assert signed["security"]["alg"] == "EdDSA"


def test_sign_message_sig_is_base64url_no_padding(
    keypair_acme: dict[str, Any],
) -> None:
    """The signature is base64url-encoded without padding.

    Spec: ARSIA-Core.md §5.1 Step 5.
    """
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    sig = signed["security"]["sig"]
    assert "=" not in sig
    assert _BASE64URL_PATTERN.match(sig) is not None
    # Ed25519 signatures are 64 bytes → 86 base64url characters.
    assert len(sig) == 86


def test_sign_message_invalid_kid_prefix_raises(
    keypair_acme: dict[str, Any],
) -> None:
    """A kid that does not start with ``from + '#'`` is rejected.

    Spec: ARSIA-Core.md §5.1 Step 6.
    """
    env = _fresh_request()
    with pytest.raises(ValueError, match="must start with"):
        sign_message(
            env,
            keypair_acme["private_key"],
            "agent:unrelated.agent#key1",
        )


def test_sign_message_missing_from_raises(
    keypair_acme: dict[str, Any],
) -> None:
    """Signing an envelope without a ``from`` field raises ValueError."""
    with pytest.raises(ValueError, match="from"):
        sign_message(
            {"v": "1.0"},
            keypair_acme["private_key"],
            "agent:acme.echo-client#key1",
        )


# ---------------------------------------------------------------------------
# verify_message
# ---------------------------------------------------------------------------


def test_verify_message_valid_round_trip(
    keypair_acme: dict[str, Any],
) -> None:
    """Sign-then-verify succeeds with the matching public key.

    Spec: ARSIA-Core.md §5.1, §5.2.
    """
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    assert verify_message(signed, keypair_acme["public_key"]) is True


def test_verify_message_tampered_payload(
    keypair_acme: dict[str, Any],
) -> None:
    """Modifying the payload after signing invalidates the signature.

    Spec: ARSIA-Core.md §5.2 Step 5.
    """
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    signed["payload"]["args"] = {"value": 99}
    assert verify_message(signed, keypair_acme["public_key"]) is False


def test_verify_message_wrong_public_key(
    keypair_acme: dict[str, Any],
) -> None:
    """Verifying with a different public key returns False.

    Spec: ARSIA-Core.md §5.2 Step 5.
    """
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    _, other_public = generate_keypair()
    assert verify_message(signed, other_public) is False


def test_verify_message_missing_security_raises(
    keypair_acme: dict[str, Any],
) -> None:
    """verify_message raises KeyError when security.sig is missing."""
    env = _fresh_request()
    with pytest.raises(KeyError, match="security.sig"):
        verify_message(env, keypair_acme["public_key"])


def test_verify_message_sig_wrong_length_returns_false(
    keypair_acme: dict[str, Any],
) -> None:
    """A base64url sig that decodes to != 64 bytes yields False.

    Core §5.2 Step 1 mandates an explicit length check: "For Ed25519,
    this MUST produce exactly 64 bytes. If decoding fails or produces
    an unexpected length, reject the message with error code
    unauthorized." verify_message returns False rather than raising so
    that it matches the existing bool contract.

    Spec: ARSIA-Core.md §5.2 Step 1.
    """
    from arsia_protocol.hazmat.primitives.ed25519 import base64url_encode

    env = _fresh_request()
    # 32 bytes is a plausible-looking length (public-key sized) but is
    # not a valid Ed25519 signature.
    env["security"] = {
        "sig_alg": "EdDSA",
        "kid": f"{_ACME}#k1",
        "sig": base64url_encode(b"\x00" * 32),
    }
    assert verify_message(env, keypair_acme["public_key"]) is False


def test_verify_message_sig_malformed_base64url_returns_false(
    keypair_acme: dict[str, Any],
) -> None:
    """A sig that cannot be base64url-decoded yields False, not an exception.

    Spec: ARSIA-Core.md §5.2 Step 1.
    """
    env = _fresh_request()
    env["security"] = {
        "sig_alg": "EdDSA",
        "kid": f"{_ACME}#k1",
        "sig": "!!!not-base64url!!!",
    }
    assert verify_message(env, keypair_acme["public_key"]) is False


# ---------------------------------------------------------------------------
# verify_message — relaxed mode (Identity §3.1)
# ---------------------------------------------------------------------------


def test_verify_message_relaxed_logs_warning(
    keypair_acme: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When relaxed=True, verify_message returns True and logs a warning.

    Spec: ARSIA-Identity.md §3.1 (req:6501e17b).
    """
    import logging

    env = _fresh_request()
    env["security"] = {"alg": "EdDSA", "kid": f"{_ACME}#k1", "sig": "bad"}
    with caplog.at_level(logging.WARNING, logger="arsia_protocol.message"):
        result = verify_message(env, keypair_acme["public_key"], relaxed=True)
    assert result is True
    assert any("without cryptographic verification" in r.message for r in caplog.records)


def test_verify_message_relaxed_false_still_verifies(
    keypair_acme: dict[str, Any],
) -> None:
    """When relaxed=False (default), bad signatures still fail.

    Spec: ARSIA-Identity.md §3.1.
    """
    env = _fresh_request()
    env["security"] = {"alg": "EdDSA", "kid": f"{_ACME}#k1", "sig": "bad"}
    assert verify_message(env, keypair_acme["public_key"], relaxed=False) is False


# ---------------------------------------------------------------------------
# check_envelope_size (Core §4.5)
# ---------------------------------------------------------------------------


def test_default_max_message_bytes_is_one_mib() -> None:
    """The default envelope size limit is 1 MiB.

    Spec: ARSIA-Core.md §4.5.
    """
    assert DEFAULT_MAX_MESSAGE_BYTES == 1_048_576


def test_check_envelope_size_small_dict_within_limit() -> None:
    """A tiny envelope dict is well within the default limit.

    Spec: ARSIA-Core.md §4.5.
    """
    env = _fresh_request()
    ok, actual = check_envelope_size(env)
    assert ok is True
    assert 0 < actual < DEFAULT_MAX_MESSAGE_BYTES


def test_check_envelope_size_dict_exceeds_limit() -> None:
    """A dict serializing beyond max_bytes is flagged over-limit.

    Spec: ARSIA-Core.md §4.5.
    """
    env = _fresh_request()
    env["payload"]["args"] = {"blob": "x" * 2000}
    ok, actual = check_envelope_size(env, max_bytes=500)
    assert ok is False
    assert actual > 500


def test_check_envelope_size_accepts_bytes_input() -> None:
    """Bytes input is measured by length directly.

    Spec: ARSIA-Core.md §4.5.
    """
    raw = b'{"v":"1.0"}'
    ok, actual = check_envelope_size(raw, max_bytes=20)
    assert ok is True
    assert actual == len(raw)


def test_check_envelope_size_accepts_str_input_utf8_measured() -> None:
    """Str input is measured as UTF-8 bytes, not code points.

    Spec: ARSIA-Core.md §4.5.
    """
    # "ñ" encodes as two bytes in UTF-8.
    text = '{"note":"ñ"}'
    ok, actual = check_envelope_size(text)
    assert ok is True
    assert actual == len(text.encode("utf-8"))
    assert actual == len(text) + 1


# --- DX-1: guard clause tests ---


class TestSignMessagePrivateKeyGuard:
    """Guard clause for sign_message when private_key is None or wrong type."""

    def test_sign_message_none_private_key_raises(self) -> None:
        env = create_request(_ACME, _RISK, "test.type", ["cap.a"])
        with pytest.raises(TypeError, match="private_key must be an Ed25519PrivateKey"):
            sign_message(env, None, f"{_ACME}#key-1")  # type: ignore[arg-type]

    def test_sign_message_wrong_type_private_key_raises(self) -> None:
        env = create_request(_ACME, _RISK, "test.type", ["cap.a"])
        with pytest.raises(TypeError, match="private_key must be an Ed25519PrivateKey"):
            sign_message(env, "not-a-key", f"{_ACME}#key-1")  # type: ignore[arg-type]

    def test_sign_message_es256_wrong_key_type_raises(self) -> None:
        from arsia_protocol.hazmat.primitives.ed25519 import generate_keypair as ed_keygen
        priv, _ = ed_keygen()
        env = create_request(_ACME, _RISK, "test.type", ["cap.a"])
        with pytest.raises(TypeError, match="EllipticCurvePrivateKey"):
            sign_message(env, priv, f"{_ACME}#key-1", alg="ES256")


class TestCreateRequestCapabilitiesGuard:
    """Guard clause for create_request when capabilities has wrong type."""

    def test_create_request_dict_capabilities_raises(self) -> None:
        with pytest.raises(TypeError, match="capabilities must be a list of strings, got dict"):
            create_request(_ACME, _RISK, "test.type", {"read": True})  # type: ignore[arg-type]

    def test_create_request_non_string_capability_raises(self) -> None:
        with pytest.raises(TypeError, match=r"capabilities\[0\] must be a string"):
            create_request(_ACME, _RISK, "test.type", [123])  # type: ignore[list-item]

    def test_create_request_list_capabilities_works(self) -> None:
        env = create_request(_ACME, _RISK, "test.type", ["a.b.c"])
        assert env["capabilities"] == ["a.b.c"]


# ---------------------------------------------------------------------------
# BL-11: create_approval_decision capabilities (Core §4.2.3)
# ---------------------------------------------------------------------------


def test_create_approval_decision_includes_capabilities() -> None:
    """approval_decision factory includes capabilities in the envelope."""
    env = create_approval_decision(
        _ACME, _RISK, str(uuid.uuid4()), "com.example.test",
        ["arsiaprotocol.oversight.approve"],
    )
    assert env["capabilities"] == ["arsiaprotocol.oversight.approve"]


def test_create_approval_decision_requires_capabilities_list() -> None:
    """approval_decision factory rejects non-list capabilities."""
    with pytest.raises(TypeError, match="capabilities must be a list"):
        create_approval_decision(
            _ACME, _RISK, str(uuid.uuid4()), "com.example.test",
            "not-a-list",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# BL-24: is_expired clock_skew profile resolution (Core §8.3)
# ---------------------------------------------------------------------------


def test_is_expired_default_skew_300() -> None:
    """Without explicit clock_skew_seconds, default is 300 s."""
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {"expires_at": format_timestamp(now - timedelta(seconds=200))}
    assert is_expired(env, now=now) is False
    env2 = {"expires_at": format_timestamp(now - timedelta(seconds=400))}
    assert is_expired(env2, now=now) is True


def test_is_expired_explicit_skew_overrides_profile() -> None:
    """Explicit clock_skew_seconds takes precedence over profile."""
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {
        "expires_at": format_timestamp(now - timedelta(seconds=50)),
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
    }
    assert is_expired(env, now=now, clock_skew_seconds=10) is True
    assert is_expired(env, now=now, clock_skew_seconds=60) is False


def test_is_expired_backward_compatible() -> None:
    """is_expired() with no new params works as before."""
    now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc)
    env = {"expires_at": format_timestamp(now + timedelta(seconds=60))}
    assert is_expired(env, now=now) is False
    env_past = {"expires_at": format_timestamp(now - timedelta(hours=1))}
    assert is_expired(env_past, now=now) is True


# ---------------------------------------------------------------------------
# ES256 sign/verify (Core §4.3.5, §5.1)
# ---------------------------------------------------------------------------


def _es256_keypair() -> tuple[Any, Any]:
    from arsia_protocol.hazmat.primitives.ecdsa import generate_keypair as ec_keygen
    return ec_keygen()


def test_sign_message_es256_round_trip() -> None:
    """ES256 sign → verify round trip succeeds."""
    priv, pub = _es256_keypair()
    env = _fresh_request()
    signed = sign_message(env, priv, f"{_ACME}#ec-key-1", alg="ES256")
    assert signed["security"]["alg"] == "ES256"
    assert signed["security"]["kid"] == f"{_ACME}#ec-key-1"
    assert verify_message(signed, pub) is True


def test_sign_message_es256_does_not_mutate_input() -> None:
    """ES256 sign_message returns a new dict."""
    priv, _ = _es256_keypair()
    env = _fresh_request()
    original = copy.deepcopy(env)
    sign_message(env, priv, f"{_ACME}#ec-key-1", alg="ES256")
    assert env == original
    assert "security" not in env


def test_verify_message_es256_wrong_key_returns_false() -> None:
    """Verification with a different P-256 key fails."""
    priv1, _ = _es256_keypair()
    _, pub2 = _es256_keypair()
    env = _fresh_request()
    signed = sign_message(env, priv1, f"{_ACME}#ec-key-1", alg="ES256")
    assert verify_message(signed, pub2) is False


def test_verify_message_es256_tampered_payload() -> None:
    """Tampered payload fails ES256 verification."""
    priv, pub = _es256_keypair()
    env = _fresh_request()
    signed = sign_message(env, priv, f"{_ACME}#ec-key-1", alg="ES256")
    signed["payload"]["args"]["value"] = 999
    assert verify_message(signed, pub) is False


def test_sign_message_unknown_alg_raises() -> None:
    """Unsupported algorithm raises ValueError."""
    priv, _ = _es256_keypair()
    env = _fresh_request()
    with pytest.raises(ValueError, match="Unsupported signing algorithm"):
        sign_message(env, priv, f"{_ACME}#ec-key-1", alg="RS256")


def test_verify_message_unknown_alg_returns_false() -> None:
    """Unknown alg in security field returns False."""
    priv, pub = _es256_keypair()
    env = _fresh_request()
    signed = sign_message(env, priv, f"{_ACME}#ec-key-1", alg="ES256")
    signed["security"]["alg"] = "RS256"
    assert verify_message(signed, pub) is False


def test_sign_message_default_is_eddsa(keypair_acme: dict[str, Any]) -> None:
    """Default alg parameter is EdDSA (backward compat)."""
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    assert signed["security"]["alg"] == "EdDSA"
    assert verify_message(signed, keypair_acme["public_key"]) is True


def test_sign_message_es256_sig_is_base64url_no_padding() -> None:
    """ES256 signature is base64url without padding."""
    priv, _ = _es256_keypair()
    env = _fresh_request()
    signed = sign_message(env, priv, f"{_ACME}#ec-key-1", alg="ES256")
    sig = signed["security"]["sig"]
    assert _BASE64URL_PATTERN.match(sig)
    assert "=" not in sig


# ---------------------------------------------------------------------------
# §5.2 — Signature failure logging (CORE-§5.2-09)
# ---------------------------------------------------------------------------


def test_verify_message_failure_logs_warning(
    keypair_acme: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Spec: ARSIA-Core §5.2 — failed verification MUST log a warning."""
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    signed["payload"]["type"] = "tampered"
    other_pub, _ = generate_keypair()
    with caplog.at_level(logging.WARNING, logger="arsia_protocol.core.message"):
        result = verify_message(signed, other_pub)
    assert result is False
    assert any("Signature verification failed" in r.message for r in caplog.records)


def test_verify_message_success_does_not_log(
    keypair_acme: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Spec: ARSIA-Core §5.2 — successful verification MUST NOT log."""
    env = _fresh_request()
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    with caplog.at_level(logging.WARNING, logger="arsia_protocol.core.message"):
        result = verify_message(signed, keypair_acme["public_key"])
    assert result is True
    assert not any("Signature verification failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# §3.2 — Pending approval context length (ACT-§3.2-13)
# ---------------------------------------------------------------------------


def test_create_pending_approval_context_within_limit_ok() -> None:
    """Context string at the limit should be accepted."""
    context_str = "x" * PENDING_APPROVAL_CONTEXT_MAX_LENGTH
    env = create_pending_approval(
        _ACME,
        _RISK,
        "00000000-0000-4000-8000-000000000001",
        "com.acme.billing/invoice",
        args={"context": context_str},
    )
    assert env["payload"]["args"]["context"] == context_str


def test_create_pending_approval_context_exceeds_1024_raises() -> None:
    """Context string exceeding 1024 chars MUST raise ValueError."""
    context_str = "x" * (PENDING_APPROVAL_CONTEXT_MAX_LENGTH + 1)
    with pytest.raises(ValueError, match="1024"):
        create_pending_approval(
            _ACME,
            _RISK,
            "00000000-0000-4000-8000-000000000001",
            "com.acme.billing/invoice",
            args={"context": context_str},
        )
