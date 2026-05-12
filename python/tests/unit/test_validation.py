# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Tests for ``arsia_protocol.validation`` (Layer 3) + version helpers.

Covers:

- L1 schema validation (:func:`validate_schema`) against
  ``arsia-message.schema.json``.
- L2 semantic rules (:func:`validate_semantic`) from ARSIA-Core.md §4.
- Combined entry point (:func:`validate_envelope`).
- Specialised L1 helpers (:func:`validate_identity_record`,
  :func:`validate_compliance_field`).
- Wire version helpers from ``arsia_protocol.version``
  (ARSIA-Core.md §7.4).

Fixtures build envelopes from plain dicts so the tests exercise the
dict-level validator the way real consumers do, not the Pydantic
models from Layer 1.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from arsia_protocol.core import validation, version


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


def _valid_request() -> dict[str, Any]:
    return {
        "v": "1.0",
        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "ts": "2026-03-24T10:00:00.000Z",
        "from": "agent:acme.echo-client",
        "to": "agent:acme.echo-server",
        "intent": "request",
        "expires_at": "2026-03-24T10:00:30.000Z",
        "capabilities": ["echo.ping"],
        "payload": {
            "type": "com.acme.echo/ping",
            "args": {"message": "hello"},
        },
        "security": {
            "alg": "EdDSA",
            "kid": "agent:acme.echo-client#key1",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
    }


def _valid_response() -> dict[str, Any]:
    return {
        "v": "1.0",
        "id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        "ts": "2026-03-24T10:00:10.000Z",
        "from": "agent:acme.echo-server",
        "to": "agent:acme.echo-client",
        "intent": "response",
        "correlation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "payload": {
            "type": "com.acme.echo/ping",
            "result": {"echoed": "hello"},
        },
        "security": {
            "alg": "EdDSA",
            "kid": "agent:acme.echo-server#key1",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
    }


def _valid_event() -> dict[str, Any]:
    return {
        "v": "1.0",
        "id": "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f",
        "ts": "2026-03-24T10:00:20.000Z",
        "from": "agent:acme.echo-server",
        "to": "agent:acme.echo-client",
        "intent": "event",
        "payload": {"type": "com.acme.echo/heartbeat", "data": {"status": "ok"}},
    }


def _valid_error() -> dict[str, Any]:
    return {
        "v": "1.0",
        "id": "d4e5f6a7-b8c9-4d0e-af1f-2a3b4c5d6e7f",
        "ts": "2026-03-24T10:00:30.000Z",
        "from": "agent:acme.echo-server",
        "to": "agent:acme.echo-client",
        "intent": "error",
        "correlation_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "payload": {
            "type": "com.acme.echo/ping",
            "error": {
                "code": "not_found",
                "description": "Resource not found",
            },
        },
    }


# ----------------------------------------------------------------------
# L1 — schema validation
# ----------------------------------------------------------------------


def test_validate_schema_valid_request() -> None:
    """A minimal valid request passes L1 schema validation.

    Spec: ARSIA-Core.md §4.
    """
    assert validation.validate_schema(_valid_request()) == []


def test_validate_schema_missing_v() -> None:
    """L1 catches a missing required field.

    Spec: ARSIA-Core.md §4.1.1.
    """
    env = _valid_request()
    env.pop("v")
    errors = validation.validate_schema(env)
    assert any(e.code == "schema_violation" and "'v'" in e.message for e in errors)


def test_validate_schema_bad_uuid() -> None:
    """L1 catches an ``id`` that is not a UUID v4.

    Spec: ARSIA-Core.md §4.1.2.
    """
    env = _valid_request()
    env["id"] = "not-a-uuid"
    errors = validation.validate_schema(env)
    assert any("id" in e.message.lower() for e in errors)


def test_validate_schema_bad_timestamp() -> None:
    """L1 catches a ``ts`` without millisecond precision.

    Spec: ARSIA-Core.md §4.1.3.
    """
    env = _valid_request()
    env["ts"] = "2026-03-24T10:00:00Z"  # no milliseconds
    errors = validation.validate_schema(env)
    assert any("ts" in e.message.lower() for e in errors)


def test_validate_schema_bad_intent() -> None:
    """L1 catches an unknown ``intent`` value.

    Spec: ARSIA-Core.md §4.1.6.
    """
    env = _valid_request()
    env["intent"] = "chitchat"
    errors = validation.validate_schema(env)
    assert any("intent" in e.message.lower() for e in errors)


# ----------------------------------------------------------------------
# L2 — semantic rules
# ----------------------------------------------------------------------


def test_validate_semantic_request_without_capabilities() -> None:
    """Request without ``capabilities`` fails L2.

    Spec: ARSIA-Core.md §4.2.3.
    """
    env = _valid_request()
    env.pop("capabilities")
    errors = validation.validate_semantic(env)
    assert any(e.code == "missing_capabilities" for e in errors)


def test_validate_semantic_request_without_expires_at() -> None:
    """Request without ``expires_at`` fails L2.

    Spec: ARSIA-Core.md §4.2.2.
    """
    env = _valid_request()
    env.pop("expires_at")
    errors = validation.validate_semantic(env)
    assert any(e.code == "missing_expires_at" for e in errors)


def test_validate_semantic_response_without_correlation_id() -> None:
    """Response without ``correlation_id`` fails L2.

    Spec: ARSIA-Core.md §4.2.1.
    """
    env = _valid_response()
    env.pop("correlation_id")
    errors = validation.validate_semantic(env)
    assert any(e.code == "missing_correlation_id" for e in errors)


def test_validate_semantic_error_without_payload_error() -> None:
    """``intent='error'`` without ``payload.error`` fails L2.

    Spec: ARSIA-Core.md §4.4.6.
    """
    env = _valid_response()
    env["intent"] = "error"
    # Strip the result and leave no error object.
    env["payload"] = {"type": "org.arsiaprotocol.error"}
    errors = validation.validate_semantic(env)
    assert any(e.code == "missing_error_object" for e in errors)


def test_validate_semantic_expires_before_ts() -> None:
    """``expires_at`` less than or equal to ``ts`` fails L2.

    Spec: ARSIA-Core.md §4.2.2.
    """
    env = _valid_request()
    env["expires_at"] = env["ts"]  # equal, not strictly greater
    errors = validation.validate_semantic(env)
    assert any(e.code == "expires_at_not_after_ts" for e in errors)


def test_idempotency_expires_at_greater_than_ts_passes() -> None:
    """``idempotency.expires_at`` strictly greater than ``ts`` is accepted.

    Spec: ARSIA-Core.md §4.3.2.
    """
    env = _valid_request()
    env["idempotency"] = {
        "key": "req-001",
        "expires_at": "2026-03-24T10:05:00.000Z",
    }
    errors = validation.validate_envelope(env)
    assert not any(e.code == "idempotency_expires_at_not_after_ts" for e in errors)


def test_idempotency_expires_at_equal_to_ts_fails() -> None:
    """``idempotency.expires_at`` equal to ``ts`` fails L2.

    Spec: ARSIA-Core.md §4.3.2.
    """
    env = _valid_request()
    env["idempotency"] = {
        "key": "req-001",
        "expires_at": env["ts"],
    }
    errors = validation.validate_envelope(env)
    assert any(e.code == "idempotency_expires_at_not_after_ts" for e in errors)


def test_idempotency_expires_at_before_ts_fails() -> None:
    """``idempotency.expires_at`` earlier than ``ts`` fails L2.

    Spec: ARSIA-Core.md §4.3.2.
    """
    env = _valid_request()
    env["idempotency"] = {
        "key": "req-001",
        "expires_at": "2026-03-24T09:59:00.000Z",
    }
    errors = validation.validate_envelope(env)
    assert any(e.code == "idempotency_expires_at_not_after_ts" for e in errors)


def test_validate_semantic_invalid_from() -> None:
    """Non-conforming ``from`` agent ID fails L2.

    Spec: ARSIA-Core.md §3.3.
    """
    env = _valid_request()
    env["from"] = "not-an-agent-id"
    errors = validation.validate_semantic(env)
    assert any(e.code == "invalid_from_agent_id" for e in errors)


def test_validate_semantic_invalid_to() -> None:
    """Non-conforming ``to`` agent ID fails L2.

    Spec: ARSIA-Core.md §3.3.
    """
    env = _valid_request()
    env["to"] = "not-an-agent-id"
    errors = validation.validate_semantic(env)
    assert any(e.code == "invalid_to_agent_id" for e in errors)


def test_validate_semantic_kid_prefix_mismatch() -> None:
    """L2 catches a ``kid`` that does not start with ``from + "#"``.

    Spec: ARSIA-Core.md §5.2 Step 6.
    """
    env = _valid_request()
    env["security"] = {
        "alg": "EdDSA",
        "kid": "agent:other.agent#key1",
        "sig": "AAA",
    }
    errors = validation.validate_semantic(env)
    assert any(e.code == "kid_prefix_mismatch" for e in errors)


def test_validate_semantic_sig_not_base64url() -> None:
    """L2 catches a ``sig`` that is not base64url-encoded.

    Spec: ARSIA-Core.md §5.1 Step 5.
    """
    env = _valid_request()
    env["security"] = {
        "alg": "EdDSA",
        "kid": "agent:acme.echo-client#key1",
        "sig": "not valid base64!=",
    }
    errors = validation.validate_semantic(env)
    assert any(e.code == "invalid_sig_encoding" for e in errors)


def test_validate_semantic_valid_request() -> None:
    """A valid request passes L2 with no errors.

    Spec: ARSIA-Core.md §4.
    """
    assert validation.validate_semantic(_valid_request()) == []


def test_validate_semantic_valid_response() -> None:
    """A valid response passes L2 with no errors.

    Spec: ARSIA-Core.md §4.
    """
    assert validation.validate_semantic(_valid_response()) == []


def test_validate_semantic_valid_event() -> None:
    """A valid event passes L2 with no errors.

    Spec: ARSIA-Core.md §4.
    """
    assert validation.validate_semantic(_valid_event()) == []


def test_validate_semantic_min_v_exceeds_protocol_version_is_rejected() -> None:
    """When min_v exceeds the SDK's PROTOCOL_VERSION, L2 flags the mismatch.

    The recipient MUST respond with not_implemented and surface the
    supported version range in the error details.

    Spec: ARSIA-Core.md §4.3.1, §7.4.
    """
    env = _valid_request()
    env["min_v"] = "2.0"
    errors = validation.validate_semantic(env)
    assert any(e.code == "unsupported_min_v" for e in errors)


def test_validate_semantic_min_v_equal_to_protocol_version_accepted() -> None:
    """min_v equal to PROTOCOL_VERSION passes the §4.3.1 check.

    Spec: ARSIA-Core.md §4.3.1.
    """
    env = _valid_request()
    env["min_v"] = version.PROTOCOL_VERSION
    errors = validation.validate_semantic(env)
    assert not any(e.code == "unsupported_min_v" for e in errors)


def test_validate_semantic_min_v_absent_accepted() -> None:
    """An envelope without min_v passes the §4.3.1 check unconditionally.

    Spec: ARSIA-Core.md §4.3.1.
    """
    env = _valid_request()
    assert "min_v" not in env
    errors = validation.validate_semantic(env)
    assert not any(e.code == "unsupported_min_v" for e in errors)


def test_validate_semantic_idempotency_key_accepts_printable_ascii() -> None:
    """An idempotency.key using 0x20-0x7E characters passes L2.

    Spec: ARSIA-Core.md §4.3.2.
    """
    env = _valid_request()
    env["idempotency"] = {
        "key": "order-42 ~ v1/final",
        "expires_at": "2026-03-24T10:05:00.000Z",
    }
    errors = validation.validate_semantic(env)
    assert not any(e.code == "idempotency_key_invalid_char" for e in errors)


def test_validate_semantic_idempotency_key_rejects_tab() -> None:
    """A tab character (0x09) in idempotency.key is rejected.

    Spec: ARSIA-Core.md §4.3.2.
    """
    env = _valid_request()
    env["idempotency"] = {
        "key": "bad\tkey",
        "expires_at": "2026-03-24T10:05:00.000Z",
    }
    errors = validation.validate_semantic(env)
    assert any(e.code == "idempotency_key_invalid_char" for e in errors)


def test_validate_semantic_idempotency_key_rejects_unicode() -> None:
    """A non-ASCII character in idempotency.key is rejected.

    Spec: ARSIA-Core.md §4.3.2.
    """
    env = _valid_request()
    env["idempotency"] = {
        "key": "chave-ñ",
        "expires_at": "2026-03-24T10:05:00.000Z",
    }
    errors = validation.validate_semantic(env)
    assert any(e.code == "idempotency_key_invalid_char" for e in errors)


def test_validate_semantic_idempotency_key_rejects_null_byte() -> None:
    """A NUL byte (0x00) in idempotency.key is rejected.

    Spec: ARSIA-Core.md §4.3.2.
    """
    env = _valid_request()
    env["idempotency"] = {
        "key": "bad\x00key",
        "expires_at": "2026-03-24T10:05:00.000Z",
    }
    errors = validation.validate_semantic(env)
    assert any(e.code == "idempotency_key_invalid_char" for e in errors)


def test_validate_semantic_strict_mode_promotes_unknown_profile() -> None:
    """Strict mode elevates Rule 1 (unknown profile) to an error.

    Spec: ARSIA-Core.md §4.3.8 Rule 1.
    """
    env = _valid_request()
    env["compliance"] = {"profile": "NO-SUCH-PROFILE-EVER"}
    lenient = validation.validate_semantic(env, strict=False)
    assert not any(e.code == "unknown_profile" for e in lenient)
    strict = validation.validate_semantic(env, strict=True)
    assert any(e.code == "unknown_profile" for e in strict)


# ----------------------------------------------------------------------
# validate_envelope — combined L1 + L2
# ----------------------------------------------------------------------


def test_validate_envelope_combined_runs_l2_on_clean_l1() -> None:
    """When L1 passes, L2 still runs and catches semantic errors.

    Spec: ARSIA-Core.md §4.
    """
    env = _valid_request()
    env["expires_at"] = env["ts"]  # semantic violation only
    errors = validation.validate_envelope(env)
    assert errors
    assert all(e.code != "schema_violation" for e in errors)


def test_validate_envelope_l1_fail_skips_l2() -> None:
    """When L1 reports errors, L2 is not run.

    L1 (schema) failures short-circuit L2 (semantic) validation.
    """
    env = _valid_request()
    env.pop("v")  # structural L1 failure
    env["from"] = "bogus-agent-id"  # would also fail L2 if reached
    errors = validation.validate_envelope(env)
    assert errors
    assert all(e.code == "schema_violation" for e in errors)


def test_validate_envelope_clean_valid() -> None:
    """A valid envelope yields an empty error list from the combined entry point.

    Spec: ARSIA-Core.md §4.
    """
    assert validation.validate_envelope(_valid_request()) == []


# ----------------------------------------------------------------------
# Specialised L1 helpers
# ----------------------------------------------------------------------


def test_validate_identity_record_rejects_empty() -> None:
    """A bare ``{}`` fails the IdentityRecord schema.

    Spec: ARSIA-Identity.md §1.
    """
    errors = validation.validate_identity_record({})
    assert errors


def test_validate_compliance_field_accepts_valid_object() -> None:
    """A well-formed compliance object passes the field schema.

    Spec: ARSIA-Core.md §4.3.6.
    """
    obj = {
        "profile": "GDPR-STANDARD",
        "pii_involved": True,
        "legal_basis": "consent",
    }
    assert validation.validate_compliance_field(obj) == []


# ----------------------------------------------------------------------
# Version helpers — ARSIA-Core.md §7.4
# ----------------------------------------------------------------------


def test_protocol_version_constant_is_1_0() -> None:
    """The SDK advertises wire protocol version 1.0.

    Spec: ARSIA-Core.md §4.1.1.
    """
    assert version.PROTOCOL_VERSION == "1.0"


def test_parse_version_valid() -> None:
    """``parse_version('1.0')`` returns ``(1, 0)``.

    Spec: ARSIA-Core.md §4.1.1.
    """
    assert version.parse_version("1.0") == (1, 0)


def test_parse_version_invalid_raises() -> None:
    """Malformed version strings raise ``ValueError``.

    Spec: ARSIA-Core.md §4.1.1.
    """
    for bad in ("1", "1.0.0", "abc", "1.x", "", "1.0-rc1"):
        with pytest.raises(ValueError):
            version.parse_version(bad)


def test_compare_versions_ordering() -> None:
    """``compare_versions`` returns -1 / 0 / 1 per major-then-minor order.

    Spec: ARSIA-Core.md §7.4.
    """
    assert version.compare_versions("1.0", "1.0") == 0
    assert version.compare_versions("1.0", "1.1") == -1
    assert version.compare_versions("2.0", "1.9") == 1


def test_is_compatible_same_major_passes() -> None:
    """Same major version is compatible regardless of minor.

    Spec: ARSIA-Core.md §7.4.
    """
    assert version.is_compatible("1.0", "1.3") is True
    assert version.is_compatible("1.3", "1.0") is True


def test_is_compatible_different_major_fails() -> None:
    """Different major versions are incompatible.

    Spec: ARSIA-Core.md §7.4.
    """
    assert version.is_compatible("1.0", "2.0") is False
    assert version.is_compatible("2.5", "1.9") is False


def test_is_compatible_respects_min_v() -> None:
    """``min_v`` constrains the receiver's version from below.

    Spec: ARSIA-Core.md §4.3.1, §7.4.
    """
    # Our 1.0 is below their required min 1.1 → incompatible.
    assert version.is_compatible("1.0", "1.2", their_min_v="1.1") is False
    # Our 1.2 meets their min 1.1 → compatible.
    assert version.is_compatible("1.2", "1.2", their_min_v="1.1") is True
    # min_v absent → always compatible on same major.
    assert version.is_compatible("1.0", "1.2", their_min_v=None) is True


# ----------------------------------------------------------------------
# Defensive — no mutation of the envelope
# ----------------------------------------------------------------------


def test_validate_envelope_does_not_mutate_input() -> None:
    """Running the validator never rewrites the caller's envelope."""
    env = _valid_request()
    env["compliance"] = {"profile": "MIFID-II", "retention_days": 90}
    snapshot = copy.deepcopy(env)
    _ = validation.validate_envelope(env)
    assert env == snapshot


# ----------------------------------------------------------------------
# §4.4.1 Payload Type Registry — req:6418cd43
# ----------------------------------------------------------------------


class TestPayloadTypeRegistry:
    """PayloadTypeRegistry recognises registered types and rejects others."""

    def test_recognised_type_accepted(self) -> None:
        """Registered payload type passes validation (§4.4.1)."""
        registry = validation.PayloadTypeRegistry()
        registry.register("com.acme.echo/ping")
        env = _valid_request()
        errors = validation.validate_semantic(env, payload_type_registry=registry)
        assert not any(e.code == "unrecognised_payload_type" for e in errors)

    def test_unrecognised_type_rejected(self) -> None:
        """Unregistered payload type is rejected with not_implemented (§4.4.1)."""
        registry = validation.PayloadTypeRegistry()
        registry.register("com.acme.echo/pong")
        env = _valid_request()
        errors = validation.validate_semantic(env, payload_type_registry=registry)
        assert any(e.code == "unrecognised_payload_type" for e in errors)
        assert any("not_implemented" in e.message for e in errors)

    def test_no_registry_skips_check(self) -> None:
        """Without a registry, any well-formed type passes."""
        env = _valid_request()
        errors = validation.validate_semantic(env)
        assert not any(e.code == "unrecognised_payload_type" for e in errors)

    def test_register_multiple_types(self) -> None:
        """Multiple types can be registered at once."""
        registry = validation.PayloadTypeRegistry()
        registry.register("com.acme.echo/ping", "com.acme.echo/pong")
        assert registry.is_recognized("com.acme.echo/ping")
        assert registry.is_recognized("com.acme.echo/pong")
        assert not registry.is_recognized("com.acme.other/foo")

    def test_registered_types_returns_frozenset(self) -> None:
        registry = validation.PayloadTypeRegistry()
        registry.register("com.acme.echo/ping")
        result = registry.registered_types()
        assert isinstance(result, frozenset)
        assert "com.acme.echo/ping" in result

    def test_validate_envelope_passes_registry(self) -> None:
        """validate_envelope propagates payload_type_registry to L2."""
        registry = validation.PayloadTypeRegistry()
        registry.register("com.acme.echo/ping")
        env = _valid_request()
        errors = validation.validate_envelope(env, payload_type_registry=registry)
        assert not errors

    def test_validate_envelope_rejects_unknown_type(self) -> None:
        """validate_envelope rejects unknown type via registry."""
        registry = validation.PayloadTypeRegistry()
        env = _valid_request()
        errors = validation.validate_envelope(env, payload_type_registry=registry)
        assert any(e.code == "unrecognised_payload_type" for e in errors)


# ----------------------------------------------------------------------
# §4.4.7 Intent Content Field Resolution — req:119f1c30 req:25daf09a
# ----------------------------------------------------------------------


class TestResolveContentField:
    """resolve_content_field returns intent-matching field and ignores others."""

    def test_request_returns_args(self) -> None:
        """request intent resolves to args (§4.4.7)."""
        env = _valid_request()
        field, value = validation.resolve_content_field(env)
        assert field == "args"
        assert value == {"message": "hello"}

    def test_response_returns_result(self) -> None:
        """response intent resolves to result (§4.4.7)."""
        env = _valid_response()
        field, value = validation.resolve_content_field(env)
        assert field == "result"
        assert value == {"echoed": "hello"}

    def test_event_returns_data(self) -> None:
        """event intent resolves to data (§4.4.7)."""
        env = _valid_event()
        field, value = validation.resolve_content_field(env)
        assert field == "data"
        assert value == {"status": "ok"}

    def test_error_returns_error(self) -> None:
        """error intent resolves to error (§4.4.7)."""
        env = _valid_error()
        field, value = validation.resolve_content_field(env)
        assert field == "error"
        assert isinstance(value, dict)
        assert value["code"] == "not_found"

    def test_pending_approval_returns_args(self) -> None:
        """pending_approval maps to args like request (§4.4.7)."""
        env = _valid_request()
        env["intent"] = "pending_approval"
        field, value = validation.resolve_content_field(env)
        assert field == "args"

    def test_approval_decision_returns_result(self) -> None:
        """approval_decision maps to result like response (§4.4.7)."""
        env = _valid_response()
        env["intent"] = "approval_decision"
        field, value = validation.resolve_content_field(env)
        assert field == "result"

    def test_missing_field_returns_none(self) -> None:
        """When the expected field is absent, value is None."""
        env = _valid_request()
        del env["payload"]["args"]
        field, value = validation.resolve_content_field(env)
        assert field == "args"
        assert value is None

    def test_extra_fields_ignored_with_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Extra content fields are ignored and logged (§4.4.7)."""
        import logging

        env = _valid_request()
        env["payload"]["result"] = {"extra": True}
        with caplog.at_level(logging.WARNING, logger="arsia_protocol.validation"):
            field, value = validation.resolve_content_field(env)
        assert field == "args"
        assert value == {"message": "hello"}
        assert any("Multiple content fields" in r.message for r in caplog.records)
        assert any("ignoring" in r.message for r in caplog.records)

    def test_unknown_intent_raises(self) -> None:
        """Unknown intent raises ValueError."""
        env = _valid_request()
        env["intent"] = "unknown"
        with pytest.raises(ValueError, match="Unknown or missing intent"):
            validation.resolve_content_field(env)

    def test_non_dict_payload_raises(self) -> None:
        """Non-dict payload raises ValueError."""
        env = _valid_request()
        env["payload"] = "encrypted-jwe-string"
        with pytest.raises(ValueError, match="payload must be a dict"):
            validation.resolve_content_field(env)


class TestIntentContentFieldMapping:
    """INTENT_CONTENT_FIELD constant covers all six intents."""

    def test_all_intents_mapped(self) -> None:
        assert set(validation.INTENT_CONTENT_FIELD) == {
            "request",
            "response",
            "event",
            "error",
            "pending_approval",
            "approval_decision",
        }


# ----------------------------------------------------------------------
# Encrypted envelope detection
# ----------------------------------------------------------------------


def test_validate_encrypted_envelope_returns_clear_error() -> None:
    """Encrypted envelope (JWE payload) yields a decrypt_and_verify hint."""
    env = _valid_request()
    env["payload"] = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9.xx.yy.zz.aa"
    env["security"] = {
        "alg": "EdDSA",
        "kid": "agent:acme.echo-client#key1",
        "sig": "AAA",
        "encrypted": True,
    }
    errors = validation.validate_envelope(env)
    assert len(errors) == 1
    assert errors[0].code == "encrypted_payload"
    assert "decrypt_and_verify()" in errors[0].message


def test_validate_encrypted_envelope_short_circuits_l2() -> None:
    """Encrypted envelope guard prevents L1 and L2 from running."""
    env = _valid_request()
    env["payload"] = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9.xx.yy.zz.aa"
    env["from"] = "not-an-agent-id"
    env["security"] = {
        "alg": "EdDSA",
        "kid": "agent:acme.echo-client#key1",
        "sig": "AAA",
        "encrypted": True,
    }
    errors = validation.validate_envelope(env)
    assert len(errors) == 1
    assert errors[0].code == "encrypted_payload"


# ----------------------------------------------------------------------
# L1 regex human-readable error messages
# ----------------------------------------------------------------------


def test_l1_agent_id_error_is_human_readable() -> None:
    """Bad agent_id produces human-readable error, not raw regex."""
    env = _valid_request()
    env["from"] = "invalid-agent-id"
    errors = validation.validate_schema(env)
    agent_errors = [e for e in errors if "/from" in e.message]
    assert agent_errors
    assert "agent:org.name" in agent_errors[0].message


def test_l1_uuid_error_is_human_readable() -> None:
    """Bad id produces a human-readable UUID error, not raw regex."""
    env = _valid_request()
    env["id"] = "not-a-uuid"
    errors = validation.validate_schema(env)
    id_errors = [e for e in errors if "/id" in e.message]
    assert id_errors
    assert "UUID v4" in id_errors[0].message or "does not match" in id_errors[0].message


# ----------------------------------------------------------------------
# $ref resolution — arsia-explanation.schema.json
# ----------------------------------------------------------------------


def test_validate_schema_accepts_explanation_field() -> None:
    """L1 accepts a valid payload.explanation object ($ref resolution)."""
    env = _valid_response()
    env["payload"]["explanation"] = {
        "reasoning": "Model assessed risk as low.",
        "confidence": 0.91,
        "inputs_used": ["state:risk/model-v3"],
    }
    errors = validation.validate_schema(env)
    assert errors == []


def test_validate_schema_rejects_invalid_explanation() -> None:
    """L1 rejects payload.explanation when it is not an object."""
    env = _valid_response()
    env["payload"]["explanation"] = "not an object"
    errors = validation.validate_schema(env)
    assert len(errors) > 0
    assert any(e.code == "schema_violation" for e in errors)


# ---------------------------------------------------------------------------
# BL-11: approval_decision capabilities validation (Core §4.2.3)
# ---------------------------------------------------------------------------


def _valid_approval_decision() -> dict[str, Any]:
    env = _valid_response()
    env["intent"] = "approval_decision"
    env["capabilities"] = ["arsiaprotocol.oversight.approve"]
    return env


def test_validate_semantic_approval_decision_with_capabilities() -> None:
    """approval_decision with capabilities passes L2."""
    env = _valid_approval_decision()
    errors = validation.validate_semantic(env)
    assert not any(e.code in ("missing_capabilities", "empty_capabilities") for e in errors)


def test_validate_semantic_approval_decision_missing_capabilities() -> None:
    """approval_decision without capabilities fails L2."""
    env = _valid_approval_decision()
    del env["capabilities"]
    errors = validation.validate_semantic(env)
    assert any(
        e.code == "missing_capabilities" and e.details.get("intent") == "approval_decision"
        for e in errors
    )


def test_validate_semantic_approval_decision_empty_capabilities() -> None:
    """approval_decision with empty capabilities fails L2."""
    env = _valid_approval_decision()
    env["capabilities"] = []
    errors = validation.validate_semantic(env)
    assert any(e.code == "empty_capabilities" for e in errors)


# ----------------------------------------------------------------------
# Major version ceiling (§4.1.1)
# ----------------------------------------------------------------------


def test_validate_semantic_v_current_accepted() -> None:
    """v='1.0' (current) produces no version-ceiling error.

    Spec: ARSIA-Core.md §4.1.1.
    """
    env = _valid_request()
    assert env["v"] == "1.0"
    errors = validation.validate_semantic(env)
    assert not any(e.code == "unsupported_protocol_version" for e in errors)


def test_validate_semantic_v_compatible_minor_bump_accepted() -> None:
    """v='1.1' (same major, higher minor) produces no version-ceiling error.

    Minor version differences within the same major version MUST be
    handled gracefully.

    Spec: ARSIA-Core.md §4.1.1.
    """
    env = _valid_request()
    env["v"] = "1.1"
    errors = validation.validate_semantic(env)
    assert not any(e.code == "unsupported_protocol_version" for e in errors)


def test_validate_semantic_v_unsupported_major_rejected() -> None:
    """v='2.0' (major > max supported) is rejected.

    Spec: ARSIA-Core.md §4.1.1.
    """
    env = _valid_request()
    env["v"] = "2.0"
    errors = validation.validate_semantic(env)
    ver_errors = [e for e in errors if e.code == "unsupported_protocol_version"]
    assert len(ver_errors) >= 1
    assert ver_errors[0].details["v"] == "2.0"
    assert ver_errors[0].details["major"] == 2
    assert ver_errors[0].details["max_supported_major"] == 1
    assert ver_errors[0].spec_ref == "Core §4.1.1"


def test_validate_semantic_v_far_future_major_rejected() -> None:
    """v='99.0' (far-future major) is rejected.

    Spec: ARSIA-Core.md §4.1.1.
    """
    env = _valid_request()
    env["v"] = "99.0"
    errors = validation.validate_semantic(env)
    assert any(e.code == "unsupported_protocol_version" for e in errors)


def test_validate_semantic_v_zero_major_accepted() -> None:
    """v='0.1' (major < current) is NOT rejected by the ceiling check.

    §4.1.1 only says MUST reject when major *exceeds* max supported.
    A lower major is not covered by this rule (it may be handled by
    other compatibility checks).

    Spec: ARSIA-Core.md §4.1.1.
    """
    env = _valid_request()
    env["v"] = "0.1"
    errors = validation.validate_semantic(env)
    assert not any(e.code == "unsupported_protocol_version" for e in errors)


# ----------------------------------------------------------------------
# validate_correlation — Core §4.2.1
# ----------------------------------------------------------------------


class TestValidateCorrelation:
    """Cross-envelope correlation_id equality checks.

    Spec: ARSIA-Core.md §4.2.1 — correlation_id MUST equal the
    original request message id (byte-for-byte).
    """

    def test_matching_ids_passes(self) -> None:
        """Identical id / correlation_id → no errors."""
        req = _valid_request()
        resp = _valid_response()
        resp["correlation_id"] = req["id"]
        errors = validation.validate_correlation(req, resp)
        assert errors == []

    def test_mismatched_ids_returns_error(self) -> None:
        """Different id / correlation_id → correlation_mismatch error."""
        req = _valid_request()
        resp = _valid_response()
        resp["correlation_id"] = "ffffffff-ffff-4fff-bfff-ffffffffffff"
        errors = validation.validate_correlation(req, resp)
        assert len(errors) == 1
        assert errors[0].code == "correlation_mismatch"

    def test_missing_correlation_id_returns_error(self) -> None:
        """Missing correlation_id → missing_correlation_id error."""
        req = _valid_request()
        resp = _valid_response()
        del resp["correlation_id"]
        errors = validation.validate_correlation(req, resp)
        assert len(errors) == 1
        assert errors[0].code == "missing_correlation_id"

    def test_error_code_is_correlation_mismatch(self) -> None:
        """Error code is exactly 'correlation_mismatch'."""
        req = _valid_request()
        resp = _valid_response()
        resp["correlation_id"] = "00000000-0000-4000-8000-000000000000"
        errors = validation.validate_correlation(req, resp)
        assert errors[0].code == "correlation_mismatch"

    def test_error_includes_both_values(self) -> None:
        """Error details include both correlation_id and request_id."""
        req = _valid_request()
        resp = _valid_response()
        resp["correlation_id"] = "00000000-0000-4000-8000-000000000000"
        errors = validation.validate_correlation(req, resp)
        assert errors[0].details["correlation_id"] == resp["correlation_id"]
        assert errors[0].details["request_id"] == req["id"]
