# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.errors``.

Covers the error code registry, retryability lookups, the error
envelope builder, and the retry delay calculation.

Spec: ARSIA-Core.md §11.1, §11.2, §11.3.
"""

from __future__ import annotations

import uuid

import pytest

from arsia_protocol.core.errors import (
    ERROR_REGISTRY,
    RETRY_POLICY,
    ErrorCodeInfo,
    build_error_envelope,
    build_forbidden_error,
    build_not_implemented_error,
    build_oversight_denied_error,
    build_oversight_expired_error,
    build_payload_too_large_error,
    build_rate_limited_error,
    build_service_unavailable_error,
    compute_retry_delay,
    get_error_info,
    is_retryable,
)

_ACME = "agent:acme.echo-client"
_RISK = "agent:arsialabs.demo.risk-assessor"

_STANDARD_CODES = {
    "invalid_request",
    "unauthorized",
    "forbidden",
    "not_found",
    "conflict",
    "payload_too_large",
    "rate_limited",
    "internal_error",
    "not_implemented",
    "service_unavailable",
    "certificate_invalid",
    "certificate_expired",
    "key_mismatch",
    "certificate_revoked",
}


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------


def test_registry_has_fourteen_codes() -> None:
    """The registry contains all Core §11.2 + Identity §6.4.3 codes.

    Spec: ARSIA-Core.md §11.2 (10) + ARSIA-Identity.md §6.4.3 (4).
    """
    assert len(ERROR_REGISTRY) == 14


def test_registry_contains_all_standard_codes() -> None:
    """The standard code names are all present.

    Spec: ARSIA-Core.md §11.2 + ARSIA-Identity.md §6.4.3.
    """
    assert set(ERROR_REGISTRY.keys()) == _STANDARD_CODES


def test_registry_http_status_mapping() -> None:
    """Each code maps to the HTTP status listed in §11.2 / §6.4.3.

    Spec: ARSIA-Core.md §11.2, ARSIA-Identity.md §6.4.3.
    """
    expected = {
        "invalid_request": 400,
        "unauthorized": 401,
        "forbidden": 403,
        "not_found": 404,
        "conflict": 409,
        "payload_too_large": 413,
        "rate_limited": 429,
        "internal_error": 500,
        "not_implemented": 501,
        "service_unavailable": 503,
        # Identity §6.4.3 — authentication failures use 401 like
        # ``unauthorized``; the spec does not assign explicit codes.
        "certificate_invalid": 401,
        "certificate_expired": 401,
        "key_mismatch": 401,
        "certificate_revoked": 401,
    }
    for code, status in expected.items():
        assert ERROR_REGISTRY[code].http_status == status


def test_certificate_error_codes_are_non_retryable() -> None:
    """Certificate authentication failures are not retryable.

    Spec: ARSIA-Identity.md §6.4.3 (auth failures).
    """
    for code in (
        "certificate_invalid",
        "certificate_expired",
        "key_mismatch",
        "certificate_revoked",
    ):
        assert ERROR_REGISTRY[code].retryable is False


def test_get_error_info_returns_frozen_dataclass() -> None:
    """``get_error_info`` returns an ``ErrorCodeInfo`` instance.

    Spec: ARSIA-Core.md §11.2.
    """
    info = get_error_info("forbidden")
    assert isinstance(info, ErrorCodeInfo)
    assert info.code == "forbidden"
    assert info.http_status == 403
    assert info.retryable is False


def test_get_error_info_unknown_code() -> None:
    """Unknown codes raise ValueError."""
    with pytest.raises(ValueError, match="unknown ARSIA error code"):
        get_error_info("teapot")


# ---------------------------------------------------------------------------
# is_retryable
# ---------------------------------------------------------------------------


def test_is_retryable_rate_limited() -> None:
    """``rate_limited`` is retryable.

    Spec: ARSIA-Core.md §11.3.
    """
    assert is_retryable("rate_limited") is True


def test_is_retryable_internal_error() -> None:
    """``internal_error`` is retryable.

    Spec: ARSIA-Core.md §11.3.
    """
    assert is_retryable("internal_error") is True


def test_is_retryable_service_unavailable() -> None:
    """``service_unavailable`` is retryable.

    Spec: ARSIA-Core.md §11.3.
    """
    assert is_retryable("service_unavailable") is True


def test_is_retryable_invalid_request() -> None:
    """``invalid_request`` is not retryable.

    Spec: ARSIA-Core.md §11.3.
    """
    assert is_retryable("invalid_request") is False


def test_is_retryable_unauthorized() -> None:
    """``unauthorized`` is not retryable.

    Spec: ARSIA-Core.md §11.3.
    """
    assert is_retryable("unauthorized") is False


def test_is_retryable_unknown_code_raises() -> None:
    """Unknown codes passed to ``is_retryable`` raise ValueError."""
    with pytest.raises(ValueError, match="unknown ARSIA error code"):
        is_retryable("nope")


# ---------------------------------------------------------------------------
# build_error_envelope
# ---------------------------------------------------------------------------


def test_build_error_envelope_structure() -> None:
    """build_error_envelope produces a complete error envelope.

    Spec: ARSIA-Core.md §11.1.
    """
    corr = str(uuid.uuid4())
    env = build_error_envelope(_RISK, _ACME, corr, "invalid_request", "bad field")
    assert env["intent"] == "error"
    assert env["correlation_id"] == corr
    assert env["payload"]["error"]["code"] == "invalid_request"
    assert env["payload"]["error"]["description"] == "bad field"


def test_build_error_envelope_unknown_code_raises() -> None:
    """Unknown codes raise ValueError before envelope construction."""
    with pytest.raises(ValueError, match="unknown ARSIA error code"):
        build_error_envelope(_RISK, _ACME, str(uuid.uuid4()), "bogus", "nope")


def test_build_error_envelope_with_details() -> None:
    """``details`` are propagated into ``payload.error.details``.

    Spec: ARSIA-Core.md §11.2 (forbidden details contract).
    """
    env = build_error_envelope(
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
    details = env["payload"]["error"]["details"]
    assert details["required_capabilities"] == ["notes.read"]
    assert details["provided_capabilities"] == []


# ---------------------------------------------------------------------------
# build_payload_too_large_error
# ---------------------------------------------------------------------------


def test_build_payload_too_large_error_populates_details_shape() -> None:
    """The builder populates the §4.5 / §11.2 details contract.

    Spec: ARSIA-Core.md §4.5, §11.2 (payload_too_large details).
    """
    corr = str(uuid.uuid4())
    env = build_payload_too_large_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=corr,
        max_message_bytes=1_048_576,
        actual_bytes=2_097_152,
    )
    assert env["intent"] == "error"
    assert env["payload"]["error"]["code"] == "payload_too_large"
    details = env["payload"]["error"]["details"]
    assert details == {
        "max_message_bytes": 1_048_576,
        "actual_bytes": 2_097_152,
    }


def test_build_payload_too_large_error_default_description_mentions_bytes() -> None:
    """The default description references both byte counts.

    Spec: ARSIA-Core.md §11.1 (actionable error messages).
    """
    env = build_payload_too_large_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        max_message_bytes=1_048_576,
        actual_bytes=2_097_152,
    )
    description = env["payload"]["error"]["description"]
    assert "1048576" in description
    assert "2097152" in description


def test_build_payload_too_large_error_custom_description_preserved() -> None:
    """A supplied description overrides the default.

    Spec: ARSIA-Core.md §11.1.
    """
    env = build_payload_too_large_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        max_message_bytes=4_194_304,
        actual_bytes=8_388_608,
        description="Split the request into smaller batches.",
    )
    assert (
        env["payload"]["error"]["description"]
        == "Split the request into smaller batches."
    )


# ---------------------------------------------------------------------------
# build_forbidden_error
# ---------------------------------------------------------------------------


def test_build_forbidden_error_populates_required_details() -> None:
    """The builder exposes required and provided capabilities as arrays.

    Spec: ARSIA-Core.md §11.2 (forbidden details).
    """
    env = build_forbidden_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        required_capabilities=["cap.one", "cap.two"],
        provided_capabilities=["cap.one"],
    )
    assert env["intent"] == "error"
    assert env["payload"]["error"]["code"] == "forbidden"
    details = env["payload"]["error"]["details"]
    assert details["required_capabilities"] == ["cap.one", "cap.two"]
    assert details["provided_capabilities"] == ["cap.one"]


def test_build_forbidden_error_default_description_lists_missing() -> None:
    """The default description names the capabilities that were missing.

    Spec: ARSIA-Core.md §11.1.
    """
    env = build_forbidden_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        required_capabilities=["cap.one", "cap.two"],
        provided_capabilities=["cap.one"],
    )
    description = env["payload"]["error"]["description"]
    assert "cap.two" in description


def test_build_forbidden_error_copies_input_lists() -> None:
    """The builder copies the input lists into details.

    Mutating the caller-supplied list after the error envelope is built
    MUST NOT mutate details — error envelopes are meant to be immutable
    once assembled.

    Spec: ARSIA-Core.md §11.2.
    """
    required = ["cap.one"]
    provided: list[str] = []
    env = build_forbidden_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        required_capabilities=required,
        provided_capabilities=provided,
    )
    required.append("cap.mutated")
    provided.append("cap.mutated")
    details = env["payload"]["error"]["details"]
    assert details["required_capabilities"] == ["cap.one"]
    assert details["provided_capabilities"] == []


# ---------------------------------------------------------------------------
# build_oversight_denied_error / build_oversight_expired_error
# ---------------------------------------------------------------------------


def test_build_oversight_denied_error_shape() -> None:
    """Spec: ARSIA-Actions.md §3.4 Path 2 Step 2."""
    env = build_oversight_denied_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        approver_id="agent:acme.supervisor",
        reason="Risk parameters incomplete",
    )
    err = env["payload"]["error"]
    assert env["intent"] == "error"
    assert err["code"] == "forbidden"
    assert err["description"] == "Action denied by human oversight"
    assert err["details"] == {
        "oversight_decision": "denied",
        "approver_id": "agent:acme.supervisor",
        "reason": "Risk parameters incomplete",
    }


def test_build_oversight_denied_error_reason_defaults_to_none() -> None:
    """Spec: ARSIA-Actions.md §3.4 — reason may be null when absent."""
    env = build_oversight_denied_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        approver_id="agent:acme.supervisor",
    )
    assert env["payload"]["error"]["details"]["reason"] is None


def test_build_oversight_expired_error_shape() -> None:
    """Spec: ARSIA-Actions.md §3.4 Path 3 Step 2."""
    deadline = "2026-04-13T12:00:00.000Z"
    env = build_oversight_expired_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        deadline=deadline,
    )
    err = env["payload"]["error"]
    assert env["intent"] == "error"
    assert err["code"] == "forbidden"
    assert err["description"] == "Action approval deadline exceeded"
    assert err["details"] == {
        "oversight_decision": "expired",
        "deadline": deadline,
    }


# ---------------------------------------------------------------------------
# build_not_implemented_error
# ---------------------------------------------------------------------------


def test_build_not_implemented_error_populates_required_details() -> None:
    """The builder sets supported_versions and requested_version.

    Spec: ARSIA-Core.md §7.4, §11.2 (not_implemented details).
    """
    env = build_not_implemented_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        supported_min="1.0",
        supported_max="1.0",
        requested_version="2.0",
        requested_min_version="1.5",
    )
    assert env["intent"] == "error"
    assert env["payload"]["error"]["code"] == "not_implemented"
    details = env["payload"]["error"]["details"]
    assert details["supported_versions"] == {"min": "1.0", "max": "1.0"}
    assert details["requested_version"] == "2.0"
    assert details["requested_min_version"] == "1.5"


def test_build_not_implemented_error_omits_requested_min_when_absent() -> None:
    """requested_min_version is omitted when the caller passes None.

    The spec example in §7.4 includes requested_min_version only when
    the rejected message carried min_v; otherwise it MUST be absent
    from details rather than present as null.

    Spec: ARSIA-Core.md §7.4.
    """
    env = build_not_implemented_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        supported_min="1.0",
        supported_max="1.0",
        requested_version="2.0",
    )
    details = env["payload"]["error"]["details"]
    assert "requested_min_version" not in details
    assert details["supported_versions"] == {"min": "1.0", "max": "1.0"}
    assert details["requested_version"] == "2.0"


def test_build_not_implemented_error_default_description_mentions_range() -> None:
    """The default description names the supported range.

    Spec: ARSIA-Core.md §11.1.
    """
    env = build_not_implemented_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        supported_min="1.0",
        supported_max="1.2",
        requested_version="2.0",
    )
    description = env["payload"]["error"]["description"]
    assert "1.0" in description
    assert "1.2" in description
    assert "2.0" in description


# ---------------------------------------------------------------------------
# build_service_unavailable_error
# ---------------------------------------------------------------------------


def test_build_service_unavailable_error_residency_variant_details() -> None:
    """The residency variant emits both mandated fields.

    Spec: ARSIA-Core.md §9.2, §11.2 (service_unavailable residency).
    """
    env = build_service_unavailable_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        data_residency_violation=True,
        required_zone="EU",
    )
    assert env["intent"] == "error"
    assert env["payload"]["error"]["code"] == "service_unavailable"
    details = env["payload"]["error"]["details"]
    assert details == {
        "data_residency_violation": True,
        "required_zone": "EU",
    }


def test_build_service_unavailable_error_residency_requires_zone() -> None:
    """Setting data_residency_violation=True without a zone raises ValueError.

    Spec: ARSIA-Core.md §11.2 (service_unavailable residency MUSTs).
    """
    with pytest.raises(ValueError, match="required_zone is mandatory"):
        build_service_unavailable_error(
            from_agent=_RISK,
            to_agent=_ACME,
            correlation_id=str(uuid.uuid4()),
            data_residency_violation=True,
        )


def test_build_service_unavailable_error_generic_has_no_details() -> None:
    """The generic variant does not emit a details object.

    Spec: ARSIA-Core.md §11.2 (service_unavailable — no mandated details
    when the cause is maintenance/overload rather than residency).
    """
    env = build_service_unavailable_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
    )
    error_obj = env["payload"]["error"]
    assert error_obj["code"] == "service_unavailable"
    assert error_obj.get("details") is None


# ---------------------------------------------------------------------------
# compute_retry_delay
# ---------------------------------------------------------------------------


def test_retry_delay_attempt_1() -> None:
    """First retry waits 1 s.

    Spec: ARSIA-Core.md §11.3 retry schedule table.
    """
    assert compute_retry_delay(1) == 1.0


def test_retry_delay_attempt_2() -> None:
    """Second retry waits 2 s.

    Spec: ARSIA-Core.md §11.3 retry schedule table.
    """
    assert compute_retry_delay(2) == 2.0


def test_retry_delay_attempt_3() -> None:
    """Third retry waits 4 s.

    Spec: ARSIA-Core.md §11.3 retry schedule table.
    """
    assert compute_retry_delay(3) == 4.0


def test_retry_delay_beyond_max_raises() -> None:
    """Attempts beyond ``max_retries`` raise ValueError.

    Spec: ARSIA-Core.md §11.3 (maximum 3 retries).
    """
    with pytest.raises(ValueError):
        compute_retry_delay(RETRY_POLICY.max_retries + 1)


def test_retry_delay_zero_raises() -> None:
    """Attempt 0 raises ValueError (the schedule is 1-indexed)."""
    with pytest.raises(ValueError):
        compute_retry_delay(0)


def test_retry_policy_constants_match_spec() -> None:
    """The RETRY_POLICY constants match the §11.3 table.

    Spec: ARSIA-Core.md §11.3.
    """
    assert RETRY_POLICY.base_delay_seconds == 1.0
    assert RETRY_POLICY.multiplier == 2.0
    assert RETRY_POLICY.max_delay_seconds == 32.0
    assert RETRY_POLICY.max_retries == 3
    assert RETRY_POLICY.jitter_range == (0.75, 1.25)


# ---------------------------------------------------------------------------
# build_rate_limited_error
# ---------------------------------------------------------------------------


def test_build_rate_limited_error_all_fields() -> None:
    """All four detail fields are emitted when provided.

    Spec: ARSIA-Core.md §11.2 (rate_limited details).
    """
    env = build_rate_limited_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        retry_after_seconds=60,
        limit=100,
        remaining=0,
        reset_at="2026-01-01T00:01:00.000Z",
    )
    err = env["payload"]["error"]
    assert err["code"] == "rate_limited"
    assert err["details"] == {
        "retry_after_seconds": 60,
        "limit": 100,
        "remaining": 0,
        "reset_at": "2026-01-01T00:01:00.000Z",
    }


def test_build_rate_limited_error_required_only() -> None:
    """Only retry_after_seconds is emitted when optionals are omitted.

    Spec: ARSIA-Core.md §11.2 (rate_limited details — SHOULD fields).
    """
    env = build_rate_limited_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        retry_after_seconds=30,
    )
    details = env["payload"]["error"]["details"]
    assert details == {"retry_after_seconds": 30}


def test_build_rate_limited_error_code_is_rate_limited() -> None:
    """The error code is 'rate_limited'.

    Spec: ARSIA-Core.md §11.2.
    """
    env = build_rate_limited_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        retry_after_seconds=10,
    )
    assert env["payload"]["error"]["code"] == "rate_limited"
    assert env["intent"] == "error"


def test_build_rate_limited_error_omits_none_fields() -> None:
    """None-valued optional fields are absent from details, not null.

    Spec: ARSIA-Core.md §11.2.
    """
    env = build_rate_limited_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        retry_after_seconds=5,
        limit=None,
        remaining=None,
        reset_at=None,
    )
    details = env["payload"]["error"]["details"]
    assert "limit" not in details
    assert "remaining" not in details
    assert "reset_at" not in details
    assert details["retry_after_seconds"] == 5


def test_build_rate_limited_error_default_description() -> None:
    """Default description is set when none provided.

    Spec: ARSIA-Core.md §11.2.
    """
    env = build_rate_limited_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        retry_after_seconds=10,
    )
    assert env["payload"]["error"]["description"] == "Request rate limit exceeded."


def test_build_rate_limited_error_custom_description() -> None:
    """Custom description overrides the default.

    Spec: ARSIA-Core.md §11.2.
    """
    env = build_rate_limited_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        retry_after_seconds=10,
        description="Too many requests from this agent.",
    )
    assert env["payload"]["error"]["description"] == "Too many requests from this agent."


# ---------------------------------------------------------------------------
# build_not_implemented_error — unsupported_type enhancement
# ---------------------------------------------------------------------------


def test_build_not_implemented_error_with_unsupported_type() -> None:
    """unsupported_type is included in details when provided.

    Spec: ARSIA-Core.md §11.2 (not_implemented — unsupported_type SHOULD).
    """
    env = build_not_implemented_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        supported_min="1.0",
        supported_max="1.0",
        requested_version="1.0",
        unsupported_type="com.unknown/action",
    )
    details = env["payload"]["error"]["details"]
    assert details["unsupported_type"] == "com.unknown/action"
    assert details["supported_versions"] == {"min": "1.0", "max": "1.0"}


def test_build_not_implemented_error_without_unsupported_type_unchanged() -> None:
    """Backward compat: unsupported_type absent when not provided.

    Spec: ARSIA-Core.md §11.2.
    """
    env = build_not_implemented_error(
        from_agent=_RISK,
        to_agent=_ACME,
        correlation_id=str(uuid.uuid4()),
        supported_min="1.0",
        supported_max="1.0",
        requested_version="2.0",
    )
    details = env["payload"]["error"]["details"]
    assert "unsupported_type" not in details
