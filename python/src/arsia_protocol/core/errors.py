# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Error code registry, retry policy, and error envelope builder.

This module is Layer 2 (Core) in the SDK dependency graph. It provides:

- :data:`ERROR_REGISTRY`: a read-only mapping from each of the
  fourteen standard error codes (ten from Core §11.2 plus four
  certificate codes from Identity §6.4.3) to an :class:`ErrorCodeInfo`
  record holding HTTP status and retryability metadata.
- :data:`RETRY_POLICY`: the exponential-backoff parameters for the
  server-error tier defined in Core §11.3.
- :func:`get_error_info` and :func:`is_retryable`: registry lookups.
- :func:`build_error_envelope`: validates the error code against the
  registry and delegates to :func:`arsia_protocol.message.create_error`.
- :func:`compute_retry_delay`: exponential backoff without jitter.

Note: :mod:`arsia_protocol.types.errors` (Layer 1) defines the Pydantic
model used inside ``payload.error``. This module (Layer 2) defines the
runtime behaviour — HTTP status mapping, retryability, builders, and
retry-delay calculations.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Mapping

from arsia_protocol.core import message


@dataclass(frozen=True)
class ErrorCodeInfo:
    """Metadata for a standard ARSIA error code.

    Attributes:
        code: The error code string.
        http_status: The HTTP status code returned when this error is
            surfaced over the HTTP transport.
        description: A human-readable description of the error
            condition.
        retryable: Whether the sender SHOULD retry a failed request
            that produced this error, subject to the retry policy in
            Core §11.3.

    Spec: ARSIA-Core.md §11.2.
    """

    code: str
    http_status: int
    description: str
    retryable: bool


_REGISTRY_ENTRIES: tuple[ErrorCodeInfo, ...] = (
    ErrorCodeInfo(
        code="invalid_request",
        http_status=400,
        description=(
            "The message envelope is malformed, missing required fields, "
            "or contains values that violate the §4 constraints."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="unauthorized",
        http_status=401,
        description=(
            "The access token is missing, expired, malformed, or the "
            "digital signature verification failed."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="forbidden",
        http_status=403,
        description=(
            "The access token is valid but does not include sufficient "
            "capabilities for the requested action."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="not_found",
        http_status=404,
        description=("The target agent or the requested resource does not exist."),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="conflict",
        http_status=409,
        description=(
            "The idempotency key collides with an in-progress request, "
            "or a state conflict prevents processing."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="payload_too_large",
        http_status=413,
        description=(
            "The message exceeds the recipient's max_message_bytes limit (§4.5)."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="rate_limited",
        http_status=429,
        description="The sender has exceeded the recipient's rate limit.",
        retryable=True,
    ),
    ErrorCodeInfo(
        code="internal_error",
        http_status=500,
        description=("An unexpected error occurred during message processing."),
        retryable=True,
    ),
    ErrorCodeInfo(
        code="not_implemented",
        http_status=501,
        description=(
            "The requested feature, capability, payload type, or "
            "protocol version is not supported by the recipient."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="service_unavailable",
        http_status=503,
        description=(
            "The recipient is temporarily unable to process requests "
            "(maintenance, overload, or dependency failure)."
        ),
        retryable=True,
    ),
    # Identity §6.4.3 — certificate-related authentication failures.
    # Specification does not assign explicit HTTP status codes; these
    # follow the §3.2 step 7 rule that authentication failures map to
    # 401 (the same status as the generic ``unauthorized`` code).
    ErrorCodeInfo(
        code="certificate_invalid",
        http_status=401,
        description=(
            "Certificate is malformed, the chain failed validation, or "
            "the agent_id is not present in the leaf SAN "
            "(Identity §6.4.3)."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="certificate_expired",
        http_status=401,
        description=("Leaf certificate notAfter is in the past (Identity §6.4.3)."),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="key_mismatch",
        http_status=401,
        description=(
            "Public key in the certificate does not match the JWKS key "
            "(Identity §6.4.3)."
        ),
        retryable=False,
    ),
    ErrorCodeInfo(
        code="certificate_revoked",
        http_status=401,
        description=(
            "OCSP or CRL indicates the certificate is revoked (Identity §6.4.3)."
        ),
        retryable=False,
    ),
)


ERROR_REGISTRY: Final[Mapping[str, ErrorCodeInfo]] = MappingProxyType(
    {entry.code: entry for entry in _REGISTRY_ENTRIES}
)
"""Read-only mapping of the fourteen standard ARSIA error codes.

Includes the ten Core codes (Core §11.2) and the four certificate
codes (Identity §6.4.3).
"""


@dataclass(frozen=True)
class RetryPolicy:
    """Exponential-backoff parameters for retryable server errors.

    Attributes:
        base_delay_seconds: Delay used for the first retry attempt.
        multiplier: Factor by which the delay grows between attempts.
        max_delay_seconds: Upper bound on any computed delay.
        max_retries: Maximum number of retry attempts before the
            sender MUST abandon the request.
        jitter_range: Recommended multiplicative jitter window
            ``(low, high)`` applied to each computed delay.

    Spec: ARSIA-Core.md §11.3.
    """

    base_delay_seconds: float
    multiplier: float
    max_delay_seconds: float
    max_retries: int
    jitter_range: tuple[float, float]


RETRY_POLICY: Final[RetryPolicy] = RetryPolicy(
    base_delay_seconds=1.0,
    multiplier=2.0,
    max_delay_seconds=32.0,
    max_retries=3,
    jitter_range=(0.75, 1.25),
)
"""Exponential-backoff parameters for ``internal_error`` and
``service_unavailable`` retries (Core §11.3).

The ``rate_limited`` code uses a separate policy driven by the
``Retry-After`` header and ``payload.error.details.retry_after_seconds``
and is NOT governed by this policy.
"""


def get_error_info(code: str) -> ErrorCodeInfo:
    """Look up the registry entry for an error code.

    Args:
        code: The error code string.

    Returns:
        The :class:`ErrorCodeInfo` for ``code``.

    Raises:
        ValueError: if ``code`` is not one of the ten standard codes.

    Spec: ARSIA-Core.md §11.2.
    """
    try:
        return ERROR_REGISTRY[code]
    except KeyError:
        raise ValueError(f"unknown ARSIA error code: {code!r} (Core §11.2)") from None


def is_retryable(code: str) -> bool:
    """Return whether an error code is retryable under Core §11.3.

    Args:
        code: The error code string.

    Returns:
        ``True`` for ``rate_limited``, ``internal_error``, and
        ``service_unavailable``; ``False`` for the other seven codes.

    Raises:
        ValueError: if ``code`` is not one of the ten standard codes.

    Spec: ARSIA-Core.md §11.2, §11.3.
    """
    return get_error_info(code).retryable


def build_error_envelope(
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    code: str,
    description: str,
    *,
    details: dict[str, Any] | None = None,
    payload_type: str = "org.arsiaprotocol.error",
    compliance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete ARSIA error response envelope.

    Validates that ``code`` is one of the ten standard codes before
    delegating to :func:`arsia_protocol.message.create_error`. Use
    this builder when you want the registry enforcement; call
    ``create_error`` directly if you need to emit an extension code.

    Args:
        from_agent: The sender agent identifier.
        to_agent: The recipient agent identifier.
        correlation_id: The ``id`` of the original message that
            produced the error.
        code: One of the ten standard codes from :data:`ERROR_REGISTRY`.
        description: Human-readable error description (English, no
            sensitive data — see Core §11.1).
        details: Optional structured error context.
        payload_type: Payload type for the envelope. Defaults to
            ``"org.arsiaprotocol.error"`` per Core §11.1.
        compliance: Optional compliance metadata.

    Returns:
        A fully populated error envelope dict (unsigned).

    Raises:
        ValueError: if ``code`` is not in :data:`ERROR_REGISTRY`, or
            if the agent identifiers are invalid (propagated from
            ``create_error``).

    Spec: ARSIA-Core.md §11.1, §11.2.
    """
    get_error_info(code)
    return message.create_error(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code=code,
        description=description,
        payload_type=payload_type,
        details=details,
        compliance=compliance,
    )


def build_payload_too_large_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    max_message_bytes: int,
    actual_bytes: int,
    description: str | None = None,
) -> dict[str, Any]:
    """Build a ``payload_too_large`` error envelope with the §4.5 details shape.

    Populates ``payload.error.details`` with the ``max_message_bytes``
    and ``actual_bytes`` fields required by Core §11.2 so callers do not
    have to assemble the dict by hand.

    Args:
        from_agent: The sender agent identifier (the recipient of the
            oversized message that is now returning the error).
        to_agent: The recipient agent identifier (the original sender).
        correlation_id: The ``id`` of the oversized message.
        max_message_bytes: The recipient's advertised size limit.
        actual_bytes: The measured serialized size of the rejected
            message.
        description: Optional human-readable description. When omitted,
            a default message referencing the two byte counts is used.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Core.md §4.5, §11.2.
    """
    if description is None:
        description = (
            f"Message size {actual_bytes} bytes exceeds the recipient's "
            f"max_message_bytes limit of {max_message_bytes} bytes (Core §4.5)."
        )
    return build_error_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="payload_too_large",
        description=description,
        details={
            "max_message_bytes": max_message_bytes,
            "actual_bytes": actual_bytes,
        },
    )


def build_forbidden_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    required_capabilities: list[str],
    provided_capabilities: list[str],
    description: str | None = None,
) -> dict[str, Any]:
    """Build a ``forbidden`` error envelope with the §11.2 details shape.

    Core §11.2 requires ``payload.error.details`` to carry
    ``required_capabilities`` and ``provided_capabilities`` arrays so
    the sender can diff the two and surface a useful remediation
    message. This builder assembles that structure to keep the two
    lists side-by-side at the call site.

    Args:
        from_agent: The sender agent identifier (the recipient denying
            the request).
        to_agent: The recipient agent identifier (the original sender).
        correlation_id: The ``id`` of the denied request.
        required_capabilities: The capabilities the recipient needed.
        provided_capabilities: The capabilities the sender actually
            presented in its access token.
        description: Optional human-readable description. When omitted,
            a default message summarising the missing capabilities is
            used.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Core.md §11.2 (forbidden details).
    """
    if description is None:
        missing = sorted(set(required_capabilities) - set(provided_capabilities))
        if missing:
            description = (
                "Access token lacks the capabilities required for this "
                f"request: {missing}."
            )
        else:
            description = (
                "Access token does not authorise the requested action (Core §11.2)."
            )
    return build_error_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="forbidden",
        description=description,
        details={
            "required_capabilities": list(required_capabilities),
            "provided_capabilities": list(provided_capabilities),
        },
    )


def build_not_implemented_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    supported_min: str,
    supported_max: str,
    requested_version: str,
    requested_min_version: str | None = None,
    unsupported_type: str | None = None,
    description: str | None = None,
    payload_type: str = "org.arsiaprotocol.error",
) -> dict[str, Any]:
    """Build a ``not_implemented`` error envelope with the §7.4 details shape.

    The negotiation failure path of §7.4 and the §11.2 error table both
    require ``payload.error.details`` to carry the recipient's supported
    version range plus the sender's requested values. This builder
    assembles that structure so callers cannot accidentally omit a
    required key.

    Args:
        from_agent: The sender agent identifier (the recipient rejecting
            the original message).
        to_agent: The recipient agent identifier (the original sender).
        correlation_id: The ``id`` of the rejected message.
        supported_min: The recipient's minimum supported wire version.
        supported_max: The recipient's maximum supported wire version.
        requested_version: The ``v`` value from the rejected message.
        requested_min_version: The ``min_v`` value from the rejected
            message, if present. Omitted from ``details`` when ``None``.
        unsupported_type: The unrecognised ``payload.type`` value, when
            the rejection is due to an unsupported payload type. Omitted
            from ``details`` when ``None``.
        description: Optional human-readable description. When omitted,
            a default message summarising the mismatch is used.
        payload_type: Payload type for the envelope. Defaults to
            ``"org.arsiaprotocol.error"``; callers SHOULD pass the
            original message's payload type per Core §11.1.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Core.md §7.4, §11.1, §11.2.
    """
    if description is None:
        description = (
            f"Requested protocol version {requested_version!r} is outside the "
            f"recipient's supported range "
            f"[{supported_min}, {supported_max}] (Core §7.4)."
        )
    details: dict[str, Any] = {
        "supported_versions": {"min": supported_min, "max": supported_max},
        "requested_version": requested_version,
    }
    if requested_min_version is not None:
        details["requested_min_version"] = requested_min_version
    if unsupported_type is not None:
        details["unsupported_type"] = unsupported_type
    return build_error_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="not_implemented",
        description=description,
        details=details,
        payload_type=payload_type,
    )


def build_service_unavailable_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    data_residency_violation: bool = False,
    required_zone: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Build a ``service_unavailable`` error envelope, optionally §9.2 flavoured.

    Core §11.2 requires ``details`` to include ``data_residency_violation``
    and ``required_zone`` when the cause is a §9.2 residency failure.
    Generic ``service_unavailable`` errors (maintenance, overload,
    dependency failure) have no mandated details shape, so this builder
    omits ``details`` entirely when ``data_residency_violation`` is False.

    Args:
        from_agent: The sender agent identifier (the recipient returning
            the error).
        to_agent: The recipient agent identifier (the original sender).
        correlation_id: The ``id`` of the rejected message.
        data_residency_violation: When True, emits the §9.2 details
            shape. ``required_zone`` MUST be supplied in that case.
        required_zone: The residency zone required by the recipient's
            policy (e.g. ``"EU"``). Required when
            ``data_residency_violation`` is True; ignored otherwise.
        description: Optional human-readable description. When omitted,
            a default tailored to the residency / generic case is used.

    Returns:
        A fully populated error envelope dict (unsigned).

    Raises:
        ValueError: if ``data_residency_violation`` is True but
            ``required_zone`` is not supplied.

    Spec: ARSIA-Core.md §9.2, §11.2 (service_unavailable details).
    """
    if data_residency_violation and required_zone is None:
        raise ValueError(
            "required_zone is mandatory when data_residency_violation=True "
            "(Core §11.2 service_unavailable details)"
        )

    details: dict[str, Any] | None
    if data_residency_violation:
        details = {
            "data_residency_violation": True,
            "required_zone": required_zone,
        }
        if description is None:
            description = (
                "Message cannot be processed outside the required data "
                f"residency zone {required_zone!r} (Core §9.2)."
            )
    else:
        details = None
        if description is None:
            description = (
                "Recipient is temporarily unable to process requests (Core §11.2)."
            )

    return build_error_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="service_unavailable",
        description=description,
        details=details,
    )


def build_rate_limited_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    retry_after_seconds: int,
    limit: int | None = None,
    remaining: int | None = None,
    reset_at: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Build a ``rate_limited`` error envelope with the §11.2 details shape.

    Core §11.2 specifies that ``payload.error.details`` SHOULD include
    ``retry_after_seconds``, ``limit``, ``remaining``, and ``reset_at``
    so the sender can implement correct back-off behaviour.

    Args:
        from_agent: The sender agent identifier (the recipient returning
            the rate-limit error).
        to_agent: The recipient agent identifier (the original sender).
        correlation_id: The ``id`` of the rate-limited message.
        retry_after_seconds: Seconds the sender should wait before
            retrying.
        limit: The rate-limit ceiling (requests per window), if known.
        remaining: Remaining requests in the current window, if known.
        reset_at: RFC 3339 timestamp when the rate-limit window resets,
            if known.
        description: Optional human-readable description. When omitted,
            a default message is used.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Core.md §11.2 (rate_limited details).
    """
    if description is None:
        description = "Request rate limit exceeded."
    details: dict[str, Any] = {
        "retry_after_seconds": retry_after_seconds,
    }
    if limit is not None:
        details["limit"] = limit
    if remaining is not None:
        details["remaining"] = remaining
    if reset_at is not None:
        details["reset_at"] = reset_at
    return build_error_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="rate_limited",
        description=description,
        details=details,
    )


def build_oversight_denied_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    approver_id: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """Build the ``forbidden`` error emitted when oversight denies an action.

    Per ARSIA-Actions.md §3.4 Path 2, when an ``approval_decision``
    with ``decision: "denied"`` is received, the executing agent
    MUST emit an error to the original requester with:

    - ``code = "forbidden"``
    - ``description = "Action denied by human oversight"``
    - ``details = {"oversight_decision": "denied",
      "approver_id": <approver>, "reason": <reason or null>}``

    Args:
        from_agent: The executing agent's identifier (the sender of
            the error).
        to_agent: The original requester's identifier.
        correlation_id: The ``id`` of the original request.
        approver_id: The agent-id of the human-oversight approver
            whose decision was ``"denied"``.
        reason: Optional free-text reason supplied with the denial.
            Emitted as ``null`` in the details when omitted.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Actions.md §3.4 Path 2 Step 2.
    """
    return build_error_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="forbidden",
        description="Action denied by human oversight",
        details={
            "oversight_decision": "denied",
            "approver_id": approver_id,
            "reason": reason,
        },
    )


def build_oversight_expired_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    deadline: str,
) -> dict[str, Any]:
    """Build the ``forbidden`` error emitted when an oversight deadline expires.

    Per ARSIA-Actions.md §3.4 Path 3, when the approval deadline
    is exceeded the executing agent MUST emit an error to the
    original requester with:

    - ``code = "forbidden"``
    - ``description = "Action approval deadline exceeded"``
    - ``details = {"oversight_decision": "expired",
      "deadline": <approval_deadline timestamp>}``

    Args:
        from_agent: The executing agent's identifier (the sender of
            the error).
        to_agent: The original requester's identifier.
        correlation_id: The ``id`` of the original request.
        deadline: The ``approval_deadline`` timestamp (RFC 3339 ms)
            that was exceeded.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Actions.md §3.4 Path 3 Step 2.
    """
    return build_error_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="forbidden",
        description="Action approval deadline exceeded",
        details={
            "oversight_decision": "expired",
            "deadline": deadline,
        },
    )


def compute_retry_delay(attempt: int) -> float:
    """Return the backoff delay (seconds) for a 1-indexed retry attempt.

    Applies the exponential-backoff formula from Core §11.3::

        delay = base_delay * (multiplier ** (attempt - 1))

    capped at :attr:`RetryPolicy.max_delay_seconds`. Jitter is NOT
    applied here — callers that need randomization multiply the
    result by a random factor drawn from
    :attr:`RetryPolicy.jitter_range`.

    This function applies to the server-error backoff tier only
    (``internal_error``, ``service_unavailable``). The ``rate_limited``
    code has a separate policy based on ``Retry-After`` headers and
    ``details.retry_after_seconds``.

    Args:
        attempt: 1-indexed retry attempt number. MUST be in
            ``[1, RETRY_POLICY.max_retries]`` inclusive.

    Returns:
        The delay in seconds before the ``attempt``-th retry.

    Raises:
        ValueError: if ``attempt`` is outside the valid range.

    Spec: ARSIA-Core.md §11.3.
    """
    if attempt < 1 or attempt > RETRY_POLICY.max_retries:
        raise ValueError(
            "attempt must be between 1 and "
            f"{RETRY_POLICY.max_retries} inclusive, got {attempt}"
        )
    raw = RETRY_POLICY.base_delay_seconds * (RETRY_POLICY.multiplier ** (attempt - 1))
    return min(raw, RETRY_POLICY.max_delay_seconds)


__all__ = [
    "ErrorCodeInfo",
    "RetryPolicy",
    "ERROR_REGISTRY",
    "RETRY_POLICY",
    "get_error_info",
    "is_retryable",
    "build_error_envelope",
    "build_forbidden_error",
    "build_not_implemented_error",
    "build_oversight_denied_error",
    "build_oversight_expired_error",
    "build_payload_too_large_error",
    "build_rate_limited_error",
    "build_service_unavailable_error",
    "compute_retry_delay",
]
