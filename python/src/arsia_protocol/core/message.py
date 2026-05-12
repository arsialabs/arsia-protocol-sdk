# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA message envelope factories and high-level sign/verify.

This module is Layer 2 (Core) in the SDK dependency graph. It provides:

- Factory functions that produce valid ARSIA envelope dicts for each of
  the six intents defined in ARSIA-Core.md §4.1.6.
- High-level :func:`sign_message` / :func:`verify_message` workflows
  that apply the envelope rules from Core §5.1 and §5.2 on top of the
  raw primitives in :mod:`arsia_protocol.hazmat`.
- Timestamp helpers (:func:`format_timestamp`, :func:`is_expired`) that
  honour the RFC 3339 millisecond format from §4.1.3 and the ±300 s
  clock skew tolerance from §8.3.

Factory functions return plain ``dict`` values rather than Pydantic
models because envelopes are built incrementally: callers may attach
compliance, context, or idempotency fields between creation and
signing. Pydantic validation is a separate concern handled by the
Layer 3 ``validation`` module.
"""

from __future__ import annotations

import copy
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_decode,
    base64url_encode,
    sign as ed25519_sign,
    verify as ed25519_verify,
)
from arsia_protocol.hazmat.primitives.ecdsa import (
    sign as es256_sign,
    verify as es256_verify,
)
from arsia_protocol.identity.agent_id import is_valid_agent_id

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "1.0"
"""The ARSIA protocol version implemented by this SDK (Core §4.1.1)."""

DEFAULT_REQUEST_TTL_SECONDS = 300
"""Default ``expires_in_seconds`` for request and pending_approval factories."""

CLOCK_SKEW_TOLERANCE_SECONDS = 300
"""Clock skew tolerance for ``expires_at`` validation (Core §8.3)."""

PENDING_APPROVAL_CONTEXT_MAX_LENGTH = 1024
"""Maximum length of the ``context`` string in pending_approval args (Actions §3.2)."""

DEFAULT_MAX_MESSAGE_BYTES = 1_048_576
"""Default maximum envelope size in bytes (1 MiB) per Core §4.5.

Implementations MAY advertise a larger limit via the ``max_message_bytes``
field of their discovery metadata (§7.1); this constant represents the
spec default when no override is published.
"""

ARSIA_CONTENT_TYPE = "application/arsia+json; v=1"
"""Canonical Content-Type for ARSIA HTTP/2 requests & responses (Core §8)."""


def matches_arsia_content_type(header_value: str | None) -> bool:
    """Accept ``application/arsia+json; v=1`` (case-insensitive, extra ws).

    The ``v`` parameter is required — it's what lets us evolve the wire
    format without changing the media type. Minor variants like
    ``application/arsia+json;v=1`` (no space) are accepted.
    """
    if not header_value:
        return False
    parts = [p.strip().lower() for p in header_value.split(";") if p.strip()]
    if not parts or parts[0] != "application/arsia+json":
        return False
    return "v=1" in parts[1:]


def check_envelope_size(
    envelope: dict[str, Any] | bytes | str,
    max_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> tuple[bool, int]:
    """Measure an envelope's serialized size and compare to a limit.

    The size that ARSIA §4.5 constrains is the UTF-8 JSON serialization
    of the envelope, including all fields and whitespace. This helper
    returns both the decision and the measured byte count so callers
    can build a ``payload_too_large`` error with accurate ``actual_bytes``.

    This utility is **not** called from :func:`validation.validate_envelope`.
    Enforcement of the size limit belongs to the transport layer
    (e.g. the FastAPI middleware added in Slice 8): §4.5 is a transport
    concern, and the SDK does not reject envelopes based on byte count
    during semantic validation.

    Args:
        envelope: Either an already-serialized envelope (``bytes`` or
            ``str``) whose length is measured directly, or a ``dict``
            which is serialized with :func:`json.dumps` and encoded as
            UTF-8 before measurement. No canonicalization is applied —
            §4.5 is about wire bytes, not canonical bytes.
        max_bytes: The maximum permitted size. Defaults to
            :data:`DEFAULT_MAX_MESSAGE_BYTES`.

    Returns:
        A ``(is_within_limit, actual_bytes)`` tuple. The first element
        is ``True`` when ``actual_bytes <= max_bytes``.

    Spec: ARSIA-Core.md §4.5.
    """
    if isinstance(envelope, (bytes, bytearray)):
        actual = len(envelope)
    elif isinstance(envelope, str):
        actual = len(envelope.encode("utf-8"))
    else:
        actual = len(json.dumps(envelope).encode("utf-8"))
    return (actual <= max_bytes, actual)


def format_timestamp(moment: datetime | None = None) -> str:
    """Return an RFC 3339 timestamp with exactly three fractional digits.

    The format produced matches the normative pattern from Core §4.1.3::

        ^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$

    Args:
        moment: The moment to format. Defaults to current UTC time. If
            a naive ``datetime`` is supplied it is assumed to be UTC;
            timezone-aware values are converted to UTC.

    Returns:
        The formatted timestamp string (millisecond precision,
        ``Z`` suffix).

    Spec: ARSIA-Core.md §4.1.3.
    """
    if moment is None:
        moment = datetime.now(timezone.utc)
    elif moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)
    # Truncate microsecond precision to milliseconds.
    millis = moment.microsecond // 1000
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{millis:03d}Z"


def is_expired(
    envelope: dict[str, Any],
    *,
    clock_skew_seconds: int = CLOCK_SKEW_TOLERANCE_SECONDS,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` when the envelope's ``expires_at`` has elapsed.

    A message is considered expired when::

        now > expires_at + clock_skew_seconds

    Envelopes without an ``expires_at`` field are never considered
    expired (responses, events, errors, and approval_decisions lack
    this field by design — Core §4.2.2).

    Args:
        envelope: The ARSIA envelope as a dict.
        clock_skew_seconds: Tolerance added to ``expires_at`` before
            comparing to ``now``. Defaults to 300 s per Core §8.3.
            When a compliance profile defines ``clock_skew_seconds``,
            callers SHOULD pass that value instead (Core §8.3).
            Pass ``0`` to compare without tolerance.
        now: Reference time. Defaults to current UTC time. Exposed for
            deterministic testing.

    Returns:
        ``True`` if the envelope has expired beyond tolerance, else
        ``False``.

    Spec: ARSIA-Core.md §4.2.2, §8.3.
    """
    expires_at_raw = envelope.get("expires_at")
    if expires_at_raw is None:
        return False
    # Python 3.12 fromisoformat() accepts the trailing 'Z' natively.
    expires_at = datetime.fromisoformat(expires_at_raw)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now > expires_at + timedelta(seconds=clock_skew_seconds)


def _build_base_envelope(
    *,
    from_agent: str,
    to_agent: str,
    intent: str,
    payload_type: str,
    ts: str,
    correlation_id: str | None = None,
    expires_at: str | None = None,
    capabilities: list[str] | None = None,
    args: Any = None,
    result: Any = None,
    data: Any = None,
    error: dict[str, Any] | None = None,
    explanation: dict[str, Any] | None = None,
    compliance: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    idempotency: dict[str, Any] | None = None,
    min_v: str | None = None,
) -> dict[str, Any]:
    """Assemble a fresh envelope dict shared by all intent factories.

    Validates agent identifiers, generates ``v`` and ``id``, builds the
    payload object, and attaches optional fields only when set. The
    caller supplies ``ts`` so that factories needing a matching
    ``expires_at`` can derive both from a single reference instant.

    Raises:
        ValueError: if ``from_agent`` or ``to_agent`` is not a valid
            ARSIA agent identifier (Core §3.3).
    """
    if not is_valid_agent_id(from_agent):
        raise ValueError(
            f"'from' is not a valid ARSIA agent identifier: {from_agent!r}"
        )
    if not is_valid_agent_id(to_agent):
        raise ValueError(f"'to' is not a valid ARSIA agent identifier: {to_agent!r}")

    payload: dict[str, Any] = {"type": payload_type}
    if args is not None:
        payload["args"] = args
    if result is not None:
        payload["result"] = result
    if data is not None:
        payload["data"] = data
    if error is not None:
        payload["error"] = error
    if explanation is not None:
        payload["explanation"] = explanation

    envelope: dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "id": str(uuid.uuid4()),
        "ts": ts,
        "from": from_agent,
        "to": to_agent,
        "intent": intent,
        "payload": payload,
    }
    if correlation_id is not None:
        envelope["correlation_id"] = correlation_id
    if expires_at is not None:
        envelope["expires_at"] = expires_at
    if capabilities is not None:
        envelope["capabilities"] = capabilities
    if min_v is not None:
        envelope["min_v"] = min_v
    if idempotency is not None:
        envelope["idempotency"] = idempotency
    if context is not None:
        envelope["context"] = context
    if compliance is not None:
        envelope["compliance"] = compliance
    return envelope


def create_request(
    from_agent: str,
    to_agent: str,
    payload_type: str,
    capabilities: list[str],
    *,
    args: Any = None,
    expires_in_seconds: int = DEFAULT_REQUEST_TTL_SECONDS,
    compliance: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    idempotency: dict[str, Any] | None = None,
    min_v: str | None = None,
) -> dict[str, Any]:
    """Build a ``request`` envelope.

    Auto-generates ``v``, ``id``, ``ts``, and ``expires_at`` (``ts`` +
    ``expires_in_seconds``). ``capabilities`` is placed at the envelope
    root per Core §4.2.3, not inside ``context``.

    Spec: ARSIA-Core.md §4.1, §4.2.2, §4.2.3, §4.4.3.
    """
    if isinstance(capabilities, dict):
        raise TypeError(
            "capabilities must be a list of strings, got dict. "
            "Example: ['com.acme.billing.create-invoice']"
        )
    if not isinstance(capabilities, (list, tuple)):
        raise TypeError(
            f"capabilities must be a list of strings, got "
            f"{type(capabilities).__name__}. "
            f"Example: ['com.acme.billing.create-invoice']"
        )
    for i, cap in enumerate(capabilities):
        if not isinstance(cap, str):
            raise TypeError(
                f"capabilities[{i}] must be a string, got {type(cap).__name__}: {cap!r}"
            )
    now = datetime.now(timezone.utc)
    ts = format_timestamp(now)
    expires_at = format_timestamp(now + timedelta(seconds=expires_in_seconds))
    return _build_base_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        intent="request",
        payload_type=payload_type,
        ts=ts,
        expires_at=expires_at,
        capabilities=list(capabilities),
        args=args,
        compliance=compliance,
        context=context,
        idempotency=idempotency,
        min_v=min_v,
    )


def create_response(
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    payload_type: str,
    *,
    result: Any = None,
    explanation: dict[str, Any] | None = None,
    compliance: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a ``response`` envelope.

    ``correlation_id`` is required and MUST reference the ``id`` of
    the original request. Responses have no ``expires_at`` and no
    ``capabilities`` field.

    Spec: ARSIA-Core.md §4.1, §4.2.1, §4.4.4.
    """
    return _build_base_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        intent="response",
        payload_type=payload_type,
        ts=format_timestamp(),
        correlation_id=correlation_id,
        result=result,
        explanation=explanation,
        compliance=compliance,
        context=context,
    )


def create_error(
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    code: str,
    description: str,
    *,
    payload_type: str = "org.arsiaprotocol.error",
    details: dict[str, Any] | None = None,
    compliance: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an ``error`` envelope.

    Sets ``intent="error"`` and populates ``payload.error`` with
    ``{code, description, details?}``. ``correlation_id`` is required
    and MUST reference the ``id`` of the message that produced the
    error.

    Spec: ARSIA-Core.md §4.1, §4.2.1, §4.4.6, §11.1.
    """
    error_obj: dict[str, Any] = {"code": code, "description": description}
    if details is not None:
        error_obj["details"] = details
    return _build_base_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        intent="error",
        payload_type=payload_type,
        ts=format_timestamp(),
        correlation_id=correlation_id,
        error=error_obj,
        compliance=compliance,
        context=context,
    )


def create_event(
    from_agent: str,
    to_agent: str,
    payload_type: str,
    *,
    data: Any = None,
    compliance: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an ``event`` envelope.

    Events are fire-and-forget: they have no ``correlation_id`` and no
    ``expires_at``.

    Spec: ARSIA-Core.md §4.1, §4.4.5.
    """
    return _build_base_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        intent="event",
        payload_type=payload_type,
        ts=format_timestamp(),
        data=data,
        compliance=compliance,
        context=context,
    )


def create_pending_approval(
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    payload_type: str,
    *,
    args: Any = None,
    explanation: dict[str, Any] | None = None,
    expires_in_seconds: int = DEFAULT_REQUEST_TTL_SECONDS,
    compliance: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a ``pending_approval`` envelope.

    Requires both ``correlation_id`` (linking to the original request)
    and ``expires_at`` (the deadline for a human decision). Per
    Core §4.4.7 the content field is ``args`` — same as a request —
    not ``result``.

    Spec: ARSIA-Core.md §4.1, §4.2.1, §4.2.2, §4.4.7;
    ARSIA-Actions.md §3.
    """
    if expires_in_seconds > 86400:
        raise ValueError(
            "approval_deadline MUST NOT exceed 24 hours (86400 seconds) "
            "from the pending_approval timestamp (Actions §3.2 Step 3)"
        )
    if (
        args is not None
        and isinstance(args, dict)
        and "context" in args
        and isinstance(args["context"], str)
        and len(args["context"]) > PENDING_APPROVAL_CONTEXT_MAX_LENGTH
    ):
        raise ValueError(
            f"Approval context MUST NOT exceed "
            f"{PENDING_APPROVAL_CONTEXT_MAX_LENGTH} characters "
            f"(got {len(args['context'])}) (Actions §3.2)"
        )
    now = datetime.now(timezone.utc)
    ts = format_timestamp(now)
    expires_at = format_timestamp(now + timedelta(seconds=expires_in_seconds))
    return _build_base_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        intent="pending_approval",
        payload_type=payload_type,
        ts=ts,
        correlation_id=correlation_id,
        expires_at=expires_at,
        args=args,
        explanation=explanation,
        compliance=compliance,
        context=context,
    )


def create_approval_decision(
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    payload_type: str,
    capabilities: list[str],
    *,
    result: Any = None,
    compliance: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an ``approval_decision`` envelope.

    ``correlation_id`` MUST reference the ``id`` of the original
    ``pending_approval`` message. ``capabilities`` is REQUIRED per
    Core §4.2.3. Per Core §4.4.7 the content field is ``result``.

    Spec: ARSIA-Core.md §4.1, §4.2.1, §4.2.3, §4.4.7;
    ARSIA-Actions.md §3.
    """
    if not isinstance(capabilities, (list, tuple)):
        raise TypeError(
            f"capabilities must be a list of strings, got {type(capabilities).__name__}"
        )
    return _build_base_envelope(
        from_agent=from_agent,
        to_agent=to_agent,
        intent="approval_decision",
        payload_type=payload_type,
        ts=format_timestamp(),
        correlation_id=correlation_id,
        capabilities=list(capabilities),
        result=result,
        compliance=compliance,
        context=context,
    )


def sign_message(
    envelope: dict[str, Any],
    private_key: Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
    kid: str,
    alg: str = "EdDSA",
) -> dict[str, Any]:
    """Sign an ARSIA envelope per the Core §5.1 procedure.

    Supports EdDSA (Ed25519, default) and ES256 (ECDSA P-256).

    The signing workflow is:

    1. Validate that ``kid`` starts with ``envelope["from"] + "#"``
       (§5.1 Step 6 — the key identifier is bound to the sender).
    2. Deep-copy the envelope so the caller's dict is not mutated.
    3. Remove any existing ``security`` field from the copy.
    4. Canonicalize the stripped copy via RFC 8785 (JCS).
    5. Produce a signature over the canonical bytes using the
       specified algorithm.
    6. Base64url-encode the signature (no padding) and populate
       ``security = {alg, kid, sig}`` on the copy.

    The returned dict is a new object with ``security`` populated; the
    input envelope is not modified.

    Args:
        envelope: The ARSIA envelope to sign.
        private_key: The sender's signing key — ``Ed25519PrivateKey``
            for EdDSA, or ``EllipticCurvePrivateKey`` (P-256) for ES256.
        kid: Key identifier as published in the sender's JWKS. MUST
            begin with ``envelope["from"] + "#"``.
        alg: Signing algorithm. ``"EdDSA"`` (default) or ``"ES256"``.

    Returns:
        A new envelope dict with ``security`` populated.

    Raises:
        ValueError: if ``envelope`` lacks a string ``from`` field,
            ``kid`` does not begin with ``envelope["from"] + "#"``,
            or ``alg`` is not a supported algorithm.
        TypeError: if ``private_key`` type does not match ``alg``.

    Spec: ARSIA-Core.md §5.1 Steps 1-6, §4.3.5.
    """
    if alg == "EdDSA":
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError(
                f"private_key must be an Ed25519PrivateKey for alg='EdDSA', got "
                f"{type(private_key).__name__}"
            )
    elif alg == "ES256":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                f"private_key must be an EllipticCurvePrivateKey for alg='ES256', "
                f"got {type(private_key).__name__}"
            )
    else:
        raise ValueError(f"Unsupported signing algorithm: {alg!r}")

    from_agent = envelope.get("from")
    if not isinstance(from_agent, str):
        raise ValueError("envelope must have a string 'from' field before signing")
    expected_prefix = f"{from_agent}#"
    if not kid.startswith(expected_prefix):
        raise ValueError(
            f"kid {kid!r} must start with {expected_prefix!r} (Core §5.1 Step 6)"
        )

    clone = copy.deepcopy(envelope)
    clone.pop("security", None)
    canonical_bytes = canonicalize(clone)

    if alg == "EdDSA":
        assert isinstance(private_key, Ed25519PrivateKey)
        signature_bytes = ed25519_sign(private_key, canonical_bytes)
    else:
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        signature_bytes = es256_sign(private_key, canonical_bytes)

    clone["security"] = {
        "alg": alg,
        "kid": kid,
        "sig": base64url_encode(signature_bytes),
    }
    return clone


def verify_message(
    envelope: dict[str, Any],
    public_key: Ed25519PublicKey | ec.EllipticCurvePublicKey,
    *,
    relaxed: bool = False,
) -> bool:
    """Verify an ARSIA envelope signature per Core §5.2.

    Dispatches to EdDSA (Ed25519) or ES256 (ECDSA P-256) based on the
    ``security.alg`` field in the envelope.

    The verification workflow is:

    1. Extract ``security.sig`` and base64url-decode to raw bytes.
    2. Deep-copy the envelope and remove the ``security`` field.
    3. Canonicalize the stripped copy via RFC 8785.
    4. Verify the signature against the canonical bytes using the
       supplied public key.

    The caller is responsible for resolving the public key from the
    sender's JWKS (§5.2 Step 2); the SDK never performs network I/O.

    .. important::

       The ``security`` object — including ``security.kid`` — is
       excluded from the signed bytes per §5.1 Step 2. This means
       ``security.kid`` is **not authenticated** by the signature;
       it is a key-lookup hint, not a tamper-proof binding. A
       modified ``kid`` will not cause this function to return
       ``False``.

       Callers MUST resolve the public key via the sender's JWKS
       using ``security.kid`` (§5.2 Step 2) so that a tampered
       ``kid`` leads to a wrong-key lookup and verification failure.
       Additionally, :func:`~arsia_protocol.validation.validate_envelope`
       enforces that ``security.kid`` starts with ``from + "#"``
       (the ``kid_prefix_mismatch`` check). Both layers together
       prevent ``kid``-substitution attacks.

    Args:
        envelope: The signed envelope to verify.
        public_key: The sender's verification key — ``Ed25519PublicKey``
            for EdDSA, or ``EllipticCurvePublicKey`` (P-256) for ES256.
        relaxed: When ``True``, skip cryptographic verification and
            return ``True`` unconditionally. A warning is logged per
            Identity §3.1.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.

    Raises:
        KeyError: if ``envelope.security.sig`` is missing.

    Spec: ARSIA-Core.md §5.2 Steps 1-6, §4.3.5.
    """
    if relaxed:
        logger.warning(
            "Signature verification relaxed — request processed "
            "without cryptographic verification (Identity §3.1)"
        )
        return True

    try:
        sig_b64 = envelope["security"]["sig"]
    except (KeyError, TypeError):
        raise KeyError("envelope is missing security.sig") from None
    if not isinstance(sig_b64, str):
        raise KeyError("envelope.security.sig must be a string")

    try:
        signature_bytes = base64url_decode(sig_b64)
    except Exception:
        security = envelope.get("security", {})
        logger.warning(
            "Signature verification failed: kid=%s, alg=%s, from=%s",
            security.get("kid", "unknown"),
            security.get("alg", "unknown"),
            envelope.get("from", "unknown"),
        )
        return False

    alg = envelope.get("security", {}).get("alg", "EdDSA")

    if len(signature_bytes) != 64:
        security = envelope.get("security", {})
        logger.warning(
            "Signature verification failed: kid=%s, alg=%s, from=%s",
            security.get("kid", "unknown"),
            security.get("alg", "unknown"),
            envelope.get("from", "unknown"),
        )
        return False
    clone = copy.deepcopy(envelope)
    clone.pop("security", None)
    canonical_bytes = canonicalize(clone)

    if alg == "EdDSA":
        if not isinstance(public_key, Ed25519PublicKey):
            logger.warning(
                "Signature verification failed: kid=%s, alg=%s, from=%s",
                envelope.get("security", {}).get("kid", "unknown"),
                alg,
                envelope.get("from", "unknown"),
            )
            return False
        result = ed25519_verify(public_key, canonical_bytes, signature_bytes)
        if not result:
            logger.warning(
                "Signature verification failed: kid=%s, alg=%s, from=%s",
                envelope.get("security", {}).get("kid", "unknown"),
                alg,
                envelope.get("from", "unknown"),
            )
        return result
    elif alg == "ES256":
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.warning(
                "Signature verification failed: kid=%s, alg=%s, from=%s",
                envelope.get("security", {}).get("kid", "unknown"),
                alg,
                envelope.get("from", "unknown"),
            )
            return False
        result = es256_verify(public_key, canonical_bytes, signature_bytes)
        if not result:
            logger.warning(
                "Signature verification failed: kid=%s, alg=%s, from=%s",
                envelope.get("security", {}).get("kid", "unknown"),
                alg,
                envelope.get("from", "unknown"),
            )
        return result
    else:
        logger.warning(
            "Signature verification failed: kid=%s, alg=%s, from=%s",
            envelope.get("security", {}).get("kid", "unknown"),
            alg,
            envelope.get("from", "unknown"),
        )
        return False


AsyncProcessingStatus = Literal["pending", "completed", "failed"]
"""Status values for the async status endpoint per §8.1."""


def build_async_status_response(
    status: AsyncProcessingStatus,
    *,
    envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the response body for the async status polling endpoint.

    Per §8.1, the status endpoint MUST return:
    - HTTP 202 with ``{"status": "pending"}`` if processing is in progress.
    - HTTP 200 with the ARSIA response envelope if processing is complete.
    - HTTP 410 (Gone) if the status resource has expired.

    The HTTP status code is the caller's responsibility; this builder
    produces only the response body.

    Args:
        status: One of ``"pending"``, ``"completed"``, or ``"failed"``.
        envelope: The ARSIA response envelope (required when status is
            ``"completed"``).

    Returns:
        A dict suitable for JSON serialization as the status endpoint
        response body.

    Spec: ARSIA-Core.md §8.1.
    """
    result: dict[str, Any] = {"status": status}
    if status == "completed" and envelope is not None:
        result["envelope"] = envelope
    return result


__all__ = [
    "ARSIA_CONTENT_TYPE",
    "PROTOCOL_VERSION",
    "DEFAULT_REQUEST_TTL_SECONDS",
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "PENDING_APPROVAL_CONTEXT_MAX_LENGTH",
    "DEFAULT_MAX_MESSAGE_BYTES",
    "matches_arsia_content_type",
    "format_timestamp",
    "is_expired",
    "check_envelope_size",
    "create_request",
    "create_response",
    "create_error",
    "create_event",
    "create_pending_approval",
    "create_approval_decision",
    "sign_message",
    "verify_message",
    "AsyncProcessingStatus",
    "build_async_status_response",
]
