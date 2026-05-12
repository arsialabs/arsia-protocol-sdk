# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""HTTP transport: send signed envelopes, receive and validate incoming."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from arsia_protocol import (
    apply_profile,
    check_identity_consistency,
    sign_message,
    validate_compliance,
    validate_envelope,
    verify_message,
)

from keys import KeyStore

logger = logging.getLogger(__name__)


async def send_envelope(
    envelope: dict[str, Any],
    key_store: KeyStore,
    target_url: str,
    *,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Sign an envelope and POST it to a peer agent.

    Steps:
    1. Apply compliance profile (sender-side normalization)
    2. Sign with this agent's private key
    3. POST to target_url/envelope
    4. Return the response body (which should be a signed envelope)
    """
    profiled = apply_profile(envelope)
    signed = sign_message(profiled, key_store.private_key, key_store.kid)

    logger.info(
        "Sending %s → %s (id=%s, intent=%s)",
        signed.get("from"), signed.get("to"),
        signed.get("id", "?")[:12], signed.get("intent"),
    )

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{target_url}/envelope",
            json=signed,
        )
        resp.raise_for_status()
        return resp.json()


class IncomingEnvelopeError(Exception):
    """Raised when an incoming envelope fails validation."""

    def __init__(self, message: str, errors: list[Any] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


def validate_incoming(
    envelope: dict[str, Any],
    key_store: KeyStore,
) -> dict[str, Any]:
    """Verify and validate an incoming envelope.

    Steps:
    1. Extract sender from envelope['from']
    2. Look up sender's public key
    3. Verify signature
    4. Validate envelope structure (L1 + L2)
    5. Validate compliance
    6. Check identity consistency (from ↔ kid)

    Returns the envelope if valid, raises IncomingEnvelopeError otherwise.
    """
    from_agent = envelope.get("from", "")
    security = envelope.get("security", {})
    kid = security.get("kid", "")

    pub_key = key_store.get_peer_public_key(from_agent)
    if pub_key is None:
        raise IncomingEnvelopeError(
            f"Unknown sender: {from_agent} — no public key registered"
        )

    if not verify_message(envelope, pub_key):
        raise IncomingEnvelopeError(
            f"Signature verification failed for envelope from {from_agent}"
        )

    errors = validate_envelope(envelope)
    if errors:
        error_msgs = [f"{e.code}: {e.message}" for e in errors]
        raise IncomingEnvelopeError(
            f"Envelope validation failed: {error_msgs}",
            errors=errors,
        )

    comp_errors = validate_compliance(envelope)
    if comp_errors:
        error_msgs = [f"{e.code}: {e.message}" for e in comp_errors]
        raise IncomingEnvelopeError(
            f"Compliance validation failed: {error_msgs}",
            errors=comp_errors,
        )

    identity_result = check_identity_consistency(from_agent=from_agent, kid=kid)
    if not identity_result.is_consistent:
        raise IncomingEnvelopeError(
            f"Identity consistency check failed: {identity_result.warnings}"
        )

    logger.info(
        "Validated incoming %s ← %s (id=%s)",
        envelope.get("to"), from_agent, envelope.get("id", "?")[:12],
    )
    return envelope
