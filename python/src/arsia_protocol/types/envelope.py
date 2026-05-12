# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic models for the ARSIA message envelope.

Mirrors ``shared/schemas/arsia-message.schema.json`` and
ARSIA-Core.md §4. The top-level type is :class:`ArsiaMessage`; it
composes :class:`ArsiaPayload`, :class:`ArsiaContext`,
:class:`ArsiaIdempotency`, :class:`ArsiaSecurity`, and
:class:`ArsiaCompliance`.

The schema uses the JSON key ``"from"`` which is a Python reserved
word, so the model attribute is ``from_`` with ``Field(alias="from")``.
:meth:`ArsiaMessage.model_dump` with ``by_alias=True`` produces the
correct JSON key.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arsia_protocol.identity.agent_id import is_valid_agent_id
from arsia_protocol.types.compliance import ArsiaCompliance
from arsia_protocol.types.errors import ArsiaError
from arsia_protocol.types.security import ArsiaSecurity

ArsiaIntent = Literal[
    "request",
    "response",
    "event",
    "error",
    "pending_approval",
    "approval_decision",
]
"""The six ARSIA message intents per ARSIA-Core.md §4.1.6."""

_VERSION_PATTERN = r"^\d+\.\d+$"
_UUID_V4_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
_CAPABILITY_PATTERN = r"^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*(\.\*)?$"
_PAYLOAD_TYPE_PATTERN = (
    r"^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*"
    r"(/[a-zA-Z][a-zA-Z0-9_-]*)*$"
)


def _check_agent_id(value: str) -> str:
    if not is_valid_agent_id(value):
        raise ValueError(f"'{value}' is not a valid ARSIA agent identifier (Core §3.3)")
    return value


class ArsiaPayload(BaseModel):
    """Application-specific payload carried by an ARSIA message.

    Only one of ``args``, ``result``, ``data``, or ``error`` SHOULD be
    present per message; the mapping to ``intent`` is defined in
    ARSIA-Core.md §4.4.7.

    Spec: ARSIA-Core.md §4.4.
    """

    model_config = ConfigDict(extra="forbid")

    type: str = Field(
        pattern=_PAYLOAD_TYPE_PATTERN,
        description="Reverse-domain payload type identifier (Core §4.4.1).",
    )
    version: str | None = Field(
        default=None,
        description="Optional semantic version of the payload schema (Core §4.4.2).",
    )
    args: Any = Field(
        default=None, description="Input parameters for requests (Core §4.4.3)."
    )
    result: Any = Field(
        default=None, description="Output value for responses (Core §4.4.4)."
    )
    data: Any = Field(
        default=None, description="Event notification content (Core §4.4.5)."
    )
    error: ArsiaError | None = Field(
        default=None,
        description="Error details when intent='error' (Core §4.4.6).",
    )


class ArsiaContext(BaseModel):
    """Distributed tracing and localisation metadata.

    Spec: ARSIA-Core.md §4.3.3.
    """

    model_config = ConfigDict(extra="forbid")

    trace_id: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{32}$",
        description="W3C Trace Context 128-bit trace identifier.",
    )
    span_id: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{16}$",
        description="W3C Trace Context 64-bit span identifier.",
    )
    flags: int | None = Field(
        default=None,
        ge=0,
        le=255,
        description="W3C Trace Context 8-bit flags.",
    )
    locale: str | None = Field(
        default=None, description="BCP 47 locale tag (e.g. 'pt-PT')."
    )
    priority: int | None = Field(
        default=None,
        ge=0,
        le=10,
        description="Priority hint 0-10 (default 5).",
    )


class ArsiaIdempotency(BaseModel):
    """Idempotency key and expiry for at-most-once semantics.

    Spec: ARSIA-Core.md §4.3.2.
    """

    model_config = ConfigDict(extra="forbid")

    key: str = Field(
        min_length=1,
        max_length=128,
        description="Idempotency key, unique per (from, to, payload.type).",
    )
    expires_at: str = Field(
        pattern=_TS_PATTERN,
        description="RFC 3339 ms timestamp after which the record may be discarded.",
    )


class ArsiaMessage(BaseModel):
    """ARSIA Protocol message envelope.

    The top-level structural type for every ARSIA message, mirroring
    ``shared/schemas/arsia-message.schema.json``. ``from_`` serialises
    to ``"from"`` in JSON via :meth:`model_dump` with ``by_alias=True``.

    Spec: ARSIA-Core.md §4.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        # Forward compatibility (Core §4.1.1): minor version differences within
        # the same major version MUST be handled gracefully. Unknown top-level
        # fields introduced in a later minor version are silently ignored
        # rather than rejected, so that a v="1.0" implementation can still
        # accept a v="1.1" message. Sub-models retain extra="forbid".
        extra="ignore",
    )

    v: str = Field(
        pattern=_VERSION_PATTERN,
        description="Protocol version 'MAJOR.MINOR' (Core §4.1.1).",
    )
    id: str = Field(
        pattern=_UUID_V4_PATTERN,
        description="UUID v4 message identifier (Core §4.1.2).",
    )
    ts: str = Field(
        pattern=_TS_PATTERN,
        description="RFC 3339 ms timestamp (Core §4.1.3).",
    )
    from_: str = Field(
        alias="from",
        serialization_alias="from",
        description="Sender agent identifier (Core §4.1.4).",
    )
    to: str = Field(description="Recipient agent identifier (Core §4.1.5).")
    intent: ArsiaIntent = Field(description="Semantic purpose (Core §4.1.6).")

    # Conditional required fields (Core §4.2).
    correlation_id: str | None = Field(
        default=None,
        pattern=_UUID_V4_PATTERN,
        description="Required when intent is response/error/approval_decision.",
    )
    expires_at: str | None = Field(
        default=None,
        pattern=_TS_PATTERN,
        description="Required when intent is request/pending_approval.",
    )
    capabilities: list[str] | None = Field(
        default=None,
        description="Required when intent='request'; non-empty, unique.",
    )

    # Optional fields (Core §4.3).
    min_v: str | None = Field(
        default=None,
        pattern=_VERSION_PATTERN,
        description="Minimum supported protocol version (Core §4.3.1).",
    )
    idempotency: ArsiaIdempotency | None = Field(
        default=None, description="Idempotency configuration (Core §4.3.2)."
    )
    context: ArsiaContext | None = Field(
        default=None, description="Distributed tracing metadata (Core §4.3.3)."
    )
    payload: ArsiaPayload | str | None = Field(
        default=None,
        description=(
            "Payload object, or a JWE compact serialization string when "
            "security.encrypted=true (Core §4.3.4, §4.4)."
        ),
    )
    security: ArsiaSecurity | None = Field(
        default=None, description="Signature and encryption metadata (Core §4.3.5)."
    )
    compliance: ArsiaCompliance | None = Field(
        default=None, description="Regulatory requirements (Core §4.3.6)."
    )

    @field_validator("from_", "to")
    @classmethod
    def _validate_agent_identifiers(cls, value: str) -> str:
        return _check_agent_id(value)

    @field_validator("capabilities")
    @classmethod
    def _validate_capabilities(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if len(value) < 1:
            raise ValueError("capabilities must contain at least one element")
        if len(set(value)) != len(value):
            raise ValueError("capabilities must be unique")
        import re

        cap_re = re.compile(_CAPABILITY_PATTERN)
        for cap in value:
            if not cap_re.fullmatch(cap):
                raise ValueError(
                    f"capability '{cap}' does not match the ARSIA capability grammar"
                )
        return value

    @model_validator(mode="after")
    def _enforce_intent_conditional_fields(self) -> "ArsiaMessage":
        intent = self.intent
        if intent == "request":
            if self.expires_at is None:
                raise ValueError(
                    "expires_at is required when intent='request' (Core §4.2.2)"
                )
            if self.capabilities is None:
                raise ValueError(
                    "capabilities is required when intent='request' (Core §4.2.3)"
                )
        elif intent in ("response", "error", "approval_decision"):
            if self.correlation_id is None:
                raise ValueError(
                    f"correlation_id is required when intent='{intent}' (Core §4.2.1)"
                )
        elif intent == "pending_approval":
            if self.expires_at is None:
                raise ValueError(
                    "expires_at is required when intent='pending_approval' "
                    "(Core §4.2.2)"
                )
        return self


__all__ = [
    "ArsiaIntent",
    "ArsiaPayload",
    "ArsiaContext",
    "ArsiaIdempotency",
    "ArsiaMessage",
]
