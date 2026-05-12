# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic models for identity, JWKS, and discovery documents.

Mirrors ``shared/schemas/arsia-identity-record.schema.json`` plus the
JWKS and discovery document definitions in ARSIA-Core.md §7.

Known limitations
-----------------

ARSIA-Identity.md §1.2.2 and §1.2.8 enumerate six legal-entity identifier
formats for ``owner_id`` and ``deployer_id``: EU VAT, US EIN, LEI, DUNS,
national registry numbers, and URNs. Implementing a multi-format regex
that correctly validates all six across jurisdictions is impractical, so
this SDK enforces only ``min_length=3`` and accepts any non-empty string.
Callers SHOULD perform format validation at the application layer when
the target jurisdiction is known.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arsia_protocol.identity.agent_id import is_valid_agent_id
from arsia_protocol.types.compliance import AISystemClassification

_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"


def _check_agent_id(value: str) -> str:
    if not is_valid_agent_id(value):
        raise ValueError(f"'{value}' is not a valid ARSIA agent identifier (Core §3.3)")
    return value


class ArsiaJWK(BaseModel):
    """A single JSON Web Key entry.

    Ed25519 keys use ``kty='OKP'`` and ``crv='Ed25519'``. Spec: ARSIA-Core.md §7.3.
    """

    model_config = ConfigDict(extra="allow")

    kty: str = Field(description="Key type, e.g. 'OKP' for Ed25519.")
    crv: str = Field(description="Curve name, e.g. 'Ed25519'.")
    x: str = Field(description="Base64url-encoded public key bytes, no padding.")
    y: str | None = Field(
        default=None, description="Base64url-encoded y-coordinate (EC keys only)."
    )
    kid: str = Field(description="Key identifier, unique within the JWKS.")
    use: str = Field(description="Intended use, e.g. 'sig' or 'enc'.")
    alg: str | None = Field(default=None, description="Algorithm hint, e.g. 'EdDSA'.")


class ArsiaJWKS(BaseModel):
    """A JSON Web Key Set, as returned by the JWKS endpoint.

    Spec: ARSIA-Core.md §7.3.
    """

    model_config = ConfigDict(extra="forbid")

    keys: list[ArsiaJWK] = Field(description="Array of JWK entries.")


class ArsiaCapabilityDescriptor(BaseModel):
    """Descriptor returned by the capability discovery endpoint.

    Spec: ARSIA-Core.md §7.2.
    """

    model_config = ConfigDict(extra="forbid")

    capability: str = Field(description="Capability identifier string.")
    description: str = Field(description="Human-readable description.")
    risk_level: int = Field(ge=0, le=10, description="Risk level 0-10.")
    rate_limit: int | None = Field(
        default=None, ge=0, description="Per-capability rate limit (requests/minute)."
    )
    requires: list[str] | None = Field(
        default=None, description="Prerequisite capability strings."
    )
    human_oversight_required: bool = Field(
        description="Whether human approval is required before execution."
    )


class IdentityRecord(BaseModel):
    """Legal, cryptographic, and compliance identity for an ARSIA agent.

    Mirrors ``shared/schemas/arsia-identity-record.schema.json``.
    Spec: ARSIA-Identity.md §1.2.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(description="Agent identifier (Core §3).")
    owner_id: str = Field(
        min_length=3,
        description="Legal entity identifier of the owner.",
    )
    owner_name: str = Field(
        min_length=1,
        description="Human-readable legal name of the owner.",
    )
    jurisdiction: str = Field(
        pattern=r"^[A-Z]{2}$",
        description="ISO 3166-1 alpha-2 country code of legal registration.",
    )
    ai_system_classification: AISystemClassification = Field(
        description="Agent-level EU AI Act classification (worst-case).",
    )
    deployer_id: str | None = Field(
        default=None,
        min_length=3,
        description="Legal entity identifier of the deployer, when different.",
    )
    deployer_name: str | None = Field(
        default=None,
        min_length=1,
        description="Human-readable legal name of the deployer.",
    )
    created_at: str = Field(
        pattern=_TS_PATTERN,
        description="When the record was created (RFC 3339 ms).",
    )
    valid_until: str | None = Field(
        default=None,
        pattern=_TS_PATTERN,
        description="Expiry date of the record (RFC 3339 ms).",
    )
    contact_email: str | None = Field(
        default=None,
        description="Role-based operational contact (used for DORA incident reporting).",
    )
    certificate_chain: list[str] | None = Field(
        default=None,
        description="PEM-encoded X.509 chain for L2/L3 trust (Identity §6.5.1).",
    )

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        return _check_agent_id(value)

    @model_validator(mode="after")
    def _require_deployer_name_when_deployer_id_set(self) -> "IdentityRecord":
        if self.deployer_id is not None and self.deployer_name is None:
            raise ValueError(
                "deployer_name is required when deployer_id is set (Identity §1.2)"
            )
        return self


class ArsiaRateLimits(BaseModel):
    """Rate-limiting hints advertised in discovery.

    Spec: ARSIA-Core.md §7.1.
    """

    model_config = ConfigDict(extra="forbid")

    requests_per_minute: int | None = Field(default=None, ge=0)
    burst_size: int | None = Field(default=None, ge=0)


class ArsiaFeatures(BaseModel):
    """Optional feature flags advertised in discovery.

    Spec: ARSIA-Core.md §7.1.
    """

    model_config = ConfigDict(extra="allow")

    async_responses: bool | None = None
    batch_requests: bool | None = None
    encryption: bool | None = None


class ArsiaDiscoveryDocument(BaseModel):
    """Response body of the ``/.well-known/arsia`` discovery endpoint.

    Spec: ARSIA-Core.md §7.1.
    """

    model_config = ConfigDict(extra="allow")

    agent_id: str = Field(description="The agent's identifier (Core §3).")
    name: str = Field(description="Human-readable display name.")
    version: str = Field(description="Agent software version.")
    protocol_version: Literal["1.0"] = Field(
        description="ARSIA protocol version; currently '1.0'."
    )
    inbox: str = Field(description="Absolute URL of the agent's inbox endpoint.")
    jwks: str = Field(description="Absolute URL of the JWKS endpoint.")
    capabilities_supported: list[str] = Field(
        description="Capability strings accepted by this agent."
    )
    max_message_bytes: int = Field(
        ge=1, description="Maximum accepted envelope size in bytes."
    )
    request_timeout_ms: int = Field(
        ge=1, description="Maximum request processing time in milliseconds."
    )
    server_min: str = Field(
        pattern=r"^\d+\.\d+$",
        description="Minimum supported protocol version.",
    )
    server_max: str = Field(
        pattern=r"^\d+\.\d+$",
        description="Maximum supported protocol version.",
    )
    features: ArsiaFeatures | None = Field(default=None)
    rate_limits: ArsiaRateLimits | None = Field(default=None)
    compliance_profiles_supported: list[str] | None = Field(default=None)

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        return _check_agent_id(value)


__all__ = [
    "ArsiaJWK",
    "ArsiaJWKS",
    "ArsiaCapabilityDescriptor",
    "IdentityRecord",
    "ArsiaRateLimits",
    "ArsiaFeatures",
    "ArsiaDiscoveryDocument",
]
