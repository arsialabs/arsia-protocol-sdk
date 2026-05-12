# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic models for the Routing primitive (brokers + capability policy).

Business logic (topology determination, broker selection, policy
evaluation) lives in ``arsia_protocol.routing`` starting in Slice 7.
This module provides the structural models only, mirroring:

- ``shared/schemas/arsia-broker-entry.schema.json`` (Routing §7.2)
- ``shared/schemas/arsia-capability-policy.schema.json`` (Identity §8)
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arsia_protocol.identity.agent_id import is_valid_agent_id

BrokerHealth = Literal["healthy", "degraded", "unhealthy"]
"""Broker health status per ARSIA-Routing.md §7.2."""

CapabilityRuleStatus = Literal["allowed", "oversight_required", "prohibited"]
"""Capability policy rule status per ARSIA-Identity.md §8.2."""

_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"


def _check_agent_id(value: str) -> str:
    if not is_valid_agent_id(value):
        raise ValueError(f"'{value}' is not a valid ARSIA agent identifier (Core §3.3)")
    return value


class BrokerCapacity(BaseModel):
    """Capacity hint for load-based broker selection.

    Spec: ARSIA-Routing.md §7.2.
    """

    model_config = ConfigDict(extra="forbid")

    requests_per_minute: int | None = Field(
        default=None, ge=0, description="Maximum relay capacity per minute."
    )
    current_load_pct: int | None = Field(
        default=None, ge=0, le=100, description="Current load as a percentage."
    )


class BrokerEntry(BaseModel):
    """One entry in the broker discovery response.

    Spec: ARSIA-Routing.md §7.2.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(description="The broker's agent identifier (Core §3).")
    inbox: str = Field(description="Absolute URL of the broker's inbox endpoint.")
    jurisdiction: str = Field(
        pattern=r"^[A-Z]{2}$",
        description="ISO 3166-1 alpha-2 of the broker's physical location.",
    )
    residency_zones: list[str] = Field(
        min_length=1,
        description="Zones this broker serves (e.g. ['EU'], ['PT', 'EU']).",
    )
    capacity: BrokerCapacity | None = Field(default=None)
    health: BrokerHealth = Field(description="Latest health check result.")
    last_health_check: str = Field(
        pattern=_TS_PATTERN,
        description="RFC 3339 ms timestamp of the most recent health check.",
    )

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        return _check_agent_id(value)

    @field_validator("residency_zones")
    @classmethod
    def _validate_residency_zones(cls, value: list[str]) -> list[str]:
        import re

        zone_re = re.compile(r"^[A-Z]{2,4}$")
        for zone in value:
            if not zone_re.fullmatch(zone):
                raise ValueError(
                    f"residency zone '{zone}' must be an uppercase alphabetic "
                    f"string of 2-4 characters"
                )
        return value


class CapabilityRule(BaseModel):
    """One rule inside a ``CapabilityPolicy``.

    Spec: ARSIA-Identity.md §8.2.
    """

    model_config = ConfigDict(extra="forbid")

    capability: str = Field(
        pattern=r"^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*$",
        description="Exact capability string — wildcards NOT permitted in rules.",
    )
    status: CapabilityRuleStatus = Field(
        description="Policy status for this capability."
    )
    max_risk_level: int | None = Field(
        default=None,
        ge=0,
        le=10,
        description="Maximum risk level at which this capability may be invoked.",
    )
    conditions: str | None = Field(
        default=None,
        description="Human-readable conditions; informational only.",
    )


class CapabilityPolicy(BaseModel):
    """Policy defining which capabilities are available to external agents.

    Input to Phase 3 (Capability Scoping) of the external-agent
    onboarding flow (ARSIA-Identity.md §7.4). Evaluation is
    deny-by-default: capabilities not listed are rejected.

    Spec: ARSIA-Identity.md §8.1.
    """

    model_config = ConfigDict(extra="forbid")

    policy_version: str = Field(
        min_length=1, description="Version identifier (e.g. 'finco-2026-q1')."
    )
    token_lifetime_seconds: int = Field(
        ge=1, description="Lifetime of access tokens issued under this policy."
    )
    capabilities: list[CapabilityRule] = Field(description="Array of capability rules.")


__all__ = [
    "BrokerHealth",
    "CapabilityRuleStatus",
    "BrokerCapacity",
    "BrokerEntry",
    "CapabilityRule",
    "CapabilityPolicy",
]
