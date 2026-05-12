# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.routing``.

Spec: ARSIA-Routing.md §7.2 and ARSIA-Identity.md §8.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arsia_protocol.types.routing import (
    BrokerCapacity,
    BrokerEntry,
    CapabilityPolicy,
    CapabilityRule,
)


def test_broker_entry_minimal_valid() -> None:
    """A minimal BrokerEntry constructs successfully.

    Spec: ARSIA-Routing.md §7.2.
    """
    entry = BrokerEntry(
        agent_id="agent:broker.eu-central",
        inbox="https://broker.example/v1/arsia/inbox",
        jurisdiction="DE",
        residency_zones=["EU"],
        health="healthy",
        last_health_check="2026-03-24T10:15:30.000Z",
    )
    assert entry.health == "healthy"
    assert entry.residency_zones == ["EU"]


def test_broker_entry_with_capacity() -> None:
    """BrokerEntry accepts optional BrokerCapacity.

    Spec: ARSIA-Routing.md §7.2.
    """
    entry = BrokerEntry(
        agent_id="agent:broker.eu-central",
        inbox="https://broker.example/v1/arsia/inbox",
        jurisdiction="DE",
        residency_zones=["EU", "DE"],
        capacity=BrokerCapacity(requests_per_minute=10000, current_load_pct=42),
        health="degraded",
        last_health_check="2026-03-24T10:15:30.000Z",
    )
    assert entry.capacity is not None
    assert entry.capacity.current_load_pct == 42


def test_broker_entry_rejects_bad_residency_zone() -> None:
    """residency_zones entries must be two-letter uppercase codes.

    Spec: ARSIA-Routing.md §7.2.
    """
    with pytest.raises(ValidationError):
        BrokerEntry(
            agent_id="agent:broker.eu",
            inbox="https://x",
            jurisdiction="DE",
            residency_zones=["eu"],
            health="healthy",
            last_health_check="2026-03-24T10:15:30.000Z",
        )


def test_broker_capacity_load_pct_bounds() -> None:
    """current_load_pct must be between 0 and 100.

    Spec: ARSIA-Routing.md §7.2.
    """
    with pytest.raises(ValidationError):
        BrokerCapacity(current_load_pct=101)


def test_capability_rule_valid() -> None:
    """A CapabilityRule with required fields constructs successfully.

    Spec: ARSIA-Identity.md §8.2.
    """
    rule = CapabilityRule(
        capability="payments.charge",
        status="oversight_required",
        max_risk_level=5,
    )
    assert rule.status == "oversight_required"


def test_capability_rule_rejects_wildcards() -> None:
    """Capability rules do not permit wildcards.

    Spec: ARSIA-Identity.md §8.2.
    """
    with pytest.raises(ValidationError):
        CapabilityRule(capability="payments.*", status="allowed")


def test_capability_rule_max_risk_level_bounds() -> None:
    """max_risk_level must be 0-10.

    Spec: ARSIA-Identity.md §8.2.
    """
    with pytest.raises(ValidationError):
        CapabilityRule(
            capability="payments.charge", status="allowed", max_risk_level=11
        )


def test_capability_policy_valid() -> None:
    """A CapabilityPolicy with one rule constructs successfully.

    Spec: ARSIA-Identity.md §8.1.
    """
    policy = CapabilityPolicy(
        policy_version="finco-2026-q1",
        token_lifetime_seconds=3600,
        capabilities=[
            CapabilityRule(capability="payments.charge", status="allowed"),
        ],
    )
    assert policy.policy_version == "finco-2026-q1"
    assert len(policy.capabilities) == 1
