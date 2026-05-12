# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.actions``.

Spec: ARSIA-Actions.md §2.1 and §5.2.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from arsia_protocol.types.actions import (
    ActionDescriptor,
    AlternativeConsidered,
    AsyncPollingStatus,
    Explanation,
)


def test_action_descriptor_minimal_valid() -> None:
    """An ActionDescriptor with all required fields constructs successfully.

    Spec: ARSIA-Actions.md §2.1.
    """
    action = ActionDescriptor(
        action_id="com.acme.billing/create-invoice",
        category="financial",
        description="Create a new invoice.",
        risk_level=6,
        reversible=True,
        idempotent=False,
        required_capabilities=["billing.create"],
        human_oversight_required=False,
        audit_required=True,
        explainability_required=True,
    )
    assert action.category == "financial"
    assert action.risk_level == 6


def test_action_descriptor_rejects_out_of_range_risk_level() -> None:
    """risk_level must be between 0 and 10.

    Spec: ARSIA-Actions.md §2.1.
    """
    with pytest.raises(ValidationError):
        ActionDescriptor(
            action_id="com.acme.billing/x",
            category="data",
            description="x",
            risk_level=11,
            reversible=True,
            idempotent=True,
            required_capabilities=["x.y"],
            human_oversight_required=False,
            audit_required=False,
            explainability_required=False,
        )


def test_action_descriptor_rejects_unknown_category() -> None:
    """Category must be one of the five Literal values.

    Spec: ARSIA-Actions.md §2.1.
    """
    with pytest.raises(ValidationError):
        ActionDescriptor(
            action_id="com.acme.x",
            category="computation",  # type: ignore[arg-type]
            description="x",
            risk_level=1,
            reversible=True,
            idempotent=True,
            required_capabilities=["x.y"],
            human_oversight_required=False,
            audit_required=False,
            explainability_required=False,
        )


def test_action_descriptor_requires_capabilities() -> None:
    """required_capabilities must be non-empty.

    Spec: ARSIA-Actions.md §2.1.
    """
    with pytest.raises(ValidationError):
        ActionDescriptor(
            action_id="com.acme.x",
            category="data",
            description="x",
            risk_level=1,
            reversible=True,
            idempotent=True,
            required_capabilities=[],
            human_oversight_required=False,
            audit_required=False,
            explainability_required=False,
        )


def test_explanation_minimal_valid() -> None:
    """An Explanation with required fields constructs successfully.

    Spec: ARSIA-Actions.md §5.2.
    """
    exp = Explanation(
        reasoning="The invoice was created because the customer requested it.",
        confidence=0.92,
        inputs_used=["customer_id", "order_total"],
    )
    assert exp.confidence == 0.92
    assert len(exp.inputs_used) == 2


def test_explanation_with_alternatives() -> None:
    """Explanation accepts a list of AlternativeConsidered entries.

    Spec: ARSIA-Actions.md §5.2.
    """
    exp = Explanation(
        reasoning="x",
        confidence=0.8,
        inputs_used=["a"],
        alternatives_considered=[
            AlternativeConsidered(
                option="do nothing",
                reason_rejected="would violate SLA",
                confidence=0.1,
            ),
        ],
    )
    assert exp.alternatives_considered is not None
    assert len(exp.alternatives_considered) == 1


def test_explanation_confidence_bounds() -> None:
    """confidence must be between 0.0 and 1.0.

    Spec: ARSIA-Actions.md §5.2.
    """
    with pytest.raises(ValidationError):
        Explanation(reasoning="x", confidence=1.5, inputs_used=["a"])


def test_alternative_considered_confidence_bounds() -> None:
    """AlternativeConsidered.confidence must be 0.0-1.0.

    Spec: ARSIA-Actions.md §5.2.
    """
    with pytest.raises(ValidationError):
        AlternativeConsidered(option="x", reason_rejected="y", confidence=-0.1)


def test_async_polling_status_values() -> None:
    """ACT-§4.3-07: async polling status is running/completed/failed."""
    assert get_args(AsyncPollingStatus) == ("running", "completed", "failed")
