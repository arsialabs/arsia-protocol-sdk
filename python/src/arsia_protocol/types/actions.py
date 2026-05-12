# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic models for the Actions primitive (descriptors + explanations).

Business logic (capability matching, oversight flows, rollback) lives in
``arsia_protocol.actions`` starting in Slice 3. This module provides the
structural models only, mirroring:

- ``shared/schemas/arsia-action-descriptor.schema.json`` (Actions §2.1)
- ``shared/schemas/arsia-explanation.schema.json`` (Actions §5.2)
"""

from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

CAPABILITY_MAX_LENGTH: Final[int] = 128
"""Upper bound on capability string length (Actions §1.1 rule 2)."""

CAPABILITY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*\.\*$"  # 1+ segments + wildcard
    r"|"
    r"^[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)+$"  # 2+ segments, no wildcard
)
"""Capability regex per Actions §1.1.

Two branches corresponding to the two legal shapes:

- **Wildcard form** — one or more segments followed by ``".*"``.
- **Concrete form** — two or more segments, no wildcard.

A single bare segment like ``"notes"`` does not match — that is the
INV-10 gate in the conformance vectors.

Defined in ``types/actions.py`` (Layer 1) so that both
``actions.py`` (Layer 4) and ``validation.py`` (Layer 3) can
import it without a layer violation.

SPEC INCONSISTENCY: The §1.1 ABNF allows digit-first segments
(``domain-part = 1*(ALPHA / DIGIT)``) while the JSON Schemas in
``shared/schemas/arsia-action-descriptor.schema.json`` require a
letter-first segment. This pattern follows the ABNF (normative)
for envelope-path capabilities; the descriptor schema applies the
stricter rule to ActionDescriptor fields. See the SPEC
INCONSISTENCY section in ``arsia_protocol/actions.py`` for the
full discussion.
"""

ActionCategory = Literal[
    "data",
    "communication",
    "financial",
    "system",
    "oversight",
]
"""Action category enum per the schema (5 values)."""

AsyncPollingStatus = Literal["running", "completed", "failed"]
"""Status values for asynchronous action execution polling.

Spec: ARSIA-Actions §4.3 — status field MUST be one of these values.
"""

_PAYLOAD_TYPE_PATTERN = (
    r"^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*"
    r"(/[a-zA-Z][a-zA-Z0-9_-]*)*$"
)
_CAPABILITY_PATTERN = r"^[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)*(\.\*)?$"
_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"


class ActionDescriptor(BaseModel):
    """Describes a single action available at an ARSIA agent.

    Spec: ARSIA-Actions.md §2.1 and
    ``shared/schemas/arsia-action-descriptor.schema.json``.

    ``extra="ignore"`` implements §2.4 forward compatibility: a v1.0
    implementation processing a v1.1 descriptor silently drops unknown
    fields rather than raising a validation error.
    """

    model_config = ConfigDict(extra="ignore")

    action_id: str = Field(
        pattern=_PAYLOAD_TYPE_PATTERN,
        description="Reverse-domain action identifier (Actions §2.1).",
    )
    category: ActionCategory = Field(description="Action category (Actions §2.1).")
    description: str = Field(
        max_length=512, description="Concise English description (Actions §2.1)."
    )
    risk_level: int = Field(
        ge=0, le=10, description="Risk level 0-10 (Actions §2.1, §2.2)."
    )
    reversible: bool = Field(
        description="Whether the action supports rollback (Actions §2.1, §4.2)."
    )
    idempotent: bool = Field(
        description="Whether repeated invocation produces the same effect."
    )
    required_capabilities: list[str] = Field(
        min_length=1,
        description="Capabilities required to invoke this action.",
    )
    optional_capabilities: list[str] | None = Field(
        default=None,
        description="Capabilities that enhance but are not required.",
    )
    human_oversight_required: bool = Field(
        description="Whether execution requires the pending_approval flow."
    )
    audit_required: bool = Field(
        description="Whether every execution must produce an audit record."
    )
    retention_days: int | None = Field(
        default=None,
        ge=1,
        description="Overrides profile retention for this action's audit records.",
    )
    explainability_required: bool = Field(
        description="Whether responses must include payload.explanation."
    )
    max_execution_ms: int | None = Field(
        default=None,
        ge=100,
        description="Maximum execution time in milliseconds (default 30000).",
    )


class AlternativeConsidered(BaseModel):
    """An alternative option the agent evaluated and rejected.

    Spec: ARSIA-Actions.md §5.2.
    """

    model_config = ConfigDict(extra="forbid")

    option: str = Field(description="Description of the alternative option.")
    reason_rejected: str = Field(description="Why this alternative was not chosen.")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence in this alternative (0.0-1.0)."
    )


class Explanation(BaseModel):
    """Structured account of the agent's reasoning.

    Included in response messages as ``payload.explanation`` when the
    action's ``explainability_required`` flag is true. Implements EU AI
    Act Article 13 transparency obligations.

    Spec: ARSIA-Actions.md §5.2 and
    ``shared/schemas/arsia-explanation.schema.json``.
    """

    model_config = ConfigDict(extra="forbid")

    reasoning: str = Field(max_length=4096, description="Plain-language reasoning.")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Agent confidence in the decision (0.0-1.0)."
    )
    inputs_used: list[str] = Field(
        min_length=1,
        description="Identifiers of inputs that influenced the decision.",
    )
    alternatives_considered: list[AlternativeConsidered] | None = Field(
        default=None,
        description="Rejected alternatives (RECOMMENDED for risk_level ≥ 7).",
    )
    model_version: str | None = Field(
        default=None, description="Identifier of the ML model used, if any."
    )
    decision_timestamp: str | None = Field(
        default=None,
        pattern=_TS_PATTERN,
        description="When the decision was made (RFC 3339 ms).",
    )


__all__ = [
    "AsyncPollingStatus",
    "CAPABILITY_MAX_LENGTH",
    "CAPABILITY_PATTERN",
    "ActionCategory",
    "ActionDescriptor",
    "AlternativeConsidered",
    "Explanation",
]
