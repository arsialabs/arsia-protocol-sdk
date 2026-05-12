# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Capability model, action descriptor validation, and execution lifecycle.

This module is Layer 4 (Primitives) in the SDK dependency graph. It
depends only on :mod:`arsia_protocol.validation` (Layer 3) and the
Pydantic models in :mod:`arsia_protocol.types.actions` (Layer 1) —
never on ``message``, ``errors``, ``hazmat``, ``compliance``,
or ``identity``.

It covers the offline, SDK-level portions of ARSIA-Actions.md:

- **§1 Capability Model** — grammar (§1.1 ABNF), hierarchy and
  wildcard matching (§1.2), downgrading (§1.3), reserved system
  capabilities (§1.4).
- **§2.1 Action Descriptor** — schema-driven validation via
  :func:`arsia_protocol.validation.validate_schema`.
- **§2.2 Risk → EU AI Act classification** — the five-bucket mapping
  (minimal / limited / elevated / high / critical).
- **§4.1 Execution Lifecycle States** — the six-state machine with
  its transition table.
- **§5.2 Explanation Object Format** — schema validation plus the
  cross-field ``decision_timestamp ≤ envelope.ts`` invariant.

What this module does NOT cover (deferred to later slices):

- Live discovery endpoint (§2.3) — Slice 8, needs HTTP.
- Token scope verification in OAuth2 context (§6.4) — Slice 4,
  needs JWT/DPoP primitives.
- HTTP oversight flow (§3) — Slice 8, needs a live agent endpoint.
- Rollback over the wire (§4.2) — Slice 8.

Spec discrepancies resolved in this module
------------------------------------------

1. **Risk classification vocabulary** — §2.2 defines five buckets
   (minimal / limited / elevated / high / critical). There is no
   ``unacceptable-risk`` category in the spec.

2. **Execution lifecycle state names** — §4.1 defines six states
   named REQUESTED, PENDING_APPROVAL, EXECUTING, COMPLETED, FAILED,
   and ROLLED_BACK. "approved" is not a state — approval is an
   event that transitions PENDING_APPROVAL → EXECUTING.

SPEC INCONSISTENCY — §1.1 ABNF vs §2.1 JSON Schemas
---------------------------------------------------

ARSIA-Actions.md contains two authoritative texts for capability
(and related) grammar that disagree on whether a segment may start
with a digit:

- **§1.1 ABNF** (normative grammar):
  ``domain-part = 1*(ALPHA / DIGIT)`` — digit-first segments allowed.
- **§2.1 JSON Schemas** (``arsia-action-descriptor.schema.json``):
  ``^[a-zA-Z][a-zA-Z0-9]*...`` — letter-first only (stricter).

Four fields are affected:

- **M1** — envelope-path capability pattern (§1.1) vs. descriptor
  schema pattern.
- **M2** — ``action_id`` pattern (§2.1 literal vs. schema).
- **M3** — ``required_capabilities`` per-item pattern in the schema.
- **M4** — ``optional_capabilities`` per-item pattern in the schema.

The SDK resolves this pragmatically per field:

- **Envelope-path capabilities** — this module's
  :data:`CAPABILITY_PATTERN` (re-exported from
  :mod:`arsia_protocol.types.actions`) is **ABNF-faithful**
  (digit-first allowed). The ABNF is normative text.
- **ActionDescriptor fields** (``action_id``,
  ``required_capabilities``, ``optional_capabilities``) — validated
  by :func:`validate_action_descriptor` against the JSON Schema, so
  the **stricter letter-first** pattern applies. Treating the schema
  as authoritative here is a defensive choice: descriptors are
  registry data authored by operators, and requiring a letter-first
  shape rules out otherwise-legal identifiers that are more likely
  to be typos than deliberate.

This is a known spec issue, not an SDK bug. Pending resolution
upstream, the two paths above are what the SDK guarantees today.
"""

from __future__ import annotations

import re as _re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Final, Literal, Mapping

from arsia_protocol.core.message import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    create_request,
)
from arsia_protocol.types.actions import (
    CAPABILITY_MAX_LENGTH,
    CAPABILITY_PATTERN,
)
from arsia_protocol.types.errors import ValidationError
from arsia_protocol.core.validation import validate_schema

# ---------------------------------------------------------------------------
# §1 — Capability Model
# ---------------------------------------------------------------------------

RESERVED_PREFIX: Final[str] = "arsiaprotocol."
"""Reserved capability namespace (Actions §1.1 rule 5)."""

RESERVED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "arsiaprotocol.oversight.approve",
        "arsiaprotocol.broker.relay",
        "arsiaprotocol.audit.read",
        "arsiaprotocol.identity.admin",
        "arsiaprotocol.state.read",
        "arsiaprotocol.state.write",
        "arsiaprotocol.state.purge",
        "arsiaprotocol.state.snapshot",
        "arsiaprotocol.assets.transfer.initiate",
        "arsiaprotocol.assets.transfer.approve",
        "arsiaprotocol.assets.transfer.reverse",
        "arsiaprotocol.assets.escrow.create",
        "arsiaprotocol.assets.escrow.release",
        "arsiaprotocol.assets.escrow.cancel",
        "arsiaprotocol.assets.audit.read",
        "arsiaprotocol.compliance.breach.notify",
    }
)
"""The 16 reserved system capabilities defined in Actions §1.4.

Application-defined capabilities MUST NOT use the ``arsiaprotocol.``
prefix. A capability that uses the reserved prefix but is not in
this set is a conformance violation per §1.1 rule 5.
"""


def validate_capability(capability: str) -> list[ValidationError]:
    """Validate a capability string against Actions §1.1.

    Checks grammar (two-segment minimum, ABNF characters, optional
    trailing wildcard), length (≤ 128), and reserved-prefix misuse
    (rule 5 — a capability using ``arsiaprotocol.`` must be one of
    the 16 reserved entries in :data:`RESERVED_CAPABILITIES`).

    Args:
        capability: The capability string to validate.

    Returns:
        A list of :class:`ValidationError`. Empty means the capability
        is conformant.

    Spec: ARSIA-Actions.md §1.1.
    """
    errors: list[ValidationError] = []
    if not isinstance(capability, str):  # defensive: caller may pass non-str
        return [
            ValidationError(
                code="invalid_capability_type",
                message=f"capability must be a string, got {type(capability).__name__}",
                details={"field": "capability", "got": type(capability).__name__},
                spec_ref="Actions §1.1",
            )
        ]
    if capability == "":
        return [
            ValidationError(
                code="empty_capability",
                message="capability must not be empty",
                details={"field": "capability"},
                spec_ref="Actions §1.1",
            )
        ]
    if len(capability) > CAPABILITY_MAX_LENGTH:
        errors.append(
            ValidationError(
                code="capability_too_long",
                message=(f"capability exceeds {CAPABILITY_MAX_LENGTH} characters"),
                details={"field": "capability", "max_length": CAPABILITY_MAX_LENGTH},
                spec_ref="Actions §1.1 rule 2",
            )
        )
    if not CAPABILITY_PATTERN.fullmatch(capability):
        errors.append(
            ValidationError(
                code="invalid_capability_grammar",
                message=(
                    f"capability {capability!r} does not match the §1.1 ABNF grammar"
                ),
                details={"field": "capability", "value": capability},
                spec_ref="Actions §1.1 rules 1, 4, 6",
            )
        )
    if (
        capability.startswith(RESERVED_PREFIX)
        and capability not in RESERVED_CAPABILITIES
    ):
        errors.append(
            ValidationError(
                code="reserved_prefix_misuse",
                message=(
                    f"capability {capability!r} uses the reserved {RESERVED_PREFIX!r} "
                    f"prefix but is not one of the 15 reserved system capabilities"
                ),
                details={"field": "capability", "value": capability},
                spec_ref="Actions §1.1 rule 5, §1.4",
            )
        )
    return errors


def is_valid_capability(capability: str) -> bool:
    """Return ``True`` if ``capability`` passes :func:`validate_capability`.

    Spec: ARSIA-Actions.md §1.1.
    """
    return not validate_capability(capability)


def is_reserved_capability(capability: str) -> bool:
    """Return ``True`` if ``capability`` is one of the 16 reserved entries.

    Spec: ARSIA-Actions.md §1.4.
    """
    return capability in RESERVED_CAPABILITIES


def is_reserved_prefix_misuse(capability: str) -> bool:
    """Return ``True`` if ``capability`` uses the reserved prefix illegally.

    A misuse is a capability string that starts with ``arsiaprotocol.``
    but is not one of the 15 entries in :data:`RESERVED_CAPABILITIES`.
    Non-reserved capabilities (``notes.read``, ``payments.charge``)
    return ``False``.

    Spec: ARSIA-Actions.md §1.1 rule 5.
    """
    if not isinstance(capability, str):
        return False
    return (
        capability.startswith(RESERVED_PREFIX)
        and capability not in RESERVED_CAPABILITIES
    )


EXPLICIT_GRANT_ONLY: Final[frozenset[str]] = frozenset(
    {
        "arsiaprotocol.state.purge",
        "arsiaprotocol.state.snapshot",
        "arsiaprotocol.oversight.approve",
    }
)
"""Non-delegable capabilities that MUST NOT be satisfied by any wildcard scope.

Per ARSIA-Actions.md §1.4, these three capabilities MUST require an
explicit grant — they MUST NOT be implied by any wildcard scope.

The gate applies only to wildcard scope entries. An exact match
(e.g. a scope that literally lists ``arsiaprotocol.state.purge``)
is always honoured.
"""


def match_capability(scope_entry: str, requested: str) -> bool:
    """Return ``True`` if ``scope_entry`` satisfies ``requested``.

    Implements the §1.2 matching rule. The token scope is the
    AUTHORITY; the requested capability is the REQUEST. A specific
    scope entry never satisfies a wildcard request — direction
    matters.

    Rules:

    - **Exact match.** ``scope_entry == requested`` (byte-for-byte).
    - **Wildcard match.** ``scope_entry`` ends with ``".*"`` and
      ``requested`` starts with ``prefix + "."`` where ``prefix`` is
      ``scope_entry`` with the trailing ``".*"`` removed. A wildcard
      scope does NOT satisfy a bare prefix (``notes.*`` does not
      satisfy ``notes``) — there must be at least one segment after
      the prefix.
    - **Explicit-grant gate.** Capabilities listed in
      :data:`EXPLICIT_GRANT_ONLY` (the three non-delegable
      capabilities per §1.4) MUST NOT be satisfied by any wildcard
      scope. An exact match still authorises them.

    Args:
        scope_entry: A single entry from the token scope.
        requested: The capability the message is asking for.

    Returns:
        ``True`` if the scope entry authorises the requested
        capability.

    Spec: ARSIA-Actions.md §1.2, §1.4.
    """
    if not isinstance(scope_entry, str) or not isinstance(requested, str):
        return False
    if scope_entry == requested:
        return True
    if not scope_entry.endswith(".*"):
        return False
    if requested in EXPLICIT_GRANT_ONLY:
        return False
    prefix = scope_entry[:-2]
    if not prefix:
        return False
    return requested.startswith(prefix + ".")


def match_capabilities(scope: list[str], requested: list[str]) -> bool:
    """Return ``True`` if every ``requested`` capability is satisfied.

    A request is satisfied when every entry in ``requested`` is
    matched by at least one entry in ``scope`` per
    :func:`match_capability`. An empty ``requested`` list is
    vacuously satisfied.

    Spec: ARSIA-Actions.md §1.2 "Multi-capability requests".
    """
    return not find_unsatisfied_capabilities(scope, requested)


def find_unsatisfied_capabilities(scope: list[str], requested: list[str]) -> list[str]:
    """Return the requested capabilities not satisfied by any scope entry.

    The returned list preserves the order of ``requested`` and
    contains no duplicates beyond those already in ``requested``.
    Used to construct ``forbidden`` error payloads per
    ARSIA-Core.md §11.2.

    Spec: ARSIA-Actions.md §1.2.
    """
    return [
        req
        for req in requested
        if not any(match_capability(entry, req) for entry in scope)
    ]


def downgrade_capabilities(requested: list[str], scope: list[str]) -> list[str]:
    """Return the subset of ``requested`` that is satisfied by ``scope``.

    Used by a receiving agent that accepts a request with reduced
    permissions rather than rejecting it outright per §1.3. The
    return value preserves the order of ``requested`` and never
    contains capabilities that were not requested.

    Per §1.3 rule 3, ``effective_capabilities`` MUST contain at
    least one capability — an empty intersection means the
    receiving agent cannot grant any of the requested capabilities
    and MUST reject the request with a ``forbidden`` error instead
    of responding with an empty downgrade. This function enforces
    that by raising :class:`ValueError` when the intersection is
    empty; callers should catch the exception and emit a
    ``forbidden`` error per ARSIA-Core.md §11.2.

    Spec: ARSIA-Actions.md §1.3 rule 3.

    Raises:
        ValueError: if no requested capability is satisfied by
            ``scope`` — silent downgrade to an empty set is
            prohibited by §1.3 rule 3.
    """
    effective = [
        req for req in requested if any(match_capability(entry, req) for entry in scope)
    ]
    if not effective:
        raise ValueError(
            "downgrade would produce an empty effective_capabilities set; "
            "per Actions §1.3 rule 3 the receiving agent MUST reject with "
            "a `forbidden` error instead of silently downgrading"
        )
    return effective


def attach_effective_capabilities(
    response_envelope: dict[str, Any], effective: list[str]
) -> dict[str, Any]:
    """Return a copy of ``response_envelope`` with ``effective_capabilities`` set.

    Per §1.3 rule 1, a downgraded response MUST place the granted
    capabilities in ``payload.result.effective_capabilities``. This
    helper deep-copies the envelope, ensures ``payload.result``
    exists (creating it as an empty dict if absent), and sets the
    field. The original envelope is not mutated.

    Args:
        response_envelope: A response envelope dict. May or may not
            already have ``payload.result``.
        effective: The downgraded capability list to attach. Callers
            should obtain this from :func:`downgrade_capabilities`.

    Returns:
        A deep copy of ``response_envelope`` with
        ``payload.result.effective_capabilities = effective``.

    Raises:
        TypeError: if ``response_envelope`` is not a dict, if its
            ``payload`` is not a dict, or if an existing
            ``payload.result`` is not a dict.
        ValueError: if ``effective`` is empty — per §1.3 rule 3 an
            empty set is prohibited.

    Spec: ARSIA-Actions.md §1.3 rule 1.
    """
    if not isinstance(response_envelope, dict):
        raise TypeError(
            f"response_envelope must be a dict, got {type(response_envelope).__name__}"
        )
    if not effective:
        raise ValueError(
            "effective_capabilities must contain at least one capability "
            "(Actions §1.3 rule 3)"
        )
    copy = deepcopy(response_envelope)
    payload = copy.get("payload")
    if not isinstance(payload, dict):
        raise TypeError(
            "response_envelope.payload must be a dict to attach effective_capabilities"
        )
    result = payload.get("result")
    if result is None:
        result = {}
        payload["result"] = result
    elif not isinstance(result, dict):
        raise TypeError(
            "response_envelope.payload.result must be a dict to attach "
            "effective_capabilities"
        )
    result["effective_capabilities"] = list(effective)
    return copy


# ---------------------------------------------------------------------------
# §2 — Action Registry
# ---------------------------------------------------------------------------

RiskClassification = Literal[
    "minimal-risk",
    "limited-risk",
    "elevated-risk",
    "high-risk",
    "critical-risk",
]
"""The five EU AI Act classification buckets defined in Actions §2.2."""

_RISK_BUCKETS: Final[tuple[tuple[int, int, RiskClassification], ...]] = (
    (0, 2, "minimal-risk"),
    (3, 4, "limited-risk"),
    (5, 6, "elevated-risk"),
    (7, 8, "high-risk"),
    (9, 10, "critical-risk"),
)
"""Inclusive-range mapping from risk level to classification (§2.2)."""

RISK_LEVEL_CLASSIFICATION: Final[Mapping[int, RiskClassification]] = MappingProxyType(
    {
        level: classification
        for low, high, classification in _RISK_BUCKETS
        for level in range(low, high + 1)
    }
)
"""Read-only direct lookup from risk level (0-10) to classification."""


def get_risk_classification(risk_level: int) -> RiskClassification:
    """Return the EU AI Act classification for ``risk_level``.

    Maps an integer risk level (0-10) to one of the five
    classification strings. Risk levels outside 0-10 raise
    :class:`ValueError` — the schema already rejects out-of-range
    descriptors at L1, so this function is only reachable from
    trusted in-SDK callers that have already validated the level.

    Args:
        risk_level: Integer in the inclusive range 0-10.

    Returns:
        One of: ``"minimal-risk"``, ``"limited-risk"``,
        ``"elevated-risk"``, ``"high-risk"``, ``"critical-risk"``.

    Raises:
        ValueError: if ``risk_level`` is not in 0-10.

    Spec: ARSIA-Actions.md §2.2.
    """
    if not isinstance(risk_level, int) or isinstance(risk_level, bool):
        raise ValueError(
            f"risk_level must be an int in 0-10, got {type(risk_level).__name__}"
        )
    if risk_level < 0 or risk_level > 10:
        raise ValueError(
            f"risk_level must be in the inclusive range 0-10, got {risk_level}"
        )
    return RISK_LEVEL_CLASSIFICATION[risk_level]


def validate_action_descriptor(descriptor: dict[str, Any]) -> list[ValidationError]:
    """Validate an ActionDescriptor dict against its JSON Schema.

    Runs L1 schema validation against
    ``shared/schemas/arsia-action-descriptor.schema.json`` via
    :func:`arsia_protocol.validation.validate_schema`.  The schema’s
    ``allOf`` conditionals enforce the §2.2 risk-band → flag rules
    (risk ≥ 5 → audit, risk ≥ 7 → explainability, risk ≥ 9 →
    human_oversight).

    Additionally emits a warning (not error) when risk_level is 3 or 4
    and ``audit_required`` is not set to true, per §2.2 SHOULD-level
    guidance.

    Spec: ARSIA-Actions.md §2.1, §2.2.
    """
    errors = validate_schema(descriptor, "arsia-action-descriptor.schema.json")

    risk_level = descriptor.get("risk_level")
    if (
        isinstance(risk_level, int)
        and not isinstance(risk_level, bool)
        and 3 <= risk_level <= 4
        and not descriptor.get("audit_required", False)
    ):
        errors.append(
            ValidationError(
                code="risk_34_audit_recommended",
                message=(
                    "Risk level 3-4 actions SHOULD have audit_required set "
                    "to true for traceability."
                ),
                details={
                    "risk_level": risk_level,
                    "audit_required": descriptor.get("audit_required"),
                    "severity": "warning",
                },
                spec_ref="Actions §2.2",
            )
        )

    return errors


# ---------------------------------------------------------------------------
# §2.4 — Version Negotiation
# ---------------------------------------------------------------------------

_SEMVER_RE: Final[_re.Pattern[str]] = _re.compile(r"^(\d+)\.(\d+)$")


def is_major_version_bump(old_version: str, new_version: str) -> bool:
    """Return ``True`` if ``new_version`` has a different major number.

    A major version bump MUST be treated as a new action for capability
    enforcement and discovery purposes. Both arguments must be
    ``"<major>.<minor>"`` strings; raises :class:`ValueError` if either
    is malformed.

    Spec: ARSIA-Actions.md §2.4.
    """
    m_old = _SEMVER_RE.fullmatch(old_version)
    m_new = _SEMVER_RE.fullmatch(new_version)
    if m_old is None:
        raise ValueError(
            f"old_version: invalid version string {old_version!r}. "
            "Expected '<major>.<minor>' format (e.g. '1.0')."
        )
    if m_new is None:
        raise ValueError(
            f"new_version: invalid version string {new_version!r}. "
            "Expected '<major>.<minor>' format (e.g. '1.0')."
        )
    return m_old.group(1) != m_new.group(1)


def resolve_action_version(
    payload: dict[str, Any],
    supported_versions: list[str],
) -> str:
    """Return the action version to use for processing.

    When ``payload`` has no ``version`` field the receiving agent MUST
    use the latest supported version. When ``version`` is present it
    is returned as-is (the caller should then check whether it is
    supported and emit a ``not_implemented`` error if not).

    Args:
        payload: The message ``payload`` dict.
        supported_versions: Versions this agent supports, ordered
            oldest-first (e.g. ``["1.0", "1.1", "2.0"]``).

    Returns:
        The version string to use.

    Raises:
        ValueError: if ``supported_versions`` is empty.

    Spec: ARSIA-Actions.md §2.4.
    """
    if not supported_versions:
        raise ValueError("supported_versions must not be empty")
    version = payload.get("version")
    if version is None:
        return supported_versions[-1]
    return str(version)


def build_version_not_supported_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    requested_version: str,
    supported_versions: list[str],
    payload_type: str = "org.arsiaprotocol.error",
) -> dict[str, Any]:
    """Build a ``not_implemented`` error for an unsupported action version.

    When a ``payload.version`` is present but the receiving agent does
    not support that version, it MUST respond with ``not_implemented``
    and include the supported version range.

    Args:
        from_agent: The receiving agent's identifier.
        to_agent: The requesting agent's identifier.
        correlation_id: The ``id`` of the rejected message.
        requested_version: The unsupported version from the payload.
        supported_versions: All versions this agent supports.
        payload_type: Payload type for the error envelope.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Actions.md §2.4, ARSIA-Core.md §11.2.
    """
    from arsia_protocol.core.message import create_error

    return create_error(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="not_implemented",
        description="Action version not supported",
        payload_type=payload_type,
        details={
            "requested_version": requested_version,
            "supported_versions": {
                "min": min(supported_versions),
                "max": max(supported_versions),
            },
        },
    )


# ---------------------------------------------------------------------------
# §4.1 — Execution Lifecycle
# ---------------------------------------------------------------------------

ExecutionState = Literal[
    "requested",
    "pending_approval",
    "executing",
    "completed",
    "failed",
    "rolled_back",
]
"""The six action lifecycle states defined in Actions §4.1.

State names use lowercase snake_case identifiers matching the
spec's uppercase names:

- ``"requested"`` — REQUESTED
- ``"pending_approval"`` — PENDING_APPROVAL
- ``"executing"`` — EXECUTING
- ``"completed"`` — COMPLETED
- ``"failed"`` — FAILED (terminal)
- ``"rolled_back"`` — ROLLED_BACK (terminal)
"""

VALID_TRANSITIONS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "requested": frozenset({"pending_approval", "executing", "failed"}),
        "pending_approval": frozenset({"executing", "failed"}),
        "executing": frozenset({"completed", "failed"}),
        "completed": frozenset({"rolled_back"}),
        "failed": frozenset(),
        "rolled_back": frozenset(),
    }
)
"""Read-only state-machine transition table per Actions §4.1.

``COMPLETED → ROLLED_BACK`` is the only non-terminal edge out of
COMPLETED and is triggered by the rollback flow defined in §4.2.
``FAILED`` and ``ROLLED_BACK`` are strictly terminal — no outgoing
transitions.
"""


def is_valid_transition(from_state: str, to_state: str) -> bool:
    """Return ``True`` if the ``from_state → to_state`` edge is allowed.

    Returns ``False`` when ``from_state`` is unknown, when
    ``to_state`` is unknown, or when the edge is not in
    :data:`VALID_TRANSITIONS`.

    Spec: ARSIA-Actions.md §4.1.
    """
    allowed = VALID_TRANSITIONS.get(from_state)
    if allowed is None:
        return False
    if to_state not in VALID_TRANSITIONS:
        return False
    return to_state in allowed


def is_terminal_state(state: str) -> bool:
    """Return ``True`` if ``state`` has no outgoing transitions.

    ``"failed"`` and ``"rolled_back"`` are terminal per §4.1. An
    unknown state name returns ``False``.

    Spec: ARSIA-Actions.md §4.1.
    """
    allowed = VALID_TRANSITIONS.get(state)
    if allowed is None:
        return False
    return not allowed


# ---------------------------------------------------------------------------
# §5.2 — Explanation
# ---------------------------------------------------------------------------


def validate_explanation(explanation: dict[str, Any]) -> list[ValidationError]:
    """Validate an Explanation dict against its JSON Schema.

    Runs L1 schema validation against
    ``shared/schemas/arsia-explanation.schema.json``. Does not check
    the cross-field ``decision_timestamp ≤ envelope.ts`` invariant —
    that rule requires the enclosing envelope's ``ts`` and is
    exposed separately as :func:`validate_explanation_timestamp`.

    Spec: ARSIA-Actions.md §5.2.
    """
    return validate_schema(explanation, "arsia-explanation.schema.json")


def _parse_rfc3339_ms(value: str) -> datetime | None:
    """Parse a spec-format RFC 3339 millisecond timestamp.

    Returns ``None`` if ``value`` is not a parseable timezone-aware
    datetime. L1 schema validation already rejects syntactically
    malformed timestamps; this helper is defensive.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def validate_explanation_timestamp(
    explanation: dict[str, Any], envelope_ts: str
) -> list[ValidationError]:
    """Enforce ``decision_timestamp ≤ envelope.ts`` per §5.2.

    When an explanation omits ``decision_timestamp`` the invariant
    is vacuously satisfied. When present, the value MUST be earlier
    than or equal to the enclosing envelope's ``ts``.

    Args:
        explanation: The explanation sub-object from ``payload``.
        envelope_ts: The enclosing envelope's ``ts`` string.

    Returns:
        A list of :class:`ValidationError`. Empty means the invariant
        holds.

    Spec: ARSIA-Actions.md §5.2 "decision_timestamp".
    """
    decision_ts_raw = explanation.get("decision_timestamp")
    if decision_ts_raw is None:
        return []
    if not isinstance(decision_ts_raw, str) or not isinstance(envelope_ts, str):
        return [
            ValidationError(
                code="invalid_timestamp_type",
                message=(
                    "explanation.decision_timestamp and envelope.ts must both be "
                    "strings"
                ),
                details={"field": "explanation.decision_timestamp"},
                spec_ref="Actions §5.2",
            )
        ]
    decision_ts = _parse_rfc3339_ms(decision_ts_raw)
    env_ts = _parse_rfc3339_ms(envelope_ts)
    if decision_ts is None or env_ts is None:
        return [
            ValidationError(
                code="unparseable_timestamp",
                message=(
                    "explanation.decision_timestamp or envelope.ts is not a "
                    "parseable RFC 3339 timestamp"
                ),
                details={"field": "explanation.decision_timestamp"},
                spec_ref="Actions §5.2",
            )
        ]
    if decision_ts > env_ts:
        return [
            ValidationError(
                code="decision_timestamp_after_envelope",
                message=(
                    "explanation.decision_timestamp must be earlier than or "
                    "equal to envelope.ts"
                ),
                details={"field": "explanation.decision_timestamp"},
                spec_ref="Actions §5.2",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# §4.2 — Rollback
# ---------------------------------------------------------------------------


def create_rollback_request(
    *,
    from_agent: str,
    to_agent: str,
    original_action_id: str,
    original_message_id: str,
    capabilities: list[str],
    expires_in_seconds: int = 300,
    compliance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a rollback request envelope per §4.2.

    A rollback request is an ordinary ``request`` envelope whose
    ``payload.type`` is ``"{original_action_id}/rollback"`` and
    whose ``payload.args`` carries the ``original_message_id`` of
    the completed action being undone. ``capabilities`` should
    mirror the original action's ``required_capabilities`` so the
    receiver can authorize the rollback against the same scope.

    Args:
        from_agent: The requesting agent's identifier.
        to_agent: The executing agent that ran the original action.
        original_action_id: The ``action_id`` of the action being
            rolled back (e.g. ``"com.example.notes/write"``).
        original_message_id: The ``id`` of the original request
            envelope whose effects should be undone.
        capabilities: The capabilities required to authorize the
            rollback. Typically the original action's
            ``required_capabilities``.
        expires_in_seconds: TTL for the rollback request envelope.
            Defaults to 300 seconds, matching
            :data:`arsia_protocol.message.DEFAULT_REQUEST_TTL_SECONDS`.
        compliance: Optional compliance metadata to carry on the
            envelope.

    Returns:
        A fully populated ``request`` envelope dict (unsigned).

    Spec: ARSIA-Actions.md §4.2 "Rollback Request".
    """
    return create_request(
        from_agent=from_agent,
        to_agent=to_agent,
        payload_type=f"{original_action_id}/rollback",
        capabilities=list(capabilities),
        args={"original_message_id": original_message_id},
        expires_in_seconds=expires_in_seconds,
        compliance=compliance,
    )


def validate_rollback(
    *,
    descriptor: dict[str, Any],
    current_state: str,
    rollback_window_seconds: int | None = None,
    completed_at: datetime | None = None,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Validate whether a rollback is permissible.

    Checks three §4.2 preconditions and returns ``None`` when the
    rollback is allowed or a pre-built error-payload dict when it is
    not. The caller should wrap the returned dict in an error envelope.

    Checks (in order):

    1. **Non-reversible** () — if the descriptor has
       ``reversible: false``, reject with ``not_implemented``.
    2. **Already rolled back** () — if ``current_state``
       is ``"rolled_back"``, reject with ``conflict`` +
       ``already_rolled_back``.
    3. **Window expiry** () — if a ``rollback_window_seconds``
       is provided and ``completed_at + window < now``, reject with
       ``conflict`` + ``rollback_window_exceeded``.

    Args:
        descriptor: The ActionDescriptor dict for the action.
        current_state: The current execution state of the action.
        rollback_window_seconds: Optional rollback window in seconds.
        completed_at: When the action completed (required when
            ``rollback_window_seconds`` is set).
        now: Current time (defaults to ``datetime.now(UTC)``).

    Returns:
        ``None`` if rollback is allowed, or a dict with ``code``,
        ``description``, and ``details`` keys for the error.

    Spec: ARSIA-Actions.md §4.2.
    """
    if descriptor.get("reversible") is False:
        return {
            "code": "not_implemented",
            "description": "Rollback not supported for this action",
        }
    if current_state == "rolled_back":
        return {
            "code": "conflict",
            "description": "Action has already been rolled back",
            "details": {"already_rolled_back": True},
        }
    if rollback_window_seconds is not None and completed_at is not None:
        if now is None:
            now = datetime.now(timezone.utc)
        deadline = completed_at + timedelta(seconds=rollback_window_seconds)
        if now > deadline:
            return {
                "code": "conflict",
                "description": "Rollback window has expired",
                "details": {"rollback_window_exceeded": True},
            }
    return None


def build_rollback_audit_record(
    *,
    original_message_id: str,
    original_action_id: str,
    rollback_message_id: str,
    timestamp: str,
    full_rollback: bool = True,
) -> dict[str, Any]:
    """Build a §4.2 rollback audit record.

    When rollback succeeds the executing agent MUST generate an audit
    record with ``event_type: "rollback"`` that includes the original
    action's identifiers, the rollback request's message_id, the
    timestamp, and whether the rollback was full or partial.

    Args:
        original_message_id: The ``id`` of the original request.
        original_action_id: The ``action_id`` of the rolled-back action.
        rollback_message_id: The ``id`` of the rollback request.
        timestamp: RFC 3339 timestamp of the rollback.
        full_rollback: ``True`` for full, ``False`` for partial.

    Returns:
        A dict suitable for inclusion in an audit store.

    Spec: ARSIA-Actions.md §4.2.
    """
    return {
        "event_type": "rollback",
        "original_message_id": original_message_id,
        "original_action_id": original_action_id,
        "rollback_message_id": rollback_message_id,
        "timestamp": timestamp,
        "full_rollback": full_rollback,
    }


def build_partial_rollback_response(
    *,
    rolled_back: list[str],
    not_rolled_back: list[str],
) -> dict[str, Any]:
    """Build a partial-rollback response per Actions §4.2.

    When only some effects of an action can be reversed, the response
    MUST include details listing which effects were reversed and which
    were not.

    Raises:
        ValueError: if either list is empty.
    """
    if not rolled_back:
        raise ValueError("rolled_back must not be empty")
    if not not_rolled_back:
        raise ValueError("not_rolled_back must not be empty")
    return {
        "partial_rollback": True,
        "rolled_back": list(rolled_back),
        "not_rolled_back": list(not_rolled_back),
    }


# ---------------------------------------------------------------------------
# §4.3 — Timeout / Async
# ---------------------------------------------------------------------------


def build_timeout_error(
    *,
    from_agent: str,
    to_agent: str,
    correlation_id: str,
    action_id: str | None = None,
    timeout_ms: int | None = None,
    elapsed_ms: int | None = None,
) -> dict[str, Any]:
    """Build a ``service_unavailable`` error for action execution timeout.

    When execution exceeds the action's timeout the executing agent
    MUST respond with ``service_unavailable`` and description
    ``"Action execution timeout"``.

    Args:
        from_agent: The executing agent's identifier.
        to_agent: The requesting agent's identifier.
        correlation_id: The ``id`` of the timed-out request.
        action_id: Optional action_id for context in details.
        timeout_ms: Optional timeout threshold in ms.
        elapsed_ms: Optional approximate elapsed time in ms.

    Returns:
        A fully populated error envelope dict (unsigned).

    Spec: ARSIA-Actions.md §4.3, ARSIA-Core.md §11.2.
    """
    from arsia_protocol.core.message import create_error

    details: dict[str, Any] | None = None
    if action_id is not None or timeout_ms is not None or elapsed_ms is not None:
        details = {}
        if action_id is not None:
            details["action_id"] = action_id
        if timeout_ms is not None:
            details["timeout_ms"] = timeout_ms
        if elapsed_ms is not None:
            details["elapsed_ms"] = elapsed_ms
    return create_error(
        from_agent=from_agent,
        to_agent=to_agent,
        correlation_id=correlation_id,
        code="service_unavailable",
        description="Action execution timeout",
        details=details,
    )


def validate_timeout_cancellation(
    *,
    current_state: str,
    max_execution_ms: int,
    started_at: datetime,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` if an action has exceeded its timeout.

    When the timeout is exceeded the executing agent MUST cease
    execution and release any resources. This function checks the
    timeout condition; the caller is responsible for actually stopping
    the work and responding with the timeout error.

    Args:
        current_state: The action's current execution state.
        max_execution_ms: The timeout threshold in milliseconds.
        started_at: When execution began (timezone-aware).
        now: Current time (defaults to ``datetime.now(UTC)``).

    Returns:
        ``True`` if the action is in ``"executing"`` state and has
        exceeded its timeout.

    Spec: ARSIA-Actions.md §4.3.
    """
    if current_state != "executing":
        return False
    if now is None:
        now = datetime.now(timezone.utc)
    deadline = started_at + timedelta(milliseconds=max_execution_ms)
    return now > deadline


def build_partial_execution_audit(
    *,
    message_id: str,
    action_id: str,
    timestamp: str,
    partial_results: dict[str, Any] | None = None,
    reason: str = "timeout",
) -> dict[str, Any]:
    """Build a partial-execution audit record for a timed-out action.

    When rollback is not possible after a timeout, the agent MUST
    document the partial execution in the audit record.

    Args:
        message_id: The ``id`` of the timed-out request.
        action_id: The ``action_id`` of the partially executed action.
        timestamp: RFC 3339 timestamp.
        partial_results: Optional description of what was completed.
        reason: Why execution was partial (default ``"timeout"``).

    Returns:
        A dict suitable for inclusion in an audit store.

    Spec: ARSIA-Actions.md §4.3.
    """
    record: dict[str, Any] = {
        "event_type": "partial_execution",
        "message_id": message_id,
        "action_id": action_id,
        "timestamp": timestamp,
        "reason": reason,
    }
    if partial_results is not None:
        record["partial_results"] = partial_results
    return record


# ---------------------------------------------------------------------------
# §5.1 — Explanation Enforcement
# ---------------------------------------------------------------------------


def is_explanation_required(
    *,
    descriptor: dict[str, Any] | None = None,
    compliance: dict[str, Any] | None = None,
) -> bool:
    """Return ``True`` if a response MUST include a ``payload.explanation``.

    An explanation is required when:

    1. The ``ActionDescriptor`` has ``explainability_required: true``
       ().
    2. The message's ``compliance`` object has
       ``explainability_required: true`` (), which
       overrides the descriptor's setting.

    Either condition alone is sufficient.

    Args:
        descriptor: The ActionDescriptor dict (may be ``None``).
        compliance: The message's ``compliance`` object (may be ``None``).

    Returns:
        ``True`` if an explanation MUST be provided.

    Spec: ARSIA-Actions.md §5.1.
    """
    if compliance is not None and compliance.get("explainability_required") is True:
        return True
    if descriptor is not None and descriptor.get("explainability_required") is True:
        return True
    return False


def validate_response_explanation(
    *,
    response_payload: dict[str, Any],
    descriptor: dict[str, Any] | None = None,
    compliance: dict[str, Any] | None = None,
) -> list[ValidationError]:
    """Validate that a response includes an explanation when required.

    Combines :func:`is_explanation_required` with a presence check
    on ``response_payload["explanation"]``. Returns a list of
    :class:`ValidationError` (empty when the response is conformant).

    Args:
        response_payload: The response envelope's ``payload`` dict.
        descriptor: The ActionDescriptor dict (may be ``None``).
        compliance: The message's ``compliance`` object (may be ``None``).

    Returns:
        A list of :class:`ValidationError`. Empty means the response
        is conformant.

    Spec: ARSIA-Actions.md §5.1.
    """
    if not is_explanation_required(descriptor=descriptor, compliance=compliance):
        return []
    explanation = response_payload.get("explanation")
    if explanation is None:
        sources: list[str] = []
        if descriptor is not None and descriptor.get("explainability_required") is True:
            sources.append("ActionDescriptor.explainability_required")
        if compliance is not None and compliance.get("explainability_required") is True:
            sources.append("compliance.explainability_required")
        return [
            ValidationError(
                code="missing_explanation",
                message=(
                    f"response payload MUST include an explanation object when "
                    f"{' or '.join(sources)} is true"
                ),
                details={"sources": sources},
                spec_ref="Actions §5.1",
            )
        ]
    return []


def is_approval_expired(
    approval_deadline: str,
    *,
    clock_skew_seconds: int = CLOCK_SKEW_TOLERANCE_SECONDS,
    now: datetime | None = None,
) -> bool:
    """Check if an approval deadline has passed (with clock skew tolerance).

    Spec: ARSIA-Actions §3.4 — Executing agent MUST verify current time
    is before the approval_deadline (+-300s clock skew).

    Returns ``True`` if expired (action should NOT be executed).
    """
    parsed = _parse_rfc3339_ms(approval_deadline)
    if parsed is None:
        return True
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now > parsed + timedelta(seconds=clock_skew_seconds)


__all__ = [
    # §1
    "CAPABILITY_MAX_LENGTH",
    "CAPABILITY_PATTERN",
    "RESERVED_PREFIX",
    "RESERVED_CAPABILITIES",
    "EXPLICIT_GRANT_ONLY",
    "validate_capability",
    "is_valid_capability",
    "is_reserved_capability",
    "is_reserved_prefix_misuse",
    "match_capability",
    "match_capabilities",
    "find_unsatisfied_capabilities",
    "downgrade_capabilities",
    "attach_effective_capabilities",
    # §2
    "RiskClassification",
    "RISK_LEVEL_CLASSIFICATION",
    "get_risk_classification",
    "validate_action_descriptor",
    # §2.4
    "is_major_version_bump",
    "resolve_action_version",
    "build_version_not_supported_error",
    # §4.1
    "ExecutionState",
    "VALID_TRANSITIONS",
    "is_valid_transition",
    "is_terminal_state",
    # §4.2
    "create_rollback_request",
    "validate_rollback",
    "build_rollback_audit_record",
    # §4.3
    "build_timeout_error",
    "validate_timeout_cancellation",
    "build_partial_execution_audit",
    # §5.1
    "is_explanation_required",
    "validate_response_explanation",
    # §3.4
    "is_approval_expired",
    # §5.2
    "validate_explanation",
    "validate_explanation_timestamp",
]
