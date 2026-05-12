# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Routing primitive — topology, broker selection, lifecycle, rate limits.

This module is Layer 4 in the SDK dependency graph. It provides the
pure-data building blocks for the Routing primitive defined in
ARSIA-Routing.md §1–§7 and ARSIA-Core.md §9. It does NOT transmit
messages: the SDK stays transport-agnostic. Every function here
either computes a decision (topology, broker, priority, retry delay),
validates a structure (broker entry, relay preconditions, audit
record), or drives the delivery state machine — all offline.

What this module provides
-------------------------

- :func:`select_topology` / :class:`RoutingDecision` — topology
  selection per §1.3 (direct vs brokered) based solely on
  ``compliance.data_residency``.
- :data:`EU_EEA_MEMBER_STATES`, :func:`is_eu_eea_member`,
  :func:`broker_serves_zone` — residency-zone helpers for the
  EU/EEA-constrained rules in §2.3, §6, and §7.3.
- :func:`validate_broker_entry` — L1 JSON Schema check against
  ``arsia-broker-entry.schema.json`` plus §7.2 / §7.3 semantic rules.
- :func:`select_broker_by_priority` / :func:`select_broker_random` —
  deterministic and pseudo-random broker choice over a list of
  :class:`BrokerEntry` (§7.4 selection criteria).
- :data:`LIFECYCLE_STATES`, :data:`LIFECYCLE_TRANSITIONS`,
  :func:`is_valid_lifecycle_transition`,
  :func:`is_terminal_lifecycle_state`,
  :func:`is_retryable_lifecycle_state` — the 9-state delivery state
  machine from §4.1.
- :func:`validate_relay_preconditions` — the offline-checkable subset
  of the 9 broker-relay rules from §7.3 (Rules 2, 3, 9).
- :class:`BrokerRelayAuditRecord`,
  :func:`build_broker_relay_audit_record`,
  :func:`validate_broker_relay_audit_record` — the audit record
  emitted by the broker when it relays a message (§7.4 format;
  §7.3 Rule 7 audit obligation).
- :func:`parse_rate_limit_headers` / :class:`RateLimitStatus` —
  parses the rate-limit headers defined in §6 and Core §9.5.
- :func:`resolve_priority` — the priority precedence rules for
  ``context.priority`` (§5).
- :func:`compute_retry_delay` — exponential-backoff delay calculator
  following Core §11.3 (base=1s, multiplier=2x, cap=32s).

Spec: ARSIA-Routing.md §1–§7; ARSIA-Core.md §9, §11.3.
"""

from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Final, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arsia_protocol.identity.agent_id import is_valid_agent_id
from arsia_protocol.types.errors import ValidationError
from arsia_protocol.types.routing import BrokerEntry
from arsia_protocol.core.validation import validate_schema

# ---------------------------------------------------------------------------
# §1.3 — Topology determination
# ---------------------------------------------------------------------------

Topology = Literal["direct", "brokered", "federated", "error"]
"""The topology outputs of :func:`select_topology`.

``"direct"`` and ``"brokered"`` are the two normative transport
topologies in v1.0 (ARSIA-Routing.md §1.2). ``"error"`` is the third
output of the §1.3 determination procedure: it signals that a broker was
required (because ``compliance.data_residency`` was declared) but no
eligible broker was discoverable. ``"federated"`` is reserved for
v1.1+ (§1.2.3) and is not produced by this function today.
"""


@dataclass(frozen=True)
class RoutingDecision:
    """Outcome of :func:`select_topology`.

    The §1.3 procedure is a single function with three possible
    outputs:

    - ``topology="direct"`` — no residency constraint; send peer-to-peer.
    - ``topology="brokered"`` — residency constraint satisfied by an
      eligible broker; the selected broker is returned in ``broker``.
    - ``topology="error"`` — residency was declared but no eligible
      broker was found; ``error`` carries the structured
      ``service_unavailable`` payload from §1.3.

    Attributes:
        topology: The selected topology.
        data_residency: The envelope's ``compliance.data_residency``
            value that produced the decision, or ``None`` when no
            residency was declared.
        reason: Human-readable explanation useful for logs and audit
            trails. Free-form — do NOT pattern-match on this field.
        broker: The broker chosen by :func:`select_broker_by_priority`
            when ``topology == "brokered"``; otherwise ``None``.
        error: The §1.3 error payload when ``topology == "error"``;
            otherwise ``None``. Shape:
            ``{"code": "service_unavailable", "description": str,
            "details": {"data_residency_violation": True,
            "required_zone": str, "available_zones": list[str]}}``.
    """

    topology: Topology
    data_residency: str | None = None
    reason: str = ""
    broker: Mapping[str, Any] | None = None
    error: Mapping[str, Any] | None = None


def select_topology(
    envelope: Mapping[str, Any],
    *,
    brokers: Sequence[BrokerEntry | Mapping[str, Any]] | None = None,
) -> RoutingDecision:
    """Return the routing decision required by ``envelope`` per §1.3.

    Implements the normative three-output procedure from
    ARSIA-Routing.md §1.3 (equivalent Core §9.4):

    1. If ``envelope['compliance']['data_residency']`` is absent or
       empty, return ``topology="direct"``.
    2. Otherwise a broker is required. ``brokers`` is filtered to
       entries that serve the required zone and are healthy (or
       degraded — see :func:`select_broker_by_priority`).
    3. If at least one eligible broker remains, the first by caller
       priority order is selected and ``topology="brokered"`` is
       returned with ``broker`` populated.
    4. If no broker is eligible, ``topology="error"`` is returned with
       a ``service_unavailable`` payload whose
       ``details.available_zones`` is the union of zones served by the
       candidate list (empty when no candidates were supplied).

    The trigger for a broker requirement is the mere presence of a
    non-empty ``data_residency`` string — the SDK does NOT maintain a
    zone allowlist. Any compliance jurisdiction the caller declares is
    honoured.

    Args:
        envelope: The ARSIA message envelope as a mapping.
        brokers: Optional broker discovery response. When omitted (or
            empty) and residency is declared, the function returns the
            §1.3 ``service_unavailable`` error. When residency is not
            declared, this argument is ignored.

    Returns:
        A :class:`RoutingDecision`.

    Spec: ARSIA-Routing.md §1.3; ARSIA-Core.md §9.4.
    """
    compliance = envelope.get("compliance")
    residency: str | None
    if isinstance(compliance, Mapping):
        value = compliance.get("data_residency")
        residency = value if isinstance(value, str) and value else None
    else:
        residency = None

    if residency is None:
        return RoutingDecision(
            topology="direct",
            data_residency=None,
            reason=(
                "no data_residency declared; direct topology selected (Routing §1.3)"
            ),
        )

    candidates: Sequence[BrokerEntry | Mapping[str, Any]] = brokers or ()
    selected = select_broker_by_priority(candidates, zone=residency)
    if selected is not None:
        return RoutingDecision(
            topology="brokered",
            data_residency=residency,
            reason=(
                f"compliance.data_residency={residency!r} requires a "
                f"Compliance Broker; selected {selected.get('agent_id')!r} "
                "(Routing §1.3)"
            ),
            broker=selected,
            error=None,
        )

    available: list[str] = []
    seen: set[str] = set()
    for b in candidates:
        d: Mapping[str, Any]
        if isinstance(b, BrokerEntry):
            d = b.model_dump()
        elif isinstance(b, Mapping):
            d = b
        else:
            continue
        zones = d.get("residency_zones")
        if isinstance(zones, Sequence) and not isinstance(zones, (str, bytes)):
            for z in zones:
                if isinstance(z, str) and z not in seen:
                    seen.add(z)
                    available.append(z)

    error_payload: Mapping[str, Any] = MappingProxyType(
        {
            "code": "service_unavailable",
            "description": (f"no eligible broker serves residency zone {residency!r}"),
            "details": MappingProxyType(
                {
                    "data_residency_violation": True,
                    "required_zone": residency,
                    "available_zones": tuple(available),
                }
            ),
        }
    )
    return RoutingDecision(
        topology="error",
        data_residency=residency,
        reason=(
            f"compliance.data_residency={residency!r} requires a "
            "Compliance Broker but none is available (Routing §1.3)"
        ),
        broker=None,
        error=error_payload,
    )


# ---------------------------------------------------------------------------
# §2.3, §6, §7 — EU/EEA residency helpers
# ---------------------------------------------------------------------------

EU_EEA_MEMBER_STATES: Final[frozenset[str]] = frozenset(
    {
        # 27 EU member states
        "AT",
        "BE",
        "BG",
        "HR",
        "CY",
        "CZ",
        "DK",
        "EE",
        "FI",
        "FR",
        "DE",
        "GR",
        "HU",
        "IE",
        "IT",
        "LV",
        "LT",
        "LU",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SK",
        "SI",
        "ES",
        "SE",
        # 3 non-EU EEA member states
        "IS",
        "LI",
        "NO",
    }
)
"""The 30 EU/EEA member states (27 EU + Iceland, Liechtenstein, Norway).

Switzerland (CH) is deliberately excluded: it is not an EEA member
state. Any EU-zone broker relay rule that references "EU/EEA" MUST
be checked against this set.

Spec: ARSIA-Routing.md §7.3 Rule 2.
"""


def is_eu_eea_member(country_code: str) -> bool:
    """Return ``True`` if ``country_code`` is an EU or EEA member state.

    The comparison is case-sensitive and expects a two-letter
    uppercase ISO 3166-1 alpha-2 code. Anything else returns
    ``False``.

    Spec: ARSIA-Routing.md §7.3 Rule 2.
    """
    return country_code in EU_EEA_MEMBER_STATES


def broker_serves_zone(broker: Mapping[str, Any], zone: str) -> bool:
    """Return ``True`` if ``broker`` lists ``zone`` in ``residency_zones``.

    The broker entry may be either a :class:`BrokerEntry` instance
    serialized via ``model_dump()`` or a raw dict read from the
    discovery endpoint. Malformed entries (missing or wrongly typed
    ``residency_zones``) return ``False`` rather than raising.

    Spec: ARSIA-Routing.md §7.2.
    """
    zones = broker.get("residency_zones")
    if not isinstance(zones, Sequence) or isinstance(zones, (str, bytes)):
        return False
    return zone in zones


# ---------------------------------------------------------------------------
# §7.2 — Broker-entry validation
# ---------------------------------------------------------------------------


def validate_broker_entry(entry: Mapping[str, Any]) -> list[ValidationError]:
    """Return the list of errors for a broker-entry dict.

    Runs L1 (JSON Schema) validation against
    ``arsia-broker-entry.schema.json`` and then layers on the §7.2 /
    §7.3 semantic rules that JSON Schema cannot fully express:

    - when ``"EU"`` appears in ``residency_zones``, the broker's
      ``jurisdiction`` MUST be an EU/EEA member state (§7.3 Rule 2);
    - ``agent_id`` MUST be a syntactically valid ARSIA agent
      identifier (Core §3.3); the schema's regex is a coarse
      pre-filter, not an authoritative check.

    Args:
        entry: The broker-entry dict as returned by the discovery
            endpoint.

    Returns:
        A list of :class:`ValidationError`; empty when valid.

    Spec: ARSIA-Routing.md §7.2, §7.3.
    """
    errors = validate_schema(dict(entry), "arsia-broker-entry.schema.json")

    agent_id = entry.get("agent_id")
    if isinstance(agent_id, str) and not is_valid_agent_id(agent_id):
        errors.append(
            ValidationError(
                code="invalid_broker_agent_id",
                message=f"agent_id {agent_id!r} is not a valid ARSIA agent identifier",
                details={"field": "agent_id", "value": agent_id},
                spec_ref="Core §3.3",
            )
        )

    zones = entry.get("residency_zones")
    jurisdiction = entry.get("jurisdiction")
    if (
        isinstance(zones, Sequence)
        and not isinstance(zones, (str, bytes))
        and "EU" in zones
        and isinstance(jurisdiction, str)
        and not is_eu_eea_member(jurisdiction)
    ):
        errors.append(
            ValidationError(
                code="eu_zone_non_eea_jurisdiction",
                message=(
                    f"broker serving zone 'EU' must have EU/EEA jurisdiction; "
                    f"got {jurisdiction!r}"
                ),
                details={"jurisdiction": jurisdiction, "zone": "EU"},
                spec_ref="Routing §7.3",
            )
        )

    if (
        isinstance(zones, Sequence)
        and not isinstance(zones, (str, bytes))
        and isinstance(jurisdiction, str)
    ):
        for z in zones:
            if (
                isinstance(z, str)
                and len(z) == 2
                and z.isalpha()
                and z.isupper()
                and z != "EU"
                and jurisdiction != z
            ):
                errors.append(
                    ValidationError(
                        code="zone_jurisdiction_mismatch",
                        message=(
                            f"broker serving country-code zone {z!r} "
                            f"must have jurisdiction={z!r}; "
                            f"got {jurisdiction!r}"
                        ),
                        details={"zone": z, "jurisdiction": jurisdiction},
                        spec_ref="Routing §5.3",
                    )
                )

    return errors


# ---------------------------------------------------------------------------
# §7.4 — Broker selection helpers
# ---------------------------------------------------------------------------


def _partition_brokers(
    brokers: Sequence[BrokerEntry | Mapping[str, Any]],
    *,
    zone: str,
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """Partition zone-serving brokers into (healthy, degraded) lists.

    Normalizes :class:`BrokerEntry` instances to dicts. ``unhealthy``
    brokers MUST be excluded (§1.4 criterion 2). ``degraded`` brokers
    are returned separately so callers can deprioritise them: healthy
    candidates are preferred, degraded act as fallback when no
    healthy broker is available.
    """
    healthy: list[Mapping[str, Any]] = []
    degraded: list[Mapping[str, Any]] = []
    for b in brokers:
        d: Mapping[str, Any]
        if isinstance(b, BrokerEntry):
            d = b.model_dump()
        elif isinstance(b, Mapping):
            d = b
        else:
            continue
        if not broker_serves_zone(d, zone):
            continue
        health = d.get("health")
        if health == "unhealthy":
            continue
        if health == "degraded":
            degraded.append(d)
        else:
            healthy.append(d)
    return healthy, degraded


def select_broker_by_priority(
    brokers: Sequence[BrokerEntry | Mapping[str, Any]],
    *,
    zone: str,
    include_degraded: bool = True,
) -> Mapping[str, Any] | None:
    """Return the first zone-serving broker, preferring healthy ones.

    Selection follows ARSIA-Routing.md §1.4 criterion 2: ``healthy``
    brokers are preferred, ``degraded`` brokers are deprioritised (used
    only as fallback when no healthy broker serves the zone), and
    ``unhealthy`` brokers are excluded. Within each tier, input order
    is preserved — the discovery endpoint response order is respected.

    Args:
        brokers: Candidate brokers from a discovery response.
        zone: Required residency zone (e.g. ``"EU"``).
        include_degraded: Deprecated; retained for signature
            compatibility and ignored. Degraded brokers are always
            eligible as a fallback per §1.4 ("SHOULD be
            deprioritised", not excluded).

    Returns:
        The first eligible broker as a mapping, or ``None`` when no
        healthy or degraded broker serves the zone.

    Spec: ARSIA-Routing.md §1.4.
    """
    del include_degraded  # kept for back-compat; §1.4 is not caller-configurable
    healthy, degraded = _partition_brokers(brokers, zone=zone)
    if healthy:
        return healthy[0]
    if degraded:
        return degraded[0]
    return None


def select_broker_random(
    brokers: Sequence[BrokerEntry | Mapping[str, Any]],
    *,
    zone: str,
    include_degraded: bool = True,
) -> Mapping[str, Any] | None:
    """Return a cryptographically random eligible broker.

    Uses :func:`secrets.choice` to avoid the biases of ``random``'s
    Mersenne-Twister stream. The healthy pool is sampled first; if
    empty, the degraded pool is used as fallback. ``unhealthy`` brokers
    are never eligible.

    Spec: ARSIA-Routing.md §1.4.
    """
    del include_degraded  # see select_broker_by_priority
    healthy, degraded = _partition_brokers(brokers, zone=zone)
    pool = healthy if healthy else degraded
    if not pool:
        return None
    return secrets.choice(pool)


# ---------------------------------------------------------------------------
# §4.1 — Delivery lifecycle state machine
# ---------------------------------------------------------------------------

LifecycleState = Literal[
    "created",
    "signed",
    "dispatched",
    "broker_relayed",
    "delivered",
    "responded",
    "dispatch_failed",
    "delivery_failed",
    "expired",
]
"""The nine delivery lifecycle states from ARSIA-Routing.md §4.1.

State-name mapping (spec uppercase → SDK lowercase_snake_case):

- ``"created"`` — CREATED
- ``"signed"`` — SIGNED
- ``"dispatched"`` — DISPATCHED
- ``"broker_relayed"`` — BROKER_RELAYED
- ``"delivered"`` — DELIVERED
- ``"responded"`` — RESPONDED
- ``"dispatch_failed"`` — DISPATCH_FAILED (retry-eligible per §11.3)
- ``"delivery_failed"`` — DELIVERY_FAILED (retry-eligible per §11.3)
- ``"expired"`` — EXPIRED (terminal)
"""

LIFECYCLE_STATES: Final[frozenset[str]] = frozenset(
    {
        "created",
        "signed",
        "dispatched",
        "broker_relayed",
        "delivered",
        "responded",
        "dispatch_failed",
        "delivery_failed",
        "expired",
    }
)
"""The set of all nine lifecycle state names (§4.1)."""

LIFECYCLE_TRANSITIONS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "created": frozenset({"signed"}),
        "signed": frozenset({"dispatched"}),
        "dispatched": frozenset(
            {
                "delivered",
                "broker_relayed",
                "dispatch_failed",
                "delivery_failed",
                "expired",
            }
        ),
        # BROKER_RELAYED never transitions to DELIVERY_FAILED: once the
        # broker has forwarded the envelope, the recipient's own error
        # response flows back through the broker as a normal reply and
        # the original message reaches DELIVERED. A broker refusal
        # surfaces as DISPATCH_FAILED (the broker's hop, not the
        # recipient's). See §7.3 Rules 4 and 7.
        "broker_relayed": frozenset({"delivered", "dispatch_failed", "expired"}),
        "delivered": frozenset({"responded"}),
        "responded": frozenset(),
        "dispatch_failed": frozenset({"dispatched"}),
        "delivery_failed": frozenset({"dispatched"}),
        "expired": frozenset(),
    }
)
"""Read-only state-machine transition table for §4.2.

``responded`` and ``expired`` are strictly terminal.
``dispatch_failed`` and ``delivery_failed`` are only *conditionally*
terminal — they re-enter ``dispatched`` when the retry policy in
Core §11.3 admits another attempt; exhausting the retry budget leaves
them as terminal states (no outgoing edge to ``expired`` — expiry is
observed only from ``dispatched`` or ``broker_relayed`` per §4.2).
"""

TERMINAL_LIFECYCLE_STATES: Final[frozenset[str]] = frozenset({"responded", "expired"})
"""States from which no further transitions are defined (§4.1)."""

RETRYABLE_LIFECYCLE_STATES: Final[frozenset[str]] = frozenset(
    {"dispatch_failed", "delivery_failed"}
)
"""Failure states that admit re-entry into ``dispatched`` via retry.

Retry admissibility is subject to the policy in Core §11.3 — reaching
one of these states does NOT by itself guarantee that another attempt
will be made.
"""


def is_valid_lifecycle_transition(from_state: str, to_state: str) -> bool:
    """Return ``True`` if the ``from_state → to_state`` edge is allowed.

    Returns ``False`` when either end is unknown or the edge is not in
    :data:`LIFECYCLE_TRANSITIONS`.

    Spec: ARSIA-Routing.md §4.1.
    """
    allowed = LIFECYCLE_TRANSITIONS.get(from_state)
    if allowed is None:
        return False
    if to_state not in LIFECYCLE_TRANSITIONS:
        return False
    return to_state in allowed


def is_terminal_lifecycle_state(state: str) -> bool:
    """Return ``True`` if ``state`` has no outgoing transitions (§4.1)."""
    return state in TERMINAL_LIFECYCLE_STATES


def is_retryable_lifecycle_state(state: str) -> bool:
    """Return ``True`` if ``state`` is a retry-eligible failure state.

    ``dispatch_failed`` and ``delivery_failed`` are the two §4.1
    states from which the sender MAY schedule another ``dispatched``
    attempt per the retry policy in Core §11.3.
    """
    return state in RETRYABLE_LIFECYCLE_STATES


# ---------------------------------------------------------------------------
# §7.3 — Broker relay preconditions (Rules 1-9)
# ---------------------------------------------------------------------------

BROKER_FORWARD_TIMEOUT_S: Final[int] = 10
"""Maximum broker forwarding latency in seconds (ARSIA-Routing.md §2.3.4)."""

BROKER_EXPIRY_SAFETY_MARGIN_S: Final[int] = 5
"""Minimum remaining time-to-expiry for a broker to accept a relay (§7.3).

Per §7.3 Rule 9, a broker MUST NOT forward a message whose
``expires_at`` is less than this many seconds in the future; doing so
would guarantee delivery after expiry.
"""


def validate_relay_preconditions(
    envelope: Mapping[str, Any],
    broker: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> list[ValidationError]:
    """Return errors for the offline subset of §7.3's broker-relay rules.

    Only the statically checkable rules are evaluated here — rules
    that require observing the wire (signature verification across
    hops, header propagation, audit emission) are out of scope.

    Rules evaluated:

    - **Rule 2** — residency zone verification. The broker MUST list
      the envelope's declared ``compliance.data_residency`` in its
      ``residency_zones``, and when the zone is ``"EU"`` the broker's
      ``jurisdiction`` MUST be an EU/EEA member state.
    - **Rule 9** — the envelope's ``expires_at`` MUST be at least
      :data:`BROKER_EXPIRY_SAFETY_MARGIN_S` seconds in the future at
      ``now`` (defaults to current UTC).

    Args:
        envelope: The ARSIA message the broker is about to relay.
        broker: The broker's discovery entry.
        now: Reference instant; defaults to ``datetime.now(UTC)``.

    Returns:
        A list of :class:`ValidationError`; empty when all offline
        preconditions are satisfied.

    Spec: ARSIA-Routing.md §7.3.
    """
    errors: list[ValidationError] = []

    compliance = envelope.get("compliance")
    residency = (
        compliance.get("data_residency") if isinstance(compliance, Mapping) else None
    )

    if isinstance(residency, str):
        # Rule 2 — residency zones listing
        if not broker_serves_zone(broker, residency):
            errors.append(
                ValidationError(
                    code="zone_not_served",
                    message=(
                        f"broker must list residency zone {residency!r} in "
                        "residency_zones (Routing §7.3 Rule 2)"
                    ),
                    details={"zone": residency},
                    spec_ref="Routing §7.3 Rule 2",
                )
            )
        # Rule 2 — EU jurisdiction narrowing
        if residency == "EU":
            jurisdiction = broker.get("jurisdiction")
            if not isinstance(jurisdiction, str) or not is_eu_eea_member(jurisdiction):
                errors.append(
                    ValidationError(
                        code="eu_jurisdiction_required",
                        message=(
                            f"broker serving EU must have EU/EEA jurisdiction; "
                            f"got {jurisdiction!r} (Routing §7.3 Rule 2)"
                        ),
                        details={"jurisdiction": jurisdiction},
                        spec_ref="Routing §7.3 Rule 2",
                    )
                )
        # §5.3 — country-code zone jurisdiction matching
        elif len(residency) == 2 and residency.isalpha() and residency.isupper():
            jurisdiction = broker.get("jurisdiction")
            if jurisdiction != residency:
                errors.append(
                    ValidationError(
                        code="zone_jurisdiction_mismatch",
                        message=(
                            f"broker serving country-code zone {residency!r} "
                            f"must have jurisdiction={residency!r}; "
                            f"got {jurisdiction!r} (Routing §5.3)"
                        ),
                        details={
                            "zone": residency,
                            "jurisdiction": jurisdiction,
                        },
                        spec_ref="Routing §5.3",
                    )
                )

    # Rule 9
    expires_at = envelope.get("expires_at")
    if isinstance(expires_at, str):
        try:
            parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append(
                ValidationError(
                    code="invalid_expires_at",
                    message=(
                        f"envelope.expires_at {expires_at!r} is not a valid "
                        "RFC 3339 timestamp (Routing §7.3 Rule 9)"
                    ),
                    details={"expires_at": expires_at},
                    spec_ref="Routing §7.3 Rule 9",
                )
            )
        else:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            reference = now if now is not None else datetime.now(timezone.utc)
            if reference.tzinfo is None:
                reference = reference.replace(tzinfo=timezone.utc)
            remaining = (parsed - reference).total_seconds()
            if remaining < BROKER_EXPIRY_SAFETY_MARGIN_S:
                errors.append(
                    ValidationError(
                        code="expiry_too_soon",
                        message=(
                            f"envelope.expires_at must be at least "
                            f"{BROKER_EXPIRY_SAFETY_MARGIN_S}s in the future; "
                            f"remaining={remaining:.3f}s (Routing §7.3 Rule 9)"
                        ),
                        details={"remaining_s": remaining},
                        spec_ref="Routing §7.3 Rule 9",
                    )
                )

    return errors


# ---------------------------------------------------------------------------
# §7.3 Rule 6 / Core §9.3 — Broker-relay audit record
# ---------------------------------------------------------------------------

PAYLOAD_HASH_HEX_LENGTH: Final[int] = 64
"""Expected lowercase-hex SHA-256 length for ``payload_hash``."""

_PAYLOAD_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")
"""Lowercase hex SHA-256 pattern (mirrors State §7.1)."""

_TS_PATTERN: Final[str] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"

_UUID_V4_PATTERN: Final[str] = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


ForwardingResult = Literal["success", "failure", "timeout"]
"""Outcome of a broker relay operation per ARSIA-Routing.md §7.4.

``"timeout"`` is the required value when the broker refuses forwarding
because completing it would breach ``expires_at`` (§7.3 Rule 9).
"""


class BrokerRelayAuditRecord(BaseModel):
    """Audit record a broker emits each time it relays a message.

    Field shape matches the normative table in ARSIA-Routing.md §7.4:
    exactly 11 REQUIRED fields, no optional fields. The record is the
    broker-local counterpart of :class:`arsia_protocol.types.state.ArsiaAuditRecord`
    — both are append-only audit entries, but this one captures the
    broker hop specifically and does NOT supersede the recipient's own
    audit obligations.

    Spec: ARSIA-Routing.md §7.4 (record format); §7.3 Rules 7 and 9.
    """

    model_config = ConfigDict(extra="forbid")

    audit_type: Literal["broker_relay"] = Field(
        default="broker_relay",
        description="Fixed value identifying this record kind (§7.4).",
    )
    relay_id: str = Field(
        pattern=_UUID_V4_PATTERN,
        description="UUID v4, unique per relay operation (§7.4).",
    )
    message_id: str = Field(
        pattern=_UUID_V4_PATTERN,
        description="UUID v4 of the relayed envelope (envelope.id).",
    )
    from_agent: str = Field(description="Agent ID of the original sender.")
    to_agent: str = Field(description="Agent ID of the ultimate recipient.")
    broker_agent_id: str = Field(description="Agent ID of the relaying broker (§7.4).")
    residency_zone: str = Field(
        pattern=r"^[A-Z]{2,4}$",
        description="compliance.data_residency that governed the relay.",
    )
    relayed_at: str = Field(
        pattern=_TS_PATTERN,
        description="RFC 3339 ms timestamp when the broker forwarded the envelope.",
    )
    payload_hash: str = Field(
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 hex of the JCS-canonicalized payload.",
    )
    relay_latency_ms: int = Field(
        ge=0,
        description="Time from receipt to forward initiation, in milliseconds (§7.4).",
    )
    forwarding_result: ForwardingResult = Field(
        description='One of "success", "failure", "timeout" (§7.4).'
    )

    @field_validator("broker_agent_id", "from_agent", "to_agent")
    @classmethod
    def _check_agent_id(cls, value: str) -> str:
        if not is_valid_agent_id(value):
            raise ValueError(
                f"{value!r} is not a valid ARSIA agent identifier (Core §3.3)"
            )
        return value


def _format_ms_timestamp(moment: datetime) -> str:
    """Format ``moment`` as an RFC 3339 ms UTC string (matches §7.1 pattern)."""
    moment = moment.astimezone(timezone.utc)
    millis = moment.microsecond // 1000
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{millis:03d}Z"


def build_broker_relay_audit_record(
    envelope: Mapping[str, Any],
    *,
    broker_agent_id: str,
    payload_hash: str,
    forwarding_result: ForwardingResult,
    relay_latency_ms: int,
    residency_zone: str | None = None,
    relayed_at: datetime | None = None,
    relay_id: str | None = None,
) -> BrokerRelayAuditRecord:
    """Assemble a :class:`BrokerRelayAuditRecord` for a broker hop.

    The builder does not persist anything: it returns a validated
    Pydantic model the caller hands to its audit store. Immutability
    and append-only guarantees are storage-layer concerns.

    Field derivation:

    - ``audit_type`` — always ``"broker_relay"`` (fixed per §7.4).
    - ``relay_id`` — caller-supplied UUID v4, or a fresh one.
    - ``message_id`` / ``from_agent`` / ``to_agent`` — read from the
      envelope's ``id``, ``from``, and ``to`` fields.
    - ``payload_hash`` — caller-supplied (typically computed via
      :func:`arsia_protocol.audit.compute_payload_hash`). Lowercased
      before the pattern check so that upstream helpers which happen
      to emit uppercase hex still pass.
    - ``residency_zone`` — caller-supplied. When omitted, falls back
      to ``envelope['compliance']['data_residency']``.
    - ``relayed_at`` — defaults to ``datetime.now(UTC)``.
    - ``relay_latency_ms`` — required by the caller; MUST be ≥ 0.
    - ``forwarding_result`` — required by the caller; one of
      ``"success"``, ``"failure"``, ``"timeout"``. Rule 9 requires
      ``"timeout"`` when the broker refuses due to ``expires_at``.

    Args:
        envelope: The relayed ARSIA message.
        broker_agent_id: Agent ID of the relaying broker.
        payload_hash: Hex SHA-256 of the JCS-canonicalized payload.
        forwarding_result: ``"success"``, ``"failure"``, or ``"timeout"``.
        relay_latency_ms: Time from receipt to forward initiation, in ms.
        residency_zone: Override; inherits from envelope when ``None``.
        relayed_at: Reference instant. Defaults to current UTC.
        relay_id: Precomputed UUID v4. Defaults to a fresh one.

    Returns:
        A validated :class:`BrokerRelayAuditRecord`.

    Raises:
        ValueError: on missing envelope fields, missing residency zone,
            negative latency, or invalid payload hash format.

    Spec: ARSIA-Routing.md §7.4; §7.3 Rules 7 and 9.
    """
    normalized_hash = payload_hash.lower()
    if not _PAYLOAD_HASH_RE.fullmatch(normalized_hash):
        raise ValueError(
            f"payload_hash must be a 64-character lowercase hex SHA-256; "
            f"got {payload_hash!r}"
        )
    if relay_latency_ms < 0:
        raise ValueError(
            f"relay_latency_ms must be >= 0; got {relay_latency_ms} (Routing §7.4)"
        )

    message_id = envelope.get("id")
    if not isinstance(message_id, str):
        raise ValueError(
            f"envelope['id']: must be a string UUID v4, got {type(message_id).__name__}"
        )
    from_agent = envelope.get("from")
    if not isinstance(from_agent, str):
        raise ValueError(
            "envelope['from']: must be a string agent-id, "
            f"got {type(from_agent).__name__}"
        )
    to_agent = envelope.get("to")
    if not isinstance(to_agent, str):
        raise ValueError(
            f"envelope['to']: must be a string agent-id, got {type(to_agent).__name__}"
        )

    resolved_zone = residency_zone
    if resolved_zone is None:
        compliance = envelope.get("compliance")
        if isinstance(compliance, Mapping):
            candidate = compliance.get("data_residency")
            if isinstance(candidate, str):
                resolved_zone = candidate
    if not isinstance(resolved_zone, str):
        raise ValueError(
            "residency_zone could not be resolved: neither argument nor "
            "envelope.compliance.data_residency was a string"
        )

    if relayed_at is None:
        relayed_at = datetime.now(timezone.utc)

    return BrokerRelayAuditRecord(
        relay_id=relay_id if relay_id is not None else str(uuid.uuid4()),
        message_id=message_id,
        from_agent=from_agent,
        to_agent=to_agent,
        broker_agent_id=broker_agent_id,
        residency_zone=resolved_zone,
        relayed_at=_format_ms_timestamp(relayed_at),
        payload_hash=normalized_hash,
        relay_latency_ms=relay_latency_ms,
        forwarding_result=forwarding_result,
    )


def validate_broker_relay_audit_record(
    record: Mapping[str, Any],
) -> list[ValidationError]:
    """Return errors for a broker-relay audit record.

    Runs the Pydantic model check. The :class:`BrokerRelayAuditRecord`
    model itself enforces every field constraint defined in §7.4, so
    the function's role is to surface errors as a list rather than an
    exception.

    Spec: ARSIA-Routing.md §7.4.
    """
    errors: list[ValidationError] = []
    try:
        BrokerRelayAuditRecord(**dict(record))
    except Exception as exc:  # pragma: no cover - pydantic wraps errors
        errors.append(
            ValidationError(
                code="invalid_audit_record",
                message=str(exc),
                spec_ref="Routing §7.4",
            )
        )

    payload_hash = record.get("payload_hash")
    if isinstance(payload_hash, str) and not _PAYLOAD_HASH_RE.fullmatch(payload_hash):
        errors.append(
            ValidationError(
                code="invalid_payload_hash",
                message=(
                    f"payload_hash must match ^[a-f0-9]{{64}}$; "
                    f"got {payload_hash!r} (Routing §7.4)"
                ),
                details={"payload_hash": payload_hash},
                spec_ref="Routing §7.4",
            )
        )

    return errors


# ---------------------------------------------------------------------------
# §6 / Core §9.5 — Rate-limit header parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateLimitStatus:
    """Parsed view of the ARSIA rate-limit response headers.

    All fields are optional because a server MAY omit any header —
    parsing is best-effort. Consumers should treat ``None`` as "server
    did not advertise this dimension" rather than as a rate-limit
    absence signal.

    Attributes:
        limit: ``X-RateLimit-Limit`` — requests allowed per
            window, as a non-negative integer.
        remaining: ``X-RateLimit-Remaining`` — requests left in
            the current window, as a non-negative integer.
        reset_at: ``X-RateLimit-Reset`` — UNIX epoch seconds at
            which the current window rolls over, as a non-negative
            integer.
        retry_after_seconds: ``Retry-After`` — seconds to wait before
            the next attempt, as a non-negative integer. Present only
            when the server surfaces a hard rate-limit response (429
            Too Many Requests).
    """

    limit: int | None = None
    remaining: int | None = None
    reset_at: int | None = None
    retry_after_seconds: int | None = None


def _parse_nonneg_int(value: Any) -> int | None:
    """Parse ``value`` as a non-negative base-10 integer.

    Returns ``None`` when the value is missing, not a string, or
    cannot be parsed.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    try:
        parsed = int(value.strip(), 10)
    except ValueError:
        return None
    if parsed < 0:
        return None
    return parsed


def parse_rate_limit_headers(headers: Mapping[str, str]) -> RateLimitStatus:
    """Parse ``X-RateLimit-*`` and ``Retry-After`` headers.

    Header lookup is case-insensitive to match HTTP semantics
    (RFC 9110 §5.1). Non-integer and negative values are silently
    dropped (surfaced as ``None``) because a malformed header is not
    actionable by the SDK — the server is the authority for rate
    limits and the caller's best response is to fall back to the
    retry policy in Core §11.3.

    Args:
        headers: The response headers as a mapping.

    Returns:
        A :class:`RateLimitStatus` with parsed values (or ``None``).

    Spec: ARSIA-Routing.md §6; ARSIA-Core.md §9.5.
    """
    folded = {k.lower(): v for k, v in headers.items()}
    return RateLimitStatus(
        limit=_parse_nonneg_int(folded.get("x-ratelimit-limit")),
        remaining=_parse_nonneg_int(folded.get("x-ratelimit-remaining")),
        reset_at=_parse_nonneg_int(folded.get("x-ratelimit-reset")),
        retry_after_seconds=_parse_nonneg_int(folded.get("retry-after")),
    )


# ---------------------------------------------------------------------------
# §5 — Priority resolution
# ---------------------------------------------------------------------------

DEFAULT_PRIORITY: Final[int] = 5
"""Default priority when neither envelope nor override is provided (§5.1)."""


def resolve_priority(
    envelope: Mapping[str, Any],
    *,
    override: int | None = None,
) -> int:
    """Return the effective priority for ``envelope`` per §5.

    Precedence (highest wins):

    1. ``override`` argument — caller's explicit value. MUST be in
       the valid range ``0..10``; anything else raises ``ValueError``.
    2. ``envelope['context']['priority']`` — when present and within
       range. Out-of-range values are ignored (§5.1 SHOULD-level).
    3. :data:`DEFAULT_PRIORITY` (5) — the §5.1 default.

    Args:
        envelope: The ARSIA message envelope.
        override: Optional caller override; must be ``0..10``.

    Returns:
        The effective priority as an int in ``0..10``.

    Raises:
        ValueError: when ``override`` is outside ``0..10``.

    Spec: ARSIA-Routing.md §5.
    """
    if override is not None:
        if not (0 <= override <= 10):
            raise ValueError(
                f"override priority must be between 0 and 10; got {override}"
            )
        return override

    context = envelope.get("context")
    if isinstance(context, Mapping):
        value = context.get("priority")
        if isinstance(value, int) and not isinstance(value, bool):
            if 0 <= value <= 10:
                return value

    return DEFAULT_PRIORITY


# ---------------------------------------------------------------------------
# Core §11.3 — Retry policy
# ---------------------------------------------------------------------------

RETRY_BASE_DELAY_S: Final[float] = 1.0
"""Base delay for the exponential-backoff policy (Core §11.3)."""

RETRY_MULTIPLIER: Final[float] = 2.0
"""Multiplier between successive retry attempts (Core §11.3)."""

MAX_RETRY_DELAY_S: Final[float] = 32.0
"""Hard cap on any retry delay (Core §11.3)."""

MAX_RETRIES_RECOMMENDED: Final[int] = 3
"""Recommended retry budget (Core §11.3).

The spec wording is RECOMMENDED, not REQUIRED, so
:func:`compute_retry_delay` accepts any ``attempt >= 1`` and lets the
caller enforce its own budget.
"""


RATE_LIMITED_DEFAULT_DELAY_S: Final[float] = 60.0
"""Default delay when no Retry-After information is available (Core §11.3)."""


NON_RETRYABLE_HTTP_CODES: Final[frozenset[int]] = frozenset(
    {
        400,  # Bad Request
        401,  # Unauthorized
        403,  # Forbidden
        404,  # Not Found
        409,  # Conflict
        413,  # Payload Too Large
        501,  # Not Implemented
    }
)
"""HTTP status codes that MUST NOT be retried per Routing §4.1.8."""


def is_retryable_http_status(status_code: int) -> bool:
    """Check if an HTTP status code is retryable.

    Returns ``False`` for 4xx codes listed in §4.1.8 and ``True`` for
    5xx (except 501). 2xx/3xx return ``False`` (not errors).

    Spec: ARSIA-Routing.md §4.1.8.
    """
    if status_code in NON_RETRYABLE_HTTP_CODES:
        return False
    if 500 <= status_code < 600:
        return True
    return False


def compute_retry_delay(attempt: int) -> float:
    """Return the exponential-backoff delay in seconds for ``attempt``.

    The formula is
    ``min(MAX_RETRY_DELAY_S, RETRY_BASE_DELAY_S * RETRY_MULTIPLIER ** (attempt - 1))``,
    producing ``1, 2, 4, 8, 16, 32, 32, ...`` seconds for attempts
    ``1, 2, 3, 4, 5, 6, 7, ...``. Attempts beyond the recommended
    budget do NOT raise — callers may use their own retry budgets.

    Args:
        attempt: The 1-indexed retry attempt number. MUST be ``>= 1``.

    Returns:
        The delay in seconds, capped at :data:`MAX_RETRY_DELAY_S`.

    Raises:
        ValueError: when ``attempt < 1``.

    Spec: ARSIA-Core.md §11.3.
    """
    if attempt < 1:
        raise ValueError(f"attempt must be >= 1; got {attempt}")
    delay = RETRY_BASE_DELAY_S * (RETRY_MULTIPLIER ** (attempt - 1))
    return min(MAX_RETRY_DELAY_S, delay)


def compute_rate_limited_delay(
    *,
    retry_after_header: int | None = None,
    details_retry_after: int | None = None,
) -> float:
    """Return the delay for a rate-limited (429) retry per §11.3.

    Per §11.3:
    1. If ``Retry-After`` header is present, MUST wait at least that
       many seconds.
    2. If ``payload.error.details.retry_after_seconds`` is present and
       no header, SHOULD use that value.
    3. If neither is available, SHOULD wait at least 60 seconds.

    Spec: ARSIA-Core.md §11.3.
    """
    if retry_after_header is not None:
        return max(0.0, float(retry_after_header))
    if details_retry_after is not None:
        return max(0.0, float(details_retry_after))
    return RATE_LIMITED_DEFAULT_DELAY_S


__all__ = [
    # Topology
    "Topology",
    "RoutingDecision",
    "select_topology",
    # Residency
    "EU_EEA_MEMBER_STATES",
    "is_eu_eea_member",
    "broker_serves_zone",
    # Broker validation & selection
    "validate_broker_entry",
    "select_broker_by_priority",
    "select_broker_random",
    # Lifecycle
    "LifecycleState",
    "LIFECYCLE_STATES",
    "LIFECYCLE_TRANSITIONS",
    "TERMINAL_LIFECYCLE_STATES",
    "RETRYABLE_LIFECYCLE_STATES",
    "is_valid_lifecycle_transition",
    "is_terminal_lifecycle_state",
    "is_retryable_lifecycle_state",
    # Broker relay
    "BROKER_FORWARD_TIMEOUT_S",
    "BROKER_EXPIRY_SAFETY_MARGIN_S",
    "validate_relay_preconditions",
    "BrokerRelayAuditRecord",
    "ForwardingResult",
    "build_broker_relay_audit_record",
    "validate_broker_relay_audit_record",
    # Rate limiting
    "RateLimitStatus",
    "parse_rate_limit_headers",
    # Priority
    "DEFAULT_PRIORITY",
    "resolve_priority",
    # HTTP retryability
    "NON_RETRYABLE_HTTP_CODES",
    "is_retryable_http_status",
    # Retry
    "RATE_LIMITED_DEFAULT_DELAY_S",
    "RETRY_BASE_DELAY_S",
    "RETRY_MULTIPLIER",
    "MAX_RETRY_DELAY_S",
    "MAX_RETRIES_RECOMMENDED",
    "compute_retry_delay",
    "compute_rate_limited_delay",
    # Constants
    "PAYLOAD_HASH_HEX_LENGTH",
]
