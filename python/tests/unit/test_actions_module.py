# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for :mod:`arsia_protocol.actions`.

The Pydantic models in ``arsia_protocol.types.actions`` are covered
by ``tests/unit/types/test_actions.py`` (Slice 1B). This file targets
the Layer 4 *functions* added in Slice 3: capability validation and
matching, risk classification mapping, execution lifecycle, and
action descriptor / explanation schema validation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from arsia_protocol import actions
from arsia_protocol.actions.actions import (
    CAPABILITY_MAX_LENGTH,
    EXPLICIT_GRANT_ONLY,
    RESERVED_CAPABILITIES,
    VALID_TRANSITIONS,
    build_partial_execution_audit,
    build_partial_rollback_response,
    build_rollback_audit_record,
    build_timeout_error,
    is_explanation_required,
    build_version_not_supported_error,
    downgrade_capabilities,
    find_unsatisfied_capabilities,
    get_risk_classification,
    is_approval_expired,
    is_major_version_bump,
    is_reserved_capability,
    is_reserved_prefix_misuse,
    is_terminal_state,
    is_valid_capability,
    is_valid_transition,
    match_capabilities,
    match_capability,
    resolve_action_version,
    validate_action_descriptor,
    validate_capability,
    validate_explanation,
    validate_explanation_timestamp,
    validate_response_explanation,
    validate_rollback,
    validate_timeout_cancellation,
)


# ---------------------------------------------------------------------------
# §1.1 — Capability validation
# ---------------------------------------------------------------------------


def test_valid_capability_simple() -> None:
    """Spec: ARSIA-Actions.md §1.1 — 'notes.read' is a valid capability."""
    assert validate_capability("notes.read") == []
    assert is_valid_capability("notes.read") is True


def test_valid_capability_multi_segment() -> None:
    """Spec: ARSIA-Actions.md §1.1 — multi-segment identifiers are valid."""
    assert validate_capability("eu.mifid.risk.assess") == []


def test_valid_capability_wildcard() -> None:
    """Spec: ARSIA-Actions.md §1.1 — trailing wildcard is valid."""
    assert validate_capability("notes.*") == []


def test_valid_capability_digit_first_segment() -> None:
    """Spec: ARSIA-Actions.md §1.1 ABNF — digits are allowed in any position.

    The §1.1 ABNF grammar is ``1*(ALPHA / DIGIT)`` per segment; rule 6
    restates that segments may contain letters or digits with no
    ordering constraint. ``7eleven.payments`` must be accepted.
    """
    assert validate_capability("7eleven.payments") == []


def test_invalid_capability_single_segment() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 1 — ≥ 2 segments required."""
    errors = validate_capability("read")
    assert errors
    assert any(e.code == "invalid_capability_grammar" for e in errors)


def test_invalid_capability_too_long() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 2 — ≤ 128 characters."""
    long_name = "a." + ("b" * (CAPABILITY_MAX_LENGTH - 1))  # 131 chars
    errors = validate_capability(long_name)
    assert any(e.code == "capability_too_long" for e in errors)


def test_invalid_capability_hyphen() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 6 — hyphens forbidden in segments."""
    errors = validate_capability("notes.read-all")
    assert errors


def test_invalid_capability_wildcard_middle() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 4 — wildcard only at the end."""
    errors = validate_capability("notes.*.read")
    assert errors


def test_invalid_capability_wildcard_only() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 4 — wildcard must follow a segment."""
    errors = validate_capability(".*")
    assert errors


def test_invalid_capability_empty_string() -> None:
    """Spec: ARSIA-Actions.md §1.1 — empty capability rejected."""
    assert validate_capability("") != []


def test_invalid_capability_reserved_prefix_misuse() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 5 — 'arsiaprotocol.' prefix is restricted.

    An invented capability using the reserved prefix that is not one of
    the 15 entries in §1.4 MUST be rejected.
    """
    errors = validate_capability("arsiaprotocol.custom.thing")
    assert any(e.code == "reserved_prefix_misuse" for e in errors)


def test_capability_case_sensitive() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 3 — matching is case-sensitive.

    ``Notes.Read`` and ``notes.read`` are distinct capabilities per
    rule 3; both must validate structurally.
    """
    assert is_valid_capability("Notes.Read")
    assert is_valid_capability("notes.read")
    assert match_capability("notes.read", "Notes.Read") is False


# ---------------------------------------------------------------------------
# §1.4 — Reserved capabilities constant
# ---------------------------------------------------------------------------


def test_reserved_capabilities_count_is_sixteen() -> None:
    """Spec: ARSIA-Actions.md §1.4 — exactly 16 reserved capabilities."""
    assert len(RESERVED_CAPABILITIES) == 16


def test_every_reserved_capability_is_syntactically_valid() -> None:
    """Spec: ARSIA-Actions.md §1.1 — reserved entries must parse.

    If this test fails, either the capability grammar or the §1.4
    reserved list diverged from the spec.
    """
    for cap in RESERVED_CAPABILITIES:
        assert validate_capability(cap) == [], (
            f"reserved capability {cap!r} fails §1.1 validation"
        )


def test_is_reserved_capability_identifies_spec_entries() -> None:
    """Spec: ARSIA-Actions.md §1.4."""
    assert is_reserved_capability("arsiaprotocol.oversight.approve") is True
    assert is_reserved_capability("arsiaprotocol.audit.read") is True
    assert is_reserved_capability("notes.read") is False
    assert is_reserved_capability("arsiaprotocol.made-up") is False


def test_is_reserved_prefix_misuse_distinguishes_from_reserved() -> None:
    """Spec: ARSIA-Actions.md §1.1 rule 5, §1.4."""
    assert is_reserved_prefix_misuse("arsiaprotocol.foo") is True
    assert is_reserved_prefix_misuse("arsiaprotocol.audit.read") is False
    assert is_reserved_prefix_misuse("notes.read") is False


# ---------------------------------------------------------------------------
# §1.2 — Capability matching
# ---------------------------------------------------------------------------


def test_match_exact() -> None:
    """Spec: ARSIA-Actions.md §1.2 — byte-for-byte exact match."""
    assert match_capability("notes.read", "notes.read") is True


def test_match_wildcard_single_hop() -> None:
    """Spec: ARSIA-Actions.md §1.2 — 'notes.*' satisfies 'notes.read'."""
    assert match_capability("notes.*", "notes.read") is True
    assert match_capability("notes.*", "notes.write") is True


def test_match_wildcard_multi_hop() -> None:
    """Spec: ARSIA-Actions.md §1.2 — wildcard covers all descendants.

    The §1.2 table row ``notes.* | notes.admin.reset | ACCEPTED`` is
    explicit: a wildcard scope covers arbitrarily deep descendants.
    """
    assert match_capability("notes.*", "notes.admin.reset") is True
    assert match_capability("eu.mifid.*", "eu.mifid.risk.assess") is True


def test_no_match_different_segment() -> None:
    """Spec: ARSIA-Actions.md §1.2 — different segments do not match."""
    assert match_capability("notes.read", "notes.write") is False


def test_specific_scope_does_not_satisfy_wildcard_request() -> None:
    """Spec: ARSIA-Actions.md §1.2 — direction matters.

    The §1.2 table row ``notes.read | notes.* | REJECTED`` nails this:
    a specific scope never satisfies a wildcard request, because the
    scope is the authority and the request is what needs authorizing.
    """
    assert match_capability("notes.read", "notes.*") is False


def test_no_match_partial_prefix_overlap() -> None:
    """Spec: ARSIA-Actions.md §1.2 — prefix must end on a segment boundary.

    ``note.*`` (singular) must not satisfy ``notes.read`` (plural) —
    the matching rule requires the prefix to be followed by a literal
    dot.
    """
    assert match_capability("note.*", "notes.read") is False


def test_wildcard_does_not_satisfy_bare_prefix() -> None:
    """Spec: ARSIA-Actions.md §1.2 — wildcard requires ≥ 1 descendant.

    ``notes.*`` must NOT satisfy ``notes`` — the match rule requires
    the requested capability to start with ``prefix + "."``, not with
    the prefix alone.
    """
    assert match_capability("notes.*", "notes") is False


def test_match_capabilities_all_satisfied() -> None:
    """Spec: ARSIA-Actions.md §1.2 — multi-capability requests.

    Every requested capability must be satisfied by at least one
    scope entry.
    """
    assert match_capabilities(
        ["notes.*", "payments.charge"],
        ["notes.read", "notes.write", "payments.charge"],
    )


def test_match_capabilities_partial_fails() -> None:
    """Spec: ARSIA-Actions.md §1.2 — one unsatisfied entry rejects."""
    assert (
        match_capabilities(
            ["notes.read"],
            ["notes.read", "notes.write"],
        )
        is False
    )


def test_find_unsatisfied_returns_only_gaps() -> None:
    """Spec: ARSIA-Actions.md §1.2."""
    gaps = find_unsatisfied_capabilities(
        ["notes.read"],
        ["notes.read", "notes.write", "notes.delete"],
    )
    assert gaps == ["notes.write", "notes.delete"]


def test_downgrade_returns_authorised_subset() -> None:
    """Spec: ARSIA-Actions.md §1.3 — downgrading preserves request order."""
    effective = downgrade_capabilities(
        ["notes.read", "notes.write", "notes.delete"],
        ["notes.read", "notes.write"],
    )
    assert effective == ["notes.read", "notes.write"]


def test_downgrade_with_wildcard_scope() -> None:
    """Spec: ARSIA-Actions.md §1.3 — wildcard grants the full subset."""
    effective = downgrade_capabilities(
        ["notes.read", "notes.write"],
        ["notes.*"],
    )
    assert effective == ["notes.read", "notes.write"]


def test_downgrade_with_zero_overlap_raises() -> None:
    """Spec: ARSIA-Actions.md §1.3 rule 3 — empty downgrade MUST be rejected."""
    with pytest.raises(ValueError, match="§1.3 rule 3"):
        downgrade_capabilities(["notes.read"], ["payments.charge"])


def test_downgrade_with_empty_requested_raises() -> None:
    """Spec: ARSIA-Actions.md §1.3 rule 3 — no overlap is always rejected."""
    with pytest.raises(ValueError):
        downgrade_capabilities([], ["notes.*"])


def test_state_purge_not_satisfied_by_state_wildcard() -> None:
    """Spec: ARSIA-Actions.md §1.4 — purge MUST require explicit grant."""
    assert (
        match_capability(
            "arsiaprotocol.state.*", "arsiaprotocol.state.purge"
        )
        is False
    )


def test_state_purge_not_satisfied_by_reserved_wildcard() -> None:
    """Spec: ARSIA-Actions.md §1.4 — purge MUST NOT be implied by any wildcard."""
    assert (
        match_capability("arsiaprotocol.*", "arsiaprotocol.state.purge")
        is False
    )


def test_state_purge_satisfied_by_exact_match() -> None:
    """Spec: ARSIA-Actions.md §1.4 — explicit grant still authorises purge."""
    assert (
        match_capability(
            "arsiaprotocol.state.purge", "arsiaprotocol.state.purge"
        )
        is True
    )


def test_state_wildcard_still_satisfies_state_read() -> None:
    """Spec: ARSIA-Actions.md §1.2 — non-purge capabilities still match normally."""
    assert (
        match_capability(
            "arsiaprotocol.state.*", "arsiaprotocol.state.read"
        )
        is True
    )


def test_attach_effective_capabilities_creates_result() -> None:
    """Spec: ARSIA-Actions.md §1.3 rule 1 — effective_capabilities lives in result."""
    from arsia_protocol.actions.actions import attach_effective_capabilities

    response = {"payload": {}}
    out = attach_effective_capabilities(response, ["notes.read"])
    assert out["payload"]["result"]["effective_capabilities"] == ["notes.read"]


def test_attach_effective_capabilities_preserves_existing_result() -> None:
    """Spec: ARSIA-Actions.md §1.3 rule 1 — existing result keys are preserved."""
    from arsia_protocol.actions.actions import attach_effective_capabilities

    response = {"payload": {"result": {"value": 42}}}
    out = attach_effective_capabilities(response, ["notes.read"])
    assert out["payload"]["result"]["value"] == 42
    assert out["payload"]["result"]["effective_capabilities"] == ["notes.read"]


def test_attach_effective_capabilities_does_not_mutate_input() -> None:
    """Spec: ARSIA-Actions.md §1.3 rule 1 — caller's envelope is untouched."""
    from arsia_protocol.actions.actions import attach_effective_capabilities

    response = {"payload": {"result": {"value": 42}}}
    attach_effective_capabilities(response, ["notes.read"])
    assert "effective_capabilities" not in response["payload"]["result"]


def test_attach_effective_capabilities_rejects_empty() -> None:
    """Spec: ARSIA-Actions.md §1.3 rule 3 — empty list is prohibited."""
    from arsia_protocol.actions.actions import attach_effective_capabilities

    with pytest.raises(ValueError):
        attach_effective_capabilities({"payload": {}}, [])


def test_create_rollback_request_payload_type_and_args() -> None:
    """Spec: ARSIA-Actions.md §4.2 — rollback payload shape."""
    from arsia_protocol.actions.actions import create_rollback_request

    env = create_rollback_request(
        from_agent="agent:acme.notes-client",
        to_agent="agent:acme.notes-server",
        original_action_id="com.example.notes/write",
        original_message_id="11111111-1111-4111-8111-111111111111",
        capabilities=["notes.write"],
    )
    assert env["intent"] == "request"
    assert env["payload"]["type"] == "com.example.notes/write/rollback"
    assert env["payload"]["args"] == {
        "original_message_id": "11111111-1111-4111-8111-111111111111"
    }
    assert env["capabilities"] == ["notes.write"]


def test_create_rollback_request_passes_compliance() -> None:
    """Spec: ARSIA-Actions.md §4.2 — compliance metadata flows through."""
    from arsia_protocol.actions.actions import create_rollback_request

    env = create_rollback_request(
        from_agent="agent:acme.notes-client",
        to_agent="agent:acme.notes-server",
        original_action_id="com.example.notes/write",
        original_message_id="11111111-1111-4111-8111-111111111111",
        capabilities=["notes.write"],
        compliance={"classification": "internal"},
    )
    assert env["compliance"]["classification"] == "internal"


def test_reserved_wildcard_covers_reserved_capabilities() -> None:
    """Spec: ARSIA-Actions.md §1.2 / §1.4 — arsiaprotocol.* covers reserved.

    The §1.2 table row ``arsiaprotocol.* | arsiaprotocol.broker.relay |
    ACCEPTED`` establishes that the reserved wildcard works like any
    other wildcard for matching purposes. Tokenization is a separate
    concern — authority to hold ``arsiaprotocol.*`` is governed by
    §1.1 rule 5, not the matcher.
    """
    assert match_capability("arsiaprotocol.*", "arsiaprotocol.broker.relay") is True
    assert match_capability("arsiaprotocol.*", "arsiaprotocol.audit.read") is True


# ---------------------------------------------------------------------------
# §2.2 — Risk → EU AI Act classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "risk_level, expected",
    [
        (0, "minimal-risk"),
        (2, "minimal-risk"),
        (3, "limited-risk"),
        (4, "limited-risk"),
        (5, "elevated-risk"),
        (6, "elevated-risk"),
        (7, "high-risk"),
        (8, "high-risk"),
        (9, "critical-risk"),
        (10, "critical-risk"),
    ],
)
def test_risk_classification_buckets(risk_level: int, expected: str) -> None:
    """Spec: ARSIA-Actions.md §2.2 — five-bucket mapping."""
    assert get_risk_classification(risk_level) == expected


def test_risk_classification_rejects_negative() -> None:
    """Spec: ARSIA-Actions.md §2.1 — risk_level is bounded 0-10."""
    with pytest.raises(ValueError):
        get_risk_classification(-1)


def test_risk_classification_rejects_too_high() -> None:
    """Spec: ARSIA-Actions.md §2.1 — risk_level is bounded 0-10."""
    with pytest.raises(ValueError):
        get_risk_classification(11)


def test_risk_classification_rejects_bool() -> None:
    """Booleans are ``int`` subclasses in Python but are not risk levels."""
    with pytest.raises(ValueError):
        get_risk_classification(True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §4.1 — Execution lifecycle state machine
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "from_state, to_state",
    [
        ("requested", "pending_approval"),
        ("requested", "executing"),
        ("requested", "failed"),
        ("pending_approval", "executing"),
        ("pending_approval", "failed"),
        ("executing", "completed"),
        ("executing", "failed"),
        ("completed", "rolled_back"),
    ],
)
def test_valid_lifecycle_transitions(from_state: str, to_state: str) -> None:
    """Spec: ARSIA-Actions.md §4.1 — edges allowed by the state diagram."""
    assert is_valid_transition(from_state, to_state) is True


@pytest.mark.parametrize(
    "from_state, to_state",
    [
        # Cannot skip approval
        ("requested", "completed"),
        # Cannot return to requested
        ("executing", "requested"),
        # Cannot resurrect a completed execution
        ("completed", "executing"),
        # Cannot roll back a failed execution
        ("failed", "rolled_back"),
        # Rolled back is terminal
        ("rolled_back", "completed"),
        # Unknown states
        ("unknown", "executing"),
        ("executing", "unknown"),
    ],
)
def test_invalid_lifecycle_transitions(from_state: str, to_state: str) -> None:
    """Spec: ARSIA-Actions.md §4.1 — edges outside the state diagram."""
    assert is_valid_transition(from_state, to_state) is False


def test_terminal_states() -> None:
    """Spec: ARSIA-Actions.md §4.1 — FAILED and ROLLED_BACK are terminal."""
    assert is_terminal_state("failed") is True
    assert is_terminal_state("rolled_back") is True
    assert is_terminal_state("executing") is False
    assert is_terminal_state("completed") is False
    assert is_terminal_state("unknown") is False


def test_valid_transitions_table_has_all_six_states() -> None:
    """Spec: ARSIA-Actions.md §4.1 — the state machine has exactly 6 states."""
    assert set(VALID_TRANSITIONS.keys()) == {
        "requested",
        "pending_approval",
        "executing",
        "completed",
        "failed",
        "rolled_back",
    }


# ---------------------------------------------------------------------------
# §2.1 — Action descriptor schema validation
# ---------------------------------------------------------------------------


def _minimal_descriptor() -> dict[str, Any]:
    """Return a minimal ActionDescriptor that passes L1 schema validation."""
    return {
        "action_id": "com.example.notes/read",
        "category": "data",
        "description": "Read notes owned by the requesting agent.",
        "risk_level": 2,
        "reversible": False,
        "idempotent": True,
        "required_capabilities": ["notes.read"],
        "human_oversight_required": False,
        "audit_required": False,
        "explainability_required": False,
    }


def test_validate_action_descriptor_valid() -> None:
    """Spec: ARSIA-Actions.md §2.1 — valid descriptor passes."""
    assert validate_action_descriptor(_minimal_descriptor()) == []


def test_validate_action_descriptor_missing_required_field() -> None:
    """Spec: ARSIA-Actions.md §2.1 — L1 catches missing fields."""
    broken = _minimal_descriptor()
    del broken["risk_level"]
    errors = validate_action_descriptor(broken)
    assert errors
    assert any("risk_level" in e.message for e in errors)


@pytest.mark.parametrize(
    "category",
    ["data", "communication", "financial", "system", "oversight"],
)
def test_validate_action_descriptor_every_category_accepted(category: str) -> None:
    """Spec: ARSIA-Actions.md §2.1 — five-value category enum."""
    descriptor = _minimal_descriptor()
    descriptor["category"] = category
    assert validate_action_descriptor(descriptor) == []


def test_validate_action_descriptor_risk_level_out_of_range() -> None:
    """Spec: ARSIA-Actions.md §2.1 — risk_level bounded 0-10."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = 11
    errors = validate_action_descriptor(descriptor)
    assert any("risk_level" in e.message for e in errors)


def test_validate_action_descriptor_rejects_unknown_category() -> None:
    """Spec: ARSIA-Actions.md §2.1 — category enum is closed."""
    descriptor = _minimal_descriptor()
    descriptor["category"] = "mystery"
    assert validate_action_descriptor(descriptor) != []


@pytest.mark.parametrize("risk_level", [5, 6])
def test_validate_descriptor_risk_5_6_requires_audit(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — elevated-risk MUST audit_required=true."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = False
    errors = validate_action_descriptor(descriptor)
    assert any("audit_required" in e.message for e in errors)


@pytest.mark.parametrize("risk_level", [5, 6])
def test_validate_descriptor_risk_5_6_with_audit_accepted(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — elevated-risk with audit_required=true passes."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = True
    assert validate_action_descriptor(descriptor) == []


@pytest.mark.parametrize("risk_level", [7, 8])
def test_validate_descriptor_risk_7_8_requires_audit(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — high-risk MUST audit_required=true."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = False
    descriptor["explainability_required"] = True
    errors = validate_action_descriptor(descriptor)
    assert any("audit_required" in e.message for e in errors)


@pytest.mark.parametrize("risk_level", [7, 8])
def test_validate_descriptor_risk_7_8_requires_explainability(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — high-risk MUST explainability_required=true."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = True
    descriptor["explainability_required"] = False
    errors = validate_action_descriptor(descriptor)
    assert any("explainability_required" in e.message for e in errors)


def test_validate_descriptor_risk_7_reports_both_flags_separately() -> None:
    """Spec: ARSIA-Actions.md §2.2 — missing flags produce one error each."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = 7
    descriptor["audit_required"] = False
    descriptor["explainability_required"] = False
    errors = validate_action_descriptor(descriptor)
    assert sum("audit_required" in e.message for e in errors) == 1
    assert sum("explainability_required" in e.message for e in errors) == 1


@pytest.mark.parametrize("risk_level", [7, 8])
def test_validate_descriptor_risk_7_8_all_flags_accepted(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — high-risk with mandatory flags passes."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = True
    descriptor["explainability_required"] = True
    assert validate_action_descriptor(descriptor) == []


@pytest.mark.parametrize("risk_level", [9, 10])
def test_validate_descriptor_risk_9_10_requires_audit(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — critical-risk MUST audit_required=true."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = False
    descriptor["explainability_required"] = True
    descriptor["human_oversight_required"] = True
    errors = validate_action_descriptor(descriptor)
    assert any("audit_required" in e.message for e in errors)


@pytest.mark.parametrize("risk_level", [9, 10])
def test_validate_descriptor_risk_9_10_requires_explainability(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — critical-risk MUST explainability_required=true."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = True
    descriptor["explainability_required"] = False
    descriptor["human_oversight_required"] = True
    errors = validate_action_descriptor(descriptor)
    assert any("explainability_required" in e.message for e in errors)


@pytest.mark.parametrize("risk_level", [9, 10])
def test_validate_descriptor_risk_9_10_requires_oversight(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — critical-risk MUST human_oversight_required=true."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = True
    descriptor["explainability_required"] = True
    descriptor["human_oversight_required"] = False
    errors = validate_action_descriptor(descriptor)
    assert any("human_oversight_required" in e.message for e in errors)


def test_validate_descriptor_risk_10_reports_all_three_flags_separately() -> None:
    """Spec: ARSIA-Actions.md §2.2 — each missing flag is a distinct error."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = 10
    descriptor["audit_required"] = False
    descriptor["explainability_required"] = False
    descriptor["human_oversight_required"] = False
    errors = validate_action_descriptor(descriptor)
    assert sum("audit_required" in e.message for e in errors) == 1
    assert sum("explainability_required" in e.message for e in errors) == 1
    assert sum("human_oversight_required" in e.message for e in errors) == 1


@pytest.mark.parametrize("risk_level", [9, 10])
def test_validate_descriptor_risk_9_10_all_flags_accepted(risk_level: int) -> None:
    """Spec: ARSIA-Actions.md §2.2 — critical-risk with all flags passes."""
    descriptor = _minimal_descriptor()
    descriptor["risk_level"] = risk_level
    descriptor["audit_required"] = True
    descriptor["explainability_required"] = True
    descriptor["human_oversight_required"] = True
    assert validate_action_descriptor(descriptor) == []


# ---------------------------------------------------------------------------
# §5.2 — Explanation schema + cross-field timestamp check
# ---------------------------------------------------------------------------


def _minimal_explanation() -> dict[str, Any]:
    return {
        "reasoning": "Matched the notes.read scope exactly.",
        "confidence": 0.93,
        "inputs_used": ["state:notes/42"],
    }


def test_validate_explanation_valid() -> None:
    """Spec: ARSIA-Actions.md §5.2 — minimal explanation passes."""
    assert validate_explanation(_minimal_explanation()) == []


def test_validate_explanation_missing_reasoning() -> None:
    """Spec: ARSIA-Actions.md §5.2 — reasoning is REQUIRED."""
    broken = _minimal_explanation()
    del broken["reasoning"]
    errors = validate_explanation(broken)
    assert any("reasoning" in e.message for e in errors)


def test_validate_explanation_timestamp_pass() -> None:
    """Spec: ARSIA-Actions.md §5.2 — decision_timestamp ≤ ts holds."""
    explanation = _minimal_explanation()
    explanation["decision_timestamp"] = "2026-03-24T14:29:58.412Z"
    assert (
        validate_explanation_timestamp(explanation, "2026-03-24T14:30:00.000Z")
        == []
    )


def test_validate_explanation_timestamp_fail() -> None:
    """Spec: ARSIA-Actions.md §5.2 — decision_timestamp > ts is rejected."""
    explanation = _minimal_explanation()
    explanation["decision_timestamp"] = "2026-03-24T14:30:01.000Z"
    errors = validate_explanation_timestamp(explanation, "2026-03-24T14:30:00.000Z")
    assert errors
    assert any(e.code == "decision_timestamp_after_envelope" for e in errors)


def test_validate_explanation_timestamp_absent_is_vacuous() -> None:
    """Spec: ARSIA-Actions.md §5.2 — decision_timestamp is OPTIONAL."""
    assert (
        validate_explanation_timestamp(
            _minimal_explanation(), "2026-03-24T14:30:00.000Z"
        )
        == []
    )


# ---------------------------------------------------------------------------
# §2.4 — Version negotiation
# ---------------------------------------------------------------------------


def test_forward_compat_unknown_fields_ignored() -> None:
    """Spec: ARSIA-Actions.md §2.4 — unknown fields are silently dropped."""
    from arsia_protocol.types.actions import ActionDescriptor

    d = ActionDescriptor(
        action_id="com.example.notes/read",
        category="data",
        description="Read notes.",
        risk_level=2,
        reversible=False,
        idempotent=True,
        required_capabilities=["notes.read"],
        human_oversight_required=False,
        audit_required=False,
        explainability_required=False,
        future_field_v11="unknown-value",
    )
    assert not hasattr(d, "future_field_v11")
    assert d.action_id == "com.example.notes/read"


def test_is_major_version_bump_same_major() -> None:
    """Spec: ARSIA-Actions.md §2.4 — 1.0 → 1.1 is NOT a major bump."""
    assert is_major_version_bump("1.0", "1.1") is False


def test_is_major_version_bump_different_major() -> None:
    """Spec: ARSIA-Actions.md §2.4 — 1.0 → 2.0 IS a major bump."""
    assert is_major_version_bump("1.0", "2.0") is True


def test_is_major_version_bump_rejects_malformed() -> None:
    """Spec: ARSIA-Actions.md §2.4 — malformed version strings are rejected."""
    with pytest.raises(ValueError):
        is_major_version_bump("bad", "1.0")
    with pytest.raises(ValueError):
        is_major_version_bump("1.0", "bad")


def test_resolve_action_version_no_version_field() -> None:
    """Spec: ARSIA-Actions.md §2.4 — absent version → latest supported."""
    version = resolve_action_version(
        {"type": "com.example.notes/read"}, ["1.0", "1.1"]
    )
    assert version == "1.1"


def test_resolve_action_version_with_version_field() -> None:
    """Spec: ARSIA-Actions.md §2.4 — present version is returned as-is."""
    version = resolve_action_version(
        {"type": "com.example.notes/read", "version": "1.0"}, ["1.0", "1.1"]
    )
    assert version == "1.0"


def test_resolve_action_version_empty_supported_raises() -> None:
    """Spec: ARSIA-Actions.md §2.4 — empty supported list is an error."""
    with pytest.raises(ValueError):
        resolve_action_version({"type": "x"}, [])


def test_build_version_not_supported_error_shape() -> None:
    """Spec: ARSIA-Actions.md §2.4 — error includes supported_versions."""
    env = build_version_not_supported_error(
        from_agent="agent:acme.server",
        to_agent="agent:acme.client",
        correlation_id="00000000-0000-4000-8000-000000000001",
        requested_version="3.0",
        supported_versions=["1.0", "2.0"],
    )
    assert env["intent"] == "error"
    assert env["payload"]["error"]["code"] == "not_implemented"
    assert env["payload"]["error"]["description"] == "Action version not supported"
    details = env["payload"]["error"]["details"]
    assert details["requested_version"] == "3.0"
    assert details["supported_versions"] == {"min": "1.0", "max": "2.0"}


# ---------------------------------------------------------------------------
# §4.2 — Rollback guards
# ---------------------------------------------------------------------------


def test_validate_rollback_non_reversible() -> None:
    """Spec: ARSIA-Actions.md §4.2 — reversible=false → not_implemented."""
    result = validate_rollback(
        descriptor={"reversible": False},
        current_state="completed",
    )
    assert result is not None
    assert result["code"] == "not_implemented"
    assert "not supported" in result["description"].lower()


def test_validate_rollback_already_rolled_back() -> None:
    """Spec: ARSIA-Actions.md §4.2 — already rolled back → conflict."""
    result = validate_rollback(
        descriptor={"reversible": True},
        current_state="rolled_back",
    )
    assert result is not None
    assert result["code"] == "conflict"
    assert result["details"]["already_rolled_back"] is True


def test_validate_rollback_window_expired() -> None:
    """Spec: ARSIA-Actions.md §4.2 — window exceeded → conflict."""
    from datetime import datetime, timedelta, timezone

    completed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    now = completed + timedelta(seconds=601)
    result = validate_rollback(
        descriptor={"reversible": True},
        current_state="completed",
        rollback_window_seconds=600,
        completed_at=completed,
        now=now,
    )
    assert result is not None
    assert result["code"] == "conflict"
    assert result["details"]["rollback_window_exceeded"] is True


def test_validate_rollback_within_window() -> None:
    """Spec: ARSIA-Actions.md §4.2 — within window → allowed."""
    from datetime import datetime, timedelta, timezone

    completed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    now = completed + timedelta(seconds=300)
    result = validate_rollback(
        descriptor={"reversible": True},
        current_state="completed",
        rollback_window_seconds=600,
        completed_at=completed,
        now=now,
    )
    assert result is None


def test_validate_rollback_reversible_not_rolled_back() -> None:
    """Spec: ARSIA-Actions.md §4.2 — allowed when preconditions met."""
    result = validate_rollback(
        descriptor={"reversible": True},
        current_state="completed",
    )
    assert result is None


def test_build_rollback_audit_record_full() -> None:
    """Spec: ARSIA-Actions.md §4.2 — full rollback audit record."""
    record = build_rollback_audit_record(
        original_message_id="msg-001",
        original_action_id="com.example.notes/write",
        rollback_message_id="msg-002",
        timestamp="2026-04-22T10:00:00.000Z",
        full_rollback=True,
    )
    assert record["event_type"] == "rollback"
    assert record["original_message_id"] == "msg-001"
    assert record["original_action_id"] == "com.example.notes/write"
    assert record["rollback_message_id"] == "msg-002"
    assert record["timestamp"] == "2026-04-22T10:00:00.000Z"
    assert record["full_rollback"] is True


def test_build_rollback_audit_record_partial() -> None:
    """Spec: ARSIA-Actions.md §4.2 — partial rollback audit record."""
    record = build_rollback_audit_record(
        original_message_id="msg-001",
        original_action_id="com.example.notes/write",
        rollback_message_id="msg-002",
        timestamp="2026-04-22T10:00:00.000Z",
        full_rollback=False,
    )
    assert record["full_rollback"] is False


def test_build_partial_rollback_response_valid() -> None:
    """Spec: ARSIA-Actions.md §4.2 — partial rollback response shape."""
    resp = build_partial_rollback_response(
        rolled_back=["effect-a", "effect-b"],
        not_rolled_back=["effect-c"],
    )
    assert resp["partial_rollback"] is True
    assert resp["rolled_back"] == ["effect-a", "effect-b"]
    assert resp["not_rolled_back"] == ["effect-c"]


def test_build_partial_rollback_response_single_items() -> None:
    """Spec: ARSIA-Actions.md §4.2 — edge case with single item each."""
    resp = build_partial_rollback_response(
        rolled_back=["only-reversed"],
        not_rolled_back=["only-kept"],
    )
    assert resp["partial_rollback"] is True
    assert len(resp["rolled_back"]) == 1
    assert len(resp["not_rolled_back"]) == 1


def test_build_partial_rollback_response_empty_rolled_back_raises() -> None:
    """Spec: ARSIA-Actions.md §4.2 — empty rolled_back is invalid."""
    with pytest.raises(ValueError, match="rolled_back must not be empty"):
        build_partial_rollback_response(
            rolled_back=[],
            not_rolled_back=["effect-c"],
        )


def test_build_partial_rollback_response_empty_not_rolled_back_raises() -> None:
    """Spec: ARSIA-Actions.md §4.2 — empty not_rolled_back is invalid."""
    with pytest.raises(ValueError, match="not_rolled_back must not be empty"):
        build_partial_rollback_response(
            rolled_back=["effect-a"],
            not_rolled_back=[],
        )


# ---------------------------------------------------------------------------
# §4.3 — Timeout / Async
# ---------------------------------------------------------------------------


def test_build_timeout_error_shape() -> None:
    """Spec: ARSIA-Actions.md §4.3 — service_unavailable + timeout description."""
    env = build_timeout_error(
        from_agent="agent:acme.server",
        to_agent="agent:acme.client",
        correlation_id="00000000-0000-4000-8000-000000000001",
    )
    assert env["intent"] == "error"
    assert env["payload"]["error"]["code"] == "service_unavailable"
    assert env["payload"]["error"]["description"] == "Action execution timeout"


def test_build_timeout_error_with_details() -> None:
    """Spec: ARSIA-Actions.md §4.3 — optional action_id and timeout_ms."""
    env = build_timeout_error(
        from_agent="agent:acme.server",
        to_agent="agent:acme.client",
        correlation_id="00000000-0000-4000-8000-000000000001",
        action_id="com.example.notes/write",
        timeout_ms=30000,
    )
    details = env["payload"]["error"]["details"]
    assert details["action_id"] == "com.example.notes/write"
    assert details["timeout_ms"] == 30000


def test_validate_timeout_cancellation_exceeded() -> None:
    """Spec: ARSIA-Actions.md §4.3 — timeout exceeded returns True."""
    from datetime import datetime, timedelta, timezone

    started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    now = started + timedelta(milliseconds=31000)
    assert validate_timeout_cancellation(
        current_state="executing",
        max_execution_ms=30000,
        started_at=started,
        now=now,
    ) is True


def test_validate_timeout_cancellation_not_exceeded() -> None:
    """Spec: ARSIA-Actions.md §4.3 — within timeout returns False."""
    from datetime import datetime, timedelta, timezone

    started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    now = started + timedelta(milliseconds=15000)
    assert validate_timeout_cancellation(
        current_state="executing",
        max_execution_ms=30000,
        started_at=started,
        now=now,
    ) is False


def test_validate_timeout_cancellation_not_executing() -> None:
    """Spec: ARSIA-Actions.md §4.3 — only executing state can timeout."""
    from datetime import datetime, timedelta, timezone

    started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    now = started + timedelta(milliseconds=31000)
    assert validate_timeout_cancellation(
        current_state="completed",
        max_execution_ms=30000,
        started_at=started,
        now=now,
    ) is False


def test_build_partial_execution_audit_shape() -> None:
    """Spec: ARSIA-Actions.md §4.3 — partial_execution audit record."""
    record = build_partial_execution_audit(
        message_id="msg-001",
        action_id="com.example.notes/write",
        timestamp="2026-04-22T10:00:00.000Z",
    )
    assert record["event_type"] == "partial_execution"
    assert record["message_id"] == "msg-001"
    assert record["action_id"] == "com.example.notes/write"
    assert record["reason"] == "timeout"
    assert "partial_results" not in record


def test_build_partial_execution_audit_with_results() -> None:
    """Spec: ARSIA-Actions.md §4.3 — partial_results included when provided."""
    record = build_partial_execution_audit(
        message_id="msg-001",
        action_id="com.example.notes/write",
        timestamp="2026-04-22T10:00:00.000Z",
        partial_results={"rows_written": 5},
    )
    assert record["partial_results"] == {"rows_written": 5}


# ---------------------------------------------------------------------------
# §5.1 — Explanation enforcement
# ---------------------------------------------------------------------------


def test_is_explanation_required_descriptor_true() -> None:
    """Spec: ARSIA-Actions.md §5.1 — descriptor explainability_required=true."""
    assert is_explanation_required(
        descriptor={"explainability_required": True}
    ) is True


def test_is_explanation_required_descriptor_false() -> None:
    """Spec: ARSIA-Actions.md §5.1 — descriptor explainability_required=false."""
    assert is_explanation_required(
        descriptor={"explainability_required": False}
    ) is False


def test_is_explanation_required_compliance_override() -> None:
    """Spec: ARSIA-Actions.md §5.1 — compliance overrides descriptor."""
    assert is_explanation_required(
        descriptor={"explainability_required": False},
        compliance={"explainability_required": True},
    ) is True


def test_is_explanation_required_both_none() -> None:
    """Spec: ARSIA-Actions.md §5.1 — no source → not required."""
    assert is_explanation_required() is False


def test_is_explanation_required_compliance_alone() -> None:
    """Spec: ARSIA-Actions.md §5.1 — compliance alone is sufficient."""
    assert is_explanation_required(
        compliance={"explainability_required": True},
    ) is True


def test_validate_response_explanation_present_when_required() -> None:
    """Spec: ARSIA-Actions.md §5.1 — explanation present → no errors."""
    errors = validate_response_explanation(
        response_payload={"explanation": {"reasoning": "test"}},
        descriptor={"explainability_required": True},
    )
    assert errors == []


def test_validate_response_explanation_missing_when_required() -> None:
    """Spec: ARSIA-Actions.md §5.1 — explanation missing → error."""
    errors = validate_response_explanation(
        response_payload={},
        descriptor={"explainability_required": True},
    )
    assert len(errors) == 1
    assert errors[0].code == "missing_explanation"


def test_validate_response_explanation_missing_compliance_override() -> None:
    """Spec: ARSIA-Actions.md §5.1 — compliance override, explanation missing → error."""
    errors = validate_response_explanation(
        response_payload={},
        descriptor={"explainability_required": False},
        compliance={"explainability_required": True},
    )
    assert len(errors) == 1
    assert errors[0].code == "missing_explanation"
    assert "compliance.explainability_required" in errors[0].details["sources"]


def test_validate_response_explanation_not_required() -> None:
    """Spec: ARSIA-Actions.md §5.1 — not required → no errors even if absent."""
    errors = validate_response_explanation(
        response_payload={},
        descriptor={"explainability_required": False},
    )
    assert errors == []


# ---------------------------------------------------------------------------
# BL-04 — EXPLICIT_GRANT_ONLY completeness (§1.4 non-delegable)
# ---------------------------------------------------------------------------


def test_explicit_grant_only_has_three_entries() -> None:
    """Spec: ARSIA-Actions.md §1.4 — exactly 3 non-delegable capabilities."""
    assert len(EXPLICIT_GRANT_ONLY) == 3
    assert "arsiaprotocol.state.purge" in EXPLICIT_GRANT_ONLY
    assert "arsiaprotocol.state.snapshot" in EXPLICIT_GRANT_ONLY
    assert "arsiaprotocol.oversight.approve" in EXPLICIT_GRANT_ONLY


def test_wildcard_does_not_satisfy_state_snapshot() -> None:
    """Spec: ARSIA-Actions.md §1.4 — snapshot MUST require explicit grant."""
    assert match_capability("arsiaprotocol.*", "arsiaprotocol.state.snapshot") is False
    assert match_capability("arsiaprotocol.state.*", "arsiaprotocol.state.snapshot") is False


def test_wildcard_does_not_satisfy_oversight_approve() -> None:
    """Spec: ARSIA-Actions.md §1.4 — oversight.approve MUST require explicit grant."""
    assert match_capability("arsiaprotocol.*", "arsiaprotocol.oversight.approve") is False
    assert match_capability("arsiaprotocol.oversight.*", "arsiaprotocol.oversight.approve") is False


def test_exact_grant_satisfies_all_non_delegable() -> None:
    """Spec: ARSIA-Actions.md §1.4 — explicit grant still authorises non-delegable."""
    for cap in EXPLICIT_GRANT_ONLY:
        assert match_capability(cap, cap) is True


def test_wildcard_still_satisfies_delegable_capabilities() -> None:
    """Spec: ARSIA-Actions.md §1.2 — non-delegable gate does not affect normal caps."""
    assert match_capability("arsiaprotocol.state.*", "arsiaprotocol.state.read") is True
    assert match_capability("arsiaprotocol.*", "arsiaprotocol.audit.read") is True


# ---------------------------------------------------------------------------
# BL-05 — RESERVED_CAPABILITIES completeness (§1.4)
# ---------------------------------------------------------------------------


def test_reserved_capabilities_includes_breach_notify() -> None:
    """Spec: ARSIA-Actions.md §1.4 — breach.notify is a reserved capability."""
    assert is_reserved_capability("arsiaprotocol.compliance.breach.notify") is True


def test_breach_notify_validates_as_reserved() -> None:
    """Spec: ARSIA-Actions.md §1.1 — breach.notify passes validate_capability."""
    assert validate_capability("arsiaprotocol.compliance.breach.notify") == []


def test_reserved_capabilities_total_is_sixteen() -> None:
    """Spec: ARSIA-Actions.md §1.4 — exactly 16 reserved capabilities."""
    assert len(RESERVED_CAPABILITIES) == 16


def test_reserved_capabilities_enumerates_all_sixteen() -> None:
    """Spec: ARSIA-Actions.md §1.4 — every reserved capability by name."""
    spec_reserved = {
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
    assert set(RESERVED_CAPABILITIES) == spec_reserved, (
        f"extra={set(RESERVED_CAPABILITIES) - spec_reserved}, "
        f"missing={spec_reserved - set(RESERVED_CAPABILITIES)}"
    )


# ---------------------------------------------------------------------------
# BL-22 — 24h approval deadline cap (§3.2 Step 3)
# ---------------------------------------------------------------------------


def test_pending_approval_24h_boundary_accepted() -> None:
    """Spec: ARSIA-Actions.md §3.2 — expires_in_seconds=86400 is the upper bound."""
    from arsia_protocol.core.message import create_pending_approval

    env = create_pending_approval(
        "agent:acme.server",
        "agent:acme.client",
        "00000000-0000-4000-8000-000000000001",
        "com.example.notes/approve",
        expires_in_seconds=86400,
    )
    assert env["intent"] == "pending_approval"


def test_pending_approval_24h_exceeded_rejected() -> None:
    """Spec: ARSIA-Actions.md §3.2 — expires_in_seconds > 86400 MUST be rejected."""
    from arsia_protocol.core.message import create_pending_approval

    with pytest.raises(ValueError, match="24 hours"):
        create_pending_approval(
            "agent:acme.server",
            "agent:acme.client",
            "00000000-0000-4000-8000-000000000001",
            "com.example.notes/approve",
            expires_in_seconds=86401,
        )


def test_pending_approval_normal_ttl_accepted() -> None:
    """Spec: ARSIA-Actions.md §3.2 — normal TTL well within bound."""
    from arsia_protocol.core.message import create_pending_approval

    env = create_pending_approval(
        "agent:acme.server",
        "agent:acme.client",
        "00000000-0000-4000-8000-000000000001",
        "com.example.notes/approve",
        expires_in_seconds=3600,
    )
    assert env["intent"] == "pending_approval"


def test_pending_approval_large_ttl_rejected() -> None:
    """Spec: ARSIA-Actions.md §3.2 — 100000s far exceeds 24h."""
    from arsia_protocol.core.message import create_pending_approval

    with pytest.raises(ValueError, match="24 hours"):
        create_pending_approval(
            "agent:acme.server",
            "agent:acme.client",
            "00000000-0000-4000-8000-000000000001",
            "com.example.notes/approve",
            expires_in_seconds=100000,
        )


# ---------------------------------------------------------------------------
# BL-23 — Timeout error field names (§4.3)
# ---------------------------------------------------------------------------


def test_timeout_error_uses_timeout_ms_key() -> None:
    """Spec: ARSIA-Actions.md §4.3 — details key is timeout_ms, not max_execution_ms."""
    env = build_timeout_error(
        from_agent="agent:acme.server",
        to_agent="agent:acme.client",
        correlation_id="00000000-0000-4000-8000-000000000001",
        timeout_ms=30000,
    )
    details = env["payload"]["error"]["details"]
    assert "timeout_ms" in details
    assert "max_execution_ms" not in details
    assert details["timeout_ms"] == 30000


def test_timeout_error_includes_elapsed_ms_when_provided() -> None:
    """Spec: ARSIA-Actions.md §4.3 — elapsed_ms SHOULD be included."""
    env = build_timeout_error(
        from_agent="agent:acme.server",
        to_agent="agent:acme.client",
        correlation_id="00000000-0000-4000-8000-000000000001",
        timeout_ms=30000,
        elapsed_ms=31200,
    )
    details = env["payload"]["error"]["details"]
    assert details["elapsed_ms"] == 31200
    assert details["timeout_ms"] == 30000


def test_timeout_error_omits_elapsed_ms_when_not_provided() -> None:
    """Spec: ARSIA-Actions.md §4.3 — elapsed_ms is optional."""
    env = build_timeout_error(
        from_agent="agent:acme.server",
        to_agent="agent:acme.client",
        correlation_id="00000000-0000-4000-8000-000000000001",
        timeout_ms=30000,
    )
    details = env["payload"]["error"]["details"]
    assert "elapsed_ms" not in details


def test_timeout_error_no_details_when_all_optional_omitted() -> None:
    """Spec: ARSIA-Actions.md §4.3 — no details when nothing provided."""
    env = build_timeout_error(
        from_agent="agent:acme.server",
        to_agent="agent:acme.client",
        correlation_id="00000000-0000-4000-8000-000000000001",
    )
    assert env["payload"]["error"].get("details") is None


# ---------------------------------------------------------------------------
# §2.2 — Risk 3-4 audit warning (ACT-§2.2-07)
# ---------------------------------------------------------------------------


def test_validate_descriptor_risk_3_no_audit_warns() -> None:
    """Risk 3 without audit_required should produce a warning."""
    descriptor = {
        "action_id": "com.acme/test",
        "category": "data",
        "description": "Test",
        "risk_level": 3,
        "reversible": True,
        "idempotent": False,
        "required_capabilities": ["test.read"],
        "human_oversight_required": False,
        "audit_required": False,
        "explainability_required": False,
    }
    errors = validate_action_descriptor(descriptor)
    codes = [e.code for e in errors]
    assert "risk_34_audit_recommended" in codes


def test_validate_descriptor_risk_4_no_audit_warns() -> None:
    """Risk 4 without audit_required should produce a warning."""
    descriptor = {
        "action_id": "com.acme/test",
        "category": "data",
        "description": "Test",
        "risk_level": 4,
        "reversible": True,
        "idempotent": False,
        "required_capabilities": ["test.read"],
        "human_oversight_required": False,
        "audit_required": False,
        "explainability_required": False,
    }
    errors = validate_action_descriptor(descriptor)
    codes = [e.code for e in errors]
    assert "risk_34_audit_recommended" in codes


def test_validate_descriptor_risk_3_with_audit_no_warning() -> None:
    """Risk 3 with audit_required=true should NOT produce a warning."""
    descriptor = {
        "action_id": "com.acme/test",
        "category": "data",
        "description": "Test",
        "risk_level": 3,
        "reversible": True,
        "idempotent": False,
        "required_capabilities": ["test.read"],
        "human_oversight_required": False,
        "audit_required": True,
        "explainability_required": False,
    }
    errors = validate_action_descriptor(descriptor)
    codes = [e.code for e in errors]
    assert "risk_34_audit_recommended" not in codes


# ---------------------------------------------------------------------------
# §3.4 — Approval deadline expiry (ACT-§3.4-05)
# ---------------------------------------------------------------------------


def test_is_approval_expired_before_deadline_returns_false() -> None:
    """Before deadline (with skew) returns False."""
    deadline = "2026-06-01T12:00:00.000Z"
    now = datetime(2026, 6, 1, 11, 50, 0, tzinfo=timezone.utc)
    assert is_approval_expired(deadline, now=now) is False


def test_is_approval_expired_after_deadline_returns_true() -> None:
    """Well past deadline returns True."""
    deadline = "2026-06-01T12:00:00.000Z"
    now = datetime(2026, 6, 1, 13, 0, 0, tzinfo=timezone.utc)
    assert is_approval_expired(deadline, now=now) is True


def test_is_approval_expired_within_clock_skew_returns_false() -> None:
    """Within the 300s clock skew window returns False."""
    deadline = "2026-06-01T12:00:00.000Z"
    now = datetime(2026, 6, 1, 12, 4, 0, tzinfo=timezone.utc)
    assert is_approval_expired(deadline, now=now) is False


# ---------------------------------------------------------------------------
# Module self-check — guards the public surface
# ---------------------------------------------------------------------------


def test_actions_module_exports_expected_symbols() -> None:
    """Every symbol listed in ``__all__`` is resolvable on the module."""
    for name in actions.__all__:
        assert hasattr(actions, name), f"actions.{name} missing"
