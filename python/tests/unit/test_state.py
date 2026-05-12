# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for the :mod:`arsia_protocol.state` primitive.

Covers the offline portions of ARSIA-State.md:

- §1 scope taxonomy
- §2.1 StateEntry validation (ownership, size limit, PII compliance,
  data residency)
- §2.1.1 key grammar + §2.2 reserved prefix
- §3 operation argument builders
- §4.1.1 effective retention formula
- §8.2 capability matrix and wildcard exclusions

HTTP-/storage-dependent cases (round-trip CRUD, concurrency, query
filtering, snapshot pagination) belong in Slice 8.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from arsia_protocol.state.state import (
    OPERATION_TO_CAPABILITY,
    PAYLOAD_TYPE_DELETE,
    PAYLOAD_TYPE_GET,
    PAYLOAD_TYPE_GRANT,
    PAYLOAD_TYPE_PURGE,
    PAYLOAD_TYPE_QUERY,
    PAYLOAD_TYPE_REVOKE,
    PAYLOAD_TYPE_SET,
    PAYLOAD_TYPE_SNAPSHOT,
    STATE_CAPABILITY_PURGE,
    STATE_CAPABILITY_READ,
    STATE_CAPABILITY_SNAPSHOT,
    STATE_CAPABILITY_WRITE,
    STATE_KEY_MAX_LENGTH,
    STATE_OPERATIONS,
    STATE_RESERVED_KEY_PREFIX,
    STATE_SCOPES,
    STATE_VALUE_MAX_BYTES,
    STATE_WILDCARD_EXCLUDES,
    build_conflict_error,
    build_delete_args,
    build_get_args,
    build_grant_args,
    build_grant_result,
    build_purge_args,
    build_purge_result,
    build_query_args,
    build_revoke_args,
    build_revoke_result,
    build_set_args,
    build_snapshot_args,
    compute_effective_retention,
    compute_value_size,
    detect_immutable_field_changes,
    enforce_value_size_limit,
    is_entry_expired,
    is_reserved_key,
    is_within_retention,
    parse_state_key,
    payload_type_for,
    required_capability_for,
    validate_eu_ai_act_response,
    validate_state_entry,
    validate_state_key,
    wildcard_covers_state_capability,
)
from arsia_protocol.types.state import StateEntry

_AGENT = "agent:acme.alpha"
_OTHER_AGENT = "agent:acme.beta"
_TS = "2026-04-13T12:00:00.000Z"


def _entry(
    *,
    key: str = f"{_AGENT}/agent/k1",
    value: object = {"hello": "world"},
    owner: str = _AGENT,
    scope: str = "agent",
    pii: str = "none",
    pii_special_categories: list[str] | None = None,
    retention_days: int | None = None,
    data_residency: str | None = None,
) -> StateEntry:
    return StateEntry(
        key=key,
        value=value,
        owner_agent_id=owner,
        scope=scope,  # type: ignore[arg-type]
        created_at=_TS,
        updated_at=_TS,
        pii_classification=pii,  # type: ignore[arg-type]
        pii_special_categories=pii_special_categories,  # type: ignore[arg-type]
        version=1,
        retention_days=retention_days,
        data_residency=data_residency,
    )


# ---------------------------------------------------------------------------
# Constants & module shape
# ---------------------------------------------------------------------------


def test_state_scopes_exactly_four() -> None:
    assert STATE_SCOPES == frozenset({"session", "agent", "shared", "global"})


def test_state_operations_exactly_eight() -> None:
    assert STATE_OPERATIONS == frozenset(
        {"GET", "SET", "DELETE", "QUERY", "SNAPSHOT", "PURGE", "GRANT", "REVOKE"}
    )


def test_state_capability_count_is_four() -> None:
    capabilities = {
        STATE_CAPABILITY_READ,
        STATE_CAPABILITY_WRITE,
        STATE_CAPABILITY_PURGE,
        STATE_CAPABILITY_SNAPSHOT,
    }
    assert len(capabilities) == 4
    assert all(c.startswith("arsiaprotocol.state.") for c in capabilities)


def test_wildcard_excludes_purge_and_snapshot() -> None:
    assert STATE_WILDCARD_EXCLUDES == frozenset(
        {STATE_CAPABILITY_PURGE, STATE_CAPABILITY_SNAPSHOT}
    )


def test_state_constants_match_spec() -> None:
    assert STATE_KEY_MAX_LENGTH == 512
    assert STATE_VALUE_MAX_BYTES == 1_048_576
    assert STATE_RESERVED_KEY_PREFIX == "arsiaprotocol."


# ---------------------------------------------------------------------------
# §2.1.1 Key grammar
# ---------------------------------------------------------------------------


def test_parse_state_key_splits_on_first_two_slashes() -> None:
    agent, scope, local = parse_state_key("agent:acme.alpha/session/a/b/c")
    assert agent == "agent:acme.alpha"
    assert scope == "session"
    assert local == "a/b/c"


def test_parse_state_key_rejects_missing_scope() -> None:
    with pytest.raises(ValueError, match=r"shape"):
        parse_state_key("agent:acme.alpha/session")


def test_parse_state_key_rejects_unknown_scope() -> None:
    with pytest.raises(ValueError, match=r"scope segment"):
        parse_state_key("agent:acme.alpha/bogus/k")


def test_parse_state_key_rejects_empty_local() -> None:
    with pytest.raises(ValueError, match=r"local-key"):
        parse_state_key("agent:acme.alpha/session/")


def test_validate_state_key_accepts_valid_key() -> None:
    errs = validate_state_key(
        f"{_AGENT}/agent/config.retries",
        expected_owner=_AGENT,
        expected_scope="agent",
    )
    assert errs == []


def test_validate_state_key_rejects_over_length() -> None:
    key = f"{_AGENT}/agent/" + "a" * 600
    errs = validate_state_key(key)
    assert any(e.code == "key_too_long" for e in errs)


def test_validate_state_key_rejects_forbidden_characters() -> None:
    errs = validate_state_key(f"{_AGENT}/agent/bad key")
    assert any(e.code == "invalid_key_characters" for e in errs)


def test_validate_state_key_rejects_owner_mismatch() -> None:
    errs = validate_state_key(
        f"{_OTHER_AGENT}/agent/k",
        expected_owner=_AGENT,
        expected_scope="agent",
    )
    assert any(e.code == "key_owner_mismatch" for e in errs)


def test_validate_state_key_rejects_scope_mismatch() -> None:
    errs = validate_state_key(
        f"{_AGENT}/session/k",
        expected_owner=_AGENT,
        expected_scope="agent",
    )
    assert any(e.code == "key_scope_mismatch" for e in errs)


def test_validate_state_key_rejects_reserved_prefix_in_local_key() -> None:
    errs = validate_state_key(f"{_AGENT}/agent/arsiaprotocol.grants.foo")
    assert any(e.code == "reserved_key_prefix" for e in errs)


def test_validate_state_key_allows_reserved_prefix_when_flagged() -> None:
    errs = validate_state_key(
        f"{_AGENT}/agent/arsiaprotocol.grants.foo",
        allow_reserved=True,
    )
    assert errs == []


def test_validate_state_key_rejects_non_string() -> None:
    errs = validate_state_key(123)  # type: ignore[arg-type]
    assert errs
    assert errs[0].code == "invalid_type"


def test_is_reserved_key_full_path() -> None:
    assert is_reserved_key(f"{_AGENT}/agent/arsiaprotocol.grants.x") is True
    assert is_reserved_key(f"{_AGENT}/agent/config.x") is False


def test_is_reserved_key_handles_malformed_input() -> None:
    # Unparseable key falls back to raw prefix check.
    assert is_reserved_key("arsiaprotocol.grants.x") is True
    assert is_reserved_key("nope") is False


# ---------------------------------------------------------------------------
# §2.1.2 Value size
# ---------------------------------------------------------------------------


def test_compute_value_size_returns_canonical_length() -> None:
    assert compute_value_size({"a": 1}) == len(b'{"a":1}')


def test_compute_value_size_wraps_scalar() -> None:
    assert compute_value_size("x") == len(b'["x"]')


def test_enforce_value_size_limit_accepts_small_value() -> None:
    assert enforce_value_size_limit({"k": "v"}) > 0


def test_enforce_value_size_limit_rejects_over_1_mib() -> None:
    huge = "x" * (STATE_VALUE_MAX_BYTES + 1)
    with pytest.raises(ValueError, match=r"payload_too_large"):
        enforce_value_size_limit(huge)


def test_enforce_value_size_limit_at_boundary() -> None:
    # A string that canonicalizes to exactly the limit passes.
    # canonicalize wraps scalars in [...] so we subtract the 2 wrapper bytes
    # and 2 quote bytes from the budget.
    payload = "x" * (STATE_VALUE_MAX_BYTES - 4)
    size = enforce_value_size_limit(payload)
    assert size == STATE_VALUE_MAX_BYTES


# ---------------------------------------------------------------------------
# §2.1 StateEntry validation
# ---------------------------------------------------------------------------


def test_validate_state_entry_accepts_valid_entry() -> None:
    entry = _entry()
    assert validate_state_entry(entry, sender_agent_id=_AGENT) == []


def test_validate_state_entry_rejects_owner_mismatch_vs_sender() -> None:
    entry = _entry()
    errs = validate_state_entry(entry, sender_agent_id=_OTHER_AGENT)
    assert any(e.code == "owner_sender_mismatch" for e in errs)


def test_validate_state_entry_rejects_key_owner_mismatch() -> None:
    entry = _entry(key=f"{_OTHER_AGENT}/agent/k1")
    errs = validate_state_entry(entry, sender_agent_id=_OTHER_AGENT)
    assert any(e.code == "key_owner_mismatch" for e in errs)


def test_validate_state_entry_rejects_key_scope_mismatch() -> None:
    entry = _entry(key=f"{_AGENT}/session/k1", scope="agent")
    errs = validate_state_entry(entry)
    assert any(e.code == "key_scope_mismatch" for e in errs)


def test_validate_state_entry_personal_pii_requires_legal_basis() -> None:
    entry = _entry(pii="personal", data_residency="PT")
    errs = validate_state_entry(
        entry,
        envelope_compliance={"data_residency": "PT"},
    )
    assert any(e.code == "missing_legal_basis" for e in errs)


def test_validate_state_entry_personal_pii_requires_data_residency() -> None:
    entry = _entry(pii="personal")
    errs = validate_state_entry(
        entry,
        envelope_compliance={"legal_basis": "consent"},
    )
    assert any(e.code == "missing_data_residency" for e in errs)


def test_validate_state_entry_personal_pii_without_compliance_fails() -> None:
    entry = _entry(pii="personal")
    errs = validate_state_entry(entry)
    assert any(e.code == "missing_compliance" for e in errs)


def test_validate_state_entry_personal_pii_with_full_compliance_passes() -> None:
    entry = _entry(pii="personal", data_residency="PT")
    errs = validate_state_entry(
        entry,
        envelope_compliance={
            "legal_basis": "consent",
            "data_residency": "PT",
        },
    )
    assert errs == []


def test_validate_state_entry_residency_mismatch_rejected() -> None:
    entry = _entry(data_residency="DE")
    errs = validate_state_entry(
        entry,
        envelope_compliance={"data_residency": "PT"},
    )
    assert any(e.code == "residency_mismatch" for e in errs)


def test_validate_state_entry_oversize_value_rejected() -> None:
    big = "x" * (STATE_VALUE_MAX_BYTES + 100)
    entry = _entry(value=big)
    errs = validate_state_entry(entry)
    assert any(e.code == "payload_too_large" for e in errs)


def test_validate_state_entry_none_pii_without_compliance_ok() -> None:
    entry = _entry(pii="none")
    assert validate_state_entry(entry) == []


def test_validate_state_entry_pseudonymised_pii_without_legal_basis_ok() -> None:
    # §2.1.10 pseudonymised doesn't require legal_basis at the entry layer.
    entry = _entry(pii="pseudonymised")
    assert validate_state_entry(entry) == []


# ---------------------------------------------------------------------------
# Sensitive PII (Art. 9(2)) validation — BL-02
# ---------------------------------------------------------------------------


def test_validate_state_entry_sensitive_pii_accepted() -> None:
    """pii_classification='sensitive' is a valid value."""
    entry = _entry(pii="sensitive", pii_special_categories=["health"], data_residency="DE")
    errs = validate_state_entry(
        entry,
        envelope_compliance={
            "legal_basis": "explicit_consent",
            "data_residency": "DE",
        },
    )
    assert errs == []


def test_validate_state_entry_sensitive_with_art9_basis_passes() -> None:
    """Sensitive entry with an Art. 9(2) legal basis passes validation."""
    entry = _entry(pii="sensitive", pii_special_categories=["health"], data_residency="EU")
    errs = validate_state_entry(
        entry,
        envelope_compliance={
            "legal_basis": "health_medicine",
            "data_residency": "EU",
        },
    )
    assert errs == []


def test_validate_state_entry_sensitive_with_art6_basis_rejected() -> None:
    """Sensitive entry with an Art. 6(1) legal basis is rejected.

    Core §4.3.6.8 Rule 8: rejection must indicate sensitive_requires_art9_basis.
    """
    entry = _entry(pii="sensitive", pii_special_categories=["health"], data_residency="DE")
    errs = validate_state_entry(
        entry,
        envelope_compliance={
            "legal_basis": "contract",
            "data_residency": "DE",
        },
    )
    assert len(errs) == 1, f"Expected exactly 1 error, got {len(errs)}: {errs}"
    err = errs[0]
    assert err.code == "sensitive_requires_art9_basis"
    assert "Art. 9(2)" in err.message
    assert err.details["legal_basis"] == "contract"


def test_validate_state_entry_sensitive_without_legal_basis_rejected() -> None:
    """Sensitive entry without legal_basis is rejected."""
    entry = _entry(pii="sensitive", pii_special_categories=["health"], data_residency="DE")
    errs = validate_state_entry(
        entry,
        envelope_compliance={"data_residency": "DE"},
    )
    assert any(e.code == "missing_legal_basis" for e in errs)


def test_validate_state_entry_sensitive_without_compliance_rejected() -> None:
    """Sensitive entry without any compliance object is rejected."""
    entry = _entry(pii="sensitive", pii_special_categories=["health"])
    errs = validate_state_entry(entry)
    assert any(e.code == "missing_compliance" for e in errs)


def test_validate_state_entry_personal_unchanged_by_sensitive_addition() -> None:
    """Personal validation still works the same way after adding sensitive."""
    entry = _entry(pii="personal", data_residency="PT")
    errs = validate_state_entry(
        entry,
        envelope_compliance={
            "legal_basis": "consent",
            "data_residency": "PT",
        },
    )
    assert errs == []


# ---------------------------------------------------------------------------
# Immutable-field detection
# ---------------------------------------------------------------------------


def test_detect_immutable_field_changes_none_when_fields_stable() -> None:
    a = _entry()
    b = _entry(value={"changed": True})
    assert detect_immutable_field_changes(a, b) == []


def test_detect_immutable_field_changes_flags_owner_scope_key_pii() -> None:
    a = _entry()
    b = _entry(owner=_OTHER_AGENT, scope="shared", key=f"{_OTHER_AGENT}/shared/k1", pii="personal")
    errs = detect_immutable_field_changes(a, b)
    flagged = {e.details["field"] for e in errs}
    assert flagged == {"owner_agent_id", "scope", "key", "pii_classification"}


def test_detect_immutable_field_changes_flags_created_at() -> None:
    a = _entry()
    b = StateEntry(
        key=a.key,
        value=a.value,
        owner_agent_id=a.owner_agent_id,
        scope=a.scope,
        created_at="2026-04-13T12:00:00.001Z",
        updated_at=_TS,
        pii_classification=a.pii_classification,
        version=1,
    )
    errs = detect_immutable_field_changes(a, b)
    assert any(e.details.get("field") == "created_at" for e in errs)


# ---------------------------------------------------------------------------
# §4.1.1 Effective retention
# ---------------------------------------------------------------------------


def test_compute_effective_retention_gdpr_has_no_mandatory_minimum() -> None:
    # State §6 / §7.3: GDPR-STANDARD has no mandatory retention minimum —
    # the 90-day default is a RECOMMENDED platform policy, not a profile
    # default. compute_effective_retention MUST surface that by returning
    # None when the entry has no override.
    assert compute_effective_retention("GDPR-STANDARD", None) is None


def test_compute_effective_retention_profile_minimums() -> None:
    # §6 profile defaults: EU-AI-ACT-HIGH-RISK=180, MIFID-II=1827,
    # PAC-AGRICULTURE=1096. GDPR-STANDARD is unset.
    assert compute_effective_retention("EU-AI-ACT-HIGH-RISK", None) == 180
    assert compute_effective_retention("MIFID-II", None) == 1827
    assert compute_effective_retention("PAC-AGRICULTURE", None) == 1096


def test_compute_effective_retention_entry_only() -> None:
    assert compute_effective_retention(None, 30) == 30


def test_compute_effective_retention_entry_extends_profile() -> None:
    # PAC-AGRICULTURE profile retention = 1096 days; entry wants 1200.
    assert compute_effective_retention("PAC-AGRICULTURE", 1200) == 1200


def test_compute_effective_retention_entry_cannot_shorten_profile() -> None:
    # MIFID-II profile retention = 1827 days; entry tries 90.
    assert compute_effective_retention("MIFID-II", 90) == 1827


def test_compute_effective_retention_both_none() -> None:
    assert compute_effective_retention(None, None) is None


def test_compute_effective_retention_gdpr_with_entry_override() -> None:
    # Even without a profile minimum, an entry override is honoured.
    assert compute_effective_retention("GDPR-STANDARD", 30) == 30


# ---------------------------------------------------------------------------
# §8.2 Capability matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "op,expected",
    [
        ("GET", STATE_CAPABILITY_READ),
        ("QUERY", STATE_CAPABILITY_READ),
        ("SET", STATE_CAPABILITY_WRITE),
        ("DELETE", STATE_CAPABILITY_WRITE),
        ("GRANT", STATE_CAPABILITY_WRITE),
        ("REVOKE", STATE_CAPABILITY_WRITE),
        ("PURGE", STATE_CAPABILITY_PURGE),
        ("SNAPSHOT", STATE_CAPABILITY_SNAPSHOT),
    ],
)
def test_required_capability_for_operation(op: str, expected: str) -> None:
    assert required_capability_for(op) == expected


def test_required_capability_for_rejects_unknown_operation() -> None:
    with pytest.raises(ValueError, match=r"unknown state operation"):
        required_capability_for("RESET")


def test_operation_to_capability_covers_all_operations() -> None:
    assert set(OPERATION_TO_CAPABILITY) == STATE_OPERATIONS


def test_wildcard_covers_read_and_write() -> None:
    wc = "arsiaprotocol.state.*"
    assert wildcard_covers_state_capability(wc, STATE_CAPABILITY_READ) is True
    assert wildcard_covers_state_capability(wc, STATE_CAPABILITY_WRITE) is True


def test_wildcard_does_not_cover_purge_or_snapshot() -> None:
    wc = "arsiaprotocol.state.*"
    assert wildcard_covers_state_capability(wc, STATE_CAPABILITY_PURGE) is False
    assert wildcard_covers_state_capability(wc, STATE_CAPABILITY_SNAPSHOT) is False


def test_wildcard_exact_match() -> None:
    assert wildcard_covers_state_capability(
        STATE_CAPABILITY_PURGE, STATE_CAPABILITY_PURGE
    ) is True


def test_wildcard_generic_prefix_behaviour() -> None:
    # A broader wildcard like "arsiaprotocol.*" still follows the prefix rule
    # but does NOT honour the §8.2 purge/snapshot exclusion (that exclusion
    # is a property of the exact "arsiaprotocol.state.*" string).
    wc = "arsiaprotocol.*"
    assert wildcard_covers_state_capability(wc, STATE_CAPABILITY_PURGE) is True


# ---------------------------------------------------------------------------
# §3 Argument builders
# ---------------------------------------------------------------------------


def test_payload_type_for_operation_covers_all() -> None:
    mapping = {op: payload_type_for(op) for op in STATE_OPERATIONS}
    assert mapping == {
        "GET": PAYLOAD_TYPE_GET,
        "SET": PAYLOAD_TYPE_SET,
        "DELETE": PAYLOAD_TYPE_DELETE,
        "QUERY": PAYLOAD_TYPE_QUERY,
        "SNAPSHOT": PAYLOAD_TYPE_SNAPSHOT,
        "PURGE": PAYLOAD_TYPE_PURGE,
        "GRANT": PAYLOAD_TYPE_GRANT,
        "REVOKE": PAYLOAD_TYPE_REVOKE,
    }


def test_payload_type_for_unknown_operation_raises() -> None:
    with pytest.raises(ValueError, match="unknown state operation"):
        payload_type_for("NOPE")


def test_build_get_args_shape() -> None:
    assert build_get_args("k") == {"key": "k"}


def test_build_set_args_returns_flat_shape_per_3_1_2() -> None:
    """Spec §3.1.2: SET args is a flat object with key/value/scope/
    pii_classification as required fields — no ``entry`` wrapper."""
    entry = _entry()
    args = build_set_args(entry, expected_version=2)
    # Required (flat) fields.
    assert args["key"] == entry.key
    assert args["value"] == entry.value
    assert args["scope"] == entry.scope
    assert args["pii_classification"] == entry.pii_classification
    # Concurrency token passed through.
    assert args["expected_version"] == 2
    # No wrapper: the old {"entry": {...}} shape is gone.
    assert "entry" not in args


def test_build_set_args_omits_server_managed_fields() -> None:
    """Spec §3.1.2: server-managed fields (owner_agent_id, version,
    created_at, updated_at, deleted) are NOT part of the SET request —
    the receiving store assigns them."""
    args = build_set_args(_entry())
    for forbidden in (
        "owner_agent_id",
        "version",
        "created_at",
        "updated_at",
        "deleted",
    ):
        assert forbidden not in args, f"{forbidden!r} must not appear in SET args"


def test_build_set_args_omits_unset_optional_fields() -> None:
    """Spec §3.1.2: expires_at, retention_days, data_residency,
    expected_version are OPTIONAL. When not supplied they MUST NOT
    appear in the args object."""
    args = build_set_args(_entry())
    for optional in (
        "expires_at",
        "retention_days",
        "data_residency",
        "expected_version",
    ):
        assert optional not in args


def test_build_set_args_propagates_optional_entry_fields() -> None:
    """Spec §3.1.2: when the entry carries retention_days / data_residency
    / expires_at they MUST appear in the flat args at the top level."""
    entry = _entry(retention_days=90, data_residency="PT")
    # expires_at via model construction so we stay within the schema's
    # RFC 3339 ms pattern.
    entry = entry.model_copy(update={"expires_at": "2027-01-01T00:00:00.000Z"})
    args = build_set_args(entry)
    assert args["retention_days"] == 90
    assert args["data_residency"] == "PT"
    assert args["expires_at"] == "2027-01-01T00:00:00.000Z"


def test_build_set_args_rejects_scope_global() -> None:
    """Spec §3.1.2: scope='global' MUST be rejected with error code
    'forbidden'. The sender-side builder raises early so a malformed
    request never reaches the wire."""
    entry = _entry(scope="global")
    with pytest.raises(ValueError, match="forbidden"):
        build_set_args(entry)


def test_build_delete_args_with_version() -> None:
    args = build_delete_args("k", expected_version=3)
    assert args == {"key": "k", "expected_version": 3}


def test_build_query_args_no_filters_returns_empty_dict() -> None:
    assert build_query_args() == {}


def test_build_query_args_rejects_unknown_scope() -> None:
    with pytest.raises(ValueError, match="unknown state scope"):
        build_query_args("nope")  # type: ignore[arg-type]


def test_build_query_args_renames_prefix_to_key_prefix() -> None:
    args = build_query_args(
        "shared", key_prefix="config.", owner_agent_id=_AGENT
    )
    assert args == {
        "scope": "shared",
        "key_prefix": "config.",
        "owner_agent_id": _AGENT,
    }


def test_build_query_args_all_filters() -> None:
    args = build_query_args(
        scope="agent",
        key_prefix="cfg/",
        owner_agent_id=_AGENT,
        pii_classification="personal",
        created_after="2026-01-01T00:00:00.000Z",
        created_before="2026-04-01T00:00:00.000Z",
        limit=50,
        offset=10,
    )
    assert args == {
        "scope": "agent",
        "owner_agent_id": _AGENT,
        "key_prefix": "cfg/",
        "pii_classification": "personal",
        "created_after": "2026-01-01T00:00:00.000Z",
        "created_before": "2026-04-01T00:00:00.000Z",
        "limit": 50,
        "offset": 10,
    }


def test_build_query_args_clamps_limit_to_1000() -> None:
    args = build_query_args(limit=5000)
    assert args["limit"] == 1000


def test_build_query_args_rejects_negative_limit() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        build_query_args(limit=-1)


def test_build_query_args_rejects_negative_offset() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        build_query_args(offset=-5)


def test_build_snapshot_args_requires_as_of() -> None:
    with pytest.raises(ValueError, match="as_of"):
        build_snapshot_args("")
    with pytest.raises(ValueError, match="as_of"):
        build_snapshot_args("2026-03-24T14:00:00Z")
    with pytest.raises(TypeError):
        build_snapshot_args()  # type: ignore[call-arg]


def test_build_snapshot_args_happy_path() -> None:
    args = build_snapshot_args("2026-03-24T14:00:00.000Z")
    assert args == {"as_of": "2026-03-24T14:00:00.000Z"}


def test_build_snapshot_args_with_filter() -> None:
    args = build_snapshot_args(
        "2026-03-24T14:00:00.000Z",
        filter={"scope": "agent", "key_prefix": "cfg/"},
    )
    assert args == {
        "as_of": "2026-03-24T14:00:00.000Z",
        "filter": {"scope": "agent", "key_prefix": "cfg/"},
    }


_PURGE_KEY = f"{_AGENT}/agent/personal-data"


def test_build_purge_args_requires_key() -> None:
    with pytest.raises(ValueError, match="key"):
        build_purge_args("", "GDPR Art. 17 request")
    with pytest.raises(ValueError, match="key"):
        build_purge_args("   ", "GDPR Art. 17 request")


def test_build_purge_args_requires_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        build_purge_args(_PURGE_KEY, "")
    with pytest.raises(ValueError, match="reason"):
        build_purge_args(_PURGE_KEY, "   ")


def test_build_purge_args_shape_is_key_plus_reason() -> None:
    args = build_purge_args(_PURGE_KEY, "GDPR Art. 17 request")
    assert args == {
        "key": _PURGE_KEY,
        "reason": "GDPR Art. 17 request",
    }
    # §3.2.2 — the request MUST NOT carry the value being erased.
    assert "value" not in args
    # The per-entry PURGE model has no subject_agent_id.
    assert "subject_agent_id" not in args


def test_build_purge_result_shape_matches_spec() -> None:
    result = build_purge_result(_PURGE_KEY, "2026-03-24T15:00:00.000Z")
    assert result == {
        "purged": True,
        "key": _PURGE_KEY,
        "purged_at": "2026-03-24T15:00:00.000Z",
    }


def test_build_purge_result_rejects_bad_timestamp() -> None:
    with pytest.raises(ValueError, match="purged_at"):
        build_purge_result(_PURGE_KEY, "2026-03-24T15:00:00Z")
    with pytest.raises(ValueError, match="purged_at"):
        build_purge_result(_PURGE_KEY, "not-a-timestamp")


def test_build_purge_result_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="key"):
        build_purge_result("", "2026-03-24T15:00:00.000Z")


_GRANT_PATTERN = f"{_AGENT}/shared/*"


def test_build_grant_args_required_only() -> None:
    args = build_grant_args(_GRANT_PATTERN, _OTHER_AGENT, "read")
    assert args == {
        "key_pattern": _GRANT_PATTERN,
        "grantee_agent_id": _OTHER_AGENT,
        "access_level": "read",
    }


def test_build_grant_args_with_valid_until() -> None:
    args = build_grant_args(
        _GRANT_PATTERN,
        _OTHER_AGENT,
        "read_write",
        valid_until="2026-06-24T00:00:00.000Z",
    )
    assert args == {
        "key_pattern": _GRANT_PATTERN,
        "grantee_agent_id": _OTHER_AGENT,
        "access_level": "read_write",
        "valid_until": "2026-06-24T00:00:00.000Z",
    }


def test_build_grant_args_rejects_blank_key_pattern() -> None:
    with pytest.raises(ValueError, match="key_pattern"):
        build_grant_args("", _OTHER_AGENT, "read")


def test_build_grant_args_rejects_blank_grantee() -> None:
    with pytest.raises(ValueError, match="grantee_agent_id"):
        build_grant_args(_GRANT_PATTERN, "", "read")


def test_build_grant_args_rejects_unknown_access_level() -> None:
    with pytest.raises(ValueError, match="access_level"):
        build_grant_args(_GRANT_PATTERN, _OTHER_AGENT, "write")  # type: ignore[arg-type]


def test_build_grant_args_rejects_bad_valid_until() -> None:
    with pytest.raises(ValueError, match="valid_until"):
        build_grant_args(
            _GRANT_PATTERN, _OTHER_AGENT, "read", valid_until="2026-06-24"
        )


def test_build_grant_result_generates_uuid_v4() -> None:
    import re as _re
    import uuid as _uuid

    result = build_grant_result(
        _GRANT_PATTERN,
        _OTHER_AGENT,
        "read_write",
        "2026-03-24T15:00:00.000Z",
    )
    assert _re.match(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        result["grant_id"],
    )
    # version=4 sanity check
    assert _uuid.UUID(result["grant_id"]).version == 4
    assert result["key_pattern"] == _GRANT_PATTERN
    assert result["grantee_agent_id"] == _OTHER_AGENT
    assert result["access_level"] == "read_write"
    assert result["valid_until"] is None
    assert result["created_at"] == "2026-03-24T15:00:00.000Z"


def test_build_grant_result_rejects_bad_created_at() -> None:
    with pytest.raises(ValueError, match="created_at"):
        build_grant_result(
            _GRANT_PATTERN, _OTHER_AGENT, "read", "2026-03-24"
        )


def test_build_revoke_args_shape() -> None:
    grant_id = "11111111-2222-4333-8444-555555555555"
    assert build_revoke_args(grant_id) == {"grant_id": grant_id}


def test_build_revoke_args_rejects_blank_grant_id() -> None:
    with pytest.raises(ValueError, match="grant_id"):
        build_revoke_args("")


def test_build_revoke_result_shape_matches_spec() -> None:
    grant_id = "11111111-2222-4333-8444-555555555555"
    assert build_revoke_result(grant_id, "2026-03-24T16:00:00.000Z") == {
        "revoked": True,
        "grant_id": grant_id,
        "revoked_at": "2026-03-24T16:00:00.000Z",
    }


def test_build_revoke_result_rejects_bad_timestamp() -> None:
    with pytest.raises(ValueError, match="revoked_at"):
        build_revoke_result("gid", "2026-03-24T16:00:00Z")


def test_grant_revoke_lifecycle_paired() -> None:
    """GRANT args → GRANT result (grant_id) → REVOKE args → REVOKE result."""
    grant_args = build_grant_args(
        _GRANT_PATTERN,
        _OTHER_AGENT,
        "read_write",
        valid_until="2026-06-24T00:00:00.000Z",
    )
    grant_result = build_grant_result(
        grant_args["key_pattern"],
        grant_args["grantee_agent_id"],
        grant_args["access_level"],
        "2026-03-24T15:00:00.000Z",
        valid_until=grant_args["valid_until"],
    )
    assert grant_result["grant_id"]

    revoke_args = build_revoke_args(grant_result["grant_id"])
    assert revoke_args == {"grant_id": grant_result["grant_id"]}

    revoke_result = build_revoke_result(
        revoke_args["grant_id"], "2026-03-24T16:00:00.000Z"
    )
    assert revoke_result["revoked"] is True
    assert revoke_result["grant_id"] == grant_result["grant_id"]


# ---------------------------------------------------------------------------
# Interaction with the Pydantic model layer
# ---------------------------------------------------------------------------


def test_state_entry_rejects_bad_timestamp_pattern() -> None:
    with pytest.raises(ValidationError):
        StateEntry(
            key=f"{_AGENT}/agent/k",
            value={},
            owner_agent_id=_AGENT,
            scope="agent",
            created_at="2026-04-13 12:00:00",
            updated_at=_TS,
            pii_classification="none",
            version=1,
        )


def test_state_entry_rejects_invalid_owner_agent_id() -> None:
    with pytest.raises(ValidationError):
        StateEntry(
            key=f"{_AGENT}/agent/k",
            value={},
            owner_agent_id="not-an-agent-id",
            scope="agent",
            created_at=_TS,
            updated_at=_TS,
            pii_classification="none",
            version=1,
        )


def test_state_entry_rejects_version_zero() -> None:
    with pytest.raises(ValidationError):
        StateEntry(
            key=f"{_AGENT}/agent/k",
            value={},
            owner_agent_id=_AGENT,
            scope="agent",
            created_at=_TS,
            updated_at=_TS,
            pii_classification="none",
            version=0,
        )


# ---------------------------------------------------------------------------
# §2.1.7 is_entry_expired
# ---------------------------------------------------------------------------


def test_is_entry_expired_returns_false_when_expires_at_missing() -> None:
    entry = {"created_at": _TS}
    assert is_entry_expired(entry) is False


def test_is_entry_expired_returns_false_when_expires_at_is_future() -> None:
    entry = {"expires_at": "2099-01-01T00:00:00.000Z"}
    now = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
    assert is_entry_expired(entry, now=now) is False


def test_is_entry_expired_returns_true_when_expires_at_in_past() -> None:
    entry = {"expires_at": "2020-01-01T00:00:00.000Z"}
    now = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
    assert is_entry_expired(entry, now=now) is True


def test_is_entry_expired_uses_default_now() -> None:
    # expires_at far in the past -> must be expired regardless of injected now.
    entry = {"expires_at": "2000-01-01T00:00:00.000Z"}
    assert is_entry_expired(entry) is True


# ---------------------------------------------------------------------------
# §4.1.1 is_within_retention
# ---------------------------------------------------------------------------


def test_is_within_retention_true_when_entry_retention_active() -> None:
    entry = {"created_at": _TS, "retention_days": 30}
    now = datetime(2026, 4, 20, 0, 0, 0, tzinfo=timezone.utc)
    assert is_within_retention(entry, now=now) is True


def test_is_within_retention_false_after_retention_elapsed() -> None:
    entry = {"created_at": _TS, "retention_days": 1}
    now = datetime(2026, 4, 20, 0, 0, 0, tzinfo=timezone.utc)
    assert is_within_retention(entry, now=now) is False


def test_is_within_retention_false_when_no_retention_applies() -> None:
    # No entry retention, no profile -> nothing to protect.
    entry = {"created_at": _TS}
    assert is_within_retention(entry) is False


def test_is_within_retention_profile_floor_applies() -> None:
    # Profile floor is 180 days (EU-AI-ACT-HIGH-RISK) — 60 days after
    # creation the entry is still within retention even without an
    # entry-level override.
    entry = {"created_at": _TS}
    profile = {"name": "EU-AI-ACT-HIGH-RISK"}
    now = datetime(2026, 6, 12, 12, 0, 0, tzinfo=timezone.utc)
    assert is_within_retention(entry, profile, now=now) is True


def test_is_within_retention_uses_injected_now() -> None:
    entry = {"created_at": _TS, "retention_days": 30}
    # Deterministically test the boundary crossing at created_at + 30d.
    before = datetime(2026, 5, 12, 0, 0, 0, tzinfo=timezone.utc)
    after = datetime(2026, 5, 14, 0, 0, 0, tzinfo=timezone.utc)
    assert is_within_retention(entry, now=before) is True
    assert is_within_retention(entry, now=after) is False


# ---------------------------------------------------------------------------
# §1.1 — Session timeout 24h (req:67ca585e)
# ---------------------------------------------------------------------------


def test_session_timeout_within_24h_passes() -> None:
    """Session entry expiring within 24h is valid."""
    entry = StateEntry(
        key=f"{_AGENT}/session/k1",
        value="x",
        owner_agent_id=_AGENT,
        scope="session",
        created_at="2026-04-13T12:00:00.000Z",
        updated_at="2026-04-13T12:00:00.000Z",
        expires_at="2026-04-14T11:59:59.000Z",
        pii_classification="none",
        version=1,
    )
    errors = validate_state_entry(entry, sender_agent_id=_AGENT)
    assert not any(e.code == "session_timeout_exceeded" for e in errors)


def test_session_timeout_exceeding_24h_rejected() -> None:
    """Session entry expiring beyond 24h is rejected (State §1.1)."""
    entry = StateEntry(
        key=f"{_AGENT}/session/k1",
        value="x",
        owner_agent_id=_AGENT,
        scope="session",
        created_at="2026-04-13T12:00:00.000Z",
        updated_at="2026-04-13T12:00:00.000Z",
        expires_at="2026-04-14T12:00:01.000Z",
        pii_classification="none",
        version=1,
    )
    errors = validate_state_entry(entry, sender_agent_id=_AGENT)
    assert any(e.code == "session_timeout_exceeded" for e in errors)


def test_session_timeout_not_checked_for_agent_scope() -> None:
    """Agent-scoped entries skip the session timeout check."""
    entry = StateEntry(
        key=f"{_AGENT}/agent/k1",
        value="x",
        owner_agent_id=_AGENT,
        scope="agent",
        created_at="2026-04-13T12:00:00.000Z",
        updated_at="2026-04-13T12:00:00.000Z",
        expires_at="2027-04-14T12:00:00.000Z",
        pii_classification="none",
        version=1,
    )
    errors = validate_state_entry(entry, sender_agent_id=_AGENT)
    assert not any(e.code == "session_timeout_exceeded" for e in errors)


def test_session_timeout_no_expires_at_passes() -> None:
    """Session entry without expires_at skips timeout check."""
    entry = StateEntry(
        key=f"{_AGENT}/session/k1",
        value="x",
        owner_agent_id=_AGENT,
        scope="session",
        created_at="2026-04-13T12:00:00.000Z",
        updated_at="2026-04-13T12:00:00.000Z",
        pii_classification="none",
        version=1,
    )
    errors = validate_state_entry(entry, sender_agent_id=_AGENT)
    assert not any(e.code == "session_timeout_exceeded" for e in errors)


# ---------------------------------------------------------------------------
# §2.3 — JSON value validation (req:b5d94a1c, req:fba2c0a2)
# ---------------------------------------------------------------------------


def test_json_value_valid_string() -> None:
    errors = validate_state_entry(_entry(value="hello"))
    assert not any(e.code == "invalid_json_value" for e in errors)


def test_json_value_valid_dict() -> None:
    errors = validate_state_entry(_entry(value={"a": 1}))
    assert not any(e.code == "invalid_json_value" for e in errors)


def test_json_value_valid_list() -> None:
    errors = validate_state_entry(_entry(value=[1, 2, 3]))
    assert not any(e.code == "invalid_json_value" for e in errors)


def test_json_value_valid_number() -> None:
    errors = validate_state_entry(_entry(value=42))
    assert not any(e.code == "invalid_json_value" for e in errors)


def test_json_value_valid_bool() -> None:
    errors = validate_state_entry(_entry(value=True))
    assert not any(e.code == "invalid_json_value" for e in errors)


def test_json_value_valid_null() -> None:
    errors = validate_state_entry(_entry(value=None))
    assert not any(e.code == "invalid_json_value" for e in errors)


def test_json_value_rejects_non_serializable() -> None:
    errors = validate_state_entry(_entry(value=object()))
    assert any(e.code == "invalid_json_value" for e in errors)


def test_json_value_rejects_nan() -> None:
    errors = validate_state_entry(_entry(value=float("nan")))
    assert any(e.code == "invalid_json_value" for e in errors)


def test_json_value_rejects_infinity() -> None:
    errors = validate_state_entry(_entry(value=float("inf")))
    assert any(e.code == "invalid_json_value" for e in errors)


# ---------------------------------------------------------------------------
# §3.2.1 — SNAPSHOT future timestamp (req:3a22d83e, req:4d6cf235)
# ---------------------------------------------------------------------------


def test_snapshot_past_timestamp_accepted() -> None:
    build_snapshot_args("2020-01-01T00:00:00.000Z")


def test_snapshot_future_timestamp_beyond_skew_rejected() -> None:
    from datetime import datetime as dt, timedelta, timezone

    future = dt.now(timezone.utc) + timedelta(seconds=600)
    ts = future.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"
    with pytest.raises(ValueError, match="future"):
        build_snapshot_args(ts)


def test_snapshot_within_skew_tolerance_accepted() -> None:
    from datetime import datetime as dt, timedelta, timezone

    near_future = dt.now(timezone.utc) + timedelta(seconds=200)
    ts = near_future.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"
    result = build_snapshot_args(ts)
    assert result["as_of"] == ts


# ---------------------------------------------------------------------------
# §3.3.1 — GRANT key_pattern prefix (req:2d20224a, req:4013bf5d, req:8c835faf)
# ---------------------------------------------------------------------------


def test_grant_key_pattern_valid_prefix() -> None:
    result = build_grant_args(
        f"{_AGENT}/agent/data.*",
        _OTHER_AGENT,
        "read",
        sender_agent_id=_AGENT,
    )
    assert result["key_pattern"] == f"{_AGENT}/agent/data.*"


def test_grant_key_pattern_rejects_wrong_prefix() -> None:
    with pytest.raises(ValueError, match="MUST NOT"):
        build_grant_args(
            f"{_OTHER_AGENT}/agent/data.*",
            _OTHER_AGENT,
            "read",
            sender_agent_id=_AGENT,
        )


def test_grant_key_pattern_without_sender_skips_check() -> None:
    result = build_grant_args(
        f"{_OTHER_AGENT}/agent/data.*",
        _OTHER_AGENT,
        "read",
    )
    assert result["key_pattern"] == f"{_OTHER_AGENT}/agent/data.*"


def test_grant_key_pattern_exact_match_valid() -> None:
    result = build_grant_args(
        f"{_AGENT}/shared/config",
        _OTHER_AGENT,
        "read_write",
        sender_agent_id=_AGENT,
    )
    assert result["access_level"] == "read_write"


# ---------------------------------------------------------------------------
# §6.2 — EU-AI-ACT response payload (req:c340c087)
# ---------------------------------------------------------------------------


def test_eu_ai_act_response_with_payload_passes() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "arsiaprotocol.state/get",
            "result": {},
            "explanation": {
                "reasoning": "Model assessed input against criteria",
                "confidence": 0.95,
                "inputs_used": ["sensor_data"],
            },
        },
    }
    assert validate_eu_ai_act_response(envelope) == []


def test_eu_ai_act_response_without_payload_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
    }
    errors = validate_eu_ai_act_response(envelope)
    assert len(errors) == 1
    assert errors[0].code == "missing_payload"


def test_eu_ai_act_request_without_payload_passes() -> None:
    envelope = {
        "intent": "request",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
    }
    assert validate_eu_ai_act_response(envelope) == []


def test_non_eu_ai_act_response_without_payload_passes() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "GDPR-STANDARD"},
    }
    assert validate_eu_ai_act_response(envelope) == []


def test_eu_ai_act_response_empty_payload_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {},
    }
    errors = validate_eu_ai_act_response(envelope)
    assert len(errors) == 1


# ---------------------------------------------------------------------------
# §8.4 — Conflict error shape (req:57b3492d)
# ---------------------------------------------------------------------------


def test_build_conflict_error_shape() -> None:
    result = build_conflict_error(current_version=3, expected_version=2)
    assert result == {
        "error_code": "conflict",
        "current_version": 3,
        "expected_version": 2,
    }


def test_build_conflict_error_version_numbers_preserved() -> None:
    result = build_conflict_error(current_version=100, expected_version=99)
    assert result["current_version"] == 100
    assert result["expected_version"] == 99


# ---------------------------------------------------------------------------
# BL-03 — pii_special_categories (State §2.1.11)
# ---------------------------------------------------------------------------


def test_state_entry_sensitive_with_valid_categories() -> None:
    entry = _entry(pii="sensitive", pii_special_categories=["health", "genetic"])
    assert entry.pii_special_categories == ["health", "genetic"]


def test_state_entry_sensitive_without_categories_rejected() -> None:
    with pytest.raises(ValidationError, match="pii_special_categories is required"):
        _entry(pii="sensitive")


def test_state_entry_sensitive_empty_categories_rejected() -> None:
    with pytest.raises(ValidationError, match="pii_special_categories is required"):
        _entry(pii="sensitive", pii_special_categories=[])


def test_state_entry_personal_with_categories_rejected() -> None:
    with pytest.raises(ValidationError, match="MUST NOT be present"):
        _entry(pii="personal", pii_special_categories=["health"])


def test_state_entry_none_with_categories_rejected() -> None:
    with pytest.raises(ValidationError, match="MUST NOT be present"):
        _entry(pii="none", pii_special_categories=["health"])


def test_state_entry_pseudonymised_with_categories_rejected() -> None:
    with pytest.raises(ValidationError, match="MUST NOT be present"):
        _entry(pii="pseudonymised", pii_special_categories=["health"])


def test_state_entry_all_art9_categories_accepted() -> None:
    cats = [
        "health", "biometric", "genetic", "racial_ethnic",
        "political", "religious", "trade_union", "sexual_orientation",
    ]
    entry = _entry(pii="sensitive", pii_special_categories=cats)
    assert len(entry.pii_special_categories) == 8


def test_state_entry_duplicate_categories_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicates"):
        _entry(pii="sensitive", pii_special_categories=["health", "health"])


def test_state_entry_invalid_category_rejected() -> None:
    with pytest.raises(ValidationError):
        _entry(pii="sensitive", pii_special_categories=["invalid_category"])


def test_build_set_args_includes_pii_special_categories() -> None:
    entry = _entry(pii="sensitive", pii_special_categories=["health"])
    args = build_set_args(entry)
    assert args["pii_special_categories"] == ["health"]


def test_build_set_args_omits_pii_special_categories_when_none() -> None:
    entry = _entry(pii="none")
    args = build_set_args(entry)
    assert "pii_special_categories" not in args


# ---------------------------------------------------------------------------
# BL-15 — build_conflict_error updated_at / updated_by (State §8.4)
# ---------------------------------------------------------------------------


def test_build_conflict_error_with_updated_at() -> None:
    result = build_conflict_error(
        current_version=5,
        expected_version=4,
        updated_at="2026-05-01T10:00:00.000Z",
    )
    assert result["updated_at"] == "2026-05-01T10:00:00.000Z"
    assert "updated_by" not in result


def test_build_conflict_error_with_updated_by() -> None:
    result = build_conflict_error(
        current_version=5,
        expected_version=4,
        updated_by="agent:acme.other",
    )
    assert result["updated_by"] == "agent:acme.other"
    assert "updated_at" not in result


def test_build_conflict_error_with_both_fields() -> None:
    result = build_conflict_error(
        current_version=5,
        expected_version=4,
        updated_at="2026-05-01T10:00:00.000Z",
        updated_by="agent:acme.other",
    )
    assert result == {
        "error_code": "conflict",
        "current_version": 5,
        "expected_version": 4,
        "updated_at": "2026-05-01T10:00:00.000Z",
        "updated_by": "agent:acme.other",
    }


def test_build_conflict_error_backward_compat() -> None:
    result = build_conflict_error(current_version=3, expected_version=2)
    assert result == {
        "error_code": "conflict",
        "current_version": 3,
        "expected_version": 2,
    }
    assert "updated_at" not in result
    assert "updated_by" not in result


# ---------------------------------------------------------------------------
# BL-16 — validate_eu_ai_act_response explanation subobject (State §6.2)
# ---------------------------------------------------------------------------


def test_eu_ai_act_missing_explanation_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {"type": "arsiaprotocol.state/get", "result": {}},
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "missing_explanation" for e in errors)


def test_eu_ai_act_explanation_without_reasoning_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {"confidence": 0.5, "inputs_used": ["a"]},
        },
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "missing_reasoning" for e in errors)


def test_eu_ai_act_explanation_without_confidence_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {"reasoning": "ok", "inputs_used": ["a"]},
        },
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "invalid_confidence" for e in errors)


def test_eu_ai_act_explanation_without_inputs_used_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {"reasoning": "ok", "confidence": 0.5},
        },
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "missing_inputs_used" for e in errors)


def test_eu_ai_act_valid_explanation_passes() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {
                "reasoning": "Based on analysis",
                "confidence": 0.85,
                "inputs_used": ["sensor_a", "sensor_b"],
            },
        },
    }
    assert validate_eu_ai_act_response(envelope) == []


def test_eu_ai_act_confidence_out_of_range_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {
                "reasoning": "ok",
                "confidence": 1.5,
                "inputs_used": ["a"],
            },
        },
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "invalid_confidence" for e in errors)


def test_eu_ai_act_confidence_negative_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {
                "reasoning": "ok",
                "confidence": -0.1,
                "inputs_used": ["a"],
            },
        },
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "invalid_confidence" for e in errors)


def test_eu_ai_act_empty_reasoning_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {
                "reasoning": "",
                "confidence": 0.5,
                "inputs_used": ["a"],
            },
        },
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "missing_reasoning" for e in errors)


def test_eu_ai_act_empty_inputs_used_rejected() -> None:
    envelope = {
        "intent": "response",
        "compliance": {"profile": "EU-AI-ACT-HIGH-RISK"},
        "payload": {
            "type": "x",
            "explanation": {
                "reasoning": "ok",
                "confidence": 0.5,
                "inputs_used": [],
            },
        },
    }
    errors = validate_eu_ai_act_response(envelope)
    assert any(e.code == "missing_inputs_used" for e in errors)


# ---------------------------------------------------------------------------
# §8.3 — Data residency inheritance (STATE-§8.3-02/03)
# ---------------------------------------------------------------------------


class TestResolveEntryDataResidency:
    """Tests for resolve_entry_data_residency."""

    def test_args_takes_precedence(self) -> None:
        from arsia_protocol.state.state import resolve_entry_data_residency

        result = resolve_entry_data_residency(
            "EU", {"data_residency": "US"}
        )
        assert result == "EU"

    def test_falls_back_to_envelope(self) -> None:
        from arsia_protocol.state.state import resolve_entry_data_residency

        result = resolve_entry_data_residency(
            None, {"data_residency": "EU"}
        )
        assert result == "EU"

    def test_none_when_neither_set(self) -> None:
        from arsia_protocol.state.state import resolve_entry_data_residency

        assert resolve_entry_data_residency(None, None) is None
        assert resolve_entry_data_residency(None, {}) is None


# ---------------------------------------------------------------------------
# §8.3 — Retention inheritance (STATE-§8.3-04)
# ---------------------------------------------------------------------------


class TestResolveEntryRetention:
    """Tests for resolve_entry_retention."""

    def test_args_takes_precedence(self) -> None:
        from arsia_protocol.state.state import resolve_entry_retention

        result = resolve_entry_retention(
            90, {"retention_days": 30}, None
        )
        assert result == 90

    def test_falls_back_to_envelope(self) -> None:
        from arsia_protocol.state.state import resolve_entry_retention

        result = resolve_entry_retention(
            None, {"retention_days": 60}, None
        )
        assert result == 60

    def test_floored_by_profile(self) -> None:
        from arsia_protocol.state.state import resolve_entry_retention

        result = resolve_entry_retention(
            10, None, "GDPR-STANDARD"
        )
        assert result is not None
        assert result >= 10

    def test_none_when_neither_set(self) -> None:
        from arsia_protocol.state.state import resolve_entry_retention

        assert resolve_entry_retention(None, None, None) is None
        assert resolve_entry_retention(None, {}, None) is None


# ---------------------------------------------------------------------------
# §8.3 — Profile defaults (STATE-§8.3-09)
# ---------------------------------------------------------------------------


class TestApplyComplianceDefaultsForState:
    """Tests for apply_compliance_defaults_for_state."""

    def test_delegates_to_apply_profile(self) -> None:
        from arsia_protocol.state.state import apply_compliance_defaults_for_state

        result = apply_compliance_defaults_for_state(
            {"profile": "GDPR-STANDARD"}, None
        )
        assert isinstance(result, dict)
        assert "retention_days" in result or "profile" in result

    def test_none_compliance_returns_empty(self) -> None:
        from arsia_protocol.state.state import apply_compliance_defaults_for_state

        result = apply_compliance_defaults_for_state(None, None)
        assert result == {}

    def test_profile_name_injected_when_missing(self) -> None:
        from arsia_protocol.state.state import apply_compliance_defaults_for_state

        result = apply_compliance_defaults_for_state({}, "GDPR-STANDARD")
        assert isinstance(result, dict)
        assert result.get("profile") == "GDPR-STANDARD"


# ---------------------------------------------------------------------------
# §2.3 — Executable content rejection (STATE-§2.3-06)
# ---------------------------------------------------------------------------


class TestValidateJsonValueExecutable:
    """Tests for executable content detection in _validate_json_value."""

    def test_rejects_javascript_uri(self) -> None:
        entry = _entry(value="javascript:alert(1)")
        errors = validate_state_entry(entry)
        assert any(e.code == "executable_content_detected" for e in errors)

    def test_rejects_script_tag(self) -> None:
        entry = _entry(value="<script>evil()</script>")
        errors = validate_state_entry(entry)
        assert any(e.code == "executable_content_detected" for e in errors)

    def test_rejects_eval_in_nested_dict(self) -> None:
        entry = _entry(value={"nested": {"deep": "eval(something)"}})
        errors = validate_state_entry(entry)
        assert any(e.code == "executable_content_detected" for e in errors)

    def test_accepts_normal_string_containing_partial_keyword(self) -> None:
        entry = _entry(value="This is a description of scripted events")
        errors = validate_state_entry(entry)
        assert not any(e.code == "executable_content_detected" for e in errors)

    def test_accepts_clean_json(self) -> None:
        entry = _entry(value={"count": 42, "items": ["a", "b"]})
        errors = validate_state_entry(entry)
        assert not any(e.code == "executable_content_detected" for e in errors)


# ---------------------------------------------------------------------------
# §8.1 — Custom payload_type validation (STATE-§8.1-02)
# ---------------------------------------------------------------------------


class TestValidateCustomStatePayloadType:
    """Tests for validate_custom_state_payload_type."""

    def test_rejects_reserved_prefix(self) -> None:
        from arsia_protocol.state.state import validate_custom_state_payload_type

        errors = validate_custom_state_payload_type("arsiaprotocol.state/custom-op")
        assert len(errors) == 1
        assert errors[0].code == "reserved_payload_type_prefix"

    def test_accepts_standard_operations(self) -> None:
        from arsia_protocol.state.state import validate_custom_state_payload_type

        for op_type in [
            "arsiaprotocol.state/get",
            "arsiaprotocol.state/set",
            "arsiaprotocol.state/delete",
            "arsiaprotocol.state/query",
            "arsiaprotocol.state/snapshot",
            "arsiaprotocol.state/purge",
            "arsiaprotocol.state/grant",
            "arsiaprotocol.state/revoke",
        ]:
            errors = validate_custom_state_payload_type(op_type)
            assert errors == [], f"Standard op {op_type} should be accepted"

    def test_accepts_custom_prefix(self) -> None:
        from arsia_protocol.state.state import validate_custom_state_payload_type

        errors = validate_custom_state_payload_type("mycompany.state/custom-op")
        assert errors == []
