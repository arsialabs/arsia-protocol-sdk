# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.identity``.

Spec: ARSIA-Core.md §3.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from arsia_protocol.types.errors import ValidationError
from arsia_protocol.types.identity import IdentityRecord
from arsia_protocol.identity.agent_id import (
    AGENT_ID_PATTERN,
    AgentId,
    is_identity_record_expired,
    is_valid_agent_id,
    parse_agent_id,
    validate_agent_id,
)


def test_parse_valid_two_segments() -> None:
    """Two-segment ID parses with empty sub tuple.

    Spec: ARSIA-Core.md §3.3.
    """
    aid = parse_agent_id("agent:acme.billing")
    assert aid.org == "acme"
    assert aid.name == "billing"
    assert aid.sub == ()
    assert aid.resource is None
    assert aid.full == "agent:acme.billing"


def test_parse_valid_three_segments() -> None:
    """Three-segment ID populates ``sub`` with the third segment.

    Spec: ARSIA-Core.md §3.3.
    """
    aid = parse_agent_id("agent:arsialabs.demo.risk-assessor")
    assert aid.org == "arsialabs"
    assert aid.name == "demo"
    assert aid.sub == ("risk-assessor",)


def test_parse_valid_four_segments() -> None:
    """Four or more segments populate ``sub`` with everything beyond ``name``.

    Spec: ARSIA-Core.md §3.3.
    """
    aid = parse_agent_id("agent:europa.mifid.compliance.checker")
    assert aid.sub == ("compliance", "checker")


def test_parse_valid_resource() -> None:
    """Resource segment is captured after '/'.

    Spec: ARSIA-Core.md §3.3 Rule 7.
    """
    aid = parse_agent_id("agent:contoso.crm/notifications")
    assert aid.org == "contoso"
    assert aid.name == "crm"
    assert aid.resource == "notifications"


def test_parse_valid_resource_with_underscore() -> None:
    """Resource segment may contain underscores.

    Spec: ARSIA-Core.md §3.3 Rule 6.
    """
    aid = parse_agent_id("agent:acme.billing/my_resource")
    assert aid.resource == "my_resource"


def test_parse_valid_resource_with_hyphen() -> None:
    """Resource segment may contain hyphens.

    Spec: ARSIA-Core.md §3.3 Rule 6.
    """
    aid = parse_agent_id("agent:acme.billing/my-resource")
    assert aid.resource == "my-resource"


def test_parse_valid_max_length() -> None:
    """Exactly-256-character IDs are accepted.

    Spec: ARSIA-Core.md §3.3 Rule 1.
    """
    # "agent:" (6) + "a" (1) + "." (1) + 248 chars = 256 total.
    ident = "agent:a." + ("b" * 248)
    assert len(ident) == 256
    aid = parse_agent_id(ident)
    assert aid.full == ident


def test_parse_missing_prefix() -> None:
    """IDs without the ``agent:`` prefix are rejected.

    Spec: ARSIA-Core.md §3.3 Rule 5.
    """
    with pytest.raises(ValueError, match="must start with 'agent:'"):
        parse_agent_id("acme.billing")


def test_parse_wrong_prefix() -> None:
    """IDs using a non-``agent:`` scheme are rejected.

    Spec: ARSIA-Core.md §3.3 Rule 5.
    """
    with pytest.raises(ValueError, match="must start with 'agent:'"):
        parse_agent_id("user:acme.billing")


def test_parse_single_segment_rejected() -> None:
    """IDs with only an org segment (no sub-segment) are rejected.

    Spec: ARSIA-Core.md §3.1 ABNF.
    """
    with pytest.raises(ValueError, match="at least an org segment"):
        parse_agent_id("agent:acme")


def test_parse_hyphen_start_org() -> None:
    """Org segment beginning with a hyphen is rejected.

    Spec: ARSIA-Core.md §3.3 Rule 7.
    """
    with pytest.raises(ValueError, match="must not start or end with a hyphen"):
        parse_agent_id("agent:-acme.billing")


def test_parse_hyphen_end_org() -> None:
    """Org segment ending with a hyphen is rejected.

    Spec: ARSIA-Core.md §3.3 Rule 7.
    """
    with pytest.raises(ValueError, match="must not start or end with a hyphen"):
        parse_agent_id("agent:acme-.billing")


def test_parse_hyphen_start_name() -> None:
    """Sub-segment beginning with a hyphen is rejected.

    Spec: ARSIA-Core.md §3.3 Rule 7.
    """
    with pytest.raises(ValueError, match="must not start or end with a hyphen"):
        parse_agent_id("agent:acme.-billing")


def test_parse_hyphen_end_name() -> None:
    """Sub-segment ending with a hyphen is rejected.

    Spec: ARSIA-Core.md §3.3 Rule 7.
    """
    with pytest.raises(ValueError, match="must not start or end with a hyphen"):
        parse_agent_id("agent:acme.billing-")


def test_parse_empty_resource() -> None:
    """Trailing slash with no resource is rejected.

    Spec: ARSIA-Core.md §3.3 Rule 7.
    """
    with pytest.raises(ValueError, match="resource segment must not be empty"):
        parse_agent_id("agent:acme.billing/")


def test_parse_too_long() -> None:
    """IDs longer than 256 characters are rejected.

    Spec: ARSIA-Core.md §3.3 Rule 1.
    """
    ident = "agent:a." + ("b" * 249)
    assert len(ident) == 257
    with pytest.raises(ValueError, match="exceeds maximum length"):
        parse_agent_id(ident)


def test_parse_unicode_rejected() -> None:
    """Non-ASCII characters in identifiers are rejected.

    Spec: ARSIA-Core.md §3.3 Rule 6.
    """
    with pytest.raises(ValueError):
        parse_agent_id("agent:acme.bïlling")


def test_parse_whitespace_rejected() -> None:
    """Whitespace inside identifiers is rejected.

    Spec: ARSIA-Core.md §3.3 Rule 6.
    """
    with pytest.raises(ValueError):
        parse_agent_id("agent:acme. billing")


def test_parse_empty_string() -> None:
    """Empty string is rejected.

    Spec: ARSIA-Core.md §3.3.
    """
    with pytest.raises(ValueError, match="must not be empty"):
        parse_agent_id("")


def test_validate_returns_list() -> None:
    """``validate_agent_id`` returns a list of error strings.

    Spec: ARSIA-Core.md §3.3.
    """
    errors = validate_agent_id("bad id")
    assert isinstance(errors, list)
    assert len(errors) >= 1
    assert all(isinstance(e, ValidationError) for e in errors)


def test_validate_valid_returns_empty() -> None:
    """Valid IDs produce an empty error list.

    Spec: ARSIA-Core.md §3.3.
    """
    assert validate_agent_id("agent:acme.billing") == []


def test_is_valid_true() -> None:
    """``is_valid_agent_id`` returns True for valid IDs.

    Spec: ARSIA-Core.md §3.3.
    """
    assert is_valid_agent_id("agent:acme.billing") is True
    assert is_valid_agent_id("agent:arsialabs.demo.risk-assessor") is True
    assert is_valid_agent_id("agent:contoso.crm/notifications") is True


def test_is_valid_false() -> None:
    """``is_valid_agent_id`` returns False for invalid IDs.

    Spec: ARSIA-Core.md §3.3.
    """
    assert is_valid_agent_id("acme.billing") is False
    assert is_valid_agent_id("agent:acme") is False
    assert is_valid_agent_id("agent:-acme.billing") is False
    assert is_valid_agent_id("agent:acme.billing/") is False


def test_case_sensitive_comparison() -> None:
    """Agent identifiers are case-sensitive.

    Spec: ARSIA-Core.md §3.3 Rule 4.
    """
    a = parse_agent_id("agent:acme.billing")
    b = parse_agent_id("agent:Acme.Billing")
    assert a != b
    assert a.full != b.full


def test_agent_id_hashable() -> None:
    """``AgentId`` instances are usable as dict keys.

    Spec: ARSIA-Core.md §3.3.
    """
    a = parse_agent_id("agent:acme.billing")
    b = parse_agent_id("agent:acme.billing")
    mapping: dict[AgentId, int] = {a: 1}
    assert mapping[b] == 1
    assert hash(a) == hash(b)


def test_agent_id_str() -> None:
    """``str(agent_id)`` returns the ``full`` field.

    Spec: ARSIA-Core.md §3.3.
    """
    aid = parse_agent_id("agent:acme.billing/invoices")
    assert str(aid) == "agent:acme.billing/invoices"


def test_regex_pattern_matches_spec_examples() -> None:
    """The compiled regex accepts all ABNF examples from §3.2.

    Spec: ARSIA-Core.md §3.2.
    """
    examples = [
        "agent:acme.billing",
        "agent:contoso.crm/notifications",
        "agent:arsialabs.demo.risk-assessor",
        "agent:europa.mifid.compliance-checker",
    ]
    for ex in examples:
        assert AGENT_ID_PATTERN.match(ex) is not None, ex


# ----------------------------------------------------------------------
# is_identity_record_expired
# ----------------------------------------------------------------------


def test_identity_record_expired_when_now_is_after_valid_until() -> None:
    """Returns True when reference instant is past valid_until.

    Spec: ARSIA-Identity.md §1.2 (valid_until).
    """
    record = {"valid_until": "2026-01-01T00:00:00.000Z"}
    now = datetime(2026, 6, 1, tzinfo=UTC)
    assert is_identity_record_expired(record, now=now) is True


def test_identity_record_not_expired_when_now_is_before_valid_until() -> None:
    """Returns False when reference instant is earlier than valid_until.

    Spec: ARSIA-Identity.md §1.2 (valid_until).
    """
    record = {"valid_until": "2027-01-01T00:00:00.000Z"}
    now = datetime(2026, 6, 1, tzinfo=UTC)
    assert is_identity_record_expired(record, now=now) is False


def test_identity_record_not_expired_when_valid_until_absent() -> None:
    """Records without valid_until are never considered expired.

    Spec: ARSIA-Identity.md §1.2 (valid_until is OPTIONAL).
    """
    assert is_identity_record_expired({"agent_id": "agent:arsia.demo"}) is False


def test_identity_record_not_expired_when_valid_until_is_none() -> None:
    """Explicit None for valid_until is treated as absent.

    Spec: ARSIA-Identity.md §1.2.
    """
    assert is_identity_record_expired({"valid_until": None}) is False


def test_identity_record_expired_uses_default_now_when_omitted() -> None:
    """When ``now`` is not provided, the helper uses the current UTC time.

    Spec: ARSIA-Identity.md §1.2.
    """
    # A clearly past timestamp must be expired against current wall clock.
    record = {"valid_until": "1990-01-01T00:00:00.000Z"}
    assert is_identity_record_expired(record) is True


def test_identity_record_expired_rejects_non_string_valid_until() -> None:
    """Numeric or other non-string types raise ValueError.

    Spec: ARSIA-Identity.md §1.2 (RFC 3339 string format).
    """
    with pytest.raises(ValueError):
        is_identity_record_expired({"valid_until": 1234567890})


# ----------------------------------------------------------------------
# IdentityRecord: deployer_name required when deployer_id set
# ----------------------------------------------------------------------

_IDENTITY_RECORD_BASE = {
    "agent_id": "agent:acme.billing",
    "owner_id": "DE123456789",
    "owner_name": "Acme GmbH",
    "jurisdiction": "DE",
    "ai_system_classification": "limited-risk",
    "created_at": "2026-01-01T00:00:00.000Z",
}


def test_identity_record_valid_without_deployer() -> None:
    """IdentityRecord valid when both deployer_id and deployer_name are None.

    Spec: ARSIA-Identity.md §1.2 (deployer fields optional).
    """
    record = IdentityRecord(**_IDENTITY_RECORD_BASE)
    assert record.deployer_id is None
    assert record.deployer_name is None


def test_identity_record_valid_with_deployer_id_and_name() -> None:
    """IdentityRecord valid when deployer_id is set with deployer_name.

    Spec: ARSIA-Identity.md §1.2 (req:449f26cd).
    """
    record = IdentityRecord(
        **_IDENTITY_RECORD_BASE,
        deployer_id="FR987654321",
        deployer_name="Acme France SAS",
    )
    assert record.deployer_id == "FR987654321"
    assert record.deployer_name == "Acme France SAS"


def test_identity_record_rejects_deployer_id_without_name() -> None:
    """IdentityRecord rejects deployer_id set without deployer_name.

    Spec: ARSIA-Identity.md §1.2 (req:449f26cd).
    """
    with pytest.raises(ValueError, match="deployer_name is required"):
        IdentityRecord(**_IDENTITY_RECORD_BASE, deployer_id="FR987654321")
