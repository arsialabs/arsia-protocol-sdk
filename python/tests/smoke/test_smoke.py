# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Minimal end-to-end smoke tests for the ARSIA Protocol SDK.

Each test is self-contained and uses only the public API
(``import from arsia_protocol``). No network, no filesystem beyond
pytest fixtures. Runs in under 5 seconds.
"""

from __future__ import annotations

from typing import Any

import arsia_protocol
from arsia_protocol import (
    IdentityRecord,
    build_discovery_document,
    create_request,
    format_timestamp,
    get_profile,
    get_profile_names,
    parse_version,
    sign_message,
    validate_envelope,
    verify_message,
)


SENDER = "agent:acme.echo-client"
RECEIVER = "agent:arsialabs.demo.risk-assessor"


def test_import_package() -> None:
    assert isinstance(arsia_protocol.__version__, str)
    assert len(arsia_protocol.__version__) > 0


def test_create_envelope(keypair_acme: dict[str, Any]) -> None:
    env = create_request(
        from_agent=SENDER,
        to_agent=RECEIVER,
        payload_type="arsia.echo.request",
        capabilities=["echo"],
    )
    for key in ("v", "id", "from", "to", "intent", "ts", "payload"):
        assert key in env, f"missing top-level key: {key}"


def test_sign_and_verify_roundtrip(keypair_acme: dict[str, Any]) -> None:
    env = create_request(
        from_agent=SENDER,
        to_agent=RECEIVER,
        payload_type="arsia.echo.request",
        capabilities=["echo"],
    )
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    assert "security" in signed
    assert verify_message(signed, keypair_acme["public_key"]) is True


def test_validate_valid_envelope(keypair_acme: dict[str, Any]) -> None:
    env = create_request(
        from_agent=SENDER,
        to_agent=RECEIVER,
        payload_type="arsia.echo.request",
        capabilities=["arsia.echo.invoke"],
    )
    signed = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    errors = validate_envelope(signed)
    assert errors == [], f"unexpected validation errors: {errors}"


def test_validate_invalid_envelope() -> None:
    errors = validate_envelope({})
    assert len(errors) > 0


def test_canonicalize_deterministic(keypair_acme: dict[str, Any]) -> None:
    env = create_request(
        from_agent=SENDER,
        to_agent=RECEIVER,
        payload_type="arsia.echo.request",
        capabilities=["echo"],
    )
    sig_a = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    sig_b = sign_message(env, keypair_acme["private_key"], keypair_acme["kid"])
    assert sig_a["security"]["sig"] == sig_b["security"]["sig"]


def test_compliance_profile_loads() -> None:
    names = get_profile_names()
    assert len(names) > 0
    profile = get_profile(names[0])
    assert isinstance(profile, dict)
    assert len(profile) > 0


def test_build_discovery_document() -> None:
    doc = build_discovery_document(
        agent_id=SENDER,
        name="Echo Client",
        version="1.0.0",
        inbox="https://example.com/inbox",
        jwks="https://example.com/.well-known/jwks.json",
        capabilities_supported=["echo"],
    )
    assert doc["agent_id"] == SENDER
    assert "protocol_version" in doc
    assert "capabilities_supported" in doc


def test_identity_record_construction() -> None:
    from datetime import datetime, timezone

    record = IdentityRecord(
        agent_id=SENDER,
        owner_id="org:acme-corp",
        owner_name="Acme Corporation",
        jurisdiction="US",
        ai_system_classification="minimal-risk",
        created_at=format_timestamp(datetime.now(timezone.utc)),
    )
    assert record.agent_id == SENDER
    assert record.owner_name == "Acme Corporation"
    assert record.ai_system_classification == "minimal-risk"


def test_version_parse() -> None:
    major, minor = parse_version("1.0")
    assert major == 1
    assert minor == 0
