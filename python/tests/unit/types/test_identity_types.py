# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.identity``.

Spec: ARSIA-Identity.md §1.2 and ARSIA-Core.md §7.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arsia_protocol.types.identity import (
    ArsiaCapabilityDescriptor,
    ArsiaDiscoveryDocument,
    ArsiaJWK,
    ArsiaJWKS,
    IdentityRecord,
)


def test_identity_record_minimal_valid() -> None:
    """Minimal IdentityRecord from the schema example constructs successfully.

    Spec: ARSIA-Identity.md §1.2, schema examples[0].
    """
    rec = IdentityRecord(
        agent_id="agent:acme.billing",
        owner_id="PT501234567",
        owner_name="Acme Corp",
        jurisdiction="PT",
        ai_system_classification="minimal-risk",
        created_at="2026-03-24T10:00:00.000Z",
    )
    assert rec.agent_id == "agent:acme.billing"


def test_identity_record_full_example_with_deployer() -> None:
    """The second schema example (with deployer) constructs successfully.

    Spec: ARSIA-Identity.md §1.2, schema examples[1].
    """
    rec = IdentityRecord(
        agent_id="agent:arsialabs.demo.risk-assessor",
        owner_id="PT509876543",
        owner_name="Arsia Labs",
        jurisdiction="PT",
        ai_system_classification="high-risk",
        deployer_id="DE812345678",
        deployer_name="Frankfurt Financial Services GmbH",
        created_at="2026-03-24T10:00:00.000Z",
        valid_until="2026-06-22T10:00:00.000Z",
        contact_email="ops@arsialabs.example",
    )
    assert rec.deployer_name == "Frankfurt Financial Services GmbH"


def test_identity_record_rejects_invalid_agent_id() -> None:
    """Agent IDs failing §3.3 are rejected.

    Spec: ARSIA-Core.md §3.3.
    """
    with pytest.raises(ValidationError):
        IdentityRecord(
            agent_id="not-an-agent-id",
            owner_id="PT501234567",
            owner_name="X",
            jurisdiction="PT",
            ai_system_classification="minimal-risk",
            created_at="2026-03-24T10:00:00.000Z",
        )


def test_identity_record_rejects_bad_jurisdiction() -> None:
    """Jurisdiction must be a two-letter uppercase code.

    Spec: ARSIA-Identity.md §1.2.
    """
    with pytest.raises(ValidationError):
        IdentityRecord(
            agent_id="agent:acme.billing",
            owner_id="PT501234567",
            owner_name="Acme",
            jurisdiction="pt",
            ai_system_classification="minimal-risk",
            created_at="2026-03-24T10:00:00.000Z",
        )


def test_jwk_ed25519_valid() -> None:
    """An Ed25519 JWK entry constructs with the expected fields.

    Spec: ARSIA-Core.md §7.3.
    """
    jwk = ArsiaJWK(
        kty="OKP",
        crv="Ed25519",
        kid="agent:acme.billing#key1",
        x="11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        use="sig",
    )
    assert jwk.kty == "OKP"
    assert jwk.crv == "Ed25519"


def test_jwks_wraps_list_of_keys() -> None:
    """JWKS contains a list of JWK entries under ``keys``.

    Spec: ARSIA-Core.md §7.3.
    """
    jwks = ArsiaJWKS(
        keys=[
            ArsiaJWK(kty="OKP", crv="Ed25519", kid="a#1", x="X", use="sig"),
            ArsiaJWK(kty="OKP", crv="Ed25519", kid="a#2", x="Y", use="sig"),
        ]
    )
    assert len(jwks.keys) == 2


def test_capability_descriptor_valid() -> None:
    """Capability descriptor with required fields constructs successfully.

    Spec: ARSIA-Core.md §7.2.
    """
    cap = ArsiaCapabilityDescriptor(
        capability="com.acme.billing.create-invoice",
        description="Create a new invoice.",
        risk_level=6,
        human_oversight_required=False,
    )
    assert cap.risk_level == 6


def test_capability_descriptor_risk_level_bounds() -> None:
    """Risk level must be between 0 and 10.

    Spec: ARSIA-Core.md §7.2.
    """
    with pytest.raises(ValidationError):
        ArsiaCapabilityDescriptor(
            capability="x",
            description="y",
            risk_level=11,
            human_oversight_required=False,
        )


def test_discovery_document_minimal_required_fields() -> None:
    """Discovery document with all required fields constructs successfully.

    Spec: ARSIA-Core.md §7.1.
    """
    doc = ArsiaDiscoveryDocument(
        agent_id="agent:acme.billing",
        name="Acme Billing Service",
        version="2.1.0",
        protocol_version="1.0",
        inbox="https://billing.acme.example/v1/arsia/inbox",
        jwks="https://billing.acme.example/.well-known/arsia/jwks.json",
        capabilities_supported=["com.acme.billing.create-invoice"],
        max_message_bytes=1048576,
        request_timeout_ms=30000,
        server_min="1.0",
        server_max="1.0",
    )
    assert doc.protocol_version == "1.0"
    assert doc.max_message_bytes == 1048576


def test_discovery_document_rejects_bad_protocol_version() -> None:
    """Only ``'1.0'`` is accepted as ``protocol_version``.

    Spec: ARSIA-Core.md §7.1.
    """
    with pytest.raises(ValidationError):
        ArsiaDiscoveryDocument(
            agent_id="agent:acme.billing",
            name="Acme",
            version="2.1.0",
            protocol_version="2.0",  # type: ignore[arg-type]
            inbox="https://x",
            jwks="https://y",
            capabilities_supported=["a.b"],
            max_message_bytes=1,
            request_timeout_ms=1,
            server_min="1.0",
            server_max="1.0",
        )
