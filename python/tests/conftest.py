# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Global pytest fixtures for the ARSIA Protocol SDK test suite."""

from __future__ import annotations

import json
from typing import Any

import pytest

from arsia_protocol._data_resolver import test_vectors_dir
from arsia_protocol.hazmat.primitives.ed25519 import (
    private_key_from_hex,
    public_key_from_hex,
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "spec(rtm_id): links test to an RTM requirement ID (e.g., CORE-§3.3-01)",
    )


@pytest.fixture(scope="session")
def keypairs() -> dict[str, dict[str, Any]]:
    """Load the Ed25519 test keypairs from ``shared/test-vectors/keypairs.json``.

    Returns a dict with the file's keys: the agent identifier, or the full
    ``kid`` when an agent publishes more than one key. Entries that are not
    Ed25519 (the ES256 and RS256 keys) are skipped. Each entry contains:

    - ``private_key``: ``Ed25519PrivateKey``
    - ``public_key``: ``Ed25519PublicKey``
    - ``kid``: str (key identifier from the JSON file)

    These keypairs are test-only and MUST NOT be used for anything else.
    """
    path = test_vectors_dir() / "keypairs.json"
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)

    loaded: dict[str, dict[str, Any]] = {}
    for agent_id, entry in raw["keypairs"].items():
        pub_bytes = bytes.fromhex(entry["public_key_hex"])
        if len(pub_bytes) != 32:
            continue
        loaded[agent_id] = {
            "private_key": private_key_from_hex(entry["private_key_hex"]),
            "public_key": public_key_from_hex(entry["public_key_hex"]),
            "kid": entry["kid"],
        }
    return loaded


@pytest.fixture()
def keypair_acme(keypairs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Keypair for ``agent:acme.echo-client``."""
    return keypairs["agent:acme.echo-client"]


@pytest.fixture()
def keypair_risk_assessor(
    keypairs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Keypair for ``agent:arsialabs.demo.risk-assessor``."""
    return keypairs["agent:arsialabs.demo.risk-assessor"]


@pytest.fixture()
def keypair_compliance_checker(
    keypairs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Keypair for ``agent:arsialabs.demo.compliance-checker``."""
    return keypairs["agent:arsialabs.demo.compliance-checker"]
