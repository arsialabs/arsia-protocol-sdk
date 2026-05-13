# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Key management: generate, store, and exchange Ed25519 keys between agents."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from arsia_protocol import build_jwk, build_jwks, generate_ed25519_keypair

logger = logging.getLogger(__name__)


class KeyStore:
    """Per-agent key store. Holds own keypair and peer public keys.

    Thread-safe via asyncio — all mutation happens in coroutines
    which run on the event loop (single-threaded by design).
    """

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self._private_key: Ed25519PrivateKey | None = None
        self._public_key: Ed25519PublicKey | None = None
        self._kid: str = f"{agent_id}#key-1"
        self._jwk: dict[str, str] = {}
        self._peer_public_keys: dict[str, Ed25519PublicKey] = {}
        self._peer_jwks: dict[str, dict[str, str]] = {}

    def generate(self) -> None:
        """Generate a fresh Ed25519 keypair for this agent."""
        self._private_key, self._public_key = generate_ed25519_keypair()
        self._jwk = build_jwk(self._public_key, self._kid)
        logger.info("Generated Ed25519 keypair for %s (kid=%s)", self.agent_id, self._kid)

    @property
    def private_key(self) -> Ed25519PrivateKey:
        if self._private_key is None:
            raise RuntimeError("Key not generated yet — call generate() first")
        return self._private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        if self._public_key is None:
            raise RuntimeError("Key not generated yet — call generate() first")
        return self._public_key

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def jwk(self) -> dict[str, str]:
        if not self._jwk:
            raise RuntimeError("Key not generated yet — call generate() first")
        return self._jwk

    @property
    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return build_jwks([self._jwk]) if self._jwk else build_jwks([])

    def register_peer(self, agent_id: str, public_key: Ed25519PublicKey, jwk: dict[str, str]) -> None:
        """Register a peer's public key for signature verification."""
        self._peer_public_keys[agent_id] = public_key
        self._peer_jwks[agent_id] = jwk
        logger.info("Registered peer key: %s (kid=%s)", agent_id, jwk.get("kid", "?"))

    def get_peer_public_key(self, agent_id: str) -> Ed25519PublicKey | None:
        return self._peer_public_keys.get(agent_id)

    def get_peer_jwk(self, agent_id: str) -> dict[str, str] | None:
        return self._peer_jwks.get(agent_id)

    def has_peer(self, agent_id: str) -> bool:
        return agent_id in self._peer_public_keys


def _decode_jwk_public_key(jwk: dict[str, str]) -> Ed25519PublicKey:
    """Decode an Ed25519 public key from a JWK dict."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as Ed25519Pub

    x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
    return Ed25519Pub.from_public_bytes(x_bytes)


async def fetch_peer_jwks(
    peer_url: str,
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Fetch a peer agent's JWKS from their /keys endpoint."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(f"{peer_url}/keys")
        resp.raise_for_status()
        return resp.json()


async def exchange_keys(
    key_store: KeyStore,
    peer_urls: dict[str, str],
    *,
    max_retries: int = 30,
    retry_delay: float = 2.0,
) -> None:
    """Exchange public keys with all peer agents at startup.

    Retries until all peers respond (agents may start at different times).
    """
    remaining = dict(peer_urls)

    for attempt in range(max_retries):
        if not remaining:
            break

        still_waiting: dict[str, str] = {}
        for agent_id, url in remaining.items():
            if agent_id == key_store.agent_id:
                continue
            try:
                jwks_data = await fetch_peer_jwks(url)
                keys = jwks_data.get("keys", [])
                if keys:
                    jwk = keys[0]
                    pub = _decode_jwk_public_key(jwk)
                    key_store.register_peer(agent_id, pub, jwk)
                else:
                    still_waiting[agent_id] = url
            except (httpx.HTTPError, Exception) as exc:
                logger.debug(
                    "Key exchange attempt %d: %s not ready (%s)",
                    attempt + 1, agent_id, exc,
                )
                still_waiting[agent_id] = url

        remaining = still_waiting
        if remaining:
            await asyncio.sleep(retry_delay)

    if remaining:
        logger.warning("Key exchange incomplete — missing peers: %s", list(remaining.keys()))
    else:
        logger.info("Key exchange complete — all peers registered")
