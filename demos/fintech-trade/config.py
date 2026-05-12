# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent and demo configuration loaded from environment variables.

Values are resolved in order: environment variable > .env file > caller default.
Place a .env file in the demo root (copy from .env.example) to override defaults
without exporting variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")


@dataclass(frozen=True)
class AgentConfig:
    """Configuration for a single ARSIA agent."""

    agent_id: str
    port: int
    ollama_url: str
    ollama_model: str
    capabilities: list[str]
    kid: str = ""

    def __post_init__(self) -> None:
        if not self.kid:
            object.__setattr__(self, "kid", f"{self.agent_id}#key-1")


@dataclass(frozen=True)
class DemoConfig:
    """Dashboard-level configuration (agent configs are loaded per-process)."""

    dashboard_port: int
    dashboard_agent_a_url: str


def _get(key: str, default: str) -> str:
    return os.environ.get(key, default)


def load_agent_config(prefix: str, defaults: dict[str, str]) -> AgentConfig:
    """Load an AgentConfig from environment variables with the given prefix."""
    return AgentConfig(
        agent_id=_get(f"{prefix}_ID", defaults["id"]),
        port=int(_get(f"{prefix}_PORT", defaults["port"])),
        ollama_url=_get(f"{prefix}_OLLAMA_URL", defaults["ollama_url"]),
        ollama_model=_get(f"{prefix}_OLLAMA_MODEL", defaults["ollama_model"]),
        capabilities=_get(f"{prefix}_CAPABILITIES", defaults["capabilities"]).split(","),
    )


def load_demo_config() -> DemoConfig:
    """Load the demo-wide configuration from environment variables / .env."""
    dashboard_port = int(_get("DASHBOARD_PORT", "3000"))
    dashboard_agent_a_url = _get(
        "DASHBOARD_AGENT_A_URL",
        f"http://localhost:{_get('AGENT_A_PORT', '8001')}",
    )

    return DemoConfig(
        dashboard_port=dashboard_port,
        dashboard_agent_a_url=dashboard_agent_a_url,
    )
