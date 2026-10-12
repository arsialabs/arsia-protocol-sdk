# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent and demo configuration loaded from environment variables.

Values are resolved in order: environment variable > .env file > caller default.
Place a .env file in the demo root (copy from .env.example) to override defaults
without exporting variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")


@dataclass(frozen=True)
class AgentConfig:
    """Configuration for a single ARSIA agent."""

    agent_id: str
    port: int
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


# ── LLM selection ─────────────────────────────────────────
# One LLM for the whole demo: the host's Ollama, a provider with the user's
# own API key, or none (deterministic fallback responses).

LLM_MODES = ("ollama", "openai", "anthropic", "gemini", "none")
DEFAULT_LLM_MODE = "ollama"

DEFAULT_MODELS = {
    "ollama": "gemma4:e2b",
    "openai": "gpt-4.1-nano",
    "anthropic": "claude-haiku-5-5",
    "gemini": "gemini-3.5-flash-lite",
}

PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
}

API_KEY_VARS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


class LLMConfigError(ValueError):
    """The LLM settings are incomplete or invalid. The message never holds a value."""


@dataclass(frozen=True)
class LLMSettings:
    """The demo's LLM: mode, model, base URL and (for providers) the API key."""

    mode: str
    model: str
    base_url: str
    base_url_overridden: bool = False
    api_key: str = field(default="", repr=False)


def load_llm_settings() -> LLMSettings:
    """Load the LLM settings from environment variables / .env.

    DEMO_LLM selects the mode (default: ollama). A provider mode needs its API
    key variable. DEMO_LLM_MODEL overrides the default model, DEMO_OLLAMA_URL
    the host Ollama's URL, and DEMO_LLM_BASE_URL a provider's base URL (for
    testing only).

    Raises:
        LLMConfigError: unknown mode, or a provider mode without its key.
    """
    mode = (_get("DEMO_LLM", "") or DEFAULT_LLM_MODE).strip().lower()
    if mode not in LLM_MODES:
        raise LLMConfigError(f"DEMO_LLM must be one of: {', '.join(LLM_MODES)}")
    if mode == "none":
        return LLMSettings(mode=mode, model="", base_url="")

    model = _get("DEMO_LLM_MODEL", "").strip() or DEFAULT_MODELS[mode]
    if mode == "ollama":
        base_url = _get("DEMO_OLLAMA_URL", "").strip() or "http://localhost:11434"
        return LLMSettings(mode=mode, model=model, base_url=base_url.rstrip("/"))

    key_var = API_KEY_VARS[mode]
    api_key = _get(key_var, "").strip()
    if not api_key:
        raise LLMConfigError(f"DEMO_LLM={mode} needs {key_var} to be set")
    override = _get("DEMO_LLM_BASE_URL", "").strip()
    base_url = (override or PROVIDER_BASE_URLS[mode]).rstrip("/")
    return LLMSettings(
        mode=mode, model=model, base_url=base_url,
        base_url_overridden=bool(override), api_key=api_key,
    )
