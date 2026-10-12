# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""LLM client for the demo agents: the host's Ollama, OpenAI, Anthropic or Gemini.

Each provider is called through the API its own documentation describes,
streaming the reply and asking for JSON output:

- Ollama and OpenAI: the chat completions endpoint (``/v1/chat/completions``).
- Anthropic: the Messages API (``/v1/messages``).
- Gemini: ``streamGenerateContent`` with server-sent events.

No dependency on any provider SDK — raw HTTP only. The API key travels in a
request header, never in the URL, and no error raised here carries the URL,
the response body or any header, so a key cannot reach a log line.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from config import LLMSettings

logger = logging.getLogger(__name__)

ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_MAX_TOKENS = 4096


class LLMError(Exception):
    """An LLM call failed. The message names the provider and what failed only."""


class LLMClient:
    """Async client for the LLM selected by the demo's settings.

    ``chat_json_stream`` is the only call the agents use. ``json_schema``
    describes the reply the agent expects; Anthropic offers JSON output only
    as a schema, so it is sent there. With mode ``none``
    the client is disabled: no request is made and callers use their
    deterministic fallback.
    """

    def __init__(
        self,
        settings: LLMSettings,
        system_prompt: str = "",
        json_schema: dict[str, Any] | None = None,
        timeout: float = 300.0,
    ) -> None:
        self._settings = settings
        self.mode = settings.mode
        self.model = settings.model
        self.enabled = settings.mode != "none"
        self.system_prompt = system_prompt
        self.json_schema = json_schema
        self.timeout = timeout

    async def chat_json_stream(
        self,
        user_message: str,
        *,
        temperature: float = 0.3,
        on_token: Any = None,
    ) -> Any:
        """Stream a chat request with JSON output, calling on_token for each token.

        Args:
            user_message: The user's message content.
            temperature: Sampling temperature, sent to Ollama only; the
                providers' current models reject or ignore other values.
            on_token: Async callback called with each token string as it arrives.

        Returns:
            The parsed JSON from the accumulated response content.
        """
        if not self.enabled:
            raise LLMError("LLM disabled (mode none)")

        url, headers, body, parse = self._request(user_message, temperature)
        content = ""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", url, headers=headers, json=body) as resp:
                    if resp.status_code >= 400:
                        raise LLMError(f"{self.mode} returned HTTP {resp.status_code}")
                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data_str = line[5:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue
                        for token in parse(chunk):
                            content += token
                            if on_token is not None:
                                await on_token(token)
        except httpx.TimeoutException:
            raise LLMError(f"{self.mode} request timed out") from None
        except httpx.HTTPError:
            raise LLMError(f"{self.mode} request failed") from None

        clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        return json.loads(clean)

    def _request(
        self, user_message: str, temperature: float,
    ) -> tuple[str, dict[str, str], dict[str, Any], Any]:
        """Build the URL, headers, body and chunk parser for the selected provider."""
        s = self._settings
        if self.mode in ("ollama", "openai"):
            messages: list[dict[str, str]] = []
            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            messages.append({"role": "user", "content": user_message})
            body: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                "stream": True,
                "response_format": {"type": "json_object"},
            }
            headers: dict[str, str] = {}
            if self.mode == "ollama":
                body["temperature"] = temperature
            else:
                headers["Authorization"] = f"Bearer {s.api_key}"
            return f"{s.base_url}/v1/chat/completions", headers, body, _openai_tokens

        if self.mode == "anthropic":
            body = {
                "model": self.model,
                "max_tokens": ANTHROPIC_MAX_TOKENS,
                "messages": [{"role": "user", "content": user_message}],
                "stream": True,
            }
            if self.system_prompt:
                body["system"] = self.system_prompt
            if self.json_schema:
                body["output_config"] = {
                    "format": {"type": "json_schema", "schema": self.json_schema},
                }
            if self.model == "claude-haiku-5-5":
                body["thinking"] = {"type": "disabled"}
            headers = {
                "Authorization": f"Bearer {s.api_key}",
                "anthropic-version": ANTHROPIC_VERSION,
            }
            return f"{s.base_url}/v1/messages", headers, body, _anthropic_tokens

        if self.mode == "gemini":
            body = {
                "contents": [{"role": "user", "parts": [{"text": user_message}]}],
                "generationConfig": {"responseMimeType": "application/json"},
            }
            if self.system_prompt:
                body["systemInstruction"] = {"parts": [{"text": self.system_prompt}]}
            headers = {"x-goog-api-key": s.api_key}
            url = f"{s.base_url}/v1beta/models/{self.model}:streamGenerateContent?alt=sse"
            return url, headers, body, _gemini_tokens

        raise LLMError(f"unknown LLM mode {self.mode!r}")

    async def health_check(self) -> bool | None:
        """Report whether the host's Ollama is reachable and has the model.

        Only Ollama mode is checked; for the other modes no request is made
        and None is returned.
        """
        if self.mode != "ollama":
            return None
        base_url = self._settings.base_url
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                model_names = [m.get("name", "") for m in data.get("models", [])]
                base_model = self.model.split(":")[0]
                available = any(base_model in name for name in model_names)
                if not available:
                    logger.warning(
                        "Ollama at %s is reachable but model %s not found (available: %s)",
                        base_url, self.model, model_names,
                    )
                return True
        except (httpx.HTTPError, Exception) as exc:
            logger.warning("Ollama health check failed at %s: %s", base_url, exc)
            return False


def _openai_tokens(chunk: dict[str, Any]) -> list[str]:
    """Text of a chat completions stream chunk."""
    token = (chunk.get("choices") or [{}])[0].get("delta", {}).get("content") or ""
    return [token] if token else []


def _anthropic_tokens(chunk: dict[str, Any]) -> list[str]:
    """Text of a Messages API stream event; an error event raises."""
    if chunk.get("type") == "error":
        error_type = chunk.get("error", {}).get("type", "error")
        raise LLMError(f"anthropic stream error ({error_type})")
    if chunk.get("type") == "content_block_delta":
        delta = chunk.get("delta", {})
        if delta.get("type") == "text_delta" and delta.get("text"):
            return [delta["text"]]
    return []


def _gemini_tokens(chunk: dict[str, Any]) -> list[str]:
    """Text parts of a streamGenerateContent chunk, without thought parts."""
    candidates = chunk.get("candidates") or [{}]
    parts = candidates[0].get("content", {}).get("parts", [])
    return [p["text"] for p in parts if p.get("text") and not p.get("thought")]
