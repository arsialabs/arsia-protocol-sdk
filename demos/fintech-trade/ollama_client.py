# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Ollama client using the OpenAI-compatible /v1/chat/completions endpoint."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class OllamaClient:
    """Async client for Ollama's OpenAI-compatible API.

    No dependency on the ollama Python package — raw HTTP only.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "gemma4:e2b",
        system_prompt: str = "",
        timeout: float = 300.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.system_prompt = system_prompt
        self.timeout = timeout

    async def chat(
        self,
        user_message: str,
        *,
        json_mode: bool = False,
        temperature: float = 0.7,
    ) -> dict[str, Any]:
        """Send a chat completion request and return the parsed response.

        Args:
            user_message: The user's message content.
            json_mode: When True, sets response_format to JSON.
            temperature: Sampling temperature.

        Returns:
            The full API response as a dict.
        """
        messages: list[dict[str, str]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": user_message})

        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/chat/completions",
                json=body,
            )
            resp.raise_for_status()
            return resp.json()

    async def chat_json(
        self,
        user_message: str,
        *,
        temperature: float = 0.3,
    ) -> Any:
        """Send a chat request with JSON mode and parse the response content.

        Returns the parsed JSON from the assistant's message content.
        Raises ValueError if the response cannot be parsed as JSON.
        """
        response = await self.chat(
            user_message,
            json_mode=True,
            temperature=temperature,
        )
        content = response["choices"][0]["message"]["content"]
        return json.loads(content)

    async def chat_json_stream(
        self,
        user_message: str,
        *,
        temperature: float = 0.3,
        on_token: Any = None,
    ) -> Any:
        """Stream a chat request with JSON mode, calling on_token for each token.

        Args:
            user_message: The user's message content.
            temperature: Sampling temperature.
            on_token: Async callback called with each token string as it arrives.

        Returns:
            The parsed JSON from the accumulated response content.
        """
        messages: list[dict[str, str]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": user_message})

        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
            "response_format": {"type": "json_object"},
        }

        content = ""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/v1/chat/completions",
                json=body,
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            content += token
                            if on_token is not None:
                                await on_token(token)
                    except json.JSONDecodeError:
                        pass

        clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        return json.loads(clean)

    async def health_check(self) -> bool:
        """Check if the Ollama instance is reachable and has the model loaded."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                model_names = [m.get("name", "") for m in data.get("models", [])]
                base_model = self.model.split(":")[0]
                available = any(base_model in name for name in model_names)
                if not available:
                    logger.warning(
                        "Ollama at %s is reachable but model %s not found (available: %s)",
                        self.base_url, self.model, model_names,
                    )
                return True
        except (httpx.HTTPError, Exception) as exc:
            logger.warning("Ollama health check failed at %s: %s", self.base_url, exc)
            return False
