from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any

from .models import ModelConfig


@dataclass
class ProviderResponse:
    content: str
    raw: dict[str, Any] | None = None


class ProviderError(RuntimeError):
    pass


def decision_from_message(message: dict[str, Any]) -> str:
    """Return normalized decision JSON from content or OpenAI tool calls."""
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    calls = message.get("tool_calls") or []
    if calls:
        call = calls[0] if isinstance(calls[0], dict) else {}
        function = call.get("function") or {}
        name = function.get("name")
        arguments = function.get("arguments") or "{}"
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        decision = {
            "thought": str(arguments.get("thought", "")),
            "tool": name,
            "done": bool(arguments.get("done", False)),
        }
        return json.dumps(decision)
    return ""


class OpenAICompatibleProvider:
    def __init__(self, config: ModelConfig):
        if not config.base_url or not config.api_key:
            raise ValueError("base_url and api_key are required")
        self.config = config

    def complete(self, messages: list[dict[str, str]], tools: list[dict[str, Any]] | None = None) -> ProviderResponse:
        body: dict[str, Any] = {"model": self.config.model, "messages": messages}
        if tools:
            body["tools"] = tools
        request = urllib.request.Request(self.config.base_url.rstrip("/") + "/chat/completions", data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = json.loads(response.read())
        except Exception as exc:
            raise ProviderError(str(exc)) from exc
        try:
            return ProviderResponse(decision_from_message(raw["choices"][0]["message"]), raw)
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("provider returned an invalid chat completion") from exc


PROVIDER_BASE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "xai": "https://api.x.ai/v1",
}


def model_config_from_environment() -> ModelConfig:
    provider = os.getenv("KILLCHAIN_MODEL_PROVIDER")
    api_keys = {
        "groq": os.getenv("GROQ_API_KEY"),
        "openrouter": os.getenv("OPENROUTER_API_KEY"),
        "openai": os.getenv("OPENAI_API_KEY"),
    }
    api_key = api_keys.get(provider) if provider else None
    if not provider:
        provider = next((name for name, value in api_keys.items() if value), "rule_based")
        api_key = api_keys.get(provider)
    return ModelConfig(
        provider=provider,
        model=os.getenv("KILLCHAIN_MODEL", "llama-3.3-70b-versatile" if provider == "groq" else "deterministic"),
        base_url=os.getenv("KILLCHAIN_MODEL_BASE_URL") or PROVIDER_BASE_URLS.get(provider),
        api_key=api_key,
    )
