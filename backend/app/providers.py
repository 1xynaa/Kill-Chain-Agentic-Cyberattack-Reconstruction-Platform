from __future__ import annotations

import json
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
            return ProviderResponse(raw["choices"][0]["message"].get("content", ""), raw)
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("provider returned an invalid chat completion") from exc


PROVIDER_BASE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "xai": "https://api.x.ai/v1",
}
