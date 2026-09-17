from __future__ import annotations

import json
import os
import urllib.error
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
        base_url = config.base_url
        api_key = config.api_key
        if not base_url or not api_key:
            raise ValueError("base_url and api_key are required")
        self.base_url, self.api_key, self.config = base_url, api_key, config

    def complete(self, messages: list[dict[str, str]], tools: list[dict[str, Any]] | None = None) -> ProviderResponse:
        models = [self.config.model]
        configured_fallbacks = os.getenv(
            "KILLCHAIN_MODEL_FALLBACKS",
            "nex-agi/nex-n2.5-mini:free,qwen/qwen3.8-27b:free,google/gemma-4-26b-a4b-it:free",
        )
        models.extend(item.strip() for item in configured_fallbacks.split(",") if item.strip() and item.strip() not in models)
        body: dict[str, Any] = {"messages": messages}
        if tools:
            body["tools"] = tools
        last_rate_limit: ProviderError | None = None
        rate_limited_models: list[str] = []
        for model in models:
            request_body = {**body, "model": model}
            request = urllib.request.Request(
                self.base_url.rstrip("/") + "/chat/completions",
                data=json.dumps(request_body).encode(),
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=int(os.getenv("KILLCHAIN_PROVIDER_TIMEOUT", "30"))) as response:
                    raw = json.loads(response.read())
                return ProviderResponse(decision_from_message(raw["choices"][0]["message"]), raw)
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    rate_limited_models.append(model)
                    last_rate_limit = ProviderError("OpenRouter rate-limited all configured models: " + ", ".join(rate_limited_models))
                    continue
                try:
                    detail = json.loads(exc.read()).get("error", {}).get("message", str(exc))
                except Exception:
                    detail = str(exc)
                raise ProviderError(str(detail)) from exc
            except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
                raise ProviderError("provider returned an invalid chat completion") from exc
            except Exception as exc:
                raise ProviderError(str(exc)) from exc
        raise last_rate_limit or ProviderError("all configured models failed")


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
