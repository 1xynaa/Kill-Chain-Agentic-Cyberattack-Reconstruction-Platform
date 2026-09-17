# Backend

FastAPI orchestration service for the Kill Chain reconstruction platform.

## Run locally

```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```

The default configuration is intentionally conservative:

- Evidence is stored under `/tmp/killchain-workspaces` in an investigation-specific directory.
- Uploaded files are hashed and never executed.
- Tool commands are selected from an explicit allowlist and run without a shell.
- Output and execution time are bounded.
- Network tools are disabled unless `KILLCHAIN_ALLOW_NETWORK_TOOLS=true` is explicitly set.
- API keys are accepted for provider configuration but are never returned or streamed.

## Endpoints

- `GET /health` — liveness check
- `POST /upload` — multipart upload of one or more evidence files
- `POST /investigate/start/{id}` — start the bounded investigation loop
- `GET /investigation/{id}` — current state and append-only events
- `WS /ws/investigate/{id}` — live event stream for the dashboard
- `GET /report/{id}` — JSON timeline, stages, narrative, and IOCs
- `GET /tools` — available allowlisted tools on this host
- `GET /skills` — indexed project skill catalog
- `POST /config/model` — provider/model configuration (secret value is masked)

## Configuration

Environment variables:

- `KILLCHAIN_WORKSPACE_ROOT`
- `KILLCHAIN_MAX_FILE_SIZE`
- `KILLCHAIN_MAX_TOOL_OUTPUT`
- `KILLCHAIN_TOOL_TIMEOUT`
- `KILLCHAIN_MAX_TOOL_CALLS`
- `KILLCHAIN_ALLOW_NETWORK_TOOLS`

The provider layer currently accepts OpenAI-compatible providers including OpenRouter, OpenAI, Groq, DeepSeek, and xAI, plus arbitrary compatible base URLs. The deterministic rule-based path remains available when no model is configured, which keeps demos and tests reproducible.

## Tests

```bash
pytest -q
```
