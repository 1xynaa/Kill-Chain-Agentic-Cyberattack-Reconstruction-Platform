# Kill-Chain Agentic Cyberattack Reconstruction Platform

> **Evidence-first, agentic forensic investigation platform.** Upload unlabeled forensic artifacts; the system autonomously investigates, maps each finding to the Cyber Kill Chain, and produces a defensible timeline, IOC set, and narrative report — all streamed live to a React dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Cyber Kill Chain Stages](#cyber-kill-chain-stages)
- [Repository Layout](#repository-layout)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Environment Setup](#environment-setup)
  - [Running Locally (one command)](#running-locally-one-command)
  - [Running Services Manually](#running-services-manually)
  - [Docker](#docker)
- [Backend](#backend)
  - [API Endpoints](#api-endpoints)
  - [WebSocket Event Stream](#websocket-event-stream)
  - [Configuration Reference](#configuration-reference)
  - [LLM Provider Setup](#llm-provider-setup)
  - [Available Forensic Tools](#available-forensic-tools)
- [Frontend](#frontend)
- [Agent Core](#agent-core)
  - [ReAct Investigation Loop](#react-investigation-loop)
  - [Skill Selection](#skill-selection)
  - [Kill Chain Mapper](#kill-chain-mapper)
  - [IOC Extraction](#ioc-extraction)
  - [Memory and Feedback](#memory-and-feedback)
- [Skills Library](#skills-library)
- [Terminal UI](#terminal-ui)
- [Testing](#testing)
- [Security Design](#security-design)
- [Contributing](#contributing)

---

## Overview

The Kill-Chain Agentic Cyberattack Reconstruction Platform is a full-stack forensic analysis system that combines:

- **Autonomous Agent** - a bounded ReAct-loop investigator that selects and runs forensic tools, reasons about output, and classifies findings
- **Kill Chain Mapper** - a rule-first classifier (with optional LLM assistance) that assigns each finding to one of nine Kill Chain stages with a confidence score
- **Live Streaming UI** - a React/TypeScript dashboard that streams the agent thought/action/observation cycle in real time via WebSocket
- **Skills Catalog** - 500+ curated cybersecurity investigation playbooks that guide tool selection
- **Report Engine** - produces a structured JSON report with a narrative, timeline, IOC list, and per-stage confidence scores

The platform operates in two modes:

| Mode | Description |
|------|-------------|
| **Rule-based** (default) | Fully deterministic; no external API calls. Useful for demos, offline environments, and reproducible tests. |
| **LLM-assisted** | Connects to any OpenAI-compatible provider (OpenRouter, OpenAI, Groq, DeepSeek, xAI, or a custom base URL) for planning and narrative generation. |

---

## Architecture

```
+-------------------------------------------------------------+
|                      React Frontend                          |
|  Upload -> Live Feed -> Kill Chain Stepper -> Report/IOCs   |
+------------------------+------------------------------------+
                         | REST + WebSocket
+------------------------v------------------------------------+
|                    FastAPI Backend                          |
|                                                             |
|  +----------+  +-----------+  +----------+  +----------+  |
|  |  Upload  |  |   Agent   |  |  Report  |  |  Skills  |  |
|  |  Store   |  |  (ReAct)  |  |  Engine  |  | Catalog  |  |
|  +----------+  +-----+-----+  +----------+  +----------+  |
|                      |                                      |
|              +-------+--------+                             |
|              |                |                             |
|        +-----v-----+   +------v------+                      |
|        | Tool Layer |   | Kill Chain  |                     |
|        | (sandboxed)|   |   Mapper    |                     |
|        +-----+------+   +-------------+                     |
|              |                                              |
|        +-----v--------------------------------+              |
|        | file, strings, tshark, sha256sum     |             |
|        | grep, yara, volatility, binwalk, ... |             |
|        +--------------------------------------+              |
+-------------------------------------------------------------+
              | (optional)
+--------------v--------------+
|  OpenAI-Compatible LLM API  |
|  OpenRouter / Groq / etc.   |
+-----------------------------+
```

**Data flow:**

1. User uploads one or more evidence files via `POST /upload`
2. A per-investigation isolated workspace is created; files are hashed and stored
3. `POST /investigate/start/{id}` launches the agent as a background async task
4. The agent runs a bounded ReAct loop: triage -> skill selection -> tool calls -> classification -> findings
5. Every event (thought, action, observation, finding, stage_update) is pushed through a WebSocket queue to the dashboard
6. After all evidence is processed, the report engine consolidates findings, IOCs, and timeline
7. The frontend renders the Kill Chain stepper, evidence graph, and final report

---

## Cyber Kill Chain Stages

The platform maps findings to nine stages (an extended Lockheed Martin model):

| # | Stage | Key Indicators |
|---|-------|----------------|
| 1 | **Reconnaissance** | Port scans, OSINT, enumeration, whois |
| 2 | **Weaponization** | Malicious archives, weaponized documents |
| 3 | **Delivery** | Phishing emails, malicious attachments, payload delivery |
| 4 | **Exploitation** | Code execution, shell spawn, SQL injection, brute force |
| 5 | **Installation** | Dropped payloads, registry run keys, scheduled tasks, services |
| 6 | **Credential Access** | LSASS handle open, Mimikatz, credential dumps |
| 7 | **Lateral Movement** | SMB sessions, WinRM, RDP, Event ID 4624 |
| 8 | **Command and Control (C2)** | Recurring beacons, DNS tunneling, C2 traffic |
| 9 | **Actions on Objectives** | Ransomware encryption, data exfiltration, destructive impact |

Each finding receives a **confidence score** (0-1) and a **tentative** flag when a timestamp cannot be extracted to anchor it in the timeline.

---

## Repository Layout

```
.
+-- backend/
|   +-- app/
|   |   +-- agent.py       # ReAct investigation loop and skill-guided planner
|   |   +-- config.py      # Settings (env vars, defaults, limits)
|   |   +-- ioc.py         # IOC extraction (IPs, domains, hashes, paths, etc.)
|   |   +-- killchain.py   # Rule-first Kill Chain classifier
|   |   +-- main.py        # FastAPI app, all REST and WebSocket routes
|   |   +-- models.py      # Pydantic data models
|   |   +-- providers.py   # OpenAI-compatible LLM provider layer
|   |   +-- report.py      # Report and IOC consolidation engine
|   |   +-- skills.py      # Skill catalog loader and indexer
|   |   +-- storage.py     # Per-investigation workspace and persistence
|   |   +-- tools.py       # Sandboxed forensic tool wrappers
|   +-- tui.py             # Terminal UI (headless investigation runner)
|   +-- README.md          # Backend-specific docs
+-- frontend/
|   +-- src/
|       +-- App.tsx         # Main UI: upload, live feed, Kill Chain stepper, report
|       +-- api/            # API client and WebSocket hooks
|       +-- hooks/          # React hooks (investigation state, WebSocket)
|       +-- index.css       # Global styles (Tailwind CSS v4)
+-- skills/
|   +-- PROJECT_CONTEXT.md  # System design brief and collaboration rules
|   +-- README.md           # Skills conventions
|   +-- <skill-name>/       # 500+ curated cybersecurity skill playbooks
|       +-- SKILL.md
+-- evidence/
|   +-- attack_scenario.pcap  # Sample evidence file for demos and tests
+-- tests/
|   +-- fixtures/           # Test evidence files (auth.log, pcap, etc.)
|   +-- test_agent.py
|   +-- test_api.py
|   +-- test_correctness_pass.py
|   +-- test_memory.py
|   +-- test_tools.py
|   +-- ...
+-- scripts/
|   +-- ci.sh               # Local CI: compile, pytest, TUI smoke test
+-- .env.example            # Environment variable template
+-- Dockerfile              # Production container (Python 3.13-slim)
+-- pyproject.toml          # Python package config and dependencies
+-- start_agent             # One-command launcher (backend + frontend)
```

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | >= 3.11 | 3.13 recommended |
| Node.js | >= 18 | For the React frontend |
| npm | >= 9 | Bundled with Node.js |
| `file` | any | Standard Unix utility |
| `strings` | any | From `binutils` |
| `sha256sum` | any | Standard on Linux/macOS |
| `tshark` | any | Optional; needed for PCAP analysis |
| `yara` | any | Optional; YARA rule scanning |
| `vol` (Volatility 3) | any | Optional; memory image analysis |
| `binwalk` | any | Optional; firmware analysis |
| `exiftool` | any | Optional; metadata extraction |

> **Kali Linux** includes most forensic tools above. On Ubuntu/Debian:
> ```bash
> sudo apt install tshark yara binwalk exiftool binutils file
> ```

### Environment Setup

```bash
# 1. Copy the environment template
cp .env.example .env.local

# 2. Edit .env.local to configure your provider (or leave as-is for rule-based mode)
```

Key variables in `.env.local`:

```bash
# Storage and limits
KILLCHAIN_WORKSPACE_ROOT=/tmp/killchain-workspaces
KILLCHAIN_MAX_FILE_SIZE=536870912    # 512 MB per file
KILLCHAIN_MAX_TOOL_OUTPUT=20000      # Characters per tool output
KILLCHAIN_TOOL_TIMEOUT=30            # Seconds per tool execution
KILLCHAIN_MAX_TOOL_CALLS=20          # Tool calls per investigation

# LLM (optional - omit to run in deterministic/rule-based mode)
OPENROUTER_API_KEY=sk-or-...
KILLCHAIN_MODEL_PROVIDER=openrouter
KILLCHAIN_MODEL=nex-agi/nex-n2.5-pro:free
```

### Running Locally (one command)

```bash
# Install Python dependencies
pip install -e .

# Install frontend dependencies
cd frontend && npm install && cd ..

# Launch both backend and frontend
bash start_agent
```

Then open **http://localhost:5173** in your browser.

The `start_agent` script:
- Detects if services are already running and reuses them
- Starts the FastAPI backend on port `8000`
- Starts the Vite dev server on port `5173`
- Logs to `.runtime/backend.log` and `.runtime/frontend.log`
- Gracefully shuts both services down on Ctrl-C

### Running Services Manually

**Backend only:**
```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```

**Frontend only:**
```bash
cd frontend
npm run dev
```

### Docker

```bash
# Build the backend image
docker build -t killchain-backend .

# Run with environment variables
docker run -p 8000:8000 \
  -e OPENROUTER_API_KEY=sk-or-... \
  -e KILLCHAIN_MODEL_PROVIDER=openrouter \
  -e KILLCHAIN_MODEL=nex-agi/nex-n2.5-pro:free \
  killchain-backend
```

The container exposes port `8000` and includes a health check at `/health`.

---

## Backend

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `GET` | `/tools` | Lists all tools with availability and network status |
| `GET` | `/skills` | Returns the indexed skill catalog |
| `POST` | `/upload` | Multipart upload of one or more evidence files |
| `POST` | `/investigate/start/{id}` | Starts the bounded investigation loop |
| `GET` | `/investigation/{id}` | Returns current investigation state and all events |
| `GET` | `/report/{id}` | Returns the final JSON report (timeline, stages, IOCs, narrative) |
| `POST` | `/replay/{id}?speed=1.0` | Replays stored events over WebSocket (demo mode) |
| `POST` | `/feedback/{inv_id}/{finding_id}` | Submit analyst feedback (confirmed/rejected) to memory |
| `GET` | `/memory/search?q=...` | Keyword search over the analyst feedback memory store |
| `POST` | `/config/model` | Update LLM provider/model at runtime |
| `WS` | `/ws/investigate/{id}` | Live event stream for the dashboard |

**Upload evidence:**
```bash
curl -X POST http://localhost:8000/upload \
  -F "files=@/path/to/evidence.pcap" \
  -F "files=@/path/to/auth.log"
```

**Start investigation:**
```bash
curl -X POST http://localhost:8000/investigate/start/<investigation_id>
```

**Get report:**
```bash
curl http://localhost:8000/report/<investigation_id> | jq .
```

### WebSocket Event Stream

Connect to `ws://localhost:8000/ws/investigate/{id}` to receive real-time events:

```json
{
  "investigation_id": "uuid",
  "sequence": 1,
  "timestamp": "2026-09-18T00:00:00Z",
  "type": "thought",
  "payload": { "text": "Start with forensic triage of auth.log." },
  "evidence_refs": ["auth.log"],
  "confidence": null
}
```

#### Event Types

| Type | Description | Key Payload Fields |
|------|-------------|-------------------|
| `status` | Investigation lifecycle update | `status`, `planner`, `tool_calls` |
| `thought` | Agent reasoning step | `text` |
| `action` | Tool invocation | `tool`, `path` |
| `observation` | Tool output | `tool`, `stdout`, `stderr`, `records_analyzed` |
| `finding` | Confirmed or tentative finding | `title`, `stage`, `confidence`, `tentative`, `iocs` |
| `stage_update` | Kill Chain stage classified | `stage`, `confidence`, `tentative` |
| `skill_select` | Skills selected for evidence type | `skills` |
| `memory_recall` | Prior feedback retrieved | `count`, `memories` |
| `llm_narrative` | LLM-generated summary | `text`, `provider`, `model` |
| `provider_error` | LLM call failed, fallback used | `error`, `fallback` |

The `stage_update` payload includes the `tentative` boolean so the frontend can correctly handle out-of-sequence stage discoveries.

### Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `KILLCHAIN_WORKSPACE_ROOT` | `/tmp/killchain-workspaces` | Root directory for per-investigation file storage |
| `KILLCHAIN_MAX_FILE_SIZE` | `536870912` (512 MB) | Maximum size for a single uploaded evidence file |
| `KILLCHAIN_MAX_TOOL_OUTPUT` | `20000` | Character limit on captured tool output |
| `KILLCHAIN_TOOL_TIMEOUT` | `30` | Seconds before a tool call is killed |
| `KILLCHAIN_MAX_TOOL_CALLS` | `20` | Maximum tool invocations per investigation |
| `KILLCHAIN_ALLOW_NETWORK_TOOLS` | `false` | Enable nmap, dig, whois (requires explicit opt-in) |
| `KILLCHAIN_MODEL_PROVIDER` | *(none)* | `openrouter`, `openai`, `groq`, `deepseek`, `xai`, or `rule_based` |
| `KILLCHAIN_MODEL` | `deterministic` | Model name to pass to the provider API |
| `KILLCHAIN_MODEL_BASE_URL` | *(auto)* | Override the provider base URL |
| `KILLCHAIN_MODEL_FALLBACKS` | *(built-in list)* | Comma-separated model fallback chain for 429 errors |
| `KILLCHAIN_PROVIDER_TIMEOUT` | `30` | HTTP timeout for LLM API calls (seconds) |
| `OPENROUTER_API_KEY` | *(none)* | API key for OpenRouter |
| `OPENAI_API_KEY` | *(none)* | API key for OpenAI |
| `GROQ_API_KEY` | *(none)* | API key for Groq |

### LLM Provider Setup

The platform works without any LLM (rule-based mode). To enable AI-assisted planning and narrative generation:

**OpenRouter (recommended free tier):**
```bash
OPENROUTER_API_KEY=sk-or-v1-...
KILLCHAIN_MODEL_PROVIDER=openrouter
KILLCHAIN_MODEL=nex-agi/nex-n2.5-pro:free
```

**Groq (fast, free tier available):**
```bash
GROQ_API_KEY=gsk_...
KILLCHAIN_MODEL_PROVIDER=groq
KILLCHAIN_MODEL=llama-3.3-70b-versatile
```

**OpenAI:**
```bash
OPENAI_API_KEY=sk-...
KILLCHAIN_MODEL_PROVIDER=openai
KILLCHAIN_MODEL=gpt-4o-mini
```

**Custom / self-hosted (any OpenAI-compatible endpoint):**
```bash
KILLCHAIN_MODEL_PROVIDER=custom
KILLCHAIN_MODEL_BASE_URL=http://localhost:11434/v1
KILLCHAIN_MODEL=llama3
```

Update the provider at runtime without restarting:
```bash
curl -X POST http://localhost:8000/config/model \
  -H "Content-Type: application/json" \
  -d '{"provider":"openrouter","model":"nex-agi/nex-n2.5-pro:free","api_key":"sk-or-..."}'
```

The response masks the API key as `[configured]`. Keys are never logged or streamed.

**Rate limit handling:** If a model returns HTTP 429, the provider layer automatically falls back through the `KILLCHAIN_MODEL_FALLBACKS` chain before raising an error.

### Available Forensic Tools

| Tool | Executable | Description | Network |
|------|-----------|-------------|---------|
| `file_triage` | `file` | Identifies evidence file type | No |
| `strings_extract` | `strings` | Extracts printable strings (>=6 chars) | No |
| `sha256sum` | `sha256sum` | Computes SHA-256 hash | No |
| `tshark_summary` | `tshark` | Summarizes IP conversations in PCAP | No |
| `tshark_details` | `tshark` | Extracts endpoints, ports, DNS, HTTP fields | No |
| `yara_scan` | `yara` | Scans evidence against `rules.yar` | No |
| `volatility_info` | `vol` | Extracts memory image metadata | No |
| `binwalk_scan` | `binwalk` | Detects embedded firmware artifacts | No |
| `exiftool_metadata` | `exiftool` | Extracts document/image metadata | No |
| `grep_indicators` | `grep` | Searches for common security indicators | No |
| `csv_events` | `python3` | Parses CSV log exports with normalized fields | No |
| `nmap` | `nmap` | Active network inventory scan | **Yes** |
| `dig` | `dig` | DNS resolution lookup | **Yes** |
| `whois` | `whois` | Domain/IP registration lookup | **Yes** |

Network tools are **disabled by default**. Set `KILLCHAIN_ALLOW_NETWORK_TOOLS=true` to enable them.

All tool calls are run without a shell (`shell=False`), bounded by timeout, output-capped, and path-validated to remain within the investigation workspace.

---

## Frontend

The frontend is a **React 19 / TypeScript / Vite** application styled with **Tailwind CSS v4**.

| Path | Description |
|------|-------------|
| `frontend/src/App.tsx` | Main application component |
| `frontend/src/api/` | Typed API client for REST endpoints |
| `frontend/src/hooks/` | WebSocket and investigation state hooks |
| `frontend/src/index.css` | Global styles |

**Features:**
- Drag-and-drop evidence upload
- Live reasoning feed (thought -> action -> observation cycle)
- Kill Chain stage stepper with per-stage confidence indicators
- Evidence graph view
- Analyst feedback submission (confirm/reject findings)
- IOC table with type-filtered display
- Report export (JSON)
- Demo replay mode at configurable playback speed
- Model/provider configuration panel

**Development server:**
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

The Vite dev server proxies `/api/*` to the backend at `http://localhost:8000`.

---

## Agent Core

### ReAct Investigation Loop

The `Agent` class (`backend/app/agent.py`) implements a bounded **Reason -> Act -> Observe** cycle:

```
For each evidence file:
  1. file_triage        -> identify file type
  2. skill_select       -> rank relevant skills from the catalog
  3. _initial_plan()    -> build tool queue based on file type:
       .pcap/.pcapng    -> [tshark_summary, tshark_details, strings_extract, sha256sum]
       .raw/.dmp/.mem   -> [strings_extract, volatility_info, sha256sum]
       .csv             -> [csv_events, grep_indicators, strings_extract, sha256sum]
       other            -> [grep_indicators, strings_extract, sha256sum]
     + skill-recommended tools appended
  4. For each tool (up to max_tool_calls budget):
       a. [optional] LLM decision: re-evaluate thought and tool choice
       b. Run tool -> emit action + observation events
       c. Classify output -> Kill Chain stage + confidence
       d. Extract IOCs
       e. Extract timestamp -> mark finding tentative if none found
       f. Emit finding + stage_update events
  5. [optional] LLM narrative: generate 3-6 paragraph plain-English summary
  6. Emit completion status event
```

When `max_tool_calls` is reached, the loop emits `budget_exhausted` and stops.

### Skill Selection

Before building the tool queue, the agent runs a keyword-weighted ranking across the 500+ skills:

- Tokenizes the evidence filename and file type
- Boosts matches for known file-type keywords (e.g., `pcap` -> network/wireshark terms)
- Scores each skill by overlap with its name, description, overview, and `when_to_use` fields
- Returns up to 8 top-ranked skills whose tools are appended to the default queue (deduped)

### Kill Chain Mapper

`backend/app/killchain.py` implements a rule-first classifier:

**Priority rules** (evaluated first):
- Ransom note indicators -> `Actions on Objectives` (confidence 0.93)
- Disk-write / persistence keywords -> `Installation` (0.88)
- LSASS handle access -> `Credential Access` (0.91)
- SMB + source/destination pattern -> `Lateral Movement` (0.88)

**General rule table** - term lists with stage and confidence tuples for all nine stages.

Returns `(Stage | None, float)`. `None` means no stage was confirmed. Generic terms like "dns", "ssh", or "download" alone are insufficient for classification.

### IOC Extraction

`backend/app/ioc.py` extracts the following indicator types using compiled regex patterns:

| IOC Type | Examples |
|----------|---------|
| `ip` | `192.168.1.1`, `10.0.0.50` |
| `domain` | `evil.example.com`, `c2.attacker.io` |
| `url` | `http://malware.site/payload.exe` |
| `sha256` | 64-character hex hashes |
| `file_path` | Windows and UNC paths |
| `registry_key` | `HKLM\SOFTWARE\...` |
| `process_name` | `mimikatz.exe`, `lsass.exe` |
| `dll_name` | `evil.dll`, `hook.sys` |
| `service_name` | Service names from log patterns |
| `username` | Account names from event logs |

Packet field labels and Volatility plugin names are excluded from domain matching to avoid false positives.

### Memory and Feedback

The platform maintains a cross-investigation memory store for analyst feedback:

- `POST /feedback/{inv_id}/{finding_id}` - submit `confirmed` or `rejected` with an optional note
- `GET /memory/search?q=...` - keyword search across all stored feedback
- Prior feedback is injected into the agent system prompt as context, not proof
- Memory records persist across investigations to improve future analysis of similar evidence

---

## Skills Library

The `skills/` directory contains **500+ curated cybersecurity investigation playbooks**, organized by technique. Each skill subdirectory contains a `SKILL.md` documenting:

- **Purpose** - what the skill is for
- **Inputs** - what evidence or prerequisites are needed
- **Outputs** - what findings or artifacts are produced
- **Workflow** - step-by-step investigation procedure
- **Tools** - specific tools referenced
- **Safety limits** - boundaries and cautions
- **Verification** - how to confirm correctness

Sample skill categories:
- `analyzing-memory-dumps-with-volatility/`
- `analyzing-network-traffic-with-wireshark/`
- `detecting-lateral-movement-with-splunk/`
- `hunting-for-cobalt-strike-beacons/`
- `investigating-ransomware-attack-artifacts/`
- `performing-malware-triage-with-yara/`
- `performing-timeline-reconstruction-with-plaso/`

Skills guide the agent's tool selection and are also useful as human-readable playbooks for analysts.

---

## Terminal UI

For headless or scripted use, the TUI runs an investigation from the command line:

```bash
# Basic usage
python -m backend.tui /path/to/evidence.pcap

# Multiple files
python -m backend.tui /path/to/auth.log /path/to/traffic.pcap

# Limit tool calls (useful for quick triage)
python -m backend.tui /path/to/evidence.pcap --max-calls 5
```

Output is color-coded in supported terminals (THOUGHT, ACTION, OBSERVATION, FINDING, STAGE_UPDATE) and concludes with a full JSON report.

---

## Testing

```bash
# Run the full test suite
pytest -q

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_api.py -v

# Run the local CI script (compile + tests + TUI smoke test)
bash scripts/ci.sh
```

**Test files:**

| File | Coverage |
|------|----------|
| `test_agent.py` | Agent ReAct loop, budget enforcement, event emission |
| `test_api.py` | All REST endpoints (upload, start, report, feedback, etc.) |
| `test_correctness_pass.py` | End-to-end classification correctness on fixture evidence |
| `test_memory.py` | Memory store persistence and search |
| `test_tools.py` | Tool runner sandbox, path validation, CSV parsing |
| `test_skills.py` | Skill catalog loading and indexing |
| `test_skills_selection.py` | Skill ranking algorithm |
| `test_providers.py` | Provider layer error handling |
| `test_tui.py` | TUI integration smoke test |
| `test_analysis.py` | IOC extraction and Kill Chain classification |
| `test_persistence.py` | Investigation state persistence |

**CI checks** (`scripts/ci.sh`):
1. `python -m compileall backend` - syntax check
2. `pytest -q` - full test suite
3. TUI smoke test on `tests/fixtures/auth.log` - verifies `Exploitation` stage is detected

---

## Security Design

The platform is designed to analyze evidence **defensively**:

| Control | Implementation |
|---------|---------------|
| **Workspace isolation** | Each investigation gets a unique UUID-keyed directory |
| **No code execution** | Uploaded files are never executed as programs |
| **No shell injection** | All subprocess calls use list arguments (`shell=False`) |
| **Tool allowlist** | Only explicitly defined tools can be invoked |
| **Path containment** | Tool calls validate the target path resolves inside the workspace |
| **File size limit** | Uploads exceeding `KILLCHAIN_MAX_FILE_SIZE` are rejected with HTTP 413 |
| **Output bounding** | Tool output is truncated at `KILLCHAIN_MAX_TOOL_OUTPUT` characters |
| **Execution timeout** | Every tool call is bounded by `KILLCHAIN_TOOL_TIMEOUT` seconds |
| **Tool call budget** | Each investigation is capped at `KILLCHAIN_MAX_TOOL_CALLS` invocations |
| **Network opt-in** | `nmap`, `dig`, and `whois` require `KILLCHAIN_ALLOW_NETWORK_TOOLS=true` |
| **Secret masking** | API keys are never logged or returned in API responses |
| **Evidence privacy** | Raw evidence is never sent to an external LLM without explicit configuration |
| **Cross-investigation isolation** | Workspaces are not shared; no cross-investigation contamination |

---

## Contributing

See `skills/PROJECT_CONTEXT.md` for the full collaboration guide. Key rules:

- Treat `main` as shared - always pull before starting work
- Use focused branches for substantial changes; coordinate before changing public API or schema contracts
- Keep commits small and descriptive
- Run `bash scripts/ci.sh` before pushing - it must pass cleanly
- A feature is not complete until it has implementation, automated test coverage, and a documented interface
- Update the relevant skill or architecture notes when a reusable workflow or interface changes
- Do not commit secrets, API keys, credentials, uploaded evidence, or local workspaces

**Adding a new forensic tool:**
1. Add a `ToolSpec` entry in `backend/app/tools.py`
2. Update the `_initial_plan` heuristics in `backend/app/agent.py` if appropriate for a specific file type
3. Add test coverage in `tests/test_tools.py`

**Adding a new Kill Chain rule:**
1. Edit `_RULES` or the priority block in `backend/app/killchain.py`
2. Add a fixture and assertion in `tests/test_correctness_pass.py`

**Adding a new skill:**
1. Create `skills/<your-skill-name>/SKILL.md` following the conventions in `skills/README.md`
2. The skill is automatically indexed at startup - no code changes needed

---

*Built with FastAPI · React · Vite · Tailwind CSS · Python 3.13 · Pydantic v2*
