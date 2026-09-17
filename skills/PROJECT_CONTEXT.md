# Kill Chain Agentic Cyberattack Reconstruction Platform — Project Context

## Mission

Build a live, evidence-first cyberattack reconstruction platform. A user uploads unlabeled forensic evidence; an agent investigates it with structured Kali-compatible tools; the UI streams the investigation; and the platform produces a defensible Cyber Kill Chain reconstruction, timeline, IOC set, evidence graph, and report.

## Current repository state

- Repository: `1xynaa/Kill-Chain-Agentic-Cyberattack-Reconstruction-Platform`
- Default branch: `main`
- Current initial implementation status: repository scaffold only; the README was the original seed.
- Local checkout used by the primary agent: `/home/shadow/Kill-Chain-Agentic-Cyberattack-Reconstruction-Platform`

## Target architecture

- Frontend: Next.js/React, TailwindCSS, live reasoning feed, kill-chain stepper, evidence graph, report/export views.
- Backend: FastAPI REST and WebSocket orchestration.
- Agent core: Hermes-oriented ReAct loop with explicit thought/action/observation events, bounded budgets, working memory, and provider-independent model access.
- Tool layer: sandboxed, structured wrappers around forensic and defensive analysis tools such as `file`, grep/log parsers, tshark, strings, YARA, Volatility, binwalk, and related utilities.
- Mapper: rule-first Cyber Kill Chain classification with confidence, timestamps, and evidence pointers; model assistance only for ambiguous cases.
- Reporting: narrative, timeline, IOC extraction/correlation, JSON export, and optional PDF export.
- Storage: per-investigation isolated workspace and state; no cross-investigation contamination.

## Cyber Kill Chain stages

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control (C2)
7. Actions on Objectives

## MVP build order

1. Evidence upload and isolated workspace creation.
2. File-type triage and one end-to-end structured tool call.
3. WebSocket event streaming to a minimal frontend feed.
4. Rule-based kill-chain mapper and confidence model.
5. Dashboard stepper and investigation state display.
6. Report generation and IOC extraction.
7. Evidence graph and replay mode.
8. Provider/model configuration panel.
9. PDF export and demo fallback replay.

## Event contract direction

Investigation events should be append-only and machine-readable. The initial event shape should include:

- `investigation_id`
- `sequence`
- `timestamp`
- `type`: `thought`, `action`, `observation`, `finding`, `stage_update`, `status`, or `error`
- `payload`
- optional `evidence_refs`
- optional `confidence`

Tool wrappers should return structured JSON with the command metadata, bounded output, parsed findings, errors, and evidence references. Raw uploaded evidence must never be sent to an external model provider without an explicit, documented configuration choice.

## Collaboration rules for four contributors

- Treat `main` as shared and always pull before starting work.
- Use focused branches for substantial changes; coordinate before changing public API/schema contracts.
- Keep commits small and descriptive.
- Do not overwrite another contributor’s work. Resolve conflicts deliberately and preserve both valid changes.
- Push to `main` only when explicitly requested by the project owner; otherwise push the working branch and open a review.
- Before merging or pushing, run the relevant tests, lint/type checks, and a smoke test for the affected service.
- Update the relevant skill or architecture notes when a reusable workflow or interface changes.

## Security and demo requirements

- Analyze evidence defensively and isolate each investigation workspace.
- Enforce file-size, archive-expansion, execution-time, tool-call, and model-call budgets.
- Do not execute uploaded files as programs.
- Avoid active network actions by default; live-target tools require an explicit opt-in in the investigation configuration.
- Redact secrets from logs and streamed events.
- Provide uncertainty instead of presenting unsupported conclusions as fact.
- Include a pre-tested evidence set and cached replay fallback for demonstrations.

## Definition of done for future features

A feature is not complete until it has implementation, automated coverage where practical, a documented interface or usage path, and a real smoke-test result. Keep the repository runnable from a clean checkout with documented environment setup.
