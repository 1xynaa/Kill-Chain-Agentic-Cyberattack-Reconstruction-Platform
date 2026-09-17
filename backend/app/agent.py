from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

from .config import Settings
from .killchain import classify
from .models import Finding, Investigation, InvestigationEvent
from .skills import load_skill_catalog
from .tools import ToolRunner

EventSink = Callable[[InvestigationEvent], Awaitable[None]]


class Agent:
    def __init__(self, settings: Settings, runner: ToolRunner, skills_root: Path):
        self.settings = settings
        self.runner = runner
        self.skills_root = skills_root

    async def investigate(self, investigation: Investigation, sink: EventSink) -> None:
        investigation.status = "running"
        sequence = 0
        calls = 0

        async def emit(kind: str, payload: dict, refs: list[str] | None = None, confidence: float | None = None):
            nonlocal sequence
            sequence += 1
            event = InvestigationEvent(investigation_id=investigation.id, sequence=sequence, type=kind, payload=payload, evidence_refs=refs or [], confidence=confidence)
            investigation.events.append(event)
            await sink(event)

        await emit("status", {"status": "running", "skill_count": len(load_skill_catalog(self.skills_root))})
        for evidence in investigation.files:
            if calls >= self.settings.max_tool_calls:
                await emit("status", {"status": "budget_exhausted"})
                break
            calls += 1
            await emit("action", {"tool": "file_triage", "path": evidence.stored_name}, [evidence.stored_name])
            result = self.runner.run("file_triage", self._workspace(investigation), evidence.stored_name)
            evidence.file_type = result.stdout.strip() or result.error or "unknown"
            await emit("observation", {"tool": result.tool, "success": result.success, "available": result.available, "stdout": result.stdout, "stderr": result.stderr, "error": result.error}, [evidence.stored_name])

            tool = "tshark_summary" if evidence.stored_name.lower().endswith((".pcap", ".pcapng")) else "grep_indicators"
            calls += 1
            await emit("thought", {"text": f"Inspecting {evidence.stored_name} with {tool}; imported skills are available for specialized follow-up."}, [evidence.stored_name])
            await emit("action", {"tool": tool, "path": evidence.stored_name}, [evidence.stored_name])
            result = self.runner.run(tool, self._workspace(investigation), evidence.stored_name)
            text = result.stdout or result.stderr or result.error or "No output"
            await emit("observation", {"tool": result.tool, "success": result.success, "available": result.available, "stdout": result.stdout, "stderr": result.stderr, "error": result.error}, [evidence.stored_name])
            stage, confidence = classify(text, evidence.original_name)
            if text and stage:
                finding = Finding(title=f"{tool} finding", description=text[:2000], source_file=evidence.stored_name, stage=stage, confidence=confidence, iocs=[])
                investigation.findings.append(finding)
                await emit("finding", finding.model_dump(mode="json"), [evidence.stored_name], confidence)
                await emit("stage_update", {"stage": stage.value, "confidence": confidence}, [evidence.stored_name], confidence)
        investigation.status = "completed"
        await emit("status", {"status": "completed", "tool_calls": calls})

    def _workspace(self, investigation: Investigation) -> Path:
        return self.settings.workspace_root / str(investigation.id)
