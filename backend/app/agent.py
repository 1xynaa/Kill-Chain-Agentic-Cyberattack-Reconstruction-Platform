from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .config import Settings
from .ioc import extract_iocs
from .killchain import classify
from .models import Finding, Investigation, InvestigationEvent, ModelConfig, Stage
from .providers import OpenAICompatibleProvider, ProviderError
from .skills import SkillSummary, load_skill_catalog
from .tools import ToolRunner

EventSink = Callable[[InvestigationEvent], Awaitable[None]]


class Agent:
    """Bounded evidence-first investigator with deterministic and LLM planners."""

    def __init__(self, settings: Settings, runner: ToolRunner, skills_root: Path, config: ModelConfig | None = None):
        self.settings, self.runner, self.skills_root = settings, runner, skills_root
        self.config = config or ModelConfig()

    async def investigate(self, investigation: Investigation, sink: EventSink) -> None:
        investigation.status = "running"
        sequence = len(investigation.events)
        calls = 0
        catalog = load_skill_catalog(self.skills_root)

        async def emit(kind: str, payload: dict[str, Any], refs: list[str] | None = None, confidence: float | None = None):
            nonlocal sequence
            sequence += 1
            event = InvestigationEvent(investigation_id=investigation.id, sequence=sequence, type=kind, payload=payload, evidence_refs=refs or [], confidence=confidence)
            investigation.events.append(event)
            await sink(event)

        await emit("status", {"status": "running", "planner": self.config.provider, "skill_count": len(catalog)})
        for evidence in investigation.files:
            if calls >= self.settings.max_tool_calls:
                await emit("status", {"status": "budget_exhausted", "tool_calls": calls})
                break
            workspace = self.settings.workspace_root / str(investigation.id)
            refs = [evidence.stored_name]
            calls += 1
            await emit("thought", {"text": f"Start with forensic triage of {evidence.stored_name}."}, refs)
            await emit("action", {"tool": "file_triage", "path": evidence.stored_name}, refs)
            triage = self.runner.run("file_triage", workspace, evidence.stored_name)
            evidence.file_type = triage.stdout.strip() or triage.error or "unknown"
            await emit("observation", self._result(triage), refs)

            selected = self._select_skills(catalog, evidence.stored_name + " " + (evidence.file_type or ""))
            if selected:
                await emit("skill_select", {"skills": [skill.name for skill in selected[:8]]}, refs)
            queue = self._initial_plan(evidence.stored_name, evidence.file_type or "")
            while queue and calls < self.settings.max_tool_calls:
                tool = queue.pop(0)
                thought = f"Inspect {evidence.stored_name} with {tool}; correlate its output with prior evidence."
                if self.config.provider != "rule_based":
                    try:
                        decision = await self._model_decision(investigation, evidence.stored_name, tool)
                        thought = decision.get("thought", thought)
                        tool = decision.get("tool", tool)
                        if decision.get("done"):
                            break
                    except ProviderError as exc:
                        await emit("provider_error", {"error": str(exc), "fallback": "rule_based"}, refs)
                calls += 1
                await emit("thought", {"text": thought}, refs)
                await emit("action", {"tool": tool, "path": evidence.stored_name}, refs)
                result = self.runner.run(tool, workspace, evidence.stored_name)
                await emit("observation", self._result(result), refs)
                text = result.stdout or result.stderr or result.error or ""
                stage, confidence = classify(text, evidence.original_name)
                if text and stage:
                    iocs = [item["value"] for item in extract_iocs(text)]
                    finding = Finding(title=f"{tool} finding", description=text[:2000], source_file=evidence.stored_name, stage=stage, confidence=confidence, iocs=iocs)
                    investigation.findings.append(finding)
                    investigation.stages[stage] = max(confidence, investigation.stages.get(stage, 0))
                    await emit("finding", finding.model_dump(mode="json"), refs, confidence)
                    await emit("stage_update", {"stage": stage.value, "confidence": confidence}, refs, confidence)
        investigation.status = "completed"
        await emit("status", {"status": "completed", "tool_calls": calls, "findings": len(investigation.findings)})

    async def _model_decision(self, investigation: Investigation, filename: str, suggested: str) -> dict[str, Any]:
        provider = OpenAICompatibleProvider(self.config)
        messages = [{"role": "system", "content": "You are a forensic analyst. Return JSON only: thought, tool, done. Choose only from the supplied tools and never invent evidence."}, {"role": "user", "content": json.dumps({"file": filename, "suggested_tool": suggested, "findings": [item.model_dump(mode="json") for item in investigation.findings[-10:]]})}]
        response = await asyncio.to_thread(provider.complete, messages, self.runner.schemas())
        try:
            value = json.loads(response.content)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderError("model response must be a JSON decision object") from exc

    @staticmethod
    def _initial_plan(name: str, file_type: str) -> list[str]:
        lower = name.lower() + " " + file_type.lower()
        if name.lower().endswith((".pcap", ".pcapng")) or "pcap" in lower:
            return ["tshark_summary", "strings_extract", "sha256sum"]
        if "memory" in lower or name.lower().endswith((".raw", ".dmp", ".mem")):
            return ["strings_extract", "volatility_info", "sha256sum"]
        return ["grep_indicators", "strings_extract", "sha256sum"]

    @staticmethod
    def _select_skills(catalog: list[SkillSummary], text: str) -> list[SkillSummary]:
        terms = set(text.lower().replace("_", " ").split())
        return [skill for skill in catalog if terms & set(skill.name.lower().replace("-", " ").split())]

    @staticmethod
    def _result(result: Any) -> dict[str, Any]:
        return {"tool": result.tool, "success": result.success, "available": result.available, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "error": result.error}
