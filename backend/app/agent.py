from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .ioc import extract_iocs
from .killchain import classify
from .models import Finding, Investigation, InvestigationEvent, MemoryRecord, ModelConfig, Stage
from .providers import OpenAICompatibleProvider, ProviderError
from .skills import SkillSummary, load_skill_catalog
from .tools import ToolRunner

EventSink = Callable[[InvestigationEvent], Awaitable[None]]


class Agent:
    """Bounded evidence-first investigator with deterministic and LLM planners."""

    def __init__(self, settings: Settings, runner: ToolRunner, skills_root: Path, config: ModelConfig | None = None):
        self.settings, self.runner, self.skills_root = settings, runner, skills_root
        self.config = config or ModelConfig()

    async def investigate(self, investigation: Investigation, sink: EventSink, prior_memories: list[MemoryRecord] | None = None) -> None:
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
        if prior_memories:
            await emit("memory_recall", {"count": len(prior_memories), "memories": [item.model_dump(mode="json") for item in prior_memories[:5]]})
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
            queue = self._initial_plan(evidence.stored_name, evidence.file_type or "", selected)
            evidence_finding_start = len(investigation.findings)
            while queue and calls < self.settings.max_tool_calls:
                tool = queue.pop(0)
                thought = f"Inspect {evidence.stored_name} with {tool}; correlate its output with prior evidence."
                if self.config.provider != "rule_based":
                    try:
                        decision = await self._model_decision(investigation, evidence.stored_name, tool, selected, prior_memories)
                        thought = decision.get("thought", thought)
                        candidate = decision.get("tool", tool)
                        allowed_tools = {item["function"]["name"] for item in self.runner.schemas()}
                        if candidate not in allowed_tools:
                            raise ProviderError("model selected an unavailable tool")
                        tool = candidate
                        if decision.get("done"):
                            break
                    except ProviderError as exc:
                        await emit("provider_error", {"error": str(exc), "fallback": "rule_based"}, refs)
                calls += 1
                await emit("thought", {"text": thought}, refs)
                await emit("action", {"tool": tool, "path": evidence.stored_name}, refs)
                result = self.runner.run(tool, workspace, evidence.stored_name)
                text = result.stdout or result.stderr or result.error or ""
                observation = self._result(result, text)
                await emit("observation", observation, refs)
                stage, confidence = classify(text, evidence.original_name)
                if text and (stage or tool not in {"sha256sum", "file_triage"}):
                    iocs = [item["value"] for item in extract_iocs([text])]
                    timestamp = self._extract_timestamp(text)
                    # Sequence is established from extracted artifact timestamps, not
                    # from whichever tool happened to run first. Missing timestamps
                    # are unknown, not evidence of an out-of-order attack.
                    is_tentative = stage is not None and timestamp is None
                    finding = Finding(title=f"{tool} finding", description=text[:2000], source_file=evidence.stored_name, stage=stage, confidence=confidence if stage else 0.45, iocs=iocs, tentative=is_tentative, timestamp=timestamp)
                    investigation.findings.append(finding)
                    if stage and not is_tentative:
                        investigation.stages[stage] = max(confidence, investigation.stages.get(stage, 0))
                    await emit("finding", finding.model_dump(mode="json"), refs, finding.confidence)
                    if stage:
                        await emit("stage_update", {"stage": stage.value, "confidence": confidence, "tentative": is_tentative}, refs, confidence)
            # A file must contribute an observation based on content even when no
            # stage-specific rule matches. Hashes and file-type labels alone do not
            # satisfy evidence coverage.
            if len(investigation.findings) == evidence_finding_start:
                coverage_text = f"No stage-specific behavior was confirmed; substantive artifact content was processed from {evidence.stored_name} ({evidence.file_type or 'unknown type'})."
                finding = Finding(title="evidence content reviewed", description=coverage_text, source_file=evidence.stored_name, confidence=0.40)
                investigation.findings.append(finding)
                await emit("finding", finding.model_dump(mode="json"), refs, finding.confidence)
        investigation.status = "completed"
        await emit("status", {"status": "completed", "tool_calls": calls, "findings": len(investigation.findings)})

    async def _model_decision(
        self,
        investigation: Investigation,
        filename: str,
        suggested: str,
        skills: list[SkillSummary] = None,
        prior_memories: list[MemoryRecord] | None = None,
    ) -> dict[str, Any]:
        provider = OpenAICompatibleProvider(self.config)
        system_prompt = "You are a forensic analyst. Return JSON only with keys thought, tool, done. Choose only from the supplied tools and never invent evidence. Make thought a specific 2-4 sentence analyst rationale: explain what the last observation means, why the selected tool is the best next step, and what evidence would confirm or weaken the hypothesis. Separate observed facts from hypotheses."
        if prior_memories:
            memory_text = "\n\n".join(f"Prior analyst feedback ({memory.kind}, confidence {memory.confidence:.2f}): {memory.content}" for memory in prior_memories[:5])
            system_prompt += f"\n\nPrior analyst feedback is context, not proof:\n{memory_text}"
        if skills:
            skill_text = "\n\n".join(f"Skill: {s.name}\nOverview: {s.overview}" for s in skills[:3] if s.overview)
            if skill_text:
                system_prompt += f"\n\nRelevant Skills:\n{skill_text}"
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": json.dumps({"file": filename, "suggested_tool": suggested, "findings": [item.model_dump(mode="json") for item in investigation.findings[-10:]]})}]
        response = await asyncio.to_thread(provider.complete, messages, self.runner.schemas())
        try:
            value = json.loads(response.content)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderError("model response must be a JSON decision object") from exc

    def _initial_plan(self, name: str, file_type: str, selected_skills: list[SkillSummary] = None) -> list[str]:
        lower = name.lower() + " " + file_type.lower()
        if name.lower().endswith((".pcap", ".pcapng")) or "pcap" in lower:
            queue = ["tshark_summary", "tshark_details", "strings_extract", "sha256sum"]
        elif "memory" in lower or name.lower().endswith((".raw", ".dmp", ".mem")):
            queue = ["strings_extract", "volatility_info", "sha256sum"]
        elif name.lower().endswith(".csv"):
            queue = ["csv_events", "grep_indicators", "strings_extract", "sha256sum"]
        else:
            queue = ["grep_indicators", "strings_extract", "sha256sum"]
            
        if selected_skills:
            available_tools = {s["function"]["name"] for s in self.runner.schemas()}
            skill_tools = []
            for skill in selected_skills:
                for t in skill.tools:
                    if t in available_tools and t not in skill_tools and t not in queue:
                        skill_tools.append(t)
            queue.extend(skill_tools)
        return queue

    @staticmethod
    def _select_skills(catalog: list[SkillSummary], text: str) -> list[SkillSummary]:
        query = set(re.findall(r"[a-z0-9]+", text.lower()))
        if not query:
            return []
        evidence_weights = {
            "pcap": {"pcap", "pcapng", "packet", "traffic", "tshark", "wireshark", "network", "dns"},
            "pcapng": {"pcap", "pcapng", "packet", "traffic", "tshark", "wireshark", "network", "dns"},
            "memory": {"memory", "volatility", "ram", "dump", "forensics"},
            "apk": {"android", "apk", "mobile", "jadx", "frida"},
            "pdf": {"pdf", "document", "malware", "peepdf"},
        }
        boosted = set().union(*(evidence_weights[key] for key in query if key in evidence_weights))
        ranked: list[tuple[int, int, SkillSummary]] = []
        for index, skill in enumerate(catalog):
            corpus = " ".join((skill.name, skill.description, skill.overview, skill.when_to_use)).lower()
            tokens = set(re.findall(r"[a-z0-9]+", corpus))
            score = len(query & tokens) + 3 * len(boosted & tokens)
            if score:
                ranked.append((score, -index, skill))
        ranked.sort(reverse=True, key=lambda item: (item[0], item[1]))
        return [item[2] for item in ranked[:8]]

    @staticmethod
    def _extract_timestamp(text: str) -> datetime | None:
        epoch = re.search(r"(?:^|\|)(1[5-9]\d{8,}|20\d{8,})(?:\.\d+)?(?:\||$)", text, re.MULTILINE)
        if epoch:
            try:
                return datetime.fromtimestamp(float(epoch.group(1)), tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                pass
        for pattern in (r"\b(20\d{2}-\d{2}-\d{2}[T ][0-9:.+-]+Z?)\b", r"\b(20\d{2}/\d{2}/\d{2}[ T][0-9:.+-]+)\b"):
            match = re.search(pattern, text)
            if match:
                value = match.group(1).replace("Z", "+00:00").replace("/", "-")
                try:
                    parsed = datetime.fromisoformat(value)
                    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _result(result: Any, text: str = "") -> dict[str, Any]:
        payload = {"tool": result.tool, "success": result.success, "available": result.available, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "error": result.error}
        if result.tool.startswith("tshark"):
            lines = [line for line in text.splitlines() if line.strip()]
            payload["records_analyzed"] = max(0, len(lines) - (1 if result.tool == "tshark_details" and lines else 0))
        elif result.tool == "csv_events":
            payload["records_analyzed"] = len([line for line in text.splitlines() if line.startswith("CSV_RECORD|")])
            payload["parse_note"] = next((line.split("|", 1)[1] for line in text.splitlines() if line.startswith("CSV_PARSE_NOTE|")), None)
        elif result.tool not in {"sha256sum", "file_triage"}:
            payload["records_analyzed"] = len([line for line in text.splitlines() if line.strip()])
        return payload
