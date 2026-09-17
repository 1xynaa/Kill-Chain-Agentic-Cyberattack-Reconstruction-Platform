from __future__ import annotations

from .ioc import extract_iocs
from .killchain import stage_scores
from .models import Investigation, ReportResponse


def _evidence_summary(investigation: Investigation) -> str:
    if not investigation.files:
        return "No evidence files were submitted."
    entries = []
    for evidence in investigation.files:
        file_type = evidence.file_type or "type not determined"
        entries.append(
            f"- {evidence.original_name} ({file_type}, {evidence.size:,} bytes, SHA-256 {evidence.sha256})"
        )
    return "\n".join(entries)


def _finding_details(investigation: Investigation, ordered) -> str:
    if not ordered:
        return "No findings were produced from the available evidence."
    details = []
    for index, finding in enumerate(ordered, 1):
        stage = finding.stage.value if finding.stage else "Unmapped"
        confidence = f"{finding.confidence:.0%}"
        source = finding.source_file or "unknown evidence"
        timestamp = finding.timestamp or "timestamp unavailable"
        iocs = ", ".join(finding.iocs) if finding.iocs else "none extracted"
        details.append(
            f"{index}. [{timestamp}] {stage} ({confidence}) from {source}. {finding.title}.\n"
            f"   What was observed: {finding.description}\n"
            f"   Indicators: {iocs}\n"
            f"   Assessment: this observation supports the {stage} stage at {confidence} confidence; "
            f"it is {'tentative and out of sequence' if finding.tentative else 'currently confirmed in the reconstructed sequence'}."
        )
    return "\n\n".join(details)


def _tool_trace(investigation: Investigation) -> str:
    actions = [event for event in investigation.events if event.type == "action"]
    observations = [event for event in investigation.events if event.type == "observation"]
    if not actions:
        return "No forensic tool actions were recorded."
    tools = ", ".join(str(event.payload.get("tool", "unknown")) for event in actions)
    return (
        f"The agent recorded {len(actions)} tool action(s) and {len(observations)} observation(s). "
        f"Tools used in order: {tools}. Each finding below is tied to the captured tool output and source file."
    )


def build_report(investigation: Investigation) -> ReportResponse:
    values = [f"{f.title} {f.description} {' '.join(f.iocs)}" for f in investigation.findings]
    iocs = extract_iocs(values)
    ordered = sorted(investigation.findings, key=lambda item: item.timestamp or investigation.created_at)
    stage_text = " → ".join(
        f"{finding.stage.value} ({finding.confidence:.0%})"
        for finding in ordered if finding.stage and not finding.tentative
    ) or "No kill-chain stages were confirmed."
    narrative = (
        f"INVESTIGATION REPORT — {investigation.id}\n\n"
        f"EXECUTIVE SUMMARY\n"
        f"Status: {investigation.status}. The investigation produced {len(investigation.findings)} finding(s) "
        f"and {len(iocs)} unique indicator(s). The evidence-supported sequence is: {stage_text}.\n\n"
        f"EVIDENCE EXAMINED\n{_evidence_summary(investigation)}\n\n"
        f"ANALYST REASONING AND FINDINGS\n{_finding_details(investigation, ordered)}\n\n"
        f"FORENSIC ACTIVITY\n{_tool_trace(investigation)}\n\n"
        f"LIMITATIONS\n"
        f"This reconstruction reflects only observable output from the submitted artifacts and the bounded tools that completed successfully. "
        f"A missing, unsupported, encrypted, corrupted, or platform-mismatched artifact can leave stages unconfirmed; unconfirmed stages are not inferred as fact."
    )
    scores = stage_scores(investigation.findings)
    return ReportResponse(
        investigation_id=investigation.id,
        status=investigation.status,
        narrative=narrative,
        timeline=ordered,
        iocs=iocs,
        stages=scores,
    )
