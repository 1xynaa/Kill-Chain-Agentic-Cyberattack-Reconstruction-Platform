from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .ioc import extract_iocs
from .killchain import STAGE_ORDER, stage_scores
from .models import Finding, Investigation, ReportResponse, Stage


def _evidence_summary(investigation: Investigation) -> str:
    if not investigation.files:
        return "No evidence files were submitted."
    counts: dict[str, list[int]] = defaultdict(list)
    for event in investigation.events:
        if event.type == "observation":
            analyzed = event.payload.get("records_analyzed")
            if analyzed is not None:
                for ref in event.evidence_refs:
                    counts[ref].append(int(analyzed))
    entries = []
    for evidence in investigation.files:
        file_type = evidence.file_type or "type not determined"
        analyzed = max(counts.get(evidence.stored_name, [0]))
        derived = sum(1 for finding in investigation.findings if finding.source_file == evidence.stored_name and finding.title != "evidence content reviewed")
        entries.append(
            f"- {evidence.original_name} ({file_type}, {evidence.size:,} bytes, SHA-256 {evidence.sha256}); "
            f"records/lines analyzed: {analyzed}; substantive findings derived: {derived}"
        )
    return "\n".join(entries)


def _finding_details(investigation: Investigation, ordered: list[Finding]) -> str:
    if not ordered:
        return "No findings were produced from the available evidence."
    details = []
    for index, finding in enumerate(ordered, 1):
        stage = finding.stage.value if finding.stage else "Unmapped"
        confidence = f"{finding.confidence:.0%}"
        source = finding.source_file or "unknown evidence"
        timestamp = finding.timestamp.isoformat() if isinstance(finding.timestamp, datetime) else "timestamp unavailable"
        iocs = ", ".join(finding.iocs) if finding.iocs else "none extracted"
        details.append(
            f"{index}. [{timestamp}] {stage} ({confidence}) from {source}. {finding.title}.\n"
            f"   What was observed: {finding.description}\n"
            f"   Indicators: {iocs}\n"
            f"   Assessment: this observation supports the {stage} stage at {confidence} confidence; "
            f"it is {'tentative because it lacks a correlatable timestamp' if finding.tentative else 'confirmed in the reconstructed sequence'}."
        )
    return "\n\n".join(details)


def _tool_trace(investigation: Investigation) -> str:
    actions = [event for event in investigation.events if event.type == "action"]
    observations = [event for event in investigation.events if event.type == "observation"]
    if not actions:
        return "No forensic tool actions were recorded."
    tools = ", ".join(str(event.payload.get("tool", "unknown")) for event in actions)
    analyzed = sum(int(event.payload.get("records_analyzed", 0)) for event in observations)
    return (
        f"The agent recorded {len(actions)} tool action(s), {len(observations)} observation(s), and analyzed "
        f"{analyzed} reported record/line unit(s) to completion. Tools used in order: {tools}."
    )


def _correlate_lateral_findings(findings: list[Finding]) -> list[Finding]:
    lateral = [f for f in findings if f.stage == Stage.LATERAL_MOVEMENT]
    if len(lateral) < 2:
        return findings
    merged: list[Finding] = []
    consumed: set[str] = set()
    for finding in lateral:
        if str(finding.id) in consumed:
            continue
        related = [other for other in lateral if other.id != finding.id and other.source_file != finding.source_file and (not finding.timestamp or not other.timestamp or abs((finding.timestamp - other.timestamp).total_seconds()) <= 300)]
        if related:
            for other in related:
                consumed.add(str(other.id))
            sources = sorted({item.source_file for item in [finding, *related] if item.source_file})
            accounts = sorted({ioc for item in [finding, *related] for ioc in item.iocs if "\\" in ioc or ioc.startswith("User:")})
            finding.description += " Supporting correlated sources: " + ", ".join(sources) + "."
            if accounts:
                finding.description += " Account indicators: " + ", ".join(accounts) + "."
            finding.confidence = min(0.99, round(max(item.confidence for item in [finding, *related]) + 0.08, 2))
            finding.tentative = False
        merged.append(finding)
    return [item for item in findings if item.stage != Stage.LATERAL_MOVEMENT or str(item.id) not in consumed]


def _indicator_text(investigation: Investigation) -> str:
    return " ".join(
        f"{finding.description} {' '.join(finding.iocs)}"
        for finding in investigation.findings
    ).lower()


def _indicator_gap(stage: Stage, indicators: str) -> str | None:
    if stage is Stage.ACTIONS and any(term in indicators for term in (".locked", "readme_to_decrypt", "readme to decrypt", "ransom note")):
        return "Actions on Objectives / Impact: impact indicators are present (.locked/ransom-note artifacts), but insufficient corroboration prevented a confirmed stage."
    if stage is Stage.LATERAL_MOVEMENT and ("445" in indicators or "smb" in indicators) and any(term in indicators for term in ("source=", "src=", "destination=", "dest=")):
        return "Lateral Movement: host-pair/SMB indicators are present, but fewer than two independently corroborating artifacts were available."
    if stage is Stage.CREDENTIAL_ACCESS and "lsass" in indicators:
        return "Credential Access: LSASS is mentioned, but no explicit handle-open/access event was confirmed."
    return None


def build_report(investigation: Investigation) -> ReportResponse:
    investigation.findings = _correlate_lateral_findings(investigation.findings)
    values = [f"{f.title} {f.description} {' '.join(f.iocs)}" for f in investigation.findings]
    iocs = extract_iocs(values)
    ordered = sorted(investigation.findings, key=lambda item: item.timestamp or investigation.created_at)
    scores = stage_scores(investigation.findings)
    stage_text = " → ".join(f"{finding.stage.value} ({finding.confidence:.0%})" for finding in ordered if finding.stage and not finding.tentative) or "No kill-chain stages were confirmed."
    missing = [stage.value for stage in STAGE_ORDER if stage not in scores]
    recon_note = "Reconnaissance: no evidence." if Stage.RECONNAISSANCE not in scores else ""
    missing_note = f" Unconfirmed stages: {', '.join(missing)}." if missing else ""
    gap_notes = []
    indicators = _indicator_text(investigation)
    if Stage.CREDENTIAL_ACCESS not in scores:
        gap_notes.append(_indicator_gap(Stage.CREDENTIAL_ACCESS, indicators) or "Credential Access: no evidence of an LSASS handle or credential-dumping signature.")
    if Stage.LATERAL_MOVEMENT not in scores:
        gap_notes.append(_indicator_gap(Stage.LATERAL_MOVEMENT, indicators) or "Lateral Movement: no evidence; source host, destination host, and account used could not be established.")
    if Stage.ACTIONS not in scores:
        gap_notes.append(_indicator_gap(Stage.ACTIONS, indicators) or "Actions on Objectives / Impact: no evidence of encryption, exfiltration, or destructive action.")
    narrative = (
        f"INVESTIGATION REPORT — {investigation.id}\n\n"
        f"EXECUTIVE SUMMARY\n"
        f"Status: {investigation.status}. The investigation produced {len(investigation.findings)} finding(s) and {len(iocs)} unique indicator(s). "
        f"The evidence-supported sequence is: {stage_text}.{missing_note}\n"
        f"{recon_note}\n" + "\n".join(gap_notes) + "\n\n"
        f"EVIDENCE EXAMINED\n{_evidence_summary(investigation)}\n\n"
        f"ANALYST REASONING AND FINDINGS\n{_finding_details(investigation, ordered)}\n\n"
        f"FORENSIC ACTIVITY\n{_tool_trace(investigation)}\n\n"
        f"LIMITATIONS\nThis reconstruction reflects only observable output from submitted artifacts and bounded tools. "
        f"Unconfirmed stages are explicitly reported as no evidence, not inferred as fact."
    )
    if investigation.llm_narrative:
        narrative += f"\n\nPLAIN-ENGLISH ATTACK PATH FROM THE AGENT\n{investigation.llm_narrative}"
    return ReportResponse(investigation_id=investigation.id, status=investigation.status, narrative=narrative, llm_narrative=investigation.llm_narrative, timeline=ordered, iocs=iocs, stages=scores)
