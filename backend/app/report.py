from __future__ import annotations

from .ioc import extract_iocs
from .killchain import stage_scores
from .models import Investigation, ReportResponse


def build_report(investigation: Investigation) -> ReportResponse:
    values = [f"{f.title} {f.description} {' '.join(f.iocs)}" for f in investigation.findings]
    iocs = extract_iocs(values)
    ordered = sorted(investigation.findings, key=lambda item: item.timestamp or investigation.created_at)
    stage_text = "; ".join(
        f"{finding.stage.value} ({finding.confidence:.0%}) — {finding.title}"
        for finding in ordered if finding.stage
    ) or "No kill-chain stages were confirmed."
    narrative = (
        f"Investigation {investigation.id} produced {len(investigation.findings)} finding(s). "
        f"The evidence-supported sequence is: {stage_text}"
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
