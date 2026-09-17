from __future__ import annotations

from .models import Finding, Stage

_RULES: list[tuple[tuple[str, ...], Stage, float]] = [
    (("scan", "recon", "whois", "dns"), Stage.RECONNAISSANCE, 0.78),
    (("payload", "malware", "archive", "weapon"), Stage.WEAPONIZATION, 0.70),
    (("phish", "email", "download", "delivery"), Stage.DELIVERY, 0.76),
    (("exploit", "brute", "credential", "sql injection", "failed", "ssh", "login"), Stage.EXPLOITATION, 0.82),
    (("cron", "service", "persistence", "installed"), Stage.INSTALLATION, 0.84),
    (("beacon", "c2", "command and control", "dns tunnel"), Stage.C2, 0.84),
    (("exfil", "ransom", "encrypt", "impact", "objective"), Stage.ACTIONS, 0.85),
]


def classify(title: str, description: str) -> tuple[Stage | None, float]:
    text = f"{title} {description}".lower()
    for terms, stage, confidence in _RULES:
        if any(term in text for term in terms):
            return stage, confidence
    return None, 0.0


def stage_scores(findings: list[Finding]) -> dict[Stage, float]:
    scores: dict[Stage, float] = {}
    for finding in findings:
        if finding.stage:
            scores[finding.stage] = max(scores.get(finding.stage, 0.0), finding.confidence)
    return scores
