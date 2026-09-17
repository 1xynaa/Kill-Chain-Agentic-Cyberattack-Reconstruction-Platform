from __future__ import annotations

from .models import Finding, Stage

# These rules are deliberately specific. A generic word such as "dns", "ssh", or
# "download" is not enough to establish a kill-chain stage.
_RULES: list[tuple[tuple[str, ...], Stage, float]] = [
    (("port scan", "network scan", "scanned ports", "whois", "osint", "enumeration", "reconnaissance"), Stage.RECONNAISSANCE, 0.82),
    (("weaponized", "weaponization", "malicious archive"), Stage.WEAPONIZATION, 0.72),
    (("phishing email", "email attachment", "malicious attachment", "delivery mechanism", "payload delivered"), Stage.DELIVERY, 0.80),
    (("macro spawned", "exploit executed", "code execution", "shell spawned", "attacker code executes", "sql injection", "brute force", "failed ssh login", "exploit"), Stage.EXPLOITATION, 0.88),
    (("written to disk", "payload written", "dropped payload", "registry run", "scheduled task", "service installed", "persistence established"), Stage.INSTALLATION, 0.88),
    (("lsass", "mimikatz", "sekurlsa", "credential dump", "dumping credentials", "opened a handle to lsass"), Stage.CREDENTIAL_ACCESS, 0.91),
    (("eventid=4624", "event id 4624", "smb session", "winrm session", "rdp session", "lateral movement", "authenticated to", "new logon"), Stage.LATERAL_MOVEMENT, 0.90),
    (("recurring outbound", "beacon", "command and control", "c2 traffic", "dns tunnel"), Stage.C2, 0.86),
    (("files encrypted", "file encryption", "exfiltrated", "data exfiltration", "destructive action", "actions on objectives", "impact"), Stage.ACTIONS, 0.90),
]

STAGE_ORDER = [
    Stage.RECONNAISSANCE, Stage.WEAPONIZATION, Stage.DELIVERY,
    Stage.EXPLOITATION, Stage.INSTALLATION, Stage.C2,
    Stage.CREDENTIAL_ACCESS, Stage.LATERAL_MOVEMENT, Stage.ACTIONS,
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


def has_reconnaissance(findings: list[Finding]) -> bool:
    return any(f.stage == Stage.RECONNAISSANCE for f in findings)
