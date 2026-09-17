from datetime import datetime, timezone
from pathlib import Path

from backend.app.ioc import extract_iocs
from backend.app.killchain import classify
from backend.app.models import EvidenceFile, Finding, Investigation, Stage
from backend.app.report import build_report


def test_indicator_classifier_rejects_artifacts_and_emits_explicit_types():
    text = (
        "User: alice authenticated via windows.pslist.PsList; "
        "services.exe loaded ntdll.dll from C:\\Windows\\System32\\x.dll; "
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater; "
        "c2-beacon.attacker-domain.com and 185.220.101.5"
    )
    iocs = extract_iocs([text])
    values = {(item["type"], item["value"]) for item in iocs}
    assert ("domain", "c2-beacon.attacker-domain.com") in values
    assert ("ip", "185.220.101.5") in values
    assert ("process_name", "services.exe") in values
    assert ("dll_name", "ntdll.dll") in values
    assert ("username", "alice") in values
    assert ("registry_key", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater") in values
    assert not any(kind == "domain" and value in {"services.exe", "ntdll.dll", "alice", "windows.pslist.PsList"} for kind, value in values)


def test_stage_classifier_does_not_call_dns_or_download_recon():
    assert classify("dns resolution", "victim resolved c2-beacon.attacker-domain.com") [0] != Stage.RECONNAISSANCE
    assert classify("payload download", "payload downloaded over HTTPS") [0] != Stage.RECONNAISSANCE
    assert classify("port scan", "attacker scanned victim ports") [0] == Stage.RECONNAISSANCE
    assert classify("lsass handle", "process opened a handle to lsass.exe") [0] == Stage.CREDENTIAL_ACCESS
    assert classify("SMB logon", "source=10.0.0.5 dest=10.0.0.15 account=CORP\\alice EventID=4624") [0] == Stage.LATERAL_MOVEMENT
    assert classify("impact", "files encrypted and exfiltrated") [0] == Stage.ACTIONS


def test_report_orders_by_extracted_timestamp_and_reports_unconfirmed_recon():
    inv = Investigation(
        files=[EvidenceFile(original_name="security.csv", stored_name="security.csv", size=10, sha256="a" * 64, file_type="CSV")],
        status="completed",
        findings=[
            Finding(title="later", description="files encrypted", source_file="security.csv", stage=Stage.ACTIONS, confidence=.9, timestamp=datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc)),
            Finding(title="earlier", description="payload written to disk", source_file="security.csv", stage=Stage.INSTALLATION, confidence=.8, timestamp=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc)),
        ],
    )
    report = build_report(inv)
    assert [item.title for item in report.timeline] == ["earlier", "later"]
    assert "Reconnaissance" not in report.stages
    assert "no confirmed evidence" in report.narrative.lower() or "unconfirmed" in report.narrative.lower()


def test_report_tracks_substantive_evidence_coverage():
    inv = Investigation(
        files=[EvidenceFile(original_name="a.log", stored_name="a.log", size=1, sha256="a" * 64, file_type="ASCII text")],
        status="completed",
        findings=[Finding(title="log observation", description="Accepted login from source host", source_file="a.log", confidence=.6)],
    )
    report = build_report(inv)
    assert "a.log" in report.narrative
    assert "substantive" in report.narrative.lower()


def test_lateral_movement_sources_are_merged_when_hosts_and_time_correlate():
    stamp = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    inv = Investigation(
        files=[
            EvidenceFile(original_name="traffic.pcap", stored_name="traffic.pcap", size=1, sha256="a" * 64),
            EvidenceFile(original_name="security.csv", stored_name="security.csv", size=1, sha256="b" * 64),
            EvidenceFile(original_name="system.csv", stored_name="system.csv", size=1, sha256="c" * 64),
        ],
        status="completed",
        findings=[
            Finding(title="SMB session", description="SMB session source=10.0.0.5 dest=10.0.0.15", source_file="traffic.pcap", stage=Stage.LATERAL_MOVEMENT, confidence=.8, timestamp=stamp, iocs=["10.0.0.5", "10.0.0.15"]),
            Finding(title="4624 logon", description="EventID=4624 source=10.0.0.5 dest=10.0.0.15 account=CORP\\alice", source_file="security.csv", stage=Stage.LATERAL_MOVEMENT, confidence=.85, timestamp=stamp, iocs=["CORP\\alice"]),
            Finding(title="7045 service", description="EventID=7045 source=10.0.0.5 dest=10.0.0.15 account=CORP\\alice", source_file="system.csv", stage=Stage.LATERAL_MOVEMENT, confidence=.82, timestamp=stamp, iocs=["CORP\\alice"]),
        ],
    )
    report = build_report(inv)
    lateral = [item for item in report.timeline if item.stage == Stage.LATERAL_MOVEMENT]
    assert len(lateral) == 1
    assert "traffic.pcap" in lateral[0].description and "security.csv" in lateral[0].description and "system.csv" in lateral[0].description
    assert "CORP\\alice" in lateral[0].description
    assert lateral[0].confidence >= .93
