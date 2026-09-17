from __future__ import annotations

import csv
import hashlib
import io
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import Settings


@dataclass(frozen=True)
class ToolSpec:
    name: str
    executable: str
    description: str
    args: Callable[[Path], list[str]]
    network: bool = False


@dataclass
class ToolResult:
    tool: str
    success: bool
    available: bool
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None


class ToolRunner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.specs = self._specs()

    def _specs(self) -> dict[str, ToolSpec]:
        return {
            "file_triage": ToolSpec("file_triage", "file", "Identify evidence type", lambda p: ["--brief", str(p)]),
            "strings_extract": ToolSpec("strings_extract", "strings", "Extract printable strings", lambda p: ["-n", "6", str(p)]),
            "sha256sum": ToolSpec("sha256sum", "sha256sum", "Hash evidence", lambda p: [str(p)]),
            "tshark_summary": ToolSpec("tshark_summary", "tshark", "Summarize packet capture conversations", lambda p: ["-r", str(p), "-q", "-z", "conv,ip"]),
            "tshark_details": ToolSpec(
                "tshark_details",
                "tshark",
                "Extract packet-level endpoints, ports, DNS names, and HTTP indicators",
                lambda p: [
                    "-r", str(p), "-Y", "ip", "-T", "fields", "-E", "header=y", "-E", "separator=|",
                    "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
                    "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags.syn", "-e", "tcp.flags.ack",
                    "-e", "udp.srcport", "-e", "udp.dstport", "-e", "dns.qry.name", "-e", "http.host",
                    "-e", "http.request.uri",
                ],
            ),
            "yara_scan": ToolSpec("yara_scan", "yara", "Scan evidence with YARA", lambda p: ["-r", "rules.yar", str(p)]),
            "volatility_info": ToolSpec("volatility_info", "vol", "Identify memory image metadata", lambda p: ["-f", str(p), "windows.info"]),
            "binwalk_scan": ToolSpec("binwalk_scan", "binwalk", "Inspect embedded firmware content", lambda p: ["--run-as=root", str(p)]),
            "exiftool_metadata": ToolSpec("exiftool_metadata", "exiftool", "Extract metadata", lambda p: [str(p)]),
            "grep_indicators": ToolSpec("grep_indicators", "grep", "Search evidence text for indicators", lambda p: ["-Ein", "(failed|accepted|ssh|sudo|exec|http|dns|beacon)", str(p)]),
            "csv_events": ToolSpec("csv_events", "python3", "Parse CSV event records and normalize security fields", lambda p: [str(p)]),
            "nmap": ToolSpec("nmap", "nmap", "Optional active network inventory", lambda p: ["-sV", "-Pn", "--", str(p)], network=True),
            "dig": ToolSpec("dig", "dig", "Optional DNS lookup", lambda p: ["+noall", "+answer", str(p)], network=True),
            "whois": ToolSpec("whois", "whois", "Optional registration lookup", lambda p: [str(p)], network=True),
        }

    def available(self) -> list[dict[str, object]]:
        return [{"name": s.name, "executable": s.executable, "available": shutil.which(s.executable) is not None, "network": s.network, "description": s.description} for s in self.specs.values()]

    def schemas(self) -> list[dict[str, object]]:
        return [{"type": "function", "function": {"name": s.name, "description": s.description, "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}} for s in self.specs.values() if not s.network]

    def run(self, name: str, workspace: Path, relative_path: str) -> ToolResult:
        spec = self.specs.get(name)
        if not spec:
            return ToolResult(name, False, False, None, "", "", "unknown tool")
        if spec.network and not self.settings.allow_network_tools:
            return ToolResult(name, False, shutil.which(spec.executable) is not None, None, "", "", "network tools disabled")
        executable = shutil.which(spec.executable)
        if not executable:
            return ToolResult(name, False, False, None, "", "", f"{spec.executable} is not installed")
        target = (workspace / relative_path).resolve()
        if workspace.resolve() not in target.parents or not target.is_file():
            return ToolResult(name, False, True, None, "", "", "evidence path is outside workspace")
        if name == "csv_events":
            return self._parse_csv_events(target)
        try:
            completed = subprocess.run([executable, *spec.args(target)], cwd=workspace, capture_output=True, text=True, timeout=self.settings.tool_timeout, shell=False)
            return ToolResult(name, completed.returncode == 0, True, completed.returncode, completed.stdout[: self.settings.max_tool_output], completed.stderr[: self.settings.max_tool_output])
        except subprocess.TimeoutExpired as exc:
            return ToolResult(name, False, True, None, (exc.stdout or "")[: self.settings.max_tool_output], (exc.stderr or "")[: self.settings.max_tool_output], "tool timeout")
        except OSError as exc:
            return ToolResult(name, False, True, None, "", "", str(exc))

    @staticmethod
    def _parse_csv_events(path: Path) -> ToolResult:
        try:
            text = path.read_text(encoding="utf-8-sig", errors="strict")
            if not text.strip():
                return ToolResult("csv_events", True, True, 0, "CSV_PARSE_NOTE|file is empty", "")
            reader = csv.DictReader(io.StringIO(text))
            headers = {str(item).strip().lower().replace(" ", "_") for item in (reader.fieldnames or [])}
            known = {"eventid", "event_id", "timecreated", "timestamp", "source", "source_ip", "destination", "destination_ip", "accountname", "account", "servicename", "service", "path", "filepath", "file_path"}
            if not headers or not headers & known:
                return ToolResult("csv_events", False, True, 0, "", "CSV_PARSE_NOTE|file parsed but contained no events matching known schemas")
            rows = []
            for row in reader:
                values = {str(key).strip(): str(value).strip() for key, value in row.items() if key and value not in (None, "")}
                if values:
                    rows.append("CSV_RECORD|" + "|".join(f"{key}={value}" for key, value in values.items()))
            if not rows:
                return ToolResult("csv_events", True, True, 0, "CSV_PARSE_NOTE|file parsed but contained no events matching known schemas", "")
            return ToolResult("csv_events", True, True, 0, "\n".join(rows), "")
        except (UnicodeDecodeError, csv.Error, OSError) as exc:
            return ToolResult("csv_events", False, True, None, "", "", f"CSV_PARSE_NOTE|file could not be parsed: {exc}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
