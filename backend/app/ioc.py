from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SHA256 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")
DOMAIN = re.compile(r"(?<![@\w])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w])")
WINDOWS_PATH = re.compile(r"(?<![\w])(?:[A-Za-z]:\\|\\\\)[^\s\"'<>;,]+")
REGISTRY_KEY = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)(?:\\[^\s\"'<>;,]+)+", re.IGNORECASE)
PROCESS = re.compile(r"\b[a-zA-Z0-9_-]+\.exe\b", re.IGNORECASE)
DLL = re.compile(r"\b[a-zA-Z0-9_-]+\.(?:dll|sys)\b", re.IGNORECASE)
SERVICE = re.compile(r"(?:service(?: name)?|svc)\s*[:=]\s*['\"]?([A-Za-z0-9_. -]{2,64})", re.IGNORECASE)
USERNAME = re.compile(r"\b(?:user|account|subjectuser(?:name)?|username)\s*[:=]\s*['\"]?([A-Za-z0-9._-]+(?:\\[A-Za-z0-9._-]+)?)", re.IGNORECASE)
PLUGIN = re.compile(r"\b(?:windows|linux)\.[a-z0-9_-]+\.[A-Z][A-Za-z0-9_]*\b")
PACKET_FIELDS = ("dns.", "http.", "ip.", "tcp.", "udp.", "frame.")
KNOWN_TLDS = {"com", "org", "net", "edu", "gov", "mil", "io", "co", "uk", "de", "fr", "ru", "cn", "jp", "in", "au", "ca", "us", "info", "biz", "me", "tv", "xyz", "online", "site", "dev", "app", "tech", "cloud", "example"}


def _is_domain(value: str) -> bool:
    if value.lower().startswith(PACKET_FIELDS) or PLUGIN.fullmatch(value):
        return False
    lower = value.lower()
    if lower.endswith((".exe", ".dll", ".sys", ".txt", ".csv", ".jsonl", ".locked", ".ps1")):
        return False
    labels = value.split(".")
    return len(labels) >= 2 and labels[-1].lower() in KNOWN_TLDS and all(1 <= len(label) <= 63 and not label.startswith("-") and not label.endswith("-") for label in labels)


def extract_iocs(values: Iterable[str]) -> list[dict[str, str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for value in values:
        protected = set()
        for match in REGISTRY_KEY.finditer(value):
            protected.add(match.group(0))
            found["registry_key"].add(match.group(0))
        for match in WINDOWS_PATH.finditer(value):
            if match.group(0) not in protected:
                found["file_path"].add(match.group(0).rstrip(".,;"))
        for match in PROCESS.finditer(value):
            found["process_name"].add(match.group(0))
        for match in DLL.finditer(value):
            found["dll_name"].add(match.group(0))
        for match in SERVICE.finditer(value):
            found["service_name"].add(match.group(1).strip())
        for match in USERNAME.finditer(value):
            found["username"].add(match.group(1).rstrip(".,;"))
        for kind, pattern in (("ip", IP), ("url", URL), ("sha256", SHA256), ("domain", DOMAIN)):
            for match in pattern.findall(value):
                cleaned = match.rstrip(".,;")
                if kind == "ip" and any(int(part) > 255 for part in cleaned.split(".")):
                    continue
                if kind == "domain" and not _is_domain(cleaned):
                    continue
                if kind == "url":
                    host = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
                    if host and (_is_domain(host) or (IP.fullmatch(host) and all(int(part) <= 255 for part in host.split(".")))):
                        found[kind].add(cleaned)
                else:
                    found[kind].add(cleaned)
    return [{"type": kind, "value": value} for kind in sorted(found) for value in sorted(found[kind])]
