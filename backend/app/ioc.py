from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL = re.compile(r"https?://[^\s\"'<>]+")
SHA256 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")
DOMAIN = re.compile(r"(?<![@\w])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w])")
_PACKET_FIELD_PREFIXES = ("dns.", "http.", "ip.", "tcp.", "udp.", "frame.")


def _is_packet_field_name(value: str) -> bool:
    return value.lower().startswith(_PACKET_FIELD_PREFIXES)


def extract_iocs(values: Iterable[str]) -> list[dict[str, str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for value in values:
        for kind, pattern in (("ip", IP), ("url", URL), ("sha256", SHA256), ("domain", DOMAIN)):
            for match in pattern.findall(value):
                cleaned = match.rstrip(".,;")
                if kind == "ip" and any(int(part) > 255 for part in cleaned.split(".")):
                    continue
                if kind == "domain" and _is_packet_field_name(cleaned):
                    continue
                found[kind].add(cleaned)
    return [{"type": kind, "value": value} for kind in sorted(found) for value in sorted(found[kind])]
