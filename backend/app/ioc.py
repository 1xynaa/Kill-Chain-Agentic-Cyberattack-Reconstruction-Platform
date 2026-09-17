from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL = re.compile(r"https?://[^\s\"'<>]+")
SHA256 = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")
DOMAIN = re.compile(r"(?<![@\w])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w])")


def extract_iocs(values: Iterable[str]) -> list[dict[str, str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for value in values:
        for kind, pattern in (("ip", IP), ("url", URL), ("sha256", SHA256), ("domain", DOMAIN)):
            for match in pattern.findall(value):
                if kind == "ip" and any(int(part) > 255 for part in match.split(".")):
                    continue
                found[kind].add(match.rstrip(".,;"))
    return [{"type": kind, "value": value} for kind in sorted(found) for value in sorted(found[kind])]
