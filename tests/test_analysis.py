import pytest

from backend.app.ioc import extract_iocs
from backend.app.killchain import classify
from backend.app.models import Stage


def test_extract_iocs_deduplicates_and_rejects_invalid_ip():
    result = extract_iocs(["src=10.0.0.1 dst=999.1.1.1 https://evil.example/a 10.0.0.1"])
    assert {item["value"] for item in result} == {"10.0.0.1", "https://evil.example/a", "evil.example"}


def test_classify_brute_force_as_exploitation():
    stage, confidence = classify("failed SSH credentials", "47 brute force attempts")
    assert stage is Stage.EXPLOITATION
    assert confidence >= 0.8
