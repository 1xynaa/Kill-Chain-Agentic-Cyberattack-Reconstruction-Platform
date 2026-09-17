import asyncio
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

from backend.app import main
from backend.app.config import Settings
from backend.app.models import Finding, Stage
from backend.app.storage import InvestigationStore
from backend.tui import run as run_tui


def test_tui_persists_completed_investigation(tmp_path: Path, monkeypatch):
    evidence = tmp_path / "auth.log"
    evidence.write_text("failed SSH login from 10.0.0.1")
    workspace = tmp_path / "workspace"
    monkeypatch.setenv("KILLCHAIN_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("KILLCHAIN_MODEL_PROVIDER", "rule_based")
    monkeypatch.setenv("KILLCHAIN_MODEL", "deterministic")

    assert asyncio.run(run_tui([str(evidence)], max_calls=1)) == 0

    store = InvestigationStore(Settings(workspace_root=workspace))
    assert len(store.items) == 1
    investigation = next(iter(store.items.values()))
    assert investigation.status == "completed"
    assert investigation.files[0].sha256


def test_memory_survives_store_restart_and_is_recalled(tmp_path: Path):
    settings = Settings(workspace_root=tmp_path)
    first = InvestigationStore(settings)
    memory = first.add_memory(
        content="SSH brute-force logs are best triaged with grep_indicators first.",
        tags=["ssh", "brute-force"],
        kind="confirmed_learning",
    )
    second = InvestigationStore(settings)
    recalled = second.search_memories("SSH brute-force", limit=5)
    assert recalled[0].id == memory.id
    assert recalled[0].kind == "confirmed_learning"


def test_feedback_creates_confirmed_learning_memory(tmp_path: Path):
    settings = Settings(workspace_root=tmp_path)
    store = InvestigationStore(settings)
    investigation = store.create()
    finding = Finding(
        title="grep finding",
        description="Repeated SSH failures from 10.0.0.1",
        source_file="auth.log",
        stage=Stage.EXPLOITATION,
        confidence=0.82,
    )
    investigation.findings.append(finding)
    store.persist(investigation)
    memory = store.record_feedback(investigation.id, finding.id, "confirmed", "Matches the incident timeline")
    assert memory.kind == "confirmed_learning"
    assert "Repeated SSH failures" in memory.content
    assert store.search_memories("SSH failures")[0].id == memory.id


def test_feedback_endpoint_and_memory_endpoint():
    with TestClient(main.app) as client:
        response = client.post(
            "/upload",
            files={"files": ("auth.log", b"failed SSH login from 10.0.0.1", "text/plain")},
        )
        investigation_id = UUID(response.json()["id"])
        finding = Finding(
            title="test finding",
            description="Confirmed SSH brute force activity",
            source_file="auth.log",
            stage=Stage.EXPLOITATION,
            confidence=0.9,
        )
        main.store.get(investigation_id).findings.append(finding)
        main.store.persist(main.store.get(investigation_id))
        feedback = client.post(
            f"/feedback/{investigation_id}/{finding.id}",
            json={"label": "confirmed", "note": "Analyst verified"},
        )
        assert feedback.status_code == 200
        memories = client.get("/memory/search", params={"q": "SSH brute force"})
        assert memories.status_code == 200
        assert memories.json()[0]["kind"] == "confirmed_learning"
