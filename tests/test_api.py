import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import main


@pytest.fixture(autouse=True)
def isolated_store(tmp_path: Path):
    main.store.items.clear()
    main.settings.workspace_root = tmp_path
    tmp_path.mkdir(exist_ok=True)
    yield
    main.store.items.clear()


def test_health_and_tool_catalog():
    with TestClient(main.app) as client:
        assert client.get("/health").json() == {"status": "ok"}
        tools = client.get("/tools").json()
        assert any(item["name"] == "file_triage" for item in tools)


def test_upload_and_report_round_trip():
    with TestClient(main.app) as client:
        response = client.post("/upload", files={"files": ("auth.log", b"failed SSH login from 10.0.0.1", "text/plain")})
        assert response.status_code == 200
        investigation_id = response.json()["id"]
        assert response.json()["files"][0]["sha256"]
        report = client.get(f"/report/{investigation_id}")
        assert report.status_code == 200
        assert report.json()["investigation_id"] == investigation_id


def test_start_investigation_emits_completion():
    with TestClient(main.app) as client:
        response = client.post("/upload", files={"files": ("auth.log", b"failed SSH login from 10.0.0.1", "text/plain")})
        investigation_id = response.json()["id"]
        started = client.post(f"/investigate/start/{investigation_id}")
        assert started.status_code == 200
        deadline = time.time() + 3
        while time.time() < deadline:
            item = client.get(f"/investigation/{investigation_id}").json()
            if item["status"] == "completed":
                break
            time.sleep(0.01)
        assert item["status"] == "completed"
        assert any(event["type"] == "observation" for event in item["events"])
        assert item["findings"]
        assert item["findings"][0]["stage"] == "Exploitation"


def test_websocket_replays_existing_events():
    with TestClient(main.app) as client:
        response = client.post("/upload", files={"files": ("auth.log", b"failed SSH login from 10.0.0.1", "text/plain")})
        investigation_id = response.json()["id"]
        client.post(f"/investigate/start/{investigation_id}")
        deadline = time.time() + 3
        while time.time() < deadline:
            state = client.get(f"/investigation/{investigation_id}").json()
            if state["status"] == "completed":
                break
            time.sleep(0.01)
        with client.websocket_connect(f"/ws/investigate/{investigation_id}") as websocket:
            event = websocket.receive_json()
            assert event["investigation_id"] == investigation_id
            assert event["sequence"] == 1
            assert event["type"] == "status"


def test_model_config_does_not_echo_api_key():
    with TestClient(main.app) as client:
        response = client.post("/config/model", json={"provider": "openrouter", "model": "test", "api_key": "secret-value"})
        assert response.status_code == 200
        assert response.json()["api_key"] == "[configured]"
        assert response.json()["base_url"] == "https://openrouter.ai/api/v1"


def test_unknown_provider_requires_base_url():
    with TestClient(main.app) as client:
        response = client.post("/config/model", json={"provider": "custom", "model": "test", "api_key": "secret-value"})
        assert response.status_code == 400
