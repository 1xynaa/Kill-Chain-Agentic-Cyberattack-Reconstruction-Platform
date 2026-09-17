from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .agent import Agent
from .config import Settings
from .models import Investigation, ModelConfig, ReportResponse
from .report import build_report
from .skills import load_skill_catalog
from .storage import InvestigationStore
from .tools import ToolRunner

settings = Settings()
store = InvestigationStore(settings)
runner = ToolRunner(settings)
agent = Agent(settings, runner, Path(__file__).resolve().parents[2] / "skills")
subscribers: dict[UUID, list[asyncio.Queue]] = {}
model_config = ModelConfig()

app = FastAPI(title="Kill Chain Backend", version="0.1.0")


class StartResponse(BaseModel):
    investigation_id: UUID
    status: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/tools")
def tools() -> list[dict[str, object]]:
    return runner.available()


@app.get("/skills")
def skills() -> list[dict[str, str]]:
    return [item.model_dump() for item in load_skill_catalog(agent.skills_root)]


@app.post("/upload", response_model=Investigation)
async def upload(files: list[UploadFile] = File(...)) -> Investigation:
    if not files:
        raise HTTPException(400, "at least one evidence file is required")
    investigation = store.create()
    try:
        for item in files:
            await store.add_file(investigation, item)
    except ValueError as exc:
        store.cleanup(investigation.id)
        store.items.pop(investigation.id, None)
        raise HTTPException(413, str(exc)) from exc
    return investigation


@app.post("/investigate/start/{investigation_id}", response_model=StartResponse)
async def start(investigation_id: UUID) -> StartResponse:
    try:
        investigation = store.get(investigation_id)
    except KeyError as exc:
        raise HTTPException(404, "investigation not found") from exc
    if investigation.status == "running":
        raise HTTPException(409, "investigation already running")
    asyncio.create_task(_run(investigation))
    return StartResponse(investigation_id=investigation.id, status="started")


async def _run(investigation: Investigation) -> None:
    async def sink(event):
        for queue in list(subscribers.get(investigation.id, [])):
            await queue.put(event.model_dump(mode="json"))
    await agent.investigate(investigation, sink)
    investigation.report = build_report(investigation).model_dump(mode="json")


@app.get("/investigation/{investigation_id}", response_model=Investigation)
def get_investigation(investigation_id: UUID) -> Investigation:
    try:
        return store.get(investigation_id)
    except KeyError as exc:
        raise HTTPException(404, "investigation not found") from exc


@app.get("/report/{investigation_id}", response_model=ReportResponse)
def report(investigation_id: UUID) -> ReportResponse:
    try:
        return build_report(store.get(investigation_id))
    except KeyError as exc:
        raise HTTPException(404, "investigation not found") from exc


@app.post("/config/model", response_model=ModelConfig)
def configure_model(config: ModelConfig) -> ModelConfig:
    global model_config
    model_config = config
    return ModelConfig(provider=config.provider, model=config.model, base_url=config.base_url, api_key="[configured]" if config.api_key else None)


@app.websocket("/ws/investigate/{investigation_id}")
async def stream(websocket: WebSocket, investigation_id: UUID) -> None:
    try:
        store.get(investigation_id)
    except KeyError:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue()
    subscribers.setdefault(investigation_id, []).append(queue)
    try:
        for event in store.get(investigation_id).events:
            await websocket.send_json(event.model_dump(mode="json"))
        while True:
            await websocket.send_json(await queue.get())
    except WebSocketDisconnect:
        pass
    finally:
        subscribers.get(investigation_id, []).remove(queue)
        if not subscribers.get(investigation_id):
            subscribers.pop(investigation_id, None)
