from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .agent import Agent
from .config import Settings
from .models import Investigation, MemoryRecord, ModelConfig, ReportResponse
from .providers import PROVIDER_BASE_URLS, model_config_from_environment
from .report import build_report
from .skills import load_skill_catalog
from .storage import InvestigationStore
from .tools import ToolRunner

settings = Settings()
store = InvestigationStore(settings)
runner = ToolRunner(settings)
skills_root = Path(__file__).resolve().parents[2] / "skills"
model_config = model_config_from_environment()
subscribers: dict[UUID, list[asyncio.Queue]] = {}
app = FastAPI(title="Kill Chain Backend", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class StartResponse(BaseModel):
    investigation_id: UUID
    status: str


class FeedbackRequest(BaseModel):
    label: Literal["confirmed", "rejected"]
    note: str = ""


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/tools")
def tools() -> list[dict[str, object]]:
    return runner.available()


@app.get("/skills")
def skills() -> list[dict[str, str]]:
    return [item.model_dump() for item in load_skill_catalog(skills_root)]


@app.get("/memory/search", response_model=list[MemoryRecord])
def search_memory(q: str = Query(min_length=1), limit: int = Query(default=5, ge=1, le=50)) -> list[MemoryRecord]:
    return store.search_memories(q, limit)


@app.post("/feedback/{investigation_id}/{finding_id}", response_model=MemoryRecord)
def feedback(investigation_id: UUID, finding_id: UUID, request: FeedbackRequest) -> MemoryRecord:
    try:
        return store.record_feedback(investigation_id, finding_id, request.label, request.note)
    except KeyError as exc:
        raise HTTPException(404, "investigation or finding not found") from exc


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


@app.post("/replay/{investigation_id}")
async def replay(investigation_id: UUID, speed: float = 1.0) -> dict[str, str]:
    try:
        investigation = store.get(investigation_id)
    except KeyError as exc:
        raise HTTPException(404, "investigation not found") from exc
    if investigation.status == "running":
        raise HTTPException(409, "investigation already running")
        
    async def _do_replay(inv: Investigation, playback_speed: float):
        interval = 0.4 / playback_speed
        for event in inv.events:
            for queue in list(subscribers.get(inv.id, [])):
                await queue.put(event.model_dump(mode="json"))
            await asyncio.sleep(interval)
            
    asyncio.create_task(_do_replay(investigation, speed))
    return {"status": "replaying"}


async def _run(investigation: Investigation) -> None:
    investigator = Agent(settings, runner, skills_root, model_config)
    prior_memories = store.search_memories(" ".join(item.original_name for item in investigation.files), limit=5)

    async def sink(event):
        store.persist(investigation)
        for queue in list(subscribers.get(investigation.id, [])):
            await queue.put(event.model_dump(mode="json"))

    try:
        await investigator.investigate(investigation, sink, prior_memories)
        investigation.report = build_report(investigation).model_dump(mode="json")
        store.persist(investigation)
    except Exception as exc:
        investigation.status = "failed"
        investigation.report = {"error": str(exc)}
        store.persist(investigation)


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
    if config.provider != "rule_based" and config.provider not in PROVIDER_BASE_URLS and not config.base_url:
        raise HTTPException(400, "unknown provider requires an explicit base_url")
    if config.provider != "rule_based" and not config.base_url:
        config.base_url = PROVIDER_BASE_URLS[config.provider]
    model_config = config
    return ModelConfig(provider=config.provider, model=config.model, base_url=config.base_url, api_key="[configured]" if config.api_key else None)


@app.websocket("/ws/investigate/{investigation_id}")
async def stream(websocket: WebSocket, investigation_id: UUID) -> None:
    try:
        investigation = store.get(investigation_id)
    except KeyError:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue()
    subscribers.setdefault(investigation_id, []).append(queue)
    try:
        for event in investigation.events:
            await websocket.send_json(event.model_dump(mode="json"))
        while True:
            await websocket.send_json(await queue.get())
    except WebSocketDisconnect:
        pass
    finally:
        if queue in subscribers.get(investigation_id, []):
            subscribers[investigation_id].remove(queue)
        if not subscribers.get(investigation_id):
            subscribers.pop(investigation_id, None)
