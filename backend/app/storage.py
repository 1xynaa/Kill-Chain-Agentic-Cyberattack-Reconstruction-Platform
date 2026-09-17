from __future__ import annotations

import json
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import UploadFile

from .config import Settings
from .models import EvidenceFile, Investigation, MemoryRecord
from .tools import sha256

_SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class InvestigationStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.settings.workspace_root.mkdir(parents=True, exist_ok=True)
        self.items: dict[UUID, Investigation] = {}
        self.memories: dict[UUID, MemoryRecord] = {}
        self.db = sqlite3.connect(self.settings.state_db or (self.settings.workspace_root / "investigations.sqlite3"), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS memories (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL)")
        self.db.commit()
        self._load()
        self._load_memories()

    def _load(self) -> None:
        for raw_id, snapshot in self.db.execute("SELECT id, snapshot FROM investigations"):
            try:
                item = Investigation.model_validate_json(snapshot)
                self.items[UUID(raw_id)] = item
                self.workspace(item.id).mkdir(parents=True, exist_ok=True)
            except Exception:
                continue

    def _load_memories(self) -> None:
        for raw_id, snapshot in self.db.execute("SELECT id, snapshot FROM memories"):
            try:
                item = MemoryRecord.model_validate_json(snapshot)
                self.memories[UUID(raw_id)] = item
            except Exception:
                continue

    def add_memory(
        self,
        content: str,
        tags: list[str] | None = None,
        kind: str = "note",
        source_investigation_id: UUID | None = None,
        source_finding_id: UUID | None = None,
        confidence: float = 1.0,
    ) -> MemoryRecord:
        item = MemoryRecord(
            kind=kind,
            content=content.strip(),
            tags=tags or [],
            source_investigation_id=source_investigation_id,
            source_finding_id=source_finding_id,
            confidence=confidence,
        )
        self.memories[item.id] = item
        self.db.execute("INSERT INTO memories(id, snapshot) VALUES (?, ?)", (str(item.id), item.model_dump_json()))
        self.db.commit()
        return item

    def search_memories(self, query: str, limit: int = 5) -> list[MemoryRecord]:
        terms = set(re.findall(r"[a-z0-9][a-z0-9_-]+", query.lower()))
        if not terms:
            return []
        ranked = []
        for item in self.memories.values():
            haystack = " ".join([item.content, *item.tags]).lower()
            score = sum(term in haystack for term in terms)
            if score:
                ranked.append((score, item.updated_at, item))
        ranked.sort(key=lambda value: (value[0], value[1]), reverse=True)
        return [item for _, _, item in ranked[:limit]]

    def record_feedback(self, investigation_id: UUID, finding_id: UUID, label: str, note: str = "") -> MemoryRecord:
        if label not in {"confirmed", "rejected"}:
            raise ValueError("label must be confirmed or rejected")
        investigation = self.get(investigation_id)
        finding = next((item for item in investigation.findings if item.id == finding_id), None)
        if finding is None:
            raise KeyError(str(finding_id))
        content = f"{finding.title}: {finding.description}"
        if note.strip():
            content += f" Analyst note: {note.strip()}"
        tags = [value for value in (finding.source_file, finding.stage.value if finding.stage else None) if value]
        return self.add_memory(
            content=content,
            tags=tags,
            kind=f"{label}_learning",
            source_investigation_id=investigation_id,
            source_finding_id=finding_id,
            confidence=finding.confidence,
        )

    def persist(self, investigation: Investigation) -> None:
        snapshot = investigation.model_dump_json()
        self.db.execute("INSERT OR REPLACE INTO investigations(id, snapshot) VALUES (?, ?)", (str(investigation.id), snapshot))
        self.db.commit()

    def create(self) -> Investigation:
        item = Investigation()
        self.items[item.id] = item
        self.workspace(item.id).mkdir(parents=True, exist_ok=True)
        self.persist(item)
        return item

    def get(self, investigation_id: UUID) -> Investigation:
        if investigation_id not in self.items:
            raise KeyError(str(investigation_id))
        return self.items[investigation_id]

    def workspace(self, investigation_id: UUID) -> Path:
        return self.settings.workspace_root / str(investigation_id)

    async def add_file(self, investigation: Investigation, upload: UploadFile) -> EvidenceFile:
        original = upload.filename or "evidence.bin"
        name = "".join(char if char in _SAFE_CHARS else "_" for char in Path(original).name)[:180] or "evidence.bin"
        destination = self.workspace(investigation.id) / name
        total = 0
        with destination.open("wb") as output:
            while chunk := await upload.read(1024 * 1024):
                total += len(chunk)
                if total > self.settings.max_file_size:
                    destination.unlink(missing_ok=True)
                    raise ValueError("file exceeds configured size limit")
                output.write(chunk)
        item = EvidenceFile(original_name=original, stored_name=name, size=total, sha256=sha256(destination))
        investigation.files.append(item)
        self.persist(investigation)
        return item

    def cleanup(self, investigation_id: UUID) -> None:
        shutil.rmtree(self.workspace(investigation_id), ignore_errors=True)
        self.db.execute("DELETE FROM investigations WHERE id = ?", (str(investigation_id),))
        self.db.commit()
