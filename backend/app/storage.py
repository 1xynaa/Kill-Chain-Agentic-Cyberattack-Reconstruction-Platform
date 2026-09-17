from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from uuid import UUID

from fastapi import UploadFile

from .config import Settings
from .models import EvidenceFile, Investigation
from .tools import sha256

_SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class InvestigationStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.settings.workspace_root.mkdir(parents=True, exist_ok=True)
        self.items: dict[UUID, Investigation] = {}
        self.db = sqlite3.connect(self.settings.state_db or (self.settings.workspace_root / "investigations.sqlite3"), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL)")
        self.db.commit()
        self._load()

    def _load(self) -> None:
        for raw_id, snapshot in self.db.execute("SELECT id, snapshot FROM investigations"):
            try:
                item = Investigation.model_validate_json(snapshot)
                self.items[UUID(raw_id)] = item
                self.workspace(item.id).mkdir(parents=True, exist_ok=True)
            except Exception:
                continue

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
