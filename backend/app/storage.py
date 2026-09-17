from __future__ import annotations

import re
import shutil
from pathlib import Path
from uuid import UUID

from fastapi import UploadFile

from .config import Settings
from .models import EvidenceFile, Investigation
from .tools import sha256

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class InvestigationStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.settings.workspace_root.mkdir(parents=True, exist_ok=True)
        self.items: dict[UUID, Investigation] = {}

    def create(self) -> Investigation:
        item = Investigation()
        self.items[item.id] = item
        self.workspace(item.id).mkdir(parents=True, exist_ok=True)
        return item

    def get(self, investigation_id: UUID) -> Investigation:
        if investigation_id not in self.items:
            raise KeyError(str(investigation_id))
        return self.items[investigation_id]

    def workspace(self, investigation_id: UUID) -> Path:
        return self.settings.workspace_root / str(investigation_id)

    async def add_file(self, investigation: Investigation, upload: UploadFile) -> EvidenceFile:
        original = upload.filename or "evidence.bin"
        safe = _SAFE.sub("_", Path(original).name)[:180] or "evidence.bin"
        destination = self.workspace(investigation.id) / safe
        total = 0
        with destination.open("wb") as output:
            while chunk := await upload.read(1024 * 1024):
                total += len(chunk)
                if total > self.settings.max_file_size:
                    destination.unlink(missing_ok=True)
                    raise ValueError("file exceeds configured size limit")
                output.write(chunk)
        item = EvidenceFile(original_name=original, stored_name=safe, size=total, sha256=sha256(destination))
        investigation.files.append(item)
        return item

    def cleanup(self, investigation_id: UUID) -> None:
        shutil.rmtree(self.workspace(investigation_id), ignore_errors=True)
