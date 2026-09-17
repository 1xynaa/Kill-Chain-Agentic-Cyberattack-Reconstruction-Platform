from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Stage(StrEnum):
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    C2 = "Command & Control (C2)"
    ACTIONS = "Actions on Objectives"


class EvidenceFile(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    original_name: str
    stored_name: str
    size: int
    sha256: str
    file_type: str | None = None


class Investigation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    status: str = "uploaded"
    created_at: datetime = Field(default_factory=utcnow)
    files: list[EvidenceFile] = Field(default_factory=list)
    events: list["InvestigationEvent"] = Field(default_factory=list)
    findings: list["Finding"] = Field(default_factory=list)
    stages: dict[Stage, float] = Field(default_factory=dict)
    report: dict[str, Any] | None = None


class InvestigationEvent(BaseModel):
    investigation_id: UUID
    sequence: int
    timestamp: datetime = Field(default_factory=utcnow)
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    source_file: str | None = None
    stage: Stage | None = None
    confidence: float = Field(ge=0, le=1)
    tentative: bool = False
    timestamp: datetime | None = None
    iocs: list[str] = Field(default_factory=list)


class ModelConfig(BaseModel):
    provider: str = "rule_based"
    model: str = "deterministic"
    base_url: str | None = None
    api_key: str | None = None


class ReportResponse(BaseModel):
    investigation_id: UUID
    status: str
    narrative: str
    timeline: list[Finding]
    iocs: list[dict[str, Any]]
    stages: dict[Stage, float]


Investigation.model_rebuild()
