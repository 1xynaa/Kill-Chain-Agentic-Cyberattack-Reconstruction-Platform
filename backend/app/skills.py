from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel


class SkillSummary(BaseModel):
    name: str
    path: str
    description: str


def load_skill_catalog(root: Path) -> list[SkillSummary]:
    result: list[SkillSummary] = []
    for skill_file in sorted(root.glob("*/SKILL.md")):
        description = ""
        try:
            lines = skill_file.read_text(errors="replace").splitlines()
            for line in lines:
                if line.lower().startswith("description:"):
                    description = line.split(":", 1)[1].strip().strip('"')
                    break
        except OSError:
            continue
        result.append(SkillSummary(name=skill_file.parent.name, path=str(skill_file), description=description))
    return result
