from __future__ import annotations

from pathlib import Path
from functools import lru_cache

from pydantic import BaseModel


import yaml

class SkillSummary(BaseModel):
    name: str
    path: str
    description: str
    overview: str = ""
    when_to_use: str = ""
    tools: list[str] = []

@lru_cache(maxsize=32)
def load_skill_catalog(root: Path) -> list[SkillSummary]:
    result: list[SkillSummary] = []
    for skill_file in sorted(root.glob("*/SKILL.md")):
        description = ""
        overview = ""
        when_to_use = ""
        tools = []
        try:
            content = skill_file.read_text(errors="replace")
            body = content
            if content.startswith("---\n"):
                parts = content.split("---\n", 2)
                if len(parts) >= 3:
                    frontmatter = parts[1]
                    body = parts[2]
                    try:
                        meta = yaml.safe_load(frontmatter) or {}
                        description = meta.get("description", str(meta.get("description", "")))
                        tools_val = meta.get("tools", [])
                        if isinstance(tools_val, str):
                            tools = [t.strip() for t in tools_val.split(",") if t.strip()]
                        elif isinstance(tools_val, list):
                            tools = [str(t) for t in tools_val]
                    except yaml.YAMLError:
                        pass
                        
            current_section = None
            section_content = []
            for line in body.splitlines():
                if line.startswith("## "):
                    if current_section == "Overview":
                        overview = "\n".join(section_content).strip()
                    elif current_section == "When to Use":
                        when_to_use = "\n".join(section_content).strip()
                    current_section = line[3:].strip()
                    section_content = []
                elif line.startswith("# ") or line.startswith("### "):
                    if current_section == "Overview":
                        overview = "\n".join(section_content).strip()
                    elif current_section == "When to Use":
                        when_to_use = "\n".join(section_content).strip()
                    current_section = None
                elif current_section:
                    section_content.append(line)
                    
            if current_section == "Overview":
                overview = "\n".join(section_content).strip()
            elif current_section == "When to Use":
                when_to_use = "\n".join(section_content).strip()

        except OSError:
            continue
        result.append(SkillSummary(name=skill_file.parent.name, path=str(skill_file), description=description, overview=overview, when_to_use=when_to_use, tools=tools))
    return result

