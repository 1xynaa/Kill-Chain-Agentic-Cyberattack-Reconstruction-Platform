from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .app.agent import Agent
from .app.config import Settings
from .app.models import EvidenceFile
from .app.providers import model_config_from_environment
from .app.storage import InvestigationStore
from .app.tools import ToolRunner, sha256


async def run(paths: list[str], max_calls: int | None = None) -> int:
    settings = Settings(max_tool_calls=max_calls or Settings().max_tool_calls)
    runner = ToolRunner(settings)
    store = InvestigationStore(settings)
    investigation = store.create()
    settings.workspace_root.mkdir(parents=True, exist_ok=True)
    workspace = store.workspace(investigation.id)
    for raw in paths:
        source = Path(raw).expanduser().resolve()
        if not source.is_file():
            print(f"[error] evidence not found: {source}", file=sys.stderr)
            return 2
        destination = workspace / source.name
        destination.write_bytes(source.read_bytes())
        investigation.files.append(EvidenceFile(original_name=source.name, stored_name=source.name, size=source.stat().st_size, sha256=sha256(destination)))
        store.persist(investigation)

    prior_memories = store.search_memories(" ".join(item.original_name for item in investigation.files), limit=5)

    async def sink(event):
        store.persist(investigation)
        payload = event.payload
        if event.type == "thought":
            print(f"\033[36mTHOUGHT\033[0m {payload.get('text', '')}")
        elif event.type == "action":
            print(f"\033[33mACTION\033[0m {payload.get('tool')} -> {payload.get('path')}")
        elif event.type == "observation":
            output = payload.get("stdout") or payload.get("error") or payload.get("stderr") or "(no output)"
            print(f"\033[32mOBSERVATION\033[0m {payload.get('tool')}: {output[:500]}")
        elif event.type in {"finding", "stage_update", "provider_error", "status", "skill_select", "memory_recall"}:
            print(f"\033[35m{event.type.upper()}\033[0m {json.dumps(payload, default=str)}")

    await Agent(settings, runner, Path(__file__).resolve().parents[1] / "skills", model_config_from_environment()).investigate(investigation, sink, prior_memories)
    print("\nREPORT")
    print(json.dumps({"investigation_id": str(investigation.id), "status": investigation.status, "findings": [item.model_dump(mode="json") for item in investigation.findings], "stages": {key.value: value for key, value in investigation.stages.items()}}, indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Kill Chain forensic investigation TUI")
    parser.add_argument("paths", nargs="+", help="evidence files")
    parser.add_argument("--max-calls", type=int, default=None)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args.paths, args.max_calls)))


if __name__ == "__main__":
    main()
