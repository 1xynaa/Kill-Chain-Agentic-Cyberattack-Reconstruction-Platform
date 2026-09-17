from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class Settings(BaseModel):
    workspace_root: Path = Field(default_factory=lambda: Path(os.getenv("KILLCHAIN_WORKSPACE_ROOT", "/tmp/killchain-workspaces")))
    state_db: Path | None = None
    max_file_size: int = int(os.getenv("KILLCHAIN_MAX_FILE_SIZE", str(512 * 1024 * 1024)))
    max_tool_output: int = int(os.getenv("KILLCHAIN_MAX_TOOL_OUTPUT", "20000"))
    tool_timeout: int = int(os.getenv("KILLCHAIN_TOOL_TIMEOUT", "30"))
    max_tool_calls: int = int(os.getenv("KILLCHAIN_MAX_TOOL_CALLS", "20"))
    allow_network_tools: bool = os.getenv("KILLCHAIN_ALLOW_NETWORK_TOOLS", "false").lower() == "true"

    def model_post_init(self, __context: object) -> None:
        if self.state_db is None:
            self.state_db = self.workspace_root / "investigations.sqlite3"
