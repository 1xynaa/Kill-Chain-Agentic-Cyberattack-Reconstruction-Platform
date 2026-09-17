from pathlib import Path

from backend.app.config import Settings
from backend.app.tools import ToolRunner


def test_unknown_tool_is_structured_error(tmp_path: Path):
    result = ToolRunner(Settings(workspace_root=tmp_path)).run("missing", tmp_path, "evidence.log")
    assert result.success is False
    assert result.error == "unknown tool"


def test_tool_rejects_path_escape(tmp_path: Path):
    (tmp_path / "evidence.log").write_text("hello")
    outside = tmp_path.parent / "outside.log"
    outside.write_text("secret")
    result = ToolRunner(Settings(workspace_root=tmp_path)).run("strings_extract", tmp_path, "../outside.log")
    assert result.success is False
    assert result.error == "evidence path is outside workspace"


def test_network_tools_disabled_by_default(tmp_path: Path):
    result = ToolRunner(Settings(workspace_root=tmp_path)).run("dig", tmp_path, "example.com")
    assert result.success is False
    assert result.error == "network tools disabled"
