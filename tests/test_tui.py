import subprocess
import sys
from pathlib import Path


def test_tui_runs_a_real_local_investigation(tmp_path: Path):
    evidence = tmp_path / "auth.log"
    evidence.write_text("failed SSH login from 192.0.2.10\n")
    result = subprocess.run([sys.executable, "-m", "backend.tui", str(evidence), "--max-calls", "4"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert "THOUGHT" in result.stdout
    assert "REPORT" in result.stdout
    assert "Exploitation" in result.stdout
