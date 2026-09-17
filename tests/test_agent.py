import pytest
import asyncio
from pathlib import Path
from backend.app.agent import Agent
from backend.app.config import Settings
from backend.app.tools import ToolRunner
from backend.app.models import Investigation, EvidenceFile
import uuid

def test_agent_investigate_extracts_iocs_from_auth_log(tmp_path: Path):
    settings = Settings(workspace_root=tmp_path, max_tool_calls=5)
    runner = ToolRunner(settings)
    skills_root = Path("skills")
    agent = Agent(settings, runner, skills_root)
    
    # Setup the workspace and file
    inv_id = str(uuid.uuid4())
    workspace = tmp_path / inv_id
    workspace.mkdir(parents=True)
    
    auth_log_source = Path("tests/fixtures/auth.log")
    auth_log_dest = workspace / "auth.log"
    auth_log_dest.write_text(auth_log_source.read_text())
    
    investigation = Investigation(
        id=inv_id,
        files=[EvidenceFile(original_name="auth.log", stored_name="auth.log", file_type="text", size=0, sha256="")]
    )
    
    events = []
    async def sink(event):
        events.append(event)
        
    asyncio.run(agent.investigate(investigation, sink))
    
    found_ioc = False
    for finding in investigation.findings:
        if "192.0.2.10" in finding.iocs:
            found_ioc = True
            break
            
    assert found_ioc, f"Expected to find IOC '192.0.2.10' in at least one finding. Found: {[f.iocs for f in investigation.findings]}"


def test_agent_investigate_tentative_stages(tmp_path: Path):
    settings = Settings(workspace_root=tmp_path, max_tool_calls=5)
    runner = ToolRunner(settings)
    skills_root = Path("skills")
    agent = Agent(settings, runner, skills_root)
    
    inv_id = str(uuid.uuid4())
    workspace = tmp_path / inv_id
    workspace.mkdir(parents=True)
    
    # "exploit" will match Stage.EXPLOITATION (index 3).
    # Since it's the first finding, highest confirmed is -1.
    # 3 > -1 + 1 (0), so it should be tentative.
    log_dest = workspace / "test.log"
    log_dest.write_text("exploit")
    
    investigation = Investigation(
        id=inv_id,
        files=[EvidenceFile(original_name="test.log", stored_name="test.log", file_type="text", size=7, sha256="")]
    )
    
    events = []
    async def sink(event):
        events.append(event)
        
    asyncio.run(agent.investigate(investigation, sink))
    
    finding = next((f for f in investigation.findings if f.stage == "Exploitation"), None)
    assert finding is not None, "Expected to find an Exploitation finding"
    assert finding.tentative is True, "Expected the Exploitation finding to be tentative (out of order)"
    
    stage_update = next((e for e in events if e.type == "stage_update" and e.payload["stage"] == "Exploitation"), None)
    assert stage_update is not None, "Expected a stage_update event for Exploitation"
    assert stage_update.payload["tentative"] is True, "Expected the stage_update payload to have tentative=True"
