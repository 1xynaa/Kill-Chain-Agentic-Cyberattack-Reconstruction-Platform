from pathlib import Path

from backend.app.skills import load_skill_catalog


def test_skill_catalog_loads_project_skills(tmp_path: Path):
    (tmp_path / "example").mkdir()
    (tmp_path / "example" / "SKILL.md").write_text('---\ndescription: "Example skill"\n---\n')
    catalog = load_skill_catalog(tmp_path)
    assert len(catalog) == 1
    assert catalog[0].name == "example"
    assert catalog[0].description == "Example skill"


def test_agent_incorporates_skills(tmp_path: Path, monkeypatch):
    import asyncio
    from backend.app.agent import Agent
    from backend.app.config import Settings
    from backend.app.tools import ToolRunner
    from backend.app.models import Investigation
    import backend.app.agent as agent_module

    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    skill_dir = skills_dir / "test-skill"
    skill_dir.mkdir()
    
    skill_dir.joinpath("SKILL.md").write_text(
        "---\n"
        "description: test skill\n"
        "tools: [file_triage]\n"
        "---\n"
        "## Overview\n"
        "This is a test overview.\n"
    )
    
    settings = Settings(workspace_root=tmp_path, max_tool_calls=5)
    runner = ToolRunner(settings)
    agent = Agent(settings, runner, skills_dir)
    
    catalog = load_skill_catalog(skills_dir)
    selected = agent._select_skills(catalog, "test skill text")
    
    assert len(selected) == 1
    assert selected[0].overview == "This is a test overview."
    
    # 1. Check rule-based plan queue expansion
    queue = agent._initial_plan("test-skill.txt", "text", selected)
    assert "file_triage" in queue
    
    # 2. Check model decision prompt expansion
    messages_sent = []
    def mock_complete(self, messages, schemas):
        messages_sent.append(messages)
        class Resp:
            content = '{"thought": "test", "tool": "file_triage", "done": true}'
        return Resp()
    monkeypatch.setattr(agent_module.OpenAICompatibleProvider, "complete", mock_complete)
    
    import uuid
    investigation = Investigation(id=str(uuid.uuid4()), files=[])
    agent.config.provider = "test_provider"
    agent.config.base_url = "http://test"
    agent.config.api_key = "test"
    
    asyncio.run(agent._model_decision(investigation, "test-skill.txt", "suggested", selected))
    
    assert len(messages_sent) == 1
    system_prompt = messages_sent[0][0]["content"]
    assert "Relevant Skills:" in system_prompt
    assert "This is a test overview." in system_prompt
