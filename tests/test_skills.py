from pathlib import Path

from backend.app.skills import load_skill_catalog


def test_skill_catalog_loads_project_skills(tmp_path: Path):
    (tmp_path / "example").mkdir()
    (tmp_path / "example" / "SKILL.md").write_text('---\ndescription: "Example skill"\n---\n')
    catalog = load_skill_catalog(tmp_path)
    assert len(catalog) == 1
    assert catalog[0].name == "example"
    assert catalog[0].description == "Example skill"
