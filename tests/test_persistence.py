from pathlib import Path

from backend.app.config import Settings
from backend.app.models import EvidenceFile
from backend.app.storage import InvestigationStore


def test_investigation_snapshot_survives_store_restart(tmp_path: Path):
    settings = Settings(workspace_root=tmp_path)
    first = InvestigationStore(settings)
    item = first.create()
    item.files.append(EvidenceFile(original_name="a.log", stored_name="a.log", size=1, sha256="a"))
    first.persist(item)
    second = InvestigationStore(settings)
    loaded = second.get(item.id)
    assert loaded.files[0].stored_name == "a.log"
