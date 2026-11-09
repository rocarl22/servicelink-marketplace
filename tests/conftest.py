import os
import pytest

from backend import database as db


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    """Run service tests against a fresh temporary SQLite database only."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(db, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(db, "DB_PATH", str(data_dir / "service_link_test.db"))
    monkeypatch.setattr(db, "BACKUP_DIR", str(data_dir / "backups"))
    monkeypatch.setattr(db, "PHOTO_DIR", str(data_dir / "profile_photos"))
    db.init_db()
    yield db
