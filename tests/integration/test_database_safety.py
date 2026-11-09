import sqlite3


def test_init_db_is_idempotent_and_adds_admin_lockout_fields(isolated_database):
    isolated_database.init_db()
    isolated_database.init_db()
    conn = isolated_database.get_conn()
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(admin_users)")}
        assert "failed_login_count" in columns
        assert "locked_until" in columns
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] >= 1
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def test_backup_creates_valid_atomic_snapshot(isolated_database, monkeypatch):
    from backend.services import backup
    monkeypatch.setattr(backup.db, "DB_PATH", isolated_database.DB_PATH)
    monkeypatch.setattr(backup.db, "BACKUP_DIR", isolated_database.BACKUP_DIR)
    conn = isolated_database.get_conn()
    try:
        conn.execute("INSERT OR REPLACE INTO app_settings(key, value) VALUES('test_key', 'test_value')")
        conn.commit()
    finally:
        conn.close()

    assert backup.run_daily_backup() is True
    import os
    names = [n for n in os.listdir(isolated_database.BACKUP_DIR) if n.endswith('.db')]
    assert len(names) == 1
    path = os.path.join(isolated_database.BACKUP_DIR, names[0])
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT value FROM app_settings WHERE key='test_key'").fetchone()[0] == "test_value"
    finally:
        conn.close()


def test_existing_rows_survive_reinitialization(isolated_database):
    from backend.services import accounts
    password = "N3w!ServiceLinkAccount#2026"
    ok, account_id = accounts.create_account(
        role="client", full_name="Preservation Test", phone="0712345679",
        email="preservation@example.invalid", password=password,
        password_confirm=password, terms_accepted=True, role_locked=True,
        service_family="", device_key="pytest-device")
    assert ok, account_id
    isolated_database.init_db()
    conn = isolated_database.get_conn()
    try:
        row = conn.execute("SELECT full_name FROM accounts WHERE account_id=?", (account_id,)).fetchone()
        assert row is not None and row["full_name"] == "Preservation Test"
    finally:
        conn.close()
