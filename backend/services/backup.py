"""Daily SQLite backup using the online backup API.

Keeps the 7 most recent backups in data/backups/.
Safe to run at every app start — it does nothing if today's backup exists.
"""
import os
import sqlite3
import tempfile
import logging
from datetime import datetime, timezone

from .. import database as db


KEEP_DAYS = 7
log = logging.getLogger("servicelink.backup")


def _validate_database(path: str):
    """Raise if a backup cannot be opened or SQLite reports corruption."""
    conn = sqlite3.connect(path, timeout=10)
    try:
        result = conn.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise sqlite3.DatabaseError(f"Backup integrity check failed: {result!r}")
        # Preserve existing data even if a legacy DB already has an orphaned
        # relationship. Report it for repair; never make backup impossible.
        violations = conn.execute("PRAGMA foreign_key_check").fetchmany(20)
        if violations:
            log.error("Backup preserved %d+ pre-existing foreign-key violation(s); investigate separately",
                      len(violations))
    finally:
        conn.close()


def run_daily_backup():
    if not os.path.exists(db.DB_PATH):
        return False
    os.makedirs(db.BACKUP_DIR, exist_ok=True)
    db.harden_permissions()

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    target_name = f"service_link_{today}.db"
    target_path = os.path.join(db.BACKUP_DIR, target_name)

    if os.path.exists(target_path):
        try:
            _validate_database(target_path)
            _prune()
            return True
        except Exception:
            # Replace a corrupt/incomplete same-day backup below.
            pass

    fd, temp_path = tempfile.mkstemp(prefix=".servicelink-backup-", suffix=".db",
                                     dir=db.BACKUP_DIR)
    os.close(fd)
    try:
        source = sqlite3.connect(db.DB_PATH, timeout=10)
        try:
            target = sqlite3.connect(temp_path, timeout=10)
            try:
                source.backup(target)
                target.commit()
            finally:
                target.close()
        finally:
            source.close()

        _validate_database(temp_path)
        os.replace(temp_path, target_path)
        _prune()
        return True
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def _prune():
    try:
        files = [
            f for f in os.listdir(db.BACKUP_DIR)
            if f.startswith("service_link_") and f.endswith(".db")
        ]
    except FileNotFoundError:
        return
    files.sort(reverse=True)
    for old in files[KEEP_DAYS:]:
        try:
            os.remove(os.path.join(db.BACKUP_DIR, old))
        except OSError:
            pass