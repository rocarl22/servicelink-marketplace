"""Key-value settings store. Backed by app_settings.

No Qt imports. Reusable on a future web backend unchanged.
"""
from .. import database as db


def get(key: str, default: str = "") -> str:
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT value FROM app_settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_value(key: str, value: str) -> None:
    conn = db.get_conn()
    try:
        conn.execute(
            "INSERT INTO app_settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


def get_theme_mode() -> str:
    mode = get("theme_mode", "auto")
    return mode if mode in ("light", "dark", "auto") else "auto"


def set_theme_mode(mode: str) -> None:
    if mode not in ("light", "dark", "auto"):
        raise ValueError("Invalid theme mode")
    set_value("theme_mode", mode)