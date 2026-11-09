"""Sliding-window rate limiter backed by the rate_limits table.

Uses the "sliding window counter" technique: the allowance is the current
fixed bucket's count plus the previous bucket's count weighted by how much of
it still overlaps the trailing window. This removes the fixed-window flaw
where a client could spend `max_count` just before a boundary and `max_count`
again just after it (2x the limit in a few seconds).

    consume(key, max_count, window_seconds) -> (allowed, remaining)
    peek(key, window_seconds)               -> weighted count in the window

No schema change: same (key, window_start, count) rows as before.
"""
import math
import time
from datetime import datetime, timedelta, timezone

from .. import database as db

_now = time.time   # injectable clock for tests


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def _geometry(window_seconds: int):
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    now = _now()
    current = int(now) - (int(now) % window_seconds)
    elapsed_fraction = (now - current) / window_seconds
    return current, current - window_seconds, elapsed_fraction


def _weighted(conn, key, window_seconds):
    current, previous, elapsed = _geometry(window_seconds)
    rows = {r["window_start"]: r["count"] for r in conn.execute(
        "SELECT window_start, count FROM rate_limits WHERE key=? AND window_start IN (?,?)",
        (key, _iso(current), _iso(previous)))}
    cur = rows.get(_iso(current), 0)
    prev = rows.get(_iso(previous), 0)
    return cur, prev * (1.0 - elapsed) + cur, _iso(current)


def consume(key: str, max_count: int, window_seconds: int):
    """Try to consume one unit. Returns (allowed, remaining)."""
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur, weighted, start = _weighted(conn, key, window_seconds)
        if weighted + 1 > max_count + 1e-9:
            conn.rollback()
            return False, 0
        if cur:
            conn.execute("UPDATE rate_limits SET count=count+1 WHERE key=? AND window_start=?",
                         (key, start))
        else:
            conn.execute("INSERT INTO rate_limits(key, window_start, count) VALUES(?,?,1)",
                         (key, start))
        conn.commit()
        return True, max(0, int(math.floor(max_count - weighted - 1 + 1e-9)))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def peek(key: str, window_seconds: int) -> int:
    """Weighted count in the trailing window, without incrementing."""
    conn = db.get_conn()
    try:
        _, weighted, _ = _weighted(conn, key, window_seconds)
        return int(math.ceil(weighted - 1e-9))
    finally:
        conn.close()


def purge_old(hours: int = 24):
    """Remove rows older than `hours` (never less than 2). Call at startup."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max(2, hours))).isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute("DELETE FROM rate_limits WHERE window_start < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()
