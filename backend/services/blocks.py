"""Blocking service.

Blocks are asymmetric — a block on (A, B) means A no longer wants to
interact with B. B is not notified. The block prevents:
    - new requests in either direction
    - accepting a request between the pair
    - chat messages between the pair
    - the blocked provider appearing in the blocker's search results

Blocks do NOT cancel existing jobs. Active jobs continue; only new
interactions are refused.

Block reasons are stored privately and mirrored into `user_reports`
for the admin portal.
"""
from .. import database as db
from .validation import now_iso


MIN_REASON_LEN = 20
MAX_REASON_LEN = 1000


def is_blocked(a_id: str, b_id: str) -> bool:
    """True if either side has blocked the other."""
    if not a_id or not b_id:
        return False
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT 1 FROM blocks
               WHERE (blocker_account_id=? AND blocked_account_id=?)
                  OR (blocker_account_id=? AND blocked_account_id=?)
               LIMIT 1""",
            (a_id, b_id, b_id, a_id),
        ).fetchone()
        return bool(row)
    finally:
        conn.close()


def has_blocked(blocker_id: str, blocked_id: str) -> bool:
    """True if `blocker_id` has specifically blocked `blocked_id`."""
    if not blocker_id or not blocked_id:
        return False
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT 1 FROM blocks
               WHERE blocker_account_id=? AND blocked_account_id=?
               LIMIT 1""",
            (blocker_id, blocked_id),
        ).fetchone()
        return bool(row)
    finally:
        conn.close()


def block_user(blocker_id: str, blocked_id: str, reason: str,
               job_id: int = 0):
    """Record a block. Also writes a user_reports row for admin.

    reason: category string, e.g. "Suspected fraud"
    notes:  free text, handled as part of the reason payload here.
    """
    reason = (reason or "").strip()
    if not reason:
        return False, "Choose a reason category."
    if len(reason) > MAX_REASON_LEN:
        reason = reason[:MAX_REASON_LEN]

    if blocker_id == blocked_id:
        return False, "You cannot block yourself."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        # Verify both accounts exist
        for aid in (blocker_id, blocked_id):
            row = conn.execute(
                "SELECT 1 FROM accounts WHERE account_id=?", (aid,)
            ).fetchone()
            if not row:
                conn.rollback()
                return False, "Account not found."

        now = now_iso()

        # Insert or replace the block
        conn.execute(
            """INSERT INTO blocks(
                blocker_account_id, blocked_account_id, reason, created_at
            ) VALUES(?,?,?,?)
            ON CONFLICT(blocker_account_id, blocked_account_id)
            DO UPDATE SET reason=excluded.reason, created_at=excluded.created_at""",
            (blocker_id, blocked_id, reason, now),
        )

        # Also log for admin review
        conn.execute(
            """INSERT INTO user_reports(
                kind, reporter_account_id, reported_account_id,
                reason, notes, context_job_id, status, created_at
            ) VALUES('block', ?, ?, ?, '', ?, 'open', ?)""",
            (blocker_id, blocked_id, reason,
             job_id or None, now),
        )

        conn.commit()
        return True, "Blocked. You will no longer see or interact with this user."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def unblock_user(blocker_id: str, blocked_id: str):
    conn = db.get_conn()
    try:
        cur = conn.execute(
            """DELETE FROM blocks
               WHERE blocker_account_id=? AND blocked_account_id=?""",
            (blocker_id, blocked_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return False, "No block found."
        return True, "Unblocked."
    finally:
        conn.close()


def list_blocked_by(blocker_id: str):
    """Return the accounts this user has blocked."""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT b.blocked_account_id AS account_id,
                      b.reason, b.created_at,
                      COALESCE(a.display_name, a.full_name) AS display_name,
                      a.role AS role
               FROM blocks b
               JOIN accounts a ON a.account_id = b.blocked_account_id
               WHERE b.blocker_account_id=?
               ORDER BY b.created_at DESC""",
            (blocker_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()