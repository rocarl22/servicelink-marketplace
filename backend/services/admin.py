"""Admin service.

Admin authentication is separate from user authentication.
Admin sessions are tracked by the bridge independently of user sessions.

Admin actions:
    - List and resolve disputes
    - Post private messages to a party (never into their shared chat)
    - List and dismiss user reports (blocks, review flags)
    - Search accounts, change account status, issue password resets
    - View audit log
    - Admin self-service (change own password, username)
"""
import hashlib
import logging
import os
import secrets
import shutil
import string
import uuid
from datetime import datetime, timedelta, timezone

from .. import database as db
from .. import face_screen
from . import passwords
from .validation import now_iso


log = logging.getLogger("servicelink.admin")


MAX_REASON_LEN = 500
TEMP_PASSWORD_LEN = 12
RESET_TTL_HOURS = 24

DISPUTE_ACTIONS = (
    "ask_question",
    "recommend_resolution",
    "hold",
    "resolve_cancel",
    "resolve_complete",
    "resolve_dismiss",
)

# Retained only to identify legacy installations that still use the old known
# credential. It is never used to create an administrator.
LEGACY_DEFAULT_ADMIN_USERNAME = "admin"
LEGACY_DEFAULT_ADMIN_PASSWORD = "admin123"
ADMIN_MAX_FAILED_ATTEMPTS = 5
ADMIN_LOCK_MINUTES = 5
ADMIN_MAX_LOCK_MINUTES = 60

MAX_EVIDENCE_SIZE_BYTES = 8 * 1024 * 1024   # 8 MB
ALLOWED_EVIDENCE_TYPES = (
    "image/jpeg", "image/png", "image/webp", "application/pdf",
)


# ------------------------------------------------------------------
# Bootstrap
# ------------------------------------------------------------------

def ensure_admin_exists():
    """Return True when first-admin setup is required; never create a default admin."""
    conn = db.get_conn()
    try:
        # Inactive tombstones preserve historical audit attribution but must
        # not prevent first-admin setup when no usable administrator remains.
        row = conn.execute("SELECT 1 FROM admin_users WHERE active=1 LIMIT 1").fetchone()
        return row is None
    finally:
        conn.close()


def create_initial_admin(username: str, password: str, confirmation: str):
    """Create the first administrator exactly once, with no shared default secret."""
    username = (username or "").strip()
    if len(username) < 3 or len(username) > 40 or any(ch.isspace() for ch in username):
        return False, "Username must be 3–40 characters and contain no spaces."
    if not password:
        return False, "Enter a password."
    if password != confirmation:
        return False, "Passwords do not match."
    ok, message = passwords.validate_password(password, context=(username,))
    if not ok:
        return False, message

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM admin_users WHERE active=1 LIMIT 1").fetchone():
            conn.rollback()
            return False, "An active administrator already exists. Sign in instead."
        admin_id = "A-" + uuid.uuid4().hex[:10].upper()
        now = now_iso()
        conn.execute(
            """INSERT INTO admin_users(
                admin_id, username, password_hash, role, active, created_at,
                last_login_at, failed_login_count, locked_until
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (admin_id, username, _hash_password(password), "admin", 1, now, "", 0, ""),
        )
        _log_admin_action(
            conn, admin_id, "admin_initial_setup", "admin", admin_id,
            before_state="no_admin", after_state="initial_admin_created",
            reason="Initial administrator setup completed",
        )
        conn.commit()
        log.info("Initial administrator setup completed")
        return True, "Initial administrator created. You can now sign in."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------
# Admin authentication
# ------------------------------------------------------------------

def _hash_password(password: str) -> str:
    from .accounts import _hash_password as _acc_hash
    return _acc_hash(password)


def _check_password(password: str, stored: str) -> bool:
    from .accounts import _check_password as _acc_check
    return _acc_check(password, stored)


def admin_login(username: str, password: str):
    username = (username or "").strip()
    if not username or not password:
        return False, "Enter your username and password."

    from . import ratelimit, security
    username_key = hashlib.sha256(username.casefold().encode("utf-8")).hexdigest()
    try:
        allowed, _remaining = ratelimit.consume(
            f"login:admin:{username_key}", max_count=30, window_seconds=900
        )
    except Exception:
        log.exception("Administrator rate-limit check failed")
        return False, "Sign-in is temporarily unavailable. Please try again."
    if not allowed:
        return False, "The username or password is incorrect. Try again later."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT admin_id, username, password_hash, role, active,
                      failed_login_count, locked_until
               FROM admin_users WHERE username=?""",
            (username,),
        ).fetchone()
        if not row:
            from .accounts import _dummy_verify
            _dummy_verify(password)
            conn.rollback()
            return False, "The username or password is incorrect."
        if not row["active"]:
            conn.rollback()
            return False, "This admin account is not active."

        lock_until = None
        try:
            lock_until = datetime.fromisoformat(row["locked_until"] or "")
            if lock_until.tzinfo is None:
                lock_until = lock_until.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            lock_until = None
        now_dt = datetime.now(timezone.utc)
        if lock_until and now_dt < lock_until:
            conn.rollback()
            return False, "Too many failed attempts. Administrator sign-in is temporarily locked."

        if not _check_password(password, row["password_hash"]):
            failed = int(row["failed_login_count"] or 0) + 1
            lock_minutes = 0
            if failed >= 15:
                lock_minutes = ADMIN_MAX_LOCK_MINUTES
            elif failed >= 10:
                lock_minutes = 15
            elif failed >= ADMIN_MAX_FAILED_ATTEMPTS:
                lock_minutes = ADMIN_LOCK_MINUTES
            new_lock = ""
            if lock_minutes:
                new_lock = (now_dt + timedelta(minutes=lock_minutes)).isoformat(timespec="seconds")
            conn.execute(
                "UPDATE admin_users SET failed_login_count=?, locked_until=? WHERE admin_id=?",
                (failed, new_lock, row["admin_id"]),
            )
            conn.commit()
            if new_lock:
                return False, "Too many failed attempts. Administrator sign-in is temporarily locked."
            return False, "The username or password is incorrect."

        now = now_iso()
        stored_hash = row["password_hash"] or ""
        from .accounts import needs_rehash
        if needs_rehash(stored_hash):
            conn.execute(
                """UPDATE admin_users SET password_hash=?, last_login_at=?,
                   failed_login_count=0, locked_until='' WHERE admin_id=?""",
                (_hash_password(password), now, row["admin_id"]),
            )
        else:
            conn.execute(
                """UPDATE admin_users
                   SET last_login_at=?, failed_login_count=0, locked_until=''
                   WHERE admin_id=?""",
                (now, row["admin_id"]),
            )
        conn.commit()
        return True, row["admin_id"]
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_admin(admin_id: str):
    if not admin_id:
        return {}
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT admin_id, username, role, active, created_at, last_login_at
               FROM admin_users WHERE admin_id=?""",
            (admin_id,),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def _log_admin_action(conn, admin_id: str, action_type: str,
                      target_type: str, target_id: str,
                      before_state: str = "", after_state: str = "",
                      reason: str = ""):
    conn.execute(
        """INSERT INTO admin_actions(
            admin_id, action_type, target_type, target_id,
            before_state, after_state, reason, created_at
        ) VALUES(?,?,?,?,?,?,?,?)""",
        (admin_id, action_type, target_type, str(target_id),
         before_state, after_state, reason or "", now_iso()),
    )


# ------------------------------------------------------------------
# Disputes
# ------------------------------------------------------------------

def list_open_disputes(limit: int = 200):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT d.dispute_id, d.job_id, d.title, d.description,
                      d.status, d.previous_state, d.created_at, d.updated_at,
                      d.opened_by_account_id,
                      COALESCE(d.is_anonymous, 0) AS is_anonymous,
                      COALESCE(opener.display_name, opener.full_name, '') AS opener_name,
                      opener.role AS opener_role,
                      j.client_account_id, j.provider_account_id,
                      j.category AS job_category, j.area AS job_area,
                      j.current_state AS job_state,
                      COALESCE(cl.display_name, cl.full_name, '') AS client_name,
                      COALESCE(pr.display_name, pr.full_name, '') AS provider_name,
                      (SELECT COUNT(*) FROM admin_party_messages m
                       WHERE m.dispute_id = d.dispute_id
                         AND m.sender_role = 'party'
                         AND m.read_by_admin = 0
                      ) AS unread_party_messages
               FROM disputes d
               JOIN jobs j ON j.job_id = d.job_id
               JOIN accounts opener ON opener.account_id = d.opened_by_account_id
               JOIN accounts cl ON cl.account_id = j.client_account_id
               JOIN accounts pr ON pr.account_id = j.provider_account_id
               WHERE d.status IN ('open', 'under_review')
               ORDER BY d.created_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_dispute_context(dispute_id: int):
    """Full context for the admin dispute detail view."""
    conn = db.get_conn()
    try:
        d = conn.execute(
            """SELECT d.*,
                      COALESCE(opener.display_name, opener.full_name, '') AS opener_name,
                      opener.role AS opener_role
               FROM disputes d
               JOIN accounts opener ON opener.account_id = d.opened_by_account_id
               WHERE d.dispute_id=?""",
            (dispute_id,),
        ).fetchone()
        if not d:
            return {}

        job = conn.execute(
            """SELECT j.*,
                      COALESCE(cl.display_name, cl.full_name, '') AS client_name,
                      COALESCE(pr.display_name, pr.full_name, '') AS provider_name,
                      COALESCE(cl.work_photo_path, '') AS client_photo,
                      COALESCE(pr.work_photo_path, '') AS provider_photo
               FROM jobs j
               JOIN accounts cl ON cl.account_id = j.client_account_id
               JOIN accounts pr ON pr.account_id = j.provider_account_id
               WHERE j.job_id=?""",
            (d["job_id"],),
        ).fetchone()
        if not job:
            return {}

        client = conn.execute(
            """SELECT account_id, role, display_name, full_name, phone,
                      area, work_photo_path, account_status
               FROM accounts WHERE account_id=?""",
            (job["client_account_id"],),
        ).fetchone()
        provider = conn.execute(
            """SELECT account_id, role, display_name, full_name, phone,
                      area, work_photo_path, account_status
               FROM accounts WHERE account_id=?""",
            (job["provider_account_id"],),
        ).fetchone()

        events = conn.execute(
            """SELECT e.event_id, e.event_type, e.from_state, e.to_state,
                      e.note, e.created_at, e.actor_role,
                      COALESCE(NULLIF(a.display_name,''), a.full_name, 'System') AS actor_name
               FROM job_events e
               LEFT JOIN accounts a ON a.account_id = e.actor_account_id
               WHERE e.job_id=?
               ORDER BY e.created_at DESC, e.event_id DESC
               LIMIT 60""",
            (d["job_id"],),
        ).fetchall()

        actions = conn.execute(
            """SELECT aa.action_id, aa.action_type, aa.reason,
                      aa.before_state, aa.after_state, aa.created_at,
                      au.username AS admin_username
               FROM admin_actions aa
               JOIN admin_users au ON au.admin_id = aa.admin_id
               WHERE aa.target_type='dispute' AND aa.target_id=?
               ORDER BY aa.created_at DESC
               LIMIT 30""",
            (str(dispute_id),),
        ).fetchall()

        client_thread = _list_thread(conn, dispute_id, job["client_account_id"])
        provider_thread = _list_thread(conn, dispute_id, job["provider_account_id"])

        return {
            "dispute": dict(d),
            "job": dict(job),
            "client": dict(client) if client else {},
            "provider": dict(provider) if provider else {},
            "events": [dict(r) for r in events],
            "admin_actions": [dict(r) for r in actions],
            "client_thread": client_thread,
            "provider_thread": provider_thread,
        }
    finally:
        conn.close()


def _list_thread(conn, dispute_id: int, party_account_id: str):
    rows = conn.execute(
        """SELECT m.message_id, m.sender_role, m.sender_admin_id,
                  m.body, m.created_at,
                  m.read_by_party, m.read_by_admin,
                  COALESCE(NULLIF(au.username, ''), '') AS admin_username
           FROM admin_party_messages m
           LEFT JOIN admin_users au ON au.admin_id = m.sender_admin_id
           WHERE m.dispute_id=? AND m.party_account_id=?
           ORDER BY m.created_at ASC, m.message_id ASC
           LIMIT 500""",
        (dispute_id, party_account_id),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["evidence"] = _list_evidence_for_message(conn, d["message_id"])
        result.append(d)
    return result


def _list_evidence_for_message(conn, message_id: int):
    rows = conn.execute(
        """SELECT evidence_id, file_path, mime_type, original_name, created_at
           FROM dispute_evidence WHERE message_id=?
           ORDER BY evidence_id ASC""",
        (message_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _evidence_dir() -> str:
    d = os.path.join(db.DATA_DIR, "dispute_evidence")
    os.makedirs(d, exist_ok=True)
    return d


def get_dispute(dispute_id: int):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT d.*,
                      COALESCE(opener.display_name, opener.full_name, '') AS opener_name,
                      opener.role AS opener_role,
                      j.client_account_id, j.provider_account_id,
                      j.category AS job_category, j.area AS job_area,
                      j.current_state AS job_state, j.description AS job_description,
                      j.created_at AS job_created_at,
                      COALESCE(cl.display_name, cl.full_name, '') AS client_name,
                      COALESCE(pr.display_name, pr.full_name, '') AS provider_name
               FROM disputes d
               JOIN jobs j ON j.job_id = d.job_id
               JOIN accounts opener ON opener.account_id = d.opened_by_account_id
               JOIN accounts cl ON cl.account_id = j.client_account_id
               JOIN accounts pr ON pr.account_id = j.provider_account_id
               WHERE d.dispute_id=?""",
            (dispute_id,),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def post_dispute_message(admin_id: str, dispute_id: int, body: str,
                         kind: str = "question", target: str = "both"):
    """Post a private admin message to one or both parties."""
    body = (body or "").strip()
    if not body:
        return False, "Message body is required."
    if len(body) < 5:
        return False, "Message is too short."
    if len(body) > 1000:
        body = body[:1000]

    if kind not in ("question", "recommendation", "note"):
        kind = "note"

    if target not in ("client", "provider", "both"):
        target = "both"

    if kind == "note":
        target = "both"

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        d = conn.execute(
            "SELECT * FROM disputes WHERE dispute_id=?", (dispute_id,)
        ).fetchone()
        if not d:
            conn.rollback()
            return False, "Dispute not found."
        if d["status"] not in ("open", "under_review"):
            conn.rollback()
            return False, "This dispute is no longer open."

        job = conn.execute(
            "SELECT * FROM jobs WHERE job_id=?", (d["job_id"],)
        ).fetchone()
        if not job:
            conn.rollback()
            return False, "Associated job not found."

        prefix = {
            "question": "Admin asks: ",
            "recommendation": "Admin recommends: ",
            "note": "Admin note: ",
        }.get(kind, "Admin note: ")
        full_body = prefix + body

        now = now_iso()

        recipients = []
        if target == "client":
            recipients = [job["client_account_id"]]
        elif target == "provider":
            recipients = [job["provider_account_id"]]
        else:
            recipients = [job["client_account_id"], job["provider_account_id"]]

        for party_id in recipients:
            if not party_id:
                continue
            conn.execute(
                """INSERT INTO admin_party_messages(
                    dispute_id, party_account_id, sender_role, sender_admin_id,
                    body, read_by_party, read_by_admin, created_at
                ) VALUES(?,?, 'admin', ?, ?, 0, 1, ?)""",
                (dispute_id, party_id, admin_id, full_body, now),
            )

        _log_admin_action(
            conn, admin_id,
            action_type=f"dispute_{kind}",
            target_type="dispute",
            target_id=str(dispute_id),
            before_state=d["status"],
            after_state=d["status"],
            reason=f"target={target} | {body[:400]}",
        )

        conn.commit()
        return True, "Message sent."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hold_dispute(admin_id: str, dispute_id: int, reason: str):
    reason = (reason or "").strip()
    if len(reason) < 10:
        return False, "Please add a short note (at least 10 characters)."
    if len(reason) > MAX_REASON_LEN:
        reason = reason[:MAX_REASON_LEN]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        d = conn.execute(
            "SELECT * FROM disputes WHERE dispute_id=?", (dispute_id,)
        ).fetchone()
        if not d:
            conn.rollback()
            return False, "Dispute not found."
        if d["status"] not in ("open", "under_review"):
            conn.rollback()
            return False, f"This dispute is already {d['status']}."

        before = d["status"]
        now = now_iso()
        conn.execute(
            """UPDATE disputes SET status='under_review', updated_at=?
               WHERE dispute_id=?""",
            (now, dispute_id),
        )

        job = conn.execute(
            "SELECT * FROM jobs WHERE job_id=?", (d["job_id"],)
        ).fetchone()
        if job:
            notice = ("An admin is reviewing this dispute. "
                      "No decision has been made yet. You can reply privately "
                      "from the dispute panel in your chat.")
            for party_id in (job["client_account_id"], job["provider_account_id"]):
                if not party_id:
                    continue
                conn.execute(
                    """INSERT INTO admin_party_messages(
                        dispute_id, party_account_id, sender_role, sender_admin_id,
                        body, read_by_party, read_by_admin, created_at
                    ) VALUES(?,?, 'admin', ?, ?, 0, 1, ?)""",
                    (dispute_id, party_id, admin_id, notice, now),
                )

        _log_admin_action(
            conn, admin_id,
            action_type="dispute_hold",
            target_type="dispute",
            target_id=str(dispute_id),
            before_state=before,
            after_state="under_review",
            reason=reason,
        )
        conn.commit()
        return True, "Dispute marked under review."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def resolve_dispute(admin_id: str, dispute_id: int, outcome: str,
                    reason: str):
    reason = (reason or "").strip()
    if len(reason) < 10:
        return False, "Please explain your decision (at least 10 characters)."
    if len(reason) > MAX_REASON_LEN:
        reason = reason[:MAX_REASON_LEN]

    if outcome not in ("dismiss", "cancel", "complete"):
        return False, "Invalid outcome."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        d = conn.execute(
            "SELECT * FROM disputes WHERE dispute_id=?", (dispute_id,)
        ).fetchone()
        if not d:
            conn.rollback()
            return False, "Dispute not found."
        if d["status"] not in ("open", "under_review"):
            conn.rollback()
            return False, f"This dispute is already {d['status']}."

        job = conn.execute(
            "SELECT * FROM jobs WHERE job_id=?", (d["job_id"],)
        ).fetchone()
        if not job:
            conn.rollback()
            return False, "Associated job not found."

        now = now_iso()
        before_state = job["current_state"]
        is_anon = bool(d["is_anonymous"]) if "is_anonymous" in d.keys() else False

        if outcome == "dismiss":
            if is_anon:
                conn.execute(
                    """UPDATE disputes
                       SET status='dismissed', resolution_note=?, resolved_by_admin_id=?,
                           updated_at=?
                       WHERE dispute_id=?""",
                    (f"[dismiss-anon] {reason}", admin_id, now, dispute_id),
                )
                after_state = d["previous_state"] or job["current_state"]
            else:
                previous = d["previous_state"] or "client_confirmed"
                conn.execute(
                    """UPDATE disputes
                       SET status='dismissed', resolution_note=?, resolved_by_admin_id=?,
                           updated_at=?
                       WHERE dispute_id=?""",
                    (f"[dismiss] {reason}", admin_id, now, dispute_id),
                )
                conn.execute(
                    "UPDATE jobs SET current_state=?, updated_at=? WHERE job_id=?",
                    (previous, now, d["job_id"]),
                )
                after_state = previous
        elif outcome == "cancel":
            conn.execute(
                """UPDATE disputes
                   SET status='resolved', resolution_note=?, resolved_by_admin_id=?,
                       updated_at=?
                   WHERE dispute_id=?""",
                (f"[cancel] {reason}", admin_id, now, dispute_id),
            )
            conn.execute(
                """UPDATE jobs
                   SET current_state='cancelled',
                       cancellation_reason=?, cancellation_by=?,
                       closed_at=?, updated_at=?
                   WHERE job_id=?""",
                (f"Admin resolved dispute - cancelled: {reason}",
                 admin_id, now, now, d["job_id"]),
            )
            after_state = "cancelled"
        else:
            conn.execute(
                """UPDATE disputes
                   SET status='resolved', resolution_note=?, resolved_by_admin_id=?,
                       updated_at=?
                   WHERE dispute_id=?""",
                (f"[complete] {reason}", admin_id, now, dispute_id),
            )
            conn.execute(
                """UPDATE jobs
                   SET current_state='completed', closed_at=?, updated_at=?
                   WHERE job_id=?""",
                (now, now, d["job_id"]),
            )
            after_state = "completed"

        outcome_text = {
            "dismiss": "The admin has closed this dispute. The job resumes from where it was.",
            "cancel": "The admin has resolved this dispute by cancelling the job.",
            "complete": "The admin has resolved this dispute by marking the job complete.",
        }.get(outcome, "The admin has resolved this dispute.")
        notice = f"{outcome_text}\n\nReason: {reason}"

        for party_id in (job["client_account_id"], job["provider_account_id"]):
            if not party_id:
                continue
            conn.execute(
                """INSERT INTO admin_party_messages(
                    dispute_id, party_account_id, sender_role, sender_admin_id,
                    body, read_by_party, read_by_admin, created_at
                ) VALUES(?,?, 'admin', ?, ?, 0, 1, ?)""",
                (dispute_id, party_id, admin_id, notice, now),
            )

        _log_admin_action(
            conn, admin_id,
            action_type=f"dispute_resolve_{outcome}",
            target_type="dispute",
            target_id=str(dispute_id),
            before_state=before_state,
            after_state=after_state,
            reason=reason,
        )

        conn.commit()
        return True, f"Dispute resolved ({outcome})."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def count_open_disputes():
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM disputes WHERE status IN ('open','under_review')"
        ).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


# ------------------------------------------------------------------
# Party-side admin thread API
# ------------------------------------------------------------------

def list_party_thread(account_id: str):
    """For a party: list their private admin threads.

    Returns every dispute the account was party to that has at least one
    admin<->party message, whether open or closed. Closed threads carry
    `resolution_note` so the UI can show the reason the admin gave.
    Open disputes sort first; within each group, newest activity first.
    """
    if not account_id:
        return []

    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT d.dispute_id, d.job_id, d.title AS dispute_title,
                      d.status AS dispute_status,
                      d.created_at AS dispute_created_at,
                      d.updated_at AS dispute_updated_at,
                      COALESCE(d.resolution_note, '') AS resolution_note,
                      j.category AS job_category,
                      j.current_state AS job_state
               FROM disputes d
               JOIN jobs j ON j.job_id = d.job_id
               WHERE (j.client_account_id = ? OR j.provider_account_id = ?)
                 AND EXISTS (
                     SELECT 1 FROM admin_party_messages m
                     WHERE m.dispute_id = d.dispute_id
                       AND m.party_account_id = ?
                 )
               ORDER BY
                 CASE WHEN d.status IN ('open','under_review') THEN 0 ELSE 1 END,
                 d.updated_at DESC
               LIMIT 100""",
            (account_id, account_id, account_id),
        ).fetchall()

        result = []
        for r in rows:
            d = dict(r)
            unread = conn.execute(
                """SELECT COUNT(*) AS n FROM admin_party_messages
                   WHERE dispute_id=? AND party_account_id=?
                     AND sender_role='admin' AND read_by_party=0""",
                (d["dispute_id"], account_id),
            ).fetchone()["n"]
            d["unread"] = unread

            msgs = conn.execute(
                """SELECT message_id, sender_role, body, created_at,
                          read_by_party
                   FROM admin_party_messages
                   WHERE dispute_id=? AND party_account_id=?
                   ORDER BY created_at ASC, message_id ASC
                   LIMIT 500""",
                (d["dispute_id"], account_id),
            ).fetchall()

            out_msgs = []
            for m in msgs:
                mm = dict(m)
                mm["evidence"] = _list_evidence_for_message(conn, mm["message_id"])
                out_msgs.append(mm)
            d["messages"] = out_msgs
            result.append(d)

        return result
    finally:
        conn.close()


def send_party_message(account_id: str, dispute_id: int, body: str,
                       evidence_path: str = ""):
    """A party sends a private message to the admin on an open dispute.

    If `evidence_path` is provided, the file is copied into the
    evidence directory, screenshotted-safe processed (EXIF stripped,
    re-encoded), and linked to the message.
    """
    body = (body or "").strip()
    evidence_path = (evidence_path or "").strip()
    if not body and not evidence_path:
        return False, "Message or evidence is required."
    if body and len(body) < 2:
        return False, "Message is too short."
    if len(body) > 1000:
        body = body[:1000]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        d = conn.execute(
            "SELECT * FROM disputes WHERE dispute_id=?", (dispute_id,)
        ).fetchone()
        if not d:
            conn.rollback()
            return False, "Dispute not found."
        if d["status"] not in ("open", "under_review"):
            conn.rollback()
            return False, "This dispute is closed. You cannot reply."

        job = conn.execute(
            "SELECT * FROM jobs WHERE job_id=?", (d["job_id"],)
        ).fetchone()
        if not job:
            conn.rollback()
            return False, "Job not found."

        if account_id not in (job["client_account_id"], job["provider_account_id"]):
            conn.rollback()
            return False, "You are not part of this dispute."

        now = now_iso()
        cur = conn.execute(
            """INSERT INTO admin_party_messages(
                dispute_id, party_account_id, sender_role, sender_admin_id,
                body, read_by_party, read_by_admin, created_at
            ) VALUES(?,?, 'party', NULL, ?, 1, 0, ?)""",
            (dispute_id, account_id, body, now),
        )
        message_id = cur.lastrowid

        # Handle evidence upload (optional)
        if evidence_path:
            ok, err, stored = _ingest_evidence(evidence_path, message_id)
            if not ok:
                conn.rollback()
                return False, err

            for ev in stored:
                conn.execute(
                    """INSERT INTO dispute_evidence(
                        message_id, file_path, mime_type, original_name, created_at
                    ) VALUES(?,?,?,?,?)""",
                    (message_id, ev["file_path"], ev["mime_type"],
                     ev["original_name"], now),
                )

        conn.commit()
        return True, "Message sent to the admin."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _ingest_evidence(src_path: str, message_id: int):
    """Copy a file into the evidence dir, strip EXIF if it's a photo,
    and return a list of stored entries.

    Returns (ok, error_message, list_of_entries).
    """
    src_path = (src_path or "").strip()
    if src_path.startswith("file:///"):
        src_path = src_path[8:]
    elif src_path.startswith("file://"):
        src_path = src_path[7:]
    if not src_path or not os.path.exists(src_path):
        return False, "Pick a file to attach.", []

    try:
        size = os.path.getsize(src_path)
    except OSError:
        return False, "Could not read the file.", []
    if size > MAX_EVIDENCE_SIZE_BYTES:
        mb = MAX_EVIDENCE_SIZE_BYTES // (1024 * 1024)
        return False, f"File is too large. Max {mb} MB.", []

    ext = os.path.splitext(src_path)[1].lower()
    original_name = os.path.basename(src_path)

    is_image = ext in (".jpg", ".jpeg", ".png", ".webp")
    is_pdf = ext == ".pdf"

    if not is_image and not is_pdf:
        return False, "Only images (JPG, PNG, WebP) and PDFs are allowed.", []

    evidence_dir = _evidence_dir()

    if is_image:
        # Run through the EXIF-stripping + re-encoding pipeline
        fname = f"msg{message_id}_{uuid.uuid4().hex[:8]}.jpg"
        dst = os.path.join(evidence_dir, fname)
        ok, msg = face_screen.prepare_profile_image(src_path, dst)
        if not ok:
            return False, msg, []
        return True, "", [{
            "file_path": dst,
            "mime_type": "image/jpeg",
            "original_name": original_name,
        }]

    # PDF: straight copy (no processing)
    fname = f"msg{message_id}_{uuid.uuid4().hex[:8]}{ext}"
    dst = os.path.join(evidence_dir, fname)
    try:
        shutil.copy2(src_path, dst)
    except Exception as e:
        log.exception("Could not copy evidence file")
        return False, f"Could not store the file: {e}", []
    return True, "", [{
        "file_path": dst,
        "mime_type": "application/pdf",
        "original_name": original_name,
    }]


def mark_thread_read(account_id: str, dispute_id: int):
    conn = db.get_conn()
    try:
        conn.execute(
            """UPDATE admin_party_messages
               SET read_by_party = 1
               WHERE dispute_id = ?
                 AND party_account_id = ?
                 AND sender_role = 'admin'
                 AND read_by_party = 0""",
            (dispute_id, account_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def mark_thread_read_by_admin(dispute_id: int, party_account_id: str):
    conn = db.get_conn()
    try:
        conn.execute(
            """UPDATE admin_party_messages
               SET read_by_admin = 1
               WHERE dispute_id = ?
                 AND party_account_id = ?
                 AND sender_role = 'party'
                 AND read_by_admin = 0""",
            (dispute_id, party_account_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


# ------------------------------------------------------------------
# Reports
# ------------------------------------------------------------------

def list_open_reports(kind: str = "", limit: int = 200):
    conn = db.get_conn()
    try:
        if kind:
            rows = conn.execute(
                """SELECT r.report_id, r.kind,
                          r.reporter_account_id, r.reported_account_id,
                          r.reason, COALESCE(r.notes, '') AS notes,
                          COALESCE(r.context_job_id, '') AS context_job_id,
                          r.status, r.created_at,
                          COALESCE(rep.display_name, rep.full_name, '') AS reporter_name,
                          rep.role AS reporter_role,
                          COALESCE(repd.display_name, repd.full_name, '') AS reported_name,
                          repd.role AS reported_role
                   FROM user_reports r
                   JOIN accounts rep ON rep.account_id = r.reporter_account_id
                   JOIN accounts repd ON repd.account_id = r.reported_account_id
                   WHERE r.status='open' AND r.kind=?
                   ORDER BY r.created_at DESC
                   LIMIT ?""",
                (kind, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT r.report_id, r.kind,
                          r.reporter_account_id, r.reported_account_id,
                          r.reason, COALESCE(r.notes, '') AS notes,
                          COALESCE(r.context_job_id, '') AS context_job_id,
                          r.status, r.created_at,
                          COALESCE(rep.display_name, rep.full_name, '') AS reporter_name,
                          rep.role AS reporter_role,
                          COALESCE(repd.display_name, repd.full_name, '') AS reported_name,
                          repd.role AS reported_role
                   FROM user_reports r
                   JOIN accounts rep ON rep.account_id = r.reporter_account_id
                   JOIN accounts repd ON repd.account_id = r.reported_account_id
                   WHERE r.status='open'
                   ORDER BY r.created_at DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def dismiss_report(admin_id: str, report_id: int, reason: str):
    reason = (reason or "").strip()
    if len(reason) < 10:
        return False, "Please explain your decision (at least 10 characters)."
    if len(reason) > MAX_REASON_LEN:
        reason = reason[:MAX_REASON_LEN]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        r = conn.execute(
            "SELECT * FROM user_reports WHERE report_id=?", (report_id,)
        ).fetchone()
        if not r:
            conn.rollback()
            return False, "Report not found."
        if r["status"] != "open":
            conn.rollback()
            return False, f"This report is already {r['status']}."

        conn.execute(
            """UPDATE user_reports
               SET status='reviewed', notes=?
               WHERE report_id=?""",
            (f"[admin {admin_id}] {reason}", report_id),
        )

        _log_admin_action(
            conn, admin_id,
            action_type="report_dismissed",
            target_type="user_report",
            target_id=str(report_id),
            before_state="open",
            after_state="reviewed",
            reason=reason,
        )
        conn.commit()
        return True, "Report reviewed."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def count_open_reports():
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM user_reports WHERE status='open'"
        ).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


# ------------------------------------------------------------------
# Accounts
# ------------------------------------------------------------------

VALID_STATUSES = (
    "active", "under_review", "restricted",
    "suspended", "on_hold", "closed",
)


def search_accounts(query: str = "", role: str = "", limit: int = 100):
    conn = db.get_conn()
    try:
        where = ["1=1"]
        params = []

        if query:
            q = f"%{query.strip()}%"
            where.append(
                """(COALESCE(a.display_name, '') LIKE ?
                    OR COALESCE(a.full_name, '') LIKE ?
                    OR a.phone LIKE ?)"""
            )
            params.extend([q, q, q])

        if role in ("client", "provider"):
            where.append("a.role=?")
            params.append(role)

        where_sql = " AND ".join(where)

        rows = conn.execute(
            f"""SELECT a.account_id, a.role, a.display_name, a.full_name,
                       a.phone, a.area, a.account_status, a.setup_complete,
                       a.created_at,
                       (SELECT COUNT(*) FROM jobs j
                        WHERE (j.client_account_id=a.account_id
                               OR j.provider_account_id=a.account_id)
                          AND j.current_state IN ('completed','completed_by_timeout')
                       ) AS completed_jobs,
                       (SELECT COUNT(*) FROM jobs j
                        WHERE (j.client_account_id=a.account_id
                               OR j.provider_account_id=a.account_id)
                          AND j.current_state IN ('cancelled','abandoned')
                       ) AS cancelled_jobs,
                       (SELECT COUNT(*) FROM user_reports ur
                        WHERE ur.reported_account_id=a.account_id
                          AND ur.status='open'
                       ) AS open_reports
                FROM accounts a
                WHERE {where_sql}
                ORDER BY a.created_at DESC
                LIMIT ?""",
            (*params, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_account_detail(account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT account_id, role, display_name, full_name, phone, email,
                      area, bio, account_status, setup_complete, created_at
               FROM accounts WHERE account_id=?""",
            (account_id,),
        ).fetchone()
        if not row:
            return {}
        d = dict(row)

        d["completed_jobs"] = conn.execute(
            """SELECT COUNT(*) AS n FROM jobs
               WHERE (client_account_id=? OR provider_account_id=?)
                 AND current_state IN ('completed','completed_by_timeout')""",
            (account_id, account_id),
        ).fetchone()["n"]

        d["cancelled_jobs"] = conn.execute(
            """SELECT COUNT(*) AS n FROM jobs
               WHERE (client_account_id=? OR provider_account_id=?)
                 AND current_state IN ('cancelled','abandoned')""",
            (account_id, account_id),
        ).fetchone()["n"]

        d["open_reports"] = conn.execute(
            """SELECT COUNT(*) AS n FROM user_reports
               WHERE reported_account_id=? AND status='open'""",
            (account_id,),
        ).fetchone()["n"]

        d["open_disputes"] = conn.execute(
            """SELECT COUNT(*) AS n FROM disputes d
               JOIN jobs j ON j.job_id = d.job_id
               WHERE (j.client_account_id=? OR j.provider_account_id=?)
                 AND d.status IN ('open','under_review')""",
            (account_id, account_id),
        ).fetchone()["n"]

        d["recent_actions"] = [
            dict(r) for r in conn.execute(
                """SELECT action_type, target_type, target_id, reason, created_at
                   FROM admin_actions
                   WHERE (target_type='account' AND target_id=?)
                      OR (target_type='account_status' AND target_id=?)
                   ORDER BY created_at DESC LIMIT 10""",
                (account_id, account_id),
            ).fetchall()
        ]
        return d
    finally:
        conn.close()


def set_account_status(admin_id: str, account_id: str, new_status: str,
                       reason: str):
    if new_status not in VALID_STATUSES:
        return False, "Invalid status."
    reason = (reason or "").strip()
    if len(reason) < 10:
        return False, "Please explain the reason (at least 10 characters)."
    if len(reason) > MAX_REASON_LEN:
        reason = reason[:MAX_REASON_LEN]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT account_id, account_status FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            conn.rollback()
            return False, "Account not found."

        old_status = row["account_status"]
        if old_status == new_status:
            conn.rollback()
            return False, f"Account is already {new_status}."

        conn.execute(
            """UPDATE accounts SET account_status=?, updated_at=?
               WHERE account_id=?""",
            (new_status, now_iso(), account_id),
        )

        _log_admin_action(
            conn, admin_id,
            action_type="account_status_changed",
            target_type="account_status",
            target_id=account_id,
            before_state=old_status,
            after_state=new_status,
            reason=reason,
        )
        conn.commit()
        return True, f"Status changed from {old_status} to {new_status}."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------
# Password reset issuance
# ------------------------------------------------------------------

def _generate_temp_password() -> str:
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    specials = "!@#$%^&*"

    chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(specials),
    ]
    alphabet = lower + upper + digits + specials
    while len(chars) < TEMP_PASSWORD_LEN:
        chars.append(secrets.choice(alphabet))

    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def issue_password_reset(admin_id: str, account_id: str, reason: str):
    reason = (reason or "").strip()
    if len(reason) < 10:
        return False, "Please explain why this reset is being issued (at least 10 characters)."
    if len(reason) > MAX_REASON_LEN:
        reason = reason[:MAX_REASON_LEN]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT account_id, phone FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            conn.rollback()
            return False, "Account not found."

        temp_password = _generate_temp_password()
        now = now_iso()
        expires_at = (datetime.now(timezone.utc)
                      + timedelta(hours=RESET_TTL_HOURS)
                      ).isoformat(timespec="seconds")

        conn.execute(
            """UPDATE accounts
               SET password_hash=?, password_upgrade_required=1, updated_at=?
               WHERE account_id=?""",
            (_hash_password(temp_password), now, account_id),
        )
        conn.execute(
            """INSERT INTO admin_password_resets(
                admin_id, target_account_id, expires_at, created_at
            ) VALUES(?,?,?,?)""",
            (admin_id, account_id, expires_at, now),
        )

        _log_admin_action(
            conn, admin_id,
            action_type="password_reset_issued",
            target_type="account",
            target_id=account_id,
            before_state="",
            after_state="password_upgrade_required=1",
            reason=reason,
        )
        conn.commit()
        return True, temp_password
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------
# Audit log
# ------------------------------------------------------------------

def list_admin_actions(limit: int = 200, admin_id: str = "",
                       action_type: str = ""):
    conn = db.get_conn()
    try:
        where = ["1=1"]
        params = []
        if admin_id:
            where.append("aa.admin_id=?")
            params.append(admin_id)
        if action_type:
            where.append("aa.action_type=?")
            params.append(action_type)

        where_sql = " AND ".join(where)
        rows = conn.execute(
            f"""SELECT aa.action_id, aa.admin_id, aa.action_type,
                       aa.target_type, aa.target_id,
                       aa.before_state, aa.after_state,
                       aa.reason, aa.created_at,
                       au.username AS admin_username
                FROM admin_actions aa
                JOIN admin_users au ON au.admin_id = aa.admin_id
                WHERE {where_sql}
                ORDER BY aa.created_at DESC
                LIMIT ?""",
            (*params, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ------------------------------------------------------------------
# Dashboard stats
# ------------------------------------------------------------------

def get_dashboard_stats():
    conn = db.get_conn()
    try:
        return {
            "open_disputes": conn.execute(
                "SELECT COUNT(*) AS n FROM disputes WHERE status IN ('open','under_review')"
            ).fetchone()["n"],
            "open_reports": conn.execute(
                "SELECT COUNT(*) AS n FROM user_reports WHERE status='open'"
            ).fetchone()["n"],
            "total_accounts": conn.execute(
                "SELECT COUNT(*) AS n FROM accounts"
            ).fetchone()["n"],
            "restricted_accounts": conn.execute(
                """SELECT COUNT(*) AS n FROM accounts
                   WHERE account_status NOT IN ('active')"""
            ).fetchone()["n"],
            "unread_admin_threads": conn.execute(
                """SELECT COUNT(*) AS n FROM admin_party_messages
                   WHERE sender_role='party' AND read_by_admin=0"""
            ).fetchone()["n"],
        }
    finally:
        conn.close()


# ------------------------------------------------------------------
# Self-service
# ------------------------------------------------------------------

def change_own_password(admin_id: str, current_password: str,
                        new_password: str, confirmation: str):
    if not current_password:
        return False, "Enter your current password."
    if not new_password:
        return False, "Enter a new password."
    if new_password != confirmation:
        return False, "New passwords do not match."

    ok, msg = passwords.validate_password(new_password)
    if not ok:
        return False, msg

    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT password_hash FROM admin_users WHERE admin_id=?",
            (admin_id,),
        ).fetchone()
        if not row:
            return False, "Admin account not found."
        if not _check_password(current_password, row["password_hash"]):
            return False, "Current password is incorrect."

        conn.execute(
            """UPDATE admin_users SET password_hash=? WHERE admin_id=?""",
            (_hash_password(new_password), admin_id),
        )
        _log_admin_action(
            conn, admin_id,
            action_type="admin_password_changed",
            target_type="admin",
            target_id=admin_id,
            before_state="",
            after_state="password updated",
            reason="Admin changed own password",
        )
        conn.commit()
        return True, "Password updated."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def change_own_username(admin_id: str, new_username: str, password: str):
    new_username = (new_username or "").strip()
    if not new_username:
        return False, "Enter a new username."
    if len(new_username) < 3:
        return False, "Username must be at least 3 characters."
    if len(new_username) > 40:
        return False, "Username must be 40 characters or fewer."
    if " " in new_username:
        return False, "Username cannot contain spaces."

    if not password:
        return False, "Confirm with your password."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT username, password_hash FROM admin_users WHERE admin_id=?",
            (admin_id,),
        ).fetchone()
        if not row:
            conn.rollback()
            return False, "Admin account not found."
        if not _check_password(password, row["password_hash"]):
            conn.rollback()
            return False, "Password is incorrect."

        old_username = row["username"]
        if new_username.lower() == old_username.lower():
            conn.rollback()
            return False, "That is already your username."

        taken = conn.execute(
            "SELECT 1 FROM admin_users WHERE lower(username)=lower(?) AND admin_id<>?",
            (new_username, admin_id),
        ).fetchone()
        if taken:
            conn.rollback()
            return False, "That username is already taken."

        conn.execute(
            "UPDATE admin_users SET username=? WHERE admin_id=?",
            (new_username, admin_id),
        )
        _log_admin_action(
            conn, admin_id,
            action_type="admin_username_changed",
            target_type="admin",
            target_id=admin_id,
            before_state=old_username,
            after_state=new_username,
            reason="Admin changed own username",
        )
        conn.commit()
        return True, "Username updated."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def is_default_password(admin_id: str) -> bool:
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT password_hash FROM admin_users WHERE admin_id=?",
            (admin_id,),
        ).fetchone()
        if not row:
            return False
        return _check_password(LEGACY_DEFAULT_ADMIN_PASSWORD, row["password_hash"])
    finally:
        conn.close()