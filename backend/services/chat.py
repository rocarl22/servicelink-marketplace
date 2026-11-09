"""Conversations and messages."""
import logging
from .. import database as db
from . import scam_shield
from .validation import clean_text, now_iso


log = logging.getLogger("servicelink.chat")

MAX_BODY_LEN = 1500
PREVIEW_LEN = 80


def ensure_conversation(client_account_id: str, provider_account_id: str) -> int:
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        c = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?", (client_account_id,)
        ).fetchone()
        p = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?", (provider_account_id,)
        ).fetchone()
        if not c or c["role"] != "client":
            conn.rollback()
            raise ValueError("client_account_id is not a client account")
        if not p or p["role"] != "provider":
            conn.rollback()
            raise ValueError("provider_account_id is not a provider account")

        row = conn.execute(
            """SELECT conversation_id FROM conversations
               WHERE client_account_id=? AND provider_account_id=?""",
            (client_account_id, provider_account_id),
        ).fetchone()
        if row:
            conn.commit()
            return row["conversation_id"]

        now = now_iso()
        cur = conn.execute(
            """INSERT INTO conversations(
                client_account_id, provider_account_id,
                last_message_at, last_message_preview,
                created_at, updated_at
            ) VALUES(?,?,?,?,?,?)""",
            (client_account_id, provider_account_id, "", "", now, now),
        )
        conversation_id = cur.lastrowid
        conn.commit()
        return conversation_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_conversations(account_id: str):
    conn = db.get_conn()
    try:
        account = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if not account:
            return []
        role = account["role"]

        if role == "client":
            sql = """
                SELECT c.conversation_id, c.client_account_id, c.provider_account_id,
                       c.last_message_at, c.last_message_preview, c.created_at,
                       COALESCE(p.display_name, p.full_name) AS counterpart_name,
                       p.account_id AS counterpart_id,
                       COALESCE(p.work_photo_path, '') AS counterpart_photo,
                       (SELECT COUNT(*) FROM messages m
                        WHERE m.conversation_id=c.conversation_id
                          AND m.sender_account_id <> ?
                          AND m.read_at='') AS unread_count
                FROM conversations c
                JOIN accounts p ON p.account_id = c.provider_account_id
                WHERE c.client_account_id=?
                ORDER BY c.last_message_at DESC, c.conversation_id DESC
            """
        else:
            sql = """
                SELECT c.conversation_id, c.client_account_id, c.provider_account_id,
                       c.last_message_at, c.last_message_preview, c.created_at,
                       COALESCE(cl.display_name, cl.full_name) AS counterpart_name,
                       cl.account_id AS counterpart_id,
                       COALESCE(cl.work_photo_path, '') AS counterpart_photo,
                       (SELECT COUNT(*) FROM messages m
                        WHERE m.conversation_id=c.conversation_id
                          AND m.sender_account_id <> ?
                          AND m.read_at='') AS unread_count
                FROM conversations c
                JOIN accounts cl ON cl.account_id = c.client_account_id
                WHERE c.provider_account_id=?
                ORDER BY c.last_message_at DESC, c.conversation_id DESC
            """
        rows = conn.execute(sql, (account_id, account_id)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_conversation(conversation_id: int, account_id: str = ""):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT c.*,
                      COALESCE(cl.display_name, cl.full_name) AS client_name,
                      COALESCE(p.display_name, p.full_name) AS provider_name,
                      COALESCE(cl.work_photo_path, '') AS client_photo,
                      COALESCE(p.work_photo_path, '') AS provider_photo
               FROM conversations c
               JOIN accounts cl ON cl.account_id = c.client_account_id
               JOIN accounts p ON p.account_id = c.provider_account_id
               WHERE c.conversation_id=?""",
            (conversation_id,),
        ).fetchone()
        if not row:
            return {}
        data = dict(row)
        if account_id and account_id not in (
            data["client_account_id"], data["provider_account_id"]
        ):
            return {}
        return data
    finally:
        conn.close()


def _has_live_engagement(conn, client_account_id: str, provider_account_id: str) -> bool:
    # Block overrides any live engagement
    row = conn.execute(
        """SELECT 1 FROM blocks
           WHERE (blocker_account_id=? AND blocked_account_id=?)
              OR (blocker_account_id=? AND blocked_account_id=?)
           LIMIT 1""",
        (client_account_id, provider_account_id,
         provider_account_id, client_account_id),
    ).fetchone()
    if row:
        return False

    # Pending direct request?
    row = conn.execute(
        """SELECT 1 FROM service_requests
           WHERE client_account_id=?
             AND provider_account_id=?
             AND status='open'
           LIMIT 1""",
        (client_account_id, provider_account_id),
    ).fetchone()
    if row:
        return True

    # Active job?
    row = conn.execute(
        """SELECT 1 FROM jobs
           WHERE client_account_id=?
             AND provider_account_id=?
             AND closed_at=''
             AND current_state NOT IN ('cancelled','abandoned')
           LIMIT 1""",
        (client_account_id, provider_account_id),
    ).fetchone()
    return bool(row)


def is_chat_live(conversation_id: int) -> bool:
    conn = db.get_conn()
    try:
        conv = conn.execute(
            """SELECT client_account_id, provider_account_id
               FROM conversations WHERE conversation_id=?""",
            (conversation_id,),
        ).fetchone()
        if not conv:
            return False
        return _has_live_engagement(
            conn, conv["client_account_id"], conv["provider_account_id"]
        )
    finally:
        conn.close()


def list_messages(conversation_id: int, account_id: str = "", limit: int = 200):
    if account_id:
        conv = get_conversation(conversation_id, account_id)
        if not conv:
            return []

    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT m.*,
                      COALESCE(a.display_name, a.full_name) AS sender_name,
                      COALESCE(a.work_photo_path, '') AS sender_photo
               FROM messages m
               LEFT JOIN accounts a ON a.account_id = m.sender_account_id
               WHERE m.conversation_id=?
               ORDER BY m.created_at DESC, m.message_id DESC
               LIMIT ?""",
            (conversation_id, limit),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]
    finally:
        conn.close()


def _post_payment_warning_once(conversation_id: int):
    """Post the off-platform-payment safety reminder unless it was posted recently."""
    conn = db.get_conn()
    try:
        recent = conn.execute(
            """SELECT body FROM messages WHERE conversation_id=? AND sender_role='system'
               ORDER BY message_id DESC LIMIT 15""", (conversation_id,)).fetchall()
    finally:
        conn.close()
    if not any(r["body"] == scam_shield.PAYMENT_WARNING for r in recent):
        send_system_message(conversation_id, scam_shield.PAYMENT_WARNING)


def send_message(conversation_id: int, sender_account_id: str, body: str):
    # Strip invisible/control characters first so they cannot be used to dodge the shield.
    body = clean_text(body).strip()
    if not body:
        return False, "Message is required."
    if len(body) > MAX_BODY_LEN:
        return False, f"Message must be {MAX_BODY_LEN} characters or fewer."
    # Scam shield: hide phone numbers / emails / links; flag off-platform payment talk.
    shield = scam_shield.screen(body)
    body = shield.text
    if shield.masked_count or shield.off_platform_payment:
        log.info("scam shield: masked=%d payment_flag=%s", shield.masked_count, shield.off_platform_payment)

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        conv = conn.execute(
            """SELECT client_account_id, provider_account_id
               FROM conversations WHERE conversation_id=?""",
            (conversation_id,),
        ).fetchone()
        if not conv:
            conn.rollback()
            return False, "Conversation not found."
        if sender_account_id not in (
            conv["client_account_id"], conv["provider_account_id"]
        ):
            conn.rollback()
            return False, "You are not part of this conversation."

        # Block check
        row = conn.execute(
            """SELECT 1 FROM blocks
               WHERE (blocker_account_id=? AND blocked_account_id=?)
                  OR (blocker_account_id=? AND blocked_account_id=?)
               LIMIT 1""",
            (conv["client_account_id"], conv["provider_account_id"],
             conv["provider_account_id"], conv["client_account_id"]),
        ).fetchone()
        if row:
            conn.rollback()
            return False, "This conversation is closed."

        # Chat gating
        if not _has_live_engagement(conn,
                                    conv["client_account_id"],
                                    conv["provider_account_id"]):
            conn.rollback()
            return False, "This conversation is closed. Send a new request to reopen it."

        role = "client" if sender_account_id == conv["client_account_id"] else "provider"
        now = now_iso()
        preview = body[:PREVIEW_LEN]

        cur = conn.execute(
            """INSERT INTO messages(
                conversation_id, sender_account_id, sender_role,
                body, read_at, created_at
            ) VALUES(?,?,?,?,?,?)""",
            (conversation_id, sender_account_id, role, body, "", now),
        )
        conn.execute(
            """UPDATE conversations
               SET last_message_at=?, last_message_preview=?, updated_at=?
               WHERE conversation_id=?""",
            (now, preview, now, conversation_id),
        )
        conn.commit()
        new_id = cur.lastrowid
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    if shield.off_platform_payment:
        _post_payment_warning_once(conversation_id)
    return True, str(new_id)


def send_system_message(conversation_id: int, body: str,
                        request_id: int = 0, job_id: int = 0):
    body = (body or "").strip()
    if not body:
        return False, "Message body is required."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conv = conn.execute(
            "SELECT conversation_id FROM conversations WHERE conversation_id=?",
            (conversation_id,),
        ).fetchone()
        if not conv:
            conn.rollback()
            return False, "Conversation not found."

        now = now_iso()
        preview = body[:PREVIEW_LEN]
        conn.execute(
            """INSERT INTO messages(
                conversation_id, sender_account_id, sender_role,
                body, request_id, job_id, read_at, created_at
            ) VALUES(?,NULL,'system',?,?,?,?,?)""",
            (conversation_id, body, request_id or None, job_id or None, now, now),
        )
        conn.execute(
            """UPDATE conversations
               SET last_message_at=?, last_message_preview=?, updated_at=?
               WHERE conversation_id=?""",
            (now, preview, now, conversation_id),
        )
        conn.commit()
        return True, "System message posted."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_read(conversation_id: int, account_id: str):
    conn = db.get_conn()
    try:
        conn.execute(
            """UPDATE messages SET read_at=?
               WHERE conversation_id=?
                 AND sender_account_id <> ?
                 AND read_at=''""",
            (now_iso(), conversation_id, account_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def unread_count(account_id: str) -> int:
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT COUNT(*) AS n FROM messages m
               JOIN conversations c ON c.conversation_id = m.conversation_id
               WHERE m.read_at=''
                 AND m.sender_account_id <> ?
                 AND (c.client_account_id=? OR c.provider_account_id=?)""",
            (account_id, account_id, account_id),
        ).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


def _account_name(account_id: str) -> str:
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT display_name, full_name FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            return ""
        return row["display_name"] or row["full_name"] or ""
    finally:
        conn.close()


def post_direct_request_message(
    client_account_id: str,
    provider_account_id: str,
    category: str,
    description: str,
    area: str,
    preferred_time: str = "",
    budget_text: str = "",
    request_id: int = 0,
) -> int:
    conversation_id = ensure_conversation(client_account_id, provider_account_id)

    client_name = _account_name(client_account_id) or "The client"
    provider_name = _account_name(provider_account_id) or "there"

    lines = [
        f"Hi {provider_name}, I'm {client_name}. I'd like to request: {category}.",
        f"{description}",
        f"Location: {area}",
    ]
    if preferred_time:
        lines.append(f"Preferred time: {preferred_time}")
    if budget_text:
        lines.append(f"Budget: {budget_text}")
    body = "\n".join(lines)

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        now = now_iso()
        preview = body[:PREVIEW_LEN]
        conn.execute(
            """INSERT INTO messages(
                conversation_id, sender_account_id, sender_role,
                body, request_id, read_at, created_at
            ) VALUES(?,?,'client',?,?,?,?)""",
            (conversation_id, client_account_id, body, request_id or None, "", now),
        )
        conn.execute(
            """UPDATE conversations
               SET last_message_at=?, last_message_preview=?, updated_at=?
               WHERE conversation_id=?""",
            (now, preview, now, conversation_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return conversation_id


def post_system_message_for_request(
    client_account_id: str,
    provider_account_id: str,
    request_id: int,
    body: str,
) -> int:
    conversation_id = ensure_conversation(client_account_id, provider_account_id)
    send_system_message(conversation_id, body, request_id=request_id or 0)
    return conversation_id