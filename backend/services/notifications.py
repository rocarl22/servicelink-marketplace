"""Derived notifications.

Notifications are not stored as rows — they are derived on demand from
existing activity (messages, job events, new direct requests, private
admin<->party threads). Read state is tracked in the
`notification_reads` table, keyed by a stable string derived from the
source event.

Key format (stable across re-derivations):
    msg:<message_id>          — a chat message
    jev:<event_id>            — a job event
    req:<request_id>          — a new direct request
    adm:<admin_msg_id>        — a private admin<->party message
"""
import logging

from .. import database as db


log = logging.getLogger("servicelink.notifications")


MAX_ITEMS = 50
MAX_TITLE_LEN = 80
MAX_BODY_LEN = 160


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def list_for_account(account_id: str, limit: int = MAX_ITEMS):
    """Return a merged, newest-first list of notifications for account_id."""
    if not account_id:
        return []

    account = _get_account(account_id)
    if not account:
        return []
    role = account["role"]

    conn = db.get_conn()
    try:
        items = []
        items.extend(_message_notifications(conn, account_id))
        items.extend(_job_event_notifications(conn, account_id, role))
        items.extend(_direct_request_notifications(conn, account_id, role))
        items.extend(_admin_thread_notifications(conn, account_id))

        items.sort(key=lambda x: x.get("created_at") or "", reverse=True)

        keys = [i["key"] for i in items[:limit]]
        seen = _load_seen(conn, account_id, keys)

        for i in items[:limit]:
            i["seen"] = i["key"] in seen
        return items[:limit]
    finally:
        conn.close()


def mark_seen(account_id: str, keys) -> int:
    if not account_id or not keys:
        return 0

    now = db.utcnow_iso()
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        inserted = 0
        for k in keys:
            k = (k or "").strip()
            if not k:
                continue
            cur = conn.execute(
                """INSERT OR IGNORE INTO notification_reads(
                    account_id, notification_key, read_at
                ) VALUES(?,?,?)""",
                (account_id, k, now),
            )
            inserted += cur.rowcount
        conn.commit()
        return inserted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def unread_count(account_id: str) -> int:
    return sum(1 for i in list_for_account(account_id) if not i.get("seen"))


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _load_seen(conn, account_id: str, keys):
    if not keys:
        return set()
    placeholders = ",".join("?" for _ in keys)
    rows = conn.execute(
        f"""SELECT notification_key FROM notification_reads
            WHERE account_id=? AND notification_key IN ({placeholders})""",
        (account_id, *keys),
    ).fetchall()
    return {r[0] for r in rows}


def _get_account(account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT account_id, role FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ------------------------------------------------------------------
# Derivers
# ------------------------------------------------------------------

def _message_notifications(conn, account_id: str):
    rows = conn.execute(
        """SELECT m.message_id,
                  m.body,
                  m.created_at,
                  m.conversation_id,
                  m.sender_account_id,
                  COALESCE(NULLIF(a.display_name,''), a.full_name, '') AS sender_name
           FROM messages m
           JOIN conversations c ON c.conversation_id = m.conversation_id
           LEFT JOIN accounts a ON a.account_id = m.sender_account_id
           WHERE m.read_at = ''
             AND m.sender_account_id IS NOT NULL
             AND m.sender_account_id <> ?
             AND (c.client_account_id = ? OR c.provider_account_id = ?)
           ORDER BY m.created_at DESC
           LIMIT 20""",
        (account_id, account_id, account_id),
    ).fetchall()

    out = []
    for r in rows:
        body = (r["body"] or "").strip()
        if len(body) > MAX_BODY_LEN:
            body = body[:MAX_BODY_LEN] + "…"
        sender = (r["sender_name"] or "").strip() or "Someone"
        out.append({
            "key": f"msg:{r['message_id']}",
            "kind": "message",
            "title": f"New message from {sender}",
            "body": body,
            "created_at": r["created_at"] or "",
            "target_type": "conversation",
            "target_id": r["conversation_id"] or 0,
        })
    return out


def _job_event_notifications(conn, account_id: str, role: str):
    if role == "client":
        actor_filter = "e.actor_account_id <> ?"
        party_filter = "j.client_account_id = ?"
    else:
        actor_filter = "e.actor_account_id <> ?"
        party_filter = "j.provider_account_id = ?"

    rows = conn.execute(
        f"""SELECT e.event_id,
                   e.event_type,
                   e.from_state,
                   e.to_state,
                   e.created_at,
                   e.job_id,
                   j.category,
                   COALESCE(NULLIF(a.display_name,''), a.full_name, '') AS actor_name
            FROM job_events e
            JOIN jobs j ON j.job_id = e.job_id
            LEFT JOIN accounts a ON a.account_id = e.actor_account_id
            WHERE {party_filter}
              AND e.event_type IN (
                  'accepted','dispatched','arrived','started',
                  'client_confirmed','done','closed',
                  'disputed','dispute_resolved',
                  'cancelled','abandoned',
                  'auto_completed','auto_confirmed'
              )
              AND (e.actor_account_id IS NULL OR {actor_filter})
            ORDER BY e.created_at DESC
            LIMIT 30""",
        (account_id, account_id),
    ).fetchall()

    out = []
    for r in rows:
        actor = (r["actor_name"] or "").strip()
        who = actor if actor else "System"
        category = (r["category"] or "").strip() or "Service"
        title, body = _describe_event(r["event_type"], who, category, r["job_id"])
        if not title:
            continue
        out.append({
            "key": f"jev:{r['event_id']}",
            "kind": "job",
            "title": title[:MAX_TITLE_LEN],
            "body": body[:MAX_BODY_LEN],
            "created_at": r["created_at"] or "",
            "target_type": "job",
            "target_id": r["job_id"] or 0,
        })
    return out


def _describe_event(event_type: str, who: str, category: str, job_id):
    if event_type == "accepted":
        return (f"{who} accepted the job", f"{category} — provider is on the way.")
    if event_type == "dispatched":
        return (f"{who} started the job", f"{category} — provider is en route.")
    if event_type == "arrived":
        return (f"{who} arrived", f"{category} — provider is on site.")
    if event_type == "started":
        return (f"{who} started the job", f"{category} — work has begun.")
    if event_type == "client_confirmed":
        return (f"{who} confirmed the job", f"{category} — awaiting completion.")
    if event_type == "done":
        return (f"{who} marked the job done", f"{category} — confirm to close.")
    if event_type in ("closed", "auto_completed", "auto_confirmed"):
        return (f"Job {event_type.replace('_', ' ')}", f"{category} — job is complete.")
    if event_type == "disputed":
        return ("A dispute was opened", f"{category} — an admin will review.")
    if event_type == "dispute_resolved":
        return ("Dispute resolved", f"{category} — see Messages for the decision.")
    if event_type == "cancelled":
        return ("Job cancelled", f"{category} — this job was cancelled.")
    if event_type == "abandoned":
        return ("Job abandoned", f"{category} — the provider left the job.")
    return ("", "")


def _direct_request_notifications(conn, account_id: str, role: str):
    if role != "provider":
        return []

    rows = conn.execute(
        """SELECT r.request_id,
                  r.category,
                  r.description,
                  r.created_at,
                  COALESCE(NULLIF(a.display_name,''), a.full_name, '') AS client_name
           FROM service_requests r
           JOIN accounts a ON a.account_id = r.client_account_id
           WHERE r.provider_account_id = ?
             AND r.mode = 'direct'
             AND r.status = 'open'
           ORDER BY r.created_at DESC
           LIMIT 20""",
        (account_id,),
    ).fetchall()

    out = []
    for r in rows:
        client = (r["client_name"] or "").strip() or "A client"
        category = (r["category"] or "").strip() or "Service"
        body = (r["description"] or "").strip()
        if len(body) > MAX_BODY_LEN:
            body = body[:MAX_BODY_LEN] + "…"
        out.append({
            "key": f"req:{r['request_id']}",
            "kind": "request",
            "title": f"New request from {client}",
            "body": f"{category} — {body}" if body else category,
            "created_at": r["created_at"] or "",
            "target_type": "conversation",
            "target_id": 0,
        })
    return out


def _admin_thread_notifications(conn, account_id: str):
    """Private admin<->party messages, unread by this party.

    Dispute resolutions get a distinct kind (`dispute_resolved`) so the
    bell can highlight them. Routine admin messages use
    `admin_message`.
    """
    rows = conn.execute(
        """SELECT m.message_id, m.dispute_id, m.body, m.created_at,
                  d.status AS dispute_status,
                  d.title AS dispute_title,
                  d.resolution_note
           FROM admin_party_messages m
           JOIN disputes d ON d.dispute_id = m.dispute_id
           WHERE m.party_account_id = ?
             AND m.sender_role = 'admin'
             AND m.read_by_party = 0
           ORDER BY m.created_at DESC
           LIMIT 30""",
        (account_id,),
    ).fetchall()

    out = []
    for r in rows:
        body = (r["body"] or "").strip()
        if len(body) > MAX_BODY_LEN:
            body = body[:MAX_BODY_LEN] + "…"

        resolution = (r["resolution_note"] or "").strip()
        is_resolution = (r["dispute_status"] in ("resolved", "dismissed")
                         and resolution != "")

        if is_resolution:
            kind = "dispute_resolved"
            title = "Admin resolved a dispute"
        else:
            kind = "admin_message"
            title = "Message from the admin"

        out.append({
            "key": f"adm:{r['message_id']}",
            "kind": kind,
            "title": title,
            "body": body,
            "created_at": r["created_at"] or "",
            "target_type": "admin_thread",
            "target_id": r["dispute_id"] or 0,
        })
    return out