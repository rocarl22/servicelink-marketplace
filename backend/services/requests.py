"""Service requests.

Two modes:
    - 'direct' — targeted at one provider. Creates a conversation and a
                 request message. Provider sees it in Messages.
    - 'open'   — open to any matching provider. Appears in the provider
                 pool (Available Requests). First-accept-wins.

Requests auto-expire after 7 days if nobody accepts them.

Rules:
    - A client can send multiple pending direct requests to different
      providers for the same category (shopping phase).
    - A client CANNOT send a second direct request to the SAME provider
      for the SAME category while the first is still open.
    - A client can have at most MAX_DIRECT_PER_PAIR open direct requests
      to any single provider, across all categories.
    - When one provider accepts, all other pending requests from the
      same client in the same category are auto-cancelled.
    - A client cannot create a new request in a category where they
      already have an active job.

Canonical categories map to a family via `categories.CATEGORIES`.
Custom categories (declared by providers in `provider_services`) are
allowed in open mode; they store `family=''` and match providers by
category on the read side.

Prices are agreed separately once work is underway; the request itself
carries no budget.
"""
from datetime import datetime, timedelta, timezone

from .. import database as db
from . import categories, chat
from .validation import required, now_iso


MAX_DESC_LEN = 1000
MAX_TIME_LEN = 60
MAX_AREA_LEN = 100
MAX_REASON_LEN = 500
EXPIRY_DAYS = 7
MAX_OPEN_POOL_PER_CLIENT = 3
MAX_DIRECT_PER_PAIR = 3


_ACTIVE_JOB_STATES = (
    "accepted", "dispatched", "arrived", "started", "client_confirmed",
)


def _account_name(account_id: str) -> str:
    if not account_id:
        return ""
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT display_name, full_name FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        return (row["display_name"] or row["full_name"] or "") if row else ""
    finally:
        conn.close()


def _request_quote(row) -> str:
    """One-liner summary of a request, for system messages.

    Format:
        <Category> - <description>
        Location: <area>

    Skips the location line when empty.
    """
    parts = [f"{row['category']} - {row['description']}"]
    area = (row["area"] if "area" in row.keys() else "") or ""
    if area:
        parts.append(f"Location: {area}")
    return "\n".join(parts)


def _is_canonical_category(category: str) -> bool:
    for cats in categories.CATEGORIES.values():
        if category in cats:
            return True
    return False


def active_category_job(conn, client_account_id: str, category: str):
    placeholders = ",".join("?" * len(_ACTIVE_JOB_STATES))
    return conn.execute(
        f"""SELECT job_id, provider_account_id, current_state
            FROM jobs
            WHERE client_account_id=?
              AND category=?
              AND current_state IN ({placeholders})
            LIMIT 1""",
        (client_account_id, category, *_ACTIVE_JOB_STATES),
    ).fetchone()


def _cancel_other_pending_requests(conn, client_account_id: str,
                                   category: str, keep_request_id: int,
                                   reason: str):
    rows = conn.execute(
        """SELECT request_id, provider_account_id
           FROM service_requests
           WHERE client_account_id=?
             AND category=?
             AND status='open'
             AND request_id <> ?""",
        (client_account_id, category, keep_request_id),
    ).fetchall()
    cancelled = []
    now = now_iso()
    for row in rows:
        conn.execute(
            """UPDATE service_requests
               SET status='cancelled', updated_at=?
               WHERE request_id=?""",
            (now, row["request_id"]),
        )
        cancelled.append((row["request_id"], row["provider_account_id"]))
    return cancelled


def _resolve_family(conn, category: str, mode: str,
                    provider_account_id: str):
    """Return the family for a request category, or '' if unresolvable.

    Canonical categories resolve to their family from CATEGORIES.
    In direct mode, a provider's declared custom service also resolves —
    matched case-insensitively against title or category.
    """
    for fam, cats in categories.CATEGORIES.items():
        if category in cats:
            return fam

    if mode == "direct" and provider_account_id:
        row = conn.execute(
            """SELECT family FROM provider_services
               WHERE provider_account_id=?
                 AND active=1
                 AND (LOWER(title)=LOWER(?) OR LOWER(category)=LOWER(?))
               LIMIT 1""",
            (provider_account_id, category, category),
        ).fetchone()
        if row and row["family"]:
            return row["family"]

    return ""


def create_request(
    client_account_id: str,
    category: str,
    description: str,
    area: str,
    preferred_time: str = "",
    provider_account_id: str = "",
    mode: str = "",
):
    category = (category or "").strip()
    description = " ".join((description or "").split())
    area = (area or "").strip()
    preferred_time = (preferred_time or "").strip()
    provider_account_id = (provider_account_id or "").strip()

    if not mode:
        mode = "direct" if provider_account_id else "open"
    if mode not in ("direct", "open"):
        return False, "Invalid request mode."
    if mode == "direct" and not provider_account_id:
        return False, "A direct request must have a provider."
    if mode == "open" and provider_account_id:
        return False, "An open request cannot have a pre-assigned provider."

    ok, msg = required({
        "Category": category,
        "Description": description,
        "Area": area,
    })
    if not ok:
        return False, msg

    if len(description) > MAX_DESC_LEN:
        return False, f"Description must be {MAX_DESC_LEN} characters or fewer."
    if len(preferred_time) > MAX_TIME_LEN:
        return False, f"Preferred time must be {MAX_TIME_LEN} characters or fewer."
    if len(area) > MAX_AREA_LEN:
        return False, f"Area must be {MAX_AREA_LEN} characters or fewer."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        client = conn.execute(
            """SELECT account_id, role, setup_complete, account_status
               FROM accounts WHERE account_id=?""",
            (client_account_id,),
        ).fetchone()
        if not client:
            conn.rollback()
            return False, "Account not found."
        if client["role"] != "client":
            conn.rollback()
            return False, "Only clients can post service requests."
        if not client["setup_complete"]:
            conn.rollback()
            return False, "Finish your profile before posting a request."
        if client["account_status"] != "active":
            conn.rollback()
            return False, "Your account is not currently able to post requests."

        is_canonical = _is_canonical_category(category)
        family = _resolve_family(conn, category, mode, provider_account_id)

        if is_canonical:
            if not family:
                conn.rollback()
                return False, "Choose a valid service category."
        else:
            if mode == "direct" and not family:
                conn.rollback()
                return False, "That provider does not offer that service."

        existing_job = active_category_job(conn, client_account_id, category)
        if existing_job:
            conn.rollback()
            return False, (
                f"You already have an active {category} job. "
                "Complete or cancel it before posting another request in this category."
            )

        if mode == "direct":
            existing_req = conn.execute(
                """SELECT request_id FROM service_requests
                   WHERE client_account_id=?
                     AND provider_account_id=?
                     AND category=?
                     AND status='open'
                   LIMIT 1""",
                (client_account_id, provider_account_id, category),
            ).fetchone()
            if existing_req:
                conn.rollback()
                return False, (
                    f"You already have a pending {category} request with this provider. "
                    "Wait for them to respond or cancel it first."
                )

            total_open = conn.execute(
                """SELECT COUNT(*) AS n FROM service_requests
                   WHERE client_account_id=?
                     AND provider_account_id=?
                     AND mode='direct'
                     AND status='open'""",
                (client_account_id, provider_account_id),
            ).fetchone()["n"]
            if total_open >= MAX_DIRECT_PER_PAIR:
                conn.rollback()
                return False, (
                    f"You already have {MAX_DIRECT_PER_PAIR} open requests with this provider. "
                    "Wait for a response, or cancel one before sending another."
                )

            prov = conn.execute(
                """SELECT account_id, role, setup_complete, account_status,
                          service_family
                   FROM accounts WHERE account_id=?""",
                (provider_account_id,),
            ).fetchone()
            if not prov:
                conn.rollback()
                return False, "The selected provider was not found."
            if prov["role"] != "provider":
                conn.rollback()
                return False, "The selected account is not a provider."
            if not prov["setup_complete"]:
                conn.rollback()
                return False, "The selected provider has not finished setup."
            if prov["account_status"] != "active":
                conn.rollback()
                return False, "The selected provider is not currently available."
            if prov["service_family"] != family:
                conn.rollback()
                return False, "The selected provider does not offer that service type."

            from . import blocks as blocks_svc
            if blocks_svc.is_blocked(client_account_id, provider_account_id):
                conn.rollback()
                return False, "You cannot send requests to this provider."

        else:
            count = conn.execute(
                """SELECT COUNT(*) AS n FROM service_requests
                   WHERE client_account_id=?
                     AND mode='open'
                     AND status='open'""",
                (client_account_id,),
            ).fetchone()["n"]
            if count >= MAX_OPEN_POOL_PER_CLIENT:
                conn.rollback()
                return False, (
                    f"You already have {MAX_OPEN_POOL_PER_CLIENT} open pool requests. "
                    "Wait for one to be accepted or cancel one first."
                )

        now = now_iso()
        cur = conn.execute(
            """INSERT INTO service_requests(
                client_account_id, provider_account_id, mode, category, family,
                description, area, preferred_time, budget_text, status,
                created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,'','open',?,?)""",
            (client_account_id,
             provider_account_id or None,
             mode, category, family, description, area,
             preferred_time, now, now),
        )
        request_id = cur.lastrowid
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if mode == "direct":
        try:
            chat.post_direct_request_message(
                client_account_id=client_account_id,
                provider_account_id=provider_account_id,
                category=category,
                description=description,
                area=area,
                preferred_time=preferred_time,
                budget_text="",
                request_id=request_id,
            )
        except Exception:
            import logging
            logging.getLogger("servicelink.requests").exception(
                "Direct request posted but chat message failed"
            )

    return True, str(request_id)


def cancel_request(client_account_id: str, request_id: int, reason: str = ""):
    reason = (reason or "").strip()[:MAX_REASON_LEN]
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        req = conn.execute(
            "SELECT * FROM service_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if not req:
            conn.rollback()
            return False, "Request not found."
        if req["client_account_id"] != client_account_id:
            conn.rollback()
            return False, "Only the client who posted this request can cancel it."
        if req["status"] != "open":
            if req["status"] == "accepted":
                conn.rollback()
                return False, "This request has already been accepted. Use Cancel Job instead."
            conn.rollback()
            return False, f"This request is already {req['status']}."

        conn.execute(
            """UPDATE service_requests
               SET status='cancelled', updated_at=?
               WHERE request_id=?""",
            (now_iso(), request_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    try:
        if req["mode"] == "direct" and req["provider_account_id"]:
            quote = _request_quote(req)
            chat.post_system_message_for_request(
                client_account_id=client_account_id,
                provider_account_id=req["provider_account_id"],
                request_id=request_id,
                body="The client cancelled the request:\n"
                     + quote
                     + (f"\n\nReason: {reason}" if reason else ""),
            )
    except Exception:
        import logging
        logging.getLogger("servicelink.requests").exception(
            "Cancel message could not be posted"
        )

    return True, "Request cancelled."


def decline_request(provider_account_id: str, request_id: int, reason: str = ""):
    reason = (reason or "").strip()[:MAX_REASON_LEN]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        req = conn.execute(
            "SELECT * FROM service_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if not req:
            conn.rollback()
            return False, "Request not found."
        if req["status"] != "open":
            conn.rollback()
            return False, f"This request is already {req['status']}."

        if req["mode"] == "direct":
            if req["provider_account_id"] != provider_account_id:
                conn.rollback()
                return False, "This request was sent to another provider."
        else:
            if req["provider_account_id"] and \
                    req["provider_account_id"] != provider_account_id:
                conn.rollback()
                return False, "This request is no longer available."

        conn.execute(
            """UPDATE service_requests
               SET status='declined', updated_at=?
               WHERE request_id=?""",
            (now_iso(), request_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if req["mode"] == "direct" and req["provider_account_id"]:
        provider_name = _account_name(req["provider_account_id"]) or "The provider"
        quote = _request_quote(req)
        try:
            chat.post_system_message_for_request(
                client_account_id=req["client_account_id"],
                provider_account_id=req["provider_account_id"],
                request_id=request_id,
                body=provider_name + " declined the request:\n"
                     + quote
                     + (f"\n\nReason: {reason}" if reason else ""),
            )
        except Exception:
            import logging
            logging.getLogger("servicelink.requests").exception(
                "Decline message could not be posted"
            )

    return True, "Request declined."


def get_request(request_id: int):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT r.*,
                      COALESCE(c.display_name, c.full_name) AS client_name,
                      COALESCE(p.display_name, p.full_name, '') AS provider_name
               FROM service_requests r
               JOIN accounts c ON c.account_id = r.client_account_id
               LEFT JOIN accounts p ON p.account_id = r.provider_account_id
               WHERE r.request_id=?""",
            (request_id,),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def get_pending_request_between(client_account_id: str,
                                provider_account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT r.*,
                      COALESCE(c.display_name, c.full_name) AS client_name,
                      COALESCE(p.display_name, p.full_name, '') AS provider_name
               FROM service_requests r
               JOIN accounts c ON c.account_id = r.client_account_id
               LEFT JOIN accounts p ON p.account_id = r.provider_account_id
               WHERE r.client_account_id=?
                 AND r.provider_account_id=?
                 AND r.mode='direct'
                 AND r.status='open'
               ORDER BY r.created_at DESC
               LIMIT 1""",
            (client_account_id, provider_account_id),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def list_open_requests_between(client_account_id: str,
                               provider_account_id: str):
    """All open direct requests between a client and a provider.

    Used by the chat bubbles to render accept/decline buttons on every
    pending request message, not just the newest one.
    """
    if not client_account_id or not provider_account_id:
        return []
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT r.*,
                      COALESCE(c.display_name, c.full_name) AS client_name,
                      COALESCE(p.display_name, p.full_name, '') AS provider_name
               FROM service_requests r
               JOIN accounts c ON c.account_id = r.client_account_id
               LEFT JOIN accounts p ON p.account_id = r.provider_account_id
               WHERE r.client_account_id=?
                 AND r.provider_account_id=?
                 AND r.mode='direct'
                 AND r.status='open'
               ORDER BY r.created_at DESC""",
            (client_account_id, provider_account_id),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_open_requests_for_provider(provider_account_id: str):
    """Open pool requests visible to this provider.

    Matches either:
      - canonical requests whose family equals the provider's family, or
      - custom requests (family='') where the provider has an active
        service whose category matches the request's category,
        case-insensitively.
    """
    expire_stale_requests()
    conn = db.get_conn()
    try:
        prov = conn.execute(
            "SELECT service_family FROM accounts WHERE account_id=?",
            (provider_account_id,),
        ).fetchone()
        if not prov:
            return []
        family = prov["service_family"]
        rows = conn.execute(
            """SELECT r.request_id,
                      r.client_account_id,
                      COALESCE(r.provider_account_id, '') AS provider_account_id,
                      r.mode,
                      r.category,
                      r.family,
                      r.description,
                      r.area,
                      COALESCE(r.preferred_time, '') AS preferred_time,
                      r.status,
                      r.created_at,
                      r.updated_at,
                      COALESCE(c.display_name, c.full_name, '') AS client_name
               FROM service_requests r
               JOIN accounts c ON c.account_id = r.client_account_id
               WHERE r.status='open'
                 AND r.mode='open'
                 AND r.provider_account_id IS NULL
                 AND (
                     r.family = ?
                     OR (
                         r.family = ''
                         AND EXISTS (
                             SELECT 1 FROM provider_services ps
                             WHERE ps.provider_account_id = ?
                               AND ps.active = 1
                               AND LOWER(ps.category) = LOWER(r.category)
                         )
                     )
                 )
               ORDER BY r.created_at DESC
               LIMIT 100""",
            (family, provider_account_id),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_client_requests(client_account_id: str):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT r.request_id,
                      r.client_account_id,
                      COALESCE(r.provider_account_id, '') AS provider_account_id,
                      r.mode,
                      r.category,
                      r.family,
                      r.description,
                      r.area,
                      COALESCE(r.preferred_time, '') AS preferred_time,
                      r.status,
                      r.created_at,
                      r.updated_at,
                      COALESCE(p.display_name, p.full_name, '') AS provider_name
               FROM service_requests r
               LEFT JOIN accounts p ON p.account_id = r.provider_account_id
               WHERE r.client_account_id=?
               ORDER BY r.updated_at DESC
               LIMIT 100""",
            (client_account_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def expire_stale_requests():
    cutoff = (datetime.now(timezone.utc) - timedelta(days=EXPIRY_DAYS)
              ).isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute(
            """UPDATE service_requests
               SET status='expired', updated_at=?
               WHERE status='open' AND created_at < ?""",
            (now_iso(), cutoff),
        )
        conn.commit()
    finally:
        conn.close()