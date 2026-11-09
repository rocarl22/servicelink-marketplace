"""Job state machine. See ARCHITECTURE.md section 5.4."""
import logging
from datetime import datetime, timedelta, timezone

from .. import database as db
from . import categories, chat, money, requests as requests_svc, scam_shield
from .validation import clean_text, now_iso, parse_iso


log = logging.getLogger("servicelink.jobs")


UNDO_WINDOW_SECONDS = 90
DISPUTE_AUTO_DISMISS_DAYS = 30

TERMINAL_STATES = (
    "completed", "completed_by_timeout", "disputed",
    "abandoned", "cancelled",
)

MAX_PRICE_LEN = 60


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _timer_windows(category: str):
    return categories.TIMERS.get(category, categories.DEFAULT_TIMERS)


def _hours_from_now(hours: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)
            ).isoformat(timespec="seconds")


def _log_event(conn, job_id, actor_account_id, actor_role, event_type,
               from_state="", to_state="", note="", evidence_path=""):
    conn.execute(
        """INSERT INTO job_events(
            job_id, actor_account_id, actor_role, event_type,
            from_state, to_state, note, evidence_path, created_at
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (job_id, actor_account_id, actor_role, event_type,
         from_state, to_state, note, evidence_path, now_iso()),
    )


def _fetch_job(conn, job_id: int):
    return conn.execute(
        "SELECT * FROM jobs WHERE job_id=?", (job_id,)
    ).fetchone()


def _account_name(account_id: str) -> str:
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT display_name, full_name FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        return (row["display_name"] or row["full_name"] or "") if row else ""
    finally:
        conn.close()


def _post_chat_message(client_account_id: str, provider_account_id: str,
                       body: str, request_id: int = 0, job_id: int = 0):
    try:
        conv_id = chat.ensure_conversation(client_account_id, provider_account_id)
        chat.send_system_message(conv_id, body,
                                 request_id=request_id or 0,
                                 job_id=job_id or 0)
    except Exception:
        log.exception("Failed to post chat message")


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def active_job_count(provider_account_id: str) -> int:
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT COUNT(*) AS n FROM jobs
               WHERE provider_account_id=?
                 AND current_state IN ('dispatched','arrived','started')""",
            (provider_account_id,),
        ).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


def accept_request(provider_account_id: str, request_id: int):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        prov = conn.execute(
            """SELECT account_id, role, setup_complete, account_status, service_family
               FROM accounts WHERE account_id=?""",
            (provider_account_id,),
        ).fetchone()
        if not prov:
            conn.rollback()
            return False, "Account not found."
        if prov["role"] != "provider":
            conn.rollback()
            return False, "Only providers can accept requests."
        if not prov["setup_complete"]:
            conn.rollback()
            return False, "Finish your profile first."
        if prov["account_status"] != "active":
            conn.rollback()
            return False, "Your account cannot accept requests right now."

        req = conn.execute(
            "SELECT * FROM service_requests WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if not req:
            conn.rollback()
            return False, "Request not found."
        if req["status"] != "open":
            conn.rollback()
            return False, "This request is no longer available."
        if req["family"] != prov["service_family"]:
            conn.rollback()
            return False, "This request is not in your service family."

        if req["mode"] == "direct":
            if req["provider_account_id"] != provider_account_id:
                conn.rollback()
                return False, "This request was sent to another provider."
        else:
            if req["provider_account_id"]:
                conn.rollback()
                return False, "This request has already been assigned."

        from . import blocks as blocks_svc
        if blocks_svc.is_blocked(provider_account_id, req["client_account_id"]):
            conn.rollback()
            return False, "This request is no longer available."

        existing = requests_svc.active_category_job(
            conn, req["client_account_id"], req["category"])
        if existing:
            conn.rollback()
            return False, (
                f"This client already has an active {req['category']} job "
                "with another provider. The job must be cancelled first."
            )

        now = now_iso()

        conn.execute(
            """UPDATE service_requests
               SET provider_account_id=?, status='accepted', updated_at=?
               WHERE request_id=?""",
            (provider_account_id, now, request_id),
        )

        cur = conn.execute(
            """INSERT INTO jobs(
                request_id, client_account_id, provider_account_id,
                category, family, description, area, agreed_price_text,
                current_state, accepted_at, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (request_id, req["client_account_id"], provider_account_id,
             req["category"], req["family"], req["description"], req["area"],
             "",
             "accepted", now, now, now),
        )
        job_id = cur.lastrowid

        _log_event(conn, job_id, provider_account_id, "provider", "accepted",
                   from_state="", to_state="accepted")

        auto_cancelled = requests_svc._cancel_other_pending_requests(
            conn,
            req["client_account_id"],
            req["category"],
            request_id,
            reason="Another provider accepted first",
        )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    provider_name = _account_name(provider_account_id) or "The provider"
    client_name = _account_name(req["client_account_id"])

    quote_parts = [f"{req['category']} - {req['description']}"]
    if req["area"]:
        quote_parts.append(f"Location: {req['area']}")
    quote = "\n".join(quote_parts)

    _post_chat_message(
        req["client_account_id"], provider_account_id,
        f"{provider_name} accepted the request from {client_name}:\n"
        f"{quote}",
        request_id=request_id, job_id=job_id,
    )

    for cancelled_req_id, cancelled_prov_id in auto_cancelled:
        if cancelled_prov_id:
            _post_chat_message(
                req["client_account_id"], cancelled_prov_id,
                f"This request was cancelled because the client's "
                f"{req['category']} job was accepted by another provider.",
                request_id=cancelled_req_id,
            )

    return True, str(job_id)


def set_agreed_price(job_id: int, provider_account_id: str, price_text: str):
    """Provider sets (or updates) the agreed price for a job.

    Only the provider can set it. The price is free text (e.g.
    "KSh 2,500" or "4,000"). Posts a system message both parties see.
    """
    price_text = clean_text(price_text).strip()
    if not price_text:
        return False, "Enter a price."
    if len(price_text) > MAX_PRICE_LEN:
        return False, f"Price must be {MAX_PRICE_LEN} characters or fewer."
    # The price text is echoed into the chat, so it goes through the same
    # contact-detail masking as ordinary messages.
    price_text = scam_shield.screen(price_text).text
    price_minor = money.parse_kes_minor(price_text)   # None if free text is ambiguous

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."

        if provider_account_id != job["provider_account_id"]:
            conn.rollback()
            return False, "Only the provider can set the agreed price."

        current = job["current_state"]
        if current in TERMINAL_STATES:
            conn.rollback()
            return False, f"This job is already {current}."

        old_price = job["agreed_price_text"] or ""
        now = now_iso()

        conn.execute(
            """UPDATE jobs
               SET agreed_price_text=?, agreed_price_minor=?, agreed_price_currency='KES',
                   updated_at=?
               WHERE job_id=?""",
            (price_text, price_minor, now, job_id),
        )

        # Note: we do not log to job_events here. The event_type
        # column has a CHECK constraint and adding a new type would
        # require a table rebuild. The chat message posted below is
        # the audit trail for price changes.

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    provider_name = _account_name(provider_account_id) or "The provider"
    if old_price:
        body = (f"{provider_name} updated the agreed price:\n"
                f"{old_price}  ->  {price_text}")
    else:
        body = f"{provider_name} set the agreed price: {price_text}"

    _post_chat_message(
        job["client_account_id"], job["provider_account_id"],
        body,
        job_id=job_id,
    )

    return True, "Price set."


def get_job(job_id: int, viewer_account_id: str = ""):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT j.*,
                      COALESCE(c.display_name, c.full_name) AS client_name,
                      COALESCE(p.display_name, p.full_name) AS provider_name,
                      COALESCE(c.work_photo_path, '') AS client_photo,
                      COALESCE(p.work_photo_path, '') AS provider_photo
               FROM jobs j
               JOIN accounts c ON c.account_id = j.client_account_id
               JOIN accounts p ON p.account_id = j.provider_account_id
               WHERE j.job_id=?""",
            (job_id,),
        ).fetchone()
        if not row:
            return {}
        job = dict(row)
        if viewer_account_id and viewer_account_id not in (
            job["client_account_id"], job["provider_account_id"]
        ):
            return {}

        events = conn.execute(
            """SELECT e.*,
                      COALESCE(a.display_name, a.full_name, 'System') AS actor_name
               FROM job_events e
               LEFT JOIN accounts a ON a.account_id = e.actor_account_id
               WHERE e.job_id=?
               ORDER BY e.created_at ASC, e.event_id ASC""",
            (job_id,),
        ).fetchall()
        job["events"] = [dict(e) for e in events]

        dispute = conn.execute(
            """SELECT opened_by_account_id, is_anonymous FROM disputes
               WHERE job_id=? AND status IN ('open','under_review')
               ORDER BY created_at DESC LIMIT 1""",
            (job_id,),
        ).fetchone()

        if dispute:
            is_anon = bool(dispute["is_anonymous"])
            opened_by = dispute["opened_by_account_id"] or ""
            if is_anon and viewer_account_id and viewer_account_id != opened_by:
                job["dispute_opened_by"] = ""
                job["dispute_is_anonymous"] = 0
            else:
                job["dispute_opened_by"] = opened_by
                job["dispute_is_anonymous"] = 1 if is_anon else 0
        else:
            job["dispute_opened_by"] = ""
            job["dispute_is_anonymous"] = 0

        return job
    finally:
        conn.close()


def list_my_jobs(account_id: str):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT j.*,
                      COALESCE(c.display_name, c.full_name) AS client_name,
                      COALESCE(p.display_name, p.full_name) AS provider_name,
                      COALESCE(c.work_photo_path, '') AS client_photo,
                      COALESCE(p.work_photo_path, '') AS provider_photo
               FROM jobs j
               JOIN accounts c ON c.account_id = j.client_account_id
               JOIN accounts p ON p.account_id = j.provider_account_id
               WHERE j.client_account_id=? OR j.provider_account_id=?
               ORDER BY j.updated_at DESC
               LIMIT 100""",
            (account_id, account_id),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def advance(job_id: int, actor_account_id: str, action: str,
            note: str = "", evidence_path: str = ""):
    PROVIDER_ACTIONS = {
        "dispatched": ("accepted",     "dispatched"),
        "arrived":    ("dispatched",   "arrived"),
        "started":    ("arrived",      "started"),
        "done":       ("client_confirmed", "done"),
    }
    CLIENT_ACTIONS = {
        "client_confirmed": ("started", "client_confirmed"),
    }

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."

        is_client = actor_account_id == job["client_account_id"]
        is_provider = actor_account_id == job["provider_account_id"]
        if not (is_client or is_provider):
            conn.rollback()
            return False, "You are not part of this job."

        role = "client" if is_client else "provider"
        current = job["current_state"]

        if current in TERMINAL_STATES:
            conn.rollback()
            return False, f"This job is already {current}."

        now = now_iso()

        if action == "dispute":
            if current not in ("arrived", "started", "client_confirmed", "done"):
                conn.rollback()
                return False, "Disputes can only be raised after the provider has arrived."
            conn.execute(
                "UPDATE jobs SET current_state='disputed', updated_at=? WHERE job_id=?",
                (now, job_id),
            )
            _log_event(conn, job_id, actor_account_id, role, "disputed",
                       from_state=current, to_state="disputed", note=note)
            conn.commit()
            return True, "Dispute opened."

        if action == "abandon":
            if not is_provider:
                conn.rollback()
                return False, "Only the provider can abandon a job."
            conn.execute(
                """UPDATE jobs SET current_state='abandoned',
                    cancellation_reason=?, cancellation_by=?,
                    closed_at=?, updated_at=? WHERE job_id=?""",
                (note or "abandoned by provider", actor_account_id,
                 now, now, job_id),
            )
            _log_event(conn, job_id, actor_account_id, "provider", "abandoned",
                       from_state=current, to_state="abandoned", note=note)
            conn.commit()
            return True, "Job abandoned."

        if action in PROVIDER_ACTIONS:
            if not is_provider:
                conn.rollback()
                return False, "Only the provider can mark this step."
            expected_from, new_state = PROVIDER_ACTIONS[action]
            if current != expected_from:
                conn.rollback()
                return False, f"Cannot mark '{action}' from state '{current}'."

            fields = ["current_state=?", "updated_at=?"]
            values = [new_state, now]

            if action == "dispatched":
                fields.append("dispatched_at=?"); values.append(now)
            elif action == "arrived":
                fields.append("arrived_at=?"); values.append(now)
            elif action == "started":
                fields.append("started_at=?"); values.append(now)
                mutual_hours, _ = _timer_windows(job["category"])
                fields.append("mutual_completion_deadline=?")
                values.append(_hours_from_now(mutual_hours))
            elif action == "done":
                fields.append("done_at=?"); values.append(now)
                _, hard_hours = _timer_windows(job["category"])
                fields.append("hard_timeout_deadline=?")
                values.append(_hours_from_now(hard_hours))

            values.append(job_id)
            conn.execute(
                f"UPDATE jobs SET {', '.join(fields)} WHERE job_id=?", values,
            )
            _log_event(conn, job_id, actor_account_id, "provider", action,
                       from_state=current, to_state=new_state,
                       note=note, evidence_path=evidence_path)
            conn.commit()
            return True, f"Marked {action}."

        if action in CLIENT_ACTIONS:
            if not is_client:
                conn.rollback()
                return False, "Only the client can confirm this step."
            expected_from, new_state = CLIENT_ACTIONS[action]
            if current != expected_from:
                conn.rollback()
                return False, f"Cannot confirm from state '{current}'."
            conn.execute(
                """UPDATE jobs SET current_state='client_confirmed',
                    client_confirmed_at=?, updated_at=? WHERE job_id=?""",
                (now, now, job_id),
            )
            _log_event(conn, job_id, actor_account_id, "client", action,
                       from_state=current, to_state=new_state,
                       note=note, evidence_path=evidence_path)
            conn.commit()
            return True, "Work confirmed."

        conn.rollback()
        return False, f"Unknown action: {action}"
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cancel_job(job_id: int, actor_account_id: str, reason: str):
    reason = (reason or "").strip()
    if len(reason) < 3:
        return False, "Please provide a reason for cancelling."
    if len(reason) > 500:
        reason = reason[:500]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."

        is_client = actor_account_id == job["client_account_id"]
        is_provider = actor_account_id == job["provider_account_id"]
        if not (is_client or is_provider):
            conn.rollback()
            return False, "You are not part of this job."

        current = job["current_state"]
        if current in ("started", "client_confirmed", "done"):
            conn.rollback()
            return False, (
                "This job can no longer be cancelled because work has started. "
                "You can raise a dispute instead."
            )
        if current in TERMINAL_STATES:
            conn.rollback()
            return False, f"This job is already {current}."

        role = "client" if is_client else "provider"
        now = now_iso()
        conn.execute(
            """UPDATE jobs SET current_state='cancelled',
                cancellation_reason=?, cancellation_by=?,
                closed_at=?, updated_at=? WHERE job_id=?""",
            (reason, actor_account_id, now, now, job_id),
        )
        _log_event(conn, job_id, actor_account_id, role, "cancelled",
                   from_state=current, to_state="cancelled", note=reason)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    who = "Client" if is_client else "Provider"
    _post_chat_message(
        job["client_account_id"], job["provider_account_id"],
        f"{who} cancelled the job. Reason: {reason}",
        job_id=job_id,
    )

    return True, "Job cancelled."


def close_job(job_id: int, actor_account_id: str, action: str):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."
        if job["current_state"] == "completed":
            conn.rollback()
            return False, "This job is already completed."
        if job["current_state"] != "done":
            conn.rollback()
            return False, "Job is not waiting for confirmation."
        if action == "client_confirmed" and actor_account_id != job["client_account_id"]:
            conn.rollback()
            return False, "Only the client can confirm this job."

        now = now_iso()
        conn.execute(
            """UPDATE jobs SET current_state='completed',
                closed_at=?, updated_at=? WHERE job_id=?""",
            (now, now, job_id),
        )
        _log_event(
            conn, job_id,
            actor_account_id=actor_account_id if action == "client_confirmed" else None,
            actor_role="client" if action == "client_confirmed" else "system",
            event_type="closed", from_state="done", to_state="completed",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    who = "Client" if action == "client_confirmed" else "System"
    _post_chat_message(
        job["client_account_id"], job["provider_account_id"],
        f"{who} confirmed the work is complete. The job is now closed.",
        job_id=job_id,
    )

    return True, "Job closed."


def undo_last_event(job_id: int, actor_account_id: str):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."
        if actor_account_id not in (job["client_account_id"], job["provider_account_id"]):
            conn.rollback()
            return False, "You are not part of this job."

        last = conn.execute(
            """SELECT * FROM job_events
               WHERE job_id=? AND actor_account_id=?
                 AND event_type IN ('dispatched','arrived','started',
                                    'client_confirmed','done')
               ORDER BY created_at DESC, event_id DESC LIMIT 1""",
            (job_id, actor_account_id),
        ).fetchone()
        if not last:
            conn.rollback()
            return False, "No recent action to undo."

        created = parse_iso(last["created_at"])
        if not created:
            conn.rollback()
            return False, "Cannot determine event time."
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        if elapsed > UNDO_WINDOW_SECONDS:
            conn.rollback()
            return False, (
                f"The undo window ({UNDO_WINDOW_SECONDS}s) has passed. "
                "Use correction request instead."
            )

        if job["current_state"] != last["to_state"]:
            conn.rollback()
            return False, "A later action has already been recorded. Cannot undo."

        now = now_iso()
        conn.execute(
            "UPDATE jobs SET current_state=?, updated_at=? WHERE job_id=?",
            (last["from_state"] or job["current_state"], now, job_id),
        )
        if last["event_type"] == "dispatched":
            conn.execute("UPDATE jobs SET dispatched_at='' WHERE job_id=?", (job_id,))
        elif last["event_type"] == "arrived":
            conn.execute("UPDATE jobs SET arrived_at='' WHERE job_id=?", (job_id,))
        elif last["event_type"] == "started":
            conn.execute(
                "UPDATE jobs SET started_at='', mutual_completion_deadline='' WHERE job_id=?",
                (job_id,))
        elif last["event_type"] == "client_confirmed":
            conn.execute("UPDATE jobs SET client_confirmed_at='' WHERE job_id=?", (job_id,))
        elif last["event_type"] == "done":
            conn.execute(
                "UPDATE jobs SET done_at='', hard_timeout_deadline='' WHERE job_id=?",
                (job_id,))

        role = "client" if actor_account_id == job["client_account_id"] else "provider"
        _log_event(conn, job_id, actor_account_id, role, "undo",
                   from_state=last["to_state"], to_state=last["from_state"] or "",
                   note=f"Undo of {last['event_type']}")
        conn.commit()
        return True, f"Undid {last['event_type']}."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def request_correction(job_id: int, actor_account_id: str, reason: str):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."
        if actor_account_id not in (job["client_account_id"], job["provider_account_id"]):
            conn.rollback()
            return False, "You are not part of this job."

        last = conn.execute(
            """SELECT * FROM job_events
               WHERE job_id=? AND actor_account_id=?
                 AND event_type IN ('dispatched','arrived','started',
                                    'client_confirmed','done')
               ORDER BY created_at DESC, event_id DESC LIMIT 1""",
            (job_id, actor_account_id),
        ).fetchone()
        if not last:
            conn.rollback()
            return False, "No recent action to correct."

        role = "client" if actor_account_id == job["client_account_id"] else "provider"
        _log_event(conn, job_id, actor_account_id, role, "correction_requested",
                   from_state=last["to_state"], to_state=last["from_state"] or "",
                   note=reason or "")
        conn.commit()
        return True, "Correction requested. The other party must approve."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def approve_correction(job_id: int, approver_account_id: str):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."
        if approver_account_id not in (job["client_account_id"], job["provider_account_id"]):
            conn.rollback()
            return False, "You are not part of this job."

        pending = conn.execute(
            """SELECT * FROM job_events
               WHERE job_id=? AND event_type='correction_requested'
               ORDER BY created_at DESC, event_id DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        if not pending:
            conn.rollback()
            return False, "No pending correction."
        if pending["actor_account_id"] == approver_account_id:
            conn.rollback()
            return False, "Only the other party can approve."

        role = "client" if approver_account_id == job["client_account_id"] else "provider"
        _log_event(conn, job_id, approver_account_id, role, "correction_approved",
                   from_state=pending["from_state"], to_state=pending["to_state"])

        conn.execute(
            "UPDATE jobs SET current_state=?, updated_at=? WHERE job_id=?",
            (pending["to_state"] or job["current_state"], now_iso(), job_id),
        )
        conn.commit()
        return True, "Correction approved."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reject_correction(job_id: int, rejector_account_id: str, reason: str = ""):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."
        if rejector_account_id not in (job["client_account_id"], job["provider_account_id"]):
            conn.rollback()
            return False, "You are not part of this job."

        pending = conn.execute(
            """SELECT * FROM job_events
               WHERE job_id=? AND event_type='correction_requested'
               ORDER BY created_at DESC, event_id DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        if not pending:
            conn.rollback()
            return False, "No pending correction."

        role = "client" if rejector_account_id == job["client_account_id"] else "provider"
        _log_event(conn, job_id, rejector_account_id, role, "correction_rejected",
                   note=reason)
        conn.commit()
        return True, "Correction rejected."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def provider_has_active_job(provider_account_id: str) -> bool:
    return active_job_count(provider_account_id) > 0


# ------------------------------------------------------------------
# Disputes
# ------------------------------------------------------------------

def open_dispute(job_id: int, actor_account_id: str, category: str,
                 description: str, anonymous: bool = False):
    category = (category or "").strip()
    description = (description or "").strip()
    if not category:
        return False, "Choose the issue category."
    if len(description) < 20:
        return False, "Please describe what happened (at least 20 characters)."
    if len(description) > 1000:
        return False, "Description must be 1000 characters or fewer."

    is_anon = 1 if anonymous else 0

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."

        if actor_account_id not in (job["client_account_id"],
                                    job["provider_account_id"]):
            conn.rollback()
            return False, "You are not part of this job."

        current = job["current_state"]

        if not is_anon:
            if current not in ("arrived", "started", "client_confirmed", "done"):
                conn.rollback()
                return False, (
                    "A formal dispute can only be raised after the provider has arrived."
                )
            if current in TERMINAL_STATES:
                conn.rollback()
                return False, f"This job is already {current}."
        else:
            if current in TERMINAL_STATES:
                conn.rollback()
                return False, f"This job is already {current}."

        if not is_anon:
            existing = conn.execute(
                """SELECT 1 FROM disputes
                   WHERE job_id=? AND status IN ('open','under_review')
                     AND is_anonymous=0
                   LIMIT 1""",
                (job_id,),
            ).fetchone()
            if existing:
                conn.rollback()
                return False, "A formal dispute is already open on this job."

        role = "client" if actor_account_id == job["client_account_id"] else "provider"
        now = now_iso()

        previous = "" if is_anon else current

        conn.execute(
            """INSERT INTO disputes(
                job_id, opened_by_account_id, title, description, status,
                previous_state, is_anonymous, created_at, updated_at
            ) VALUES(?,?,?,?, 'open', ?, ?, ?, ?)""",
            (job_id, actor_account_id, category, description,
             previous, is_anon, now, now),
        )

        if not is_anon:
            conn.execute(
                "UPDATE jobs SET current_state='disputed', updated_at=? WHERE job_id=?",
                (now, job_id),
            )
            _log_event(conn, job_id, actor_account_id, role, "disputed",
                       from_state=current, to_state="disputed", note=category)

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if not is_anon:
        who = "Client" if role == "client" else "Provider"
        _post_chat_message(
            job["client_account_id"], job["provider_account_id"],
            f"{who} reported a problem on this job: {category}. "
            f"An admin will review the dispute.",
            job_id=job_id,
        )
        return True, "Dispute submitted. An admin will review it."

    return True, "Your report has been submitted. The other party is not notified."


def get_dispute_for_job(job_id: int):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT * FROM disputes WHERE job_id=?
               ORDER BY created_at DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def get_open_dispute_between(client_account_id: str,
                             provider_account_id: str,
                             viewer_account_id: str = ""):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT d.* FROM disputes d
               JOIN jobs j ON j.job_id = d.job_id
               WHERE j.client_account_id=?
                 AND j.provider_account_id=?
                 AND d.status IN ('open','under_review')
                 AND (
                     COALESCE(d.is_anonymous, 0) = 0
                     OR (COALESCE(d.is_anonymous, 0) = 1
                         AND d.opened_by_account_id = ?)
                 )
               ORDER BY d.created_at DESC
               LIMIT 1""",
            (client_account_id, provider_account_id, viewer_account_id or ""),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def withdraw_dispute(job_id: int, actor_account_id: str):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."

        dispute = conn.execute(
            """SELECT * FROM disputes
               WHERE job_id=? AND status IN ('open','under_review')
                 AND COALESCE(is_anonymous, 0) = 0
               ORDER BY created_at DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        if not dispute:
            conn.rollback()
            return False, "No open formal dispute on this job."
        if dispute["opened_by_account_id"] != actor_account_id:
            conn.rollback()
            return False, "Only the party who raised the dispute can withdraw it."

        keys = dispute.keys()
        previous = (dispute["previous_state"]
                    if "previous_state" in keys else "") or "client_confirmed"
        now = now_iso()

        conn.execute(
            """UPDATE disputes SET status='dismissed', updated_at=?
               WHERE dispute_id=?""",
            (now, dispute["dispute_id"]),
        )
        conn.execute(
            "UPDATE jobs SET current_state=?, updated_at=? WHERE job_id=?",
            (previous, now, job_id),
        )

        role = "client" if actor_account_id == job["client_account_id"] else "provider"
        _log_event(conn, job_id, actor_account_id, role, "dispute_resolved",
                   from_state="disputed", to_state=previous,
                   note="Dispute withdrawn by raiser")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    who = "Client" if role == "client" else "Provider"
    _post_chat_message(
        job["client_account_id"], job["provider_account_id"],
        f"{who} withdrew the dispute. The job resumes from {previous}.",
        job_id=job_id,
    )
    return True, "Dispute withdrawn."


def accept_dispute(job_id: int, actor_account_id: str, note: str = ""):
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _fetch_job(conn, job_id)
        if not job:
            conn.rollback()
            return False, "Job not found."

        if actor_account_id not in (job["client_account_id"],
                                    job["provider_account_id"]):
            conn.rollback()
            return False, "You are not part of this job."

        dispute = conn.execute(
            """SELECT * FROM disputes
               WHERE job_id=? AND status IN ('open','under_review')
                 AND COALESCE(is_anonymous, 0) = 0
               ORDER BY created_at DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        if not dispute:
            conn.rollback()
            return False, "No open formal dispute on this job."
        if dispute["opened_by_account_id"] == actor_account_id:
            conn.rollback()
            return False, "You cannot accept your own dispute."

        now = now_iso()
        conn.execute(
            """UPDATE disputes SET status='resolved', resolution_note=?,
               updated_at=? WHERE dispute_id=?""",
            (note or "Accepted by the other party",
             now, dispute["dispute_id"]),
        )
        conn.execute(
            """UPDATE jobs SET current_state='cancelled',
               cancellation_reason=?, cancellation_by=?,
               closed_at=?, updated_at=? WHERE job_id=?""",
            (f"Dispute accepted: {dispute['title']}",
             actor_account_id, now, now, job_id),
        )

        role = "client" if actor_account_id == job["client_account_id"] else "provider"
        _log_event(conn, job_id, actor_account_id, role, "dispute_resolved",
                   from_state="disputed", to_state="cancelled",
                   note=note or "Dispute accepted by the other party")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    who = "Client" if role == "client" else "Provider"
    _post_chat_message(
        job["client_account_id"], job["provider_account_id"],
        f"{who} accepted the dispute. The job is now closed.",
        job_id=job_id,
    )
    return True, "Dispute accepted."


def auto_dismiss_stale_disputes():
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        stale = conn.execute(
            """SELECT d.dispute_id, d.job_id, d.opened_by_account_id
               FROM disputes d
               WHERE d.status IN ('open','under_review')
                 AND COALESCE(d.is_anonymous, 0) = 0
                 AND d.created_at < datetime('now', ?)""",
            (f"-{DISPUTE_AUTO_DISMISS_DAYS} days",),
        ).fetchall()

        dismissed = []
        now = now_iso()
        for row in stale:
            conn.execute(
                "UPDATE disputes SET status='dismissed', updated_at=? WHERE dispute_id=?",
                (now, row["dispute_id"]),
            )
            conn.execute(
                """UPDATE jobs SET current_state='completed_by_timeout',
                   completed_by_timeout=1, closed_at=?, updated_at=?
                   WHERE job_id=? AND current_state='disputed'""",
                (now, now, row["job_id"]),
            )
            dismissed.append(row["job_id"])

        conn.commit()
        return dismissed
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()