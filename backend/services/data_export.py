"""Privacy-oriented account data export for ServiceLink users.

Exports the requesting account's profile and associated marketplace records.
Authentication hashes, lockout counters, OS usernames, and local media paths are
never included. This is a JSON data export; referenced photos/evidence are not
embedded in the file.
"""
from datetime import datetime, timezone

from .. import database as db


def _rows(conn, sql, params=()):
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def export_account_data(account_id: str) -> dict:
    if not account_id:
        raise ValueError("An account is required.")
    conn = db.get_conn()
    try:
        conn.execute("BEGIN")
        account_row = conn.execute(
            """SELECT account_id, role, full_name, phone, email, display_name,
                      area, bio, service_family, account_status, terms_version,
                      terms_accepted_at, setup_complete, created_at, updated_at,
                      CASE WHEN COALESCE(work_photo_path, '') <> '' THEN 1 ELSE 0 END
                        AS has_profile_photo
               FROM accounts WHERE account_id=?""",
            (account_id,),
        ).fetchone()
        if not account_row:
            raise ValueError("Account not found.")
        account = dict(account_row)

        requests = _rows(conn, """SELECT request_id, client_account_id,
            provider_account_id, mode, category, family, description, area,
            preferred_time, budget_text, status, created_at, updated_at
            FROM service_requests WHERE client_account_id=? OR provider_account_id=?
            ORDER BY request_id""", (account_id, account_id))
        jobs = _rows(conn, """SELECT job_id, request_id, client_account_id,
            provider_account_id, category, family, description, area,
            agreed_price_text, current_state, accepted_at, dispatched_at,
            arrived_at, started_at, client_confirmed_at, done_at, closed_at,
            cancellation_reason, cancellation_by, created_at, updated_at
            FROM jobs WHERE client_account_id=? OR provider_account_id=?
            ORDER BY job_id""", (account_id, account_id))
        job_ids = [j["job_id"] for j in jobs]
        if job_ids:
            marks = ",".join("?" for _ in job_ids)
            events = _rows(conn, f"""SELECT event_id, job_id, actor_role,
                event_type, from_state, to_state, note, created_at
                FROM job_events WHERE job_id IN ({marks}) ORDER BY event_id""", job_ids)
            disputes = _rows(conn, f"""SELECT dispute_id, job_id,
                opened_by_account_id, title, description, status, resolution_note,
                created_at, updated_at, is_anonymous FROM disputes
                WHERE job_id IN ({marks}) ORDER BY dispute_id""", job_ids)
        else:
            events, disputes = [], []

        reviews = _rows(conn, """SELECT review_id, job_id, reviewer_account_id,
            reviewee_account_id, reviewer_role, stars, comment, created_at,
            updated_at, editable_until FROM reviews
            WHERE reviewer_account_id=? OR reviewee_account_id=? ORDER BY review_id""",
            (account_id, account_id))
        services = _rows(conn, """SELECT service_id, title, category, family,
            description, rate_text, active, created_at, updated_at
            FROM provider_services WHERE provider_account_id=? ORDER BY service_id""",
            (account_id,))
        portfolio = _rows(conn, """SELECT item_id, job_id, title, description,
            visible, created_at, CASE WHEN COALESCE(photo_path, '') <> ''
            THEN 1 ELSE 0 END AS has_photo FROM portfolio
            WHERE provider_account_id=? ORDER BY item_id""", (account_id,))
        conversations = _rows(conn, """SELECT conversation_id, client_account_id,
            provider_account_id, last_message_at, created_at, updated_at
            FROM conversations WHERE client_account_id=? OR provider_account_id=?
            ORDER BY conversation_id""", (account_id, account_id))
        conversation_ids = [c["conversation_id"] for c in conversations]
        if conversation_ids:
            marks = ",".join("?" for _ in conversation_ids)
            messages = _rows(conn, f"""SELECT message_id, conversation_id,
                sender_account_id, sender_role, body, request_id, created_at,
                job_id, target_account_id, is_admin_message FROM messages
                WHERE conversation_id IN ({marks}) ORDER BY message_id""",
                conversation_ids)
        else:
            messages = []
        saved_providers = _rows(conn, """SELECT provider_account_id, created_at
            FROM saved_providers WHERE client_account_id=? ORDER BY created_at""",
            (account_id,))
        blocks = _rows(conn, """SELECT blocker_account_id, blocked_account_id,
            reason, created_at FROM blocks
            WHERE blocker_account_id=? OR blocked_account_id=? ORDER BY created_at""",
            (account_id, account_id))
        reports = _rows(conn, """SELECT report_id, kind, reported_account_id,
            reason, notes, context_job_id, status, created_at FROM user_reports
            WHERE reporter_account_id=? ORDER BY report_id""", (account_id,))
        admin_messages = _rows(conn, """SELECT message_id, dispute_id, sender_role,
            body, read_by_party, created_at FROM admin_party_messages
            WHERE party_account_id=? ORDER BY message_id""", (account_id,))
        notification_reads = _rows(conn, """SELECT notification_key, read_at
            FROM notification_reads WHERE account_id=? ORDER BY read_at""", (account_id,))
        conn.commit()
        return {
            "product": "ServiceLink",
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "format_version": 1,
            "notice": "Media files are not embedded. Passwords, password hashes, internal file paths, and device identifiers are excluded.",
            "account": account,
            "service_requests": requests,
            "jobs": jobs,
            "job_events": events,
            "disputes": disputes,
            "reviews": reviews,
            "provider_services": services,
            "portfolio_items": portfolio,
            "conversations": conversations,
            "messages": messages,
            "saved_providers": saved_providers,
            "blocks": blocks,
            "reports_submitted": reports,
            "admin_thread_messages": admin_messages,
            "notification_read_state": notification_reads,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
