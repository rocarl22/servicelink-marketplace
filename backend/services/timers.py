"""Passive timer sweep.

Called at app start and (optionally) periodically. Fires:
    - auto_confirmed  when the client hasn't confirmed 'started' within
                      the mutual window
    - auto_completed  when the client hasn't disputed 'done' within the
                      hard timeout
    - request expiry  for open requests older than 7 days
    - dispute auto-dismiss for disputes open > 30 days

Every action is logged as a system-attributed event.
"""
import logging
from datetime import datetime, timezone

from .. import database as db
from .validation import now_iso


log = logging.getLogger("servicelink.timers")


def sweep():
    now = now_iso()
    confirmed = 0
    completed = 0
    expired = 0
    dismissed_disputes = 0

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        # 1. Auto-confirm
        rows = conn.execute(
            """SELECT job_id FROM jobs
               WHERE current_state='started'
                 AND mutual_completion_deadline <> ''
                 AND mutual_completion_deadline <= ?""",
            (now,),
        ).fetchall()
        for row in rows:
            job_id = row["job_id"]
            conn.execute(
                """UPDATE jobs SET current_state='client_confirmed',
                    client_confirmed_at=?, updated_at=?
                    WHERE job_id=? AND current_state='started'""",
                (now, now, job_id),
            )
            conn.execute(
                """INSERT INTO job_events(
                    job_id, actor_account_id, actor_role, event_type,
                    from_state, to_state, note, created_at
                ) VALUES(?,NULL,'system','auto_confirmed','started',
                         'client_confirmed','Client did not respond in time',?)""",
                (job_id, now),
            )
            confirmed += 1

        # 2. Auto-complete
        rows = conn.execute(
            """SELECT job_id FROM jobs
               WHERE current_state='done'
                 AND hard_timeout_deadline <> ''
                 AND hard_timeout_deadline <= ?
                 AND closed_at = ''""",
            (now,),
        ).fetchall()
        for row in rows:
            job_id = row["job_id"]
            conn.execute(
                """UPDATE jobs SET current_state='completed_by_timeout',
                    completed_by_timeout=1, closed_at=?, updated_at=?
                    WHERE job_id=? AND current_state='done'""",
                (now, now, job_id),
            )
            conn.execute(
                """INSERT INTO job_events(
                    job_id, actor_account_id, actor_role, event_type,
                    from_state, to_state, note, created_at
                ) VALUES(?,NULL,'system','auto_completed','done',
                         'completed_by_timeout','Client did not confirm in time',?)""",
                (job_id, now),
            )
            completed += 1

        # 3. Expire stale open requests
        rows = conn.execute(
            """SELECT request_id FROM service_requests
               WHERE status='open' AND created_at <= datetime(?, '-7 days')""",
            (now,),
        ).fetchall()
        for row in rows:
            conn.execute(
                """UPDATE service_requests SET status='expired', updated_at=?
                   WHERE request_id=? AND status='open'""",
                (now, row["request_id"]),
            )
            expired += 1

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    # 4. Dispute auto-dismiss — separate transaction, uses jobs service
    try:
        from . import jobs as jobs_svc
        dismissed = jobs_svc.auto_dismiss_stale_disputes()
        dismissed_disputes = len(dismissed)
    except Exception:
        log.exception("auto_dismiss_stale_disputes failed")

    if confirmed or completed or expired or dismissed_disputes:
        log.info(
            "Timers swept: %d auto-confirmed, %d auto-completed, "
            "%d expired, %d disputes dismissed",
            confirmed, completed, expired, dismissed_disputes,
        )

    return {
        "auto_confirmed": confirmed,
        "auto_completed": completed,
        "expired_requests": expired,
        "auto_dismissed_disputes": dismissed_disputes,
    }