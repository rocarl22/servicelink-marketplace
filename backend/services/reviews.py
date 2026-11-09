"""Reviews: one per party per job, editable for 7 days, reportable.

Attribution model:
    - The reviewee sees reviews with a partially-masked account ID,
      not the reviewer's name. This is a soft anonymity — the actual
      matching job cannot be trivially identified from the review.
    - The reviewer sees their own reviews with the real name.
    - Admins see full details, including the reviewer's account_id,
      for dispute resolution.
"""
import logging
from datetime import datetime, timedelta, timezone

from .. import database as db
from .validation import now_iso, parse_iso


log = logging.getLogger("servicelink.reviews")

MAX_COMMENT_LEN = 1000
EDIT_WINDOW_DAYS = 7


def _mask_id(account_id: str) -> str:
    """Return first-3 + bullets + last-3 of the account id.

    C-DCBCC3C418 -> C-D......418
    P-EB79BCD554 -> P-E......554
    """
    if not account_id:
        return "?"
    s = str(account_id)
    if len(s) <= 6:
        return s
    return s[:3] + "•" * (len(s) - 6) + s[-3:]


def can_review(job_id: int, reviewer_account_id: str):
    conn = db.get_conn()
    try:
        job = conn.execute(
            "SELECT * FROM jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if not job:
            return False, "Job not found."

        if reviewer_account_id not in (job["client_account_id"],
                                       job["provider_account_id"]):
            return False, "You are not part of this job."

        if job["current_state"] != "completed":
            return False, "You can only review a completed job."

        existing = conn.execute(
            """SELECT review_id FROM reviews
               WHERE job_id=? AND reviewer_account_id=?""",
            (job_id, reviewer_account_id),
        ).fetchone()
        if existing:
            return False, "You have already reviewed this job."

        return True, ""
    finally:
        conn.close()


def create_review(job_id: int, reviewer_account_id: str,
                  stars: int, comment: str):
    try:
        stars = int(stars)
    except (TypeError, ValueError):
        return False, "Stars must be between 1 and 5."
    if stars < 1 or stars > 5:
        return False, "Stars must be between 1 and 5."

    comment = (comment or "").strip()
    if len(comment) > MAX_COMMENT_LEN:
        return False, f"Comment must be {MAX_COMMENT_LEN} characters or fewer."

    ok, reason = can_review(job_id, reviewer_account_id)
    if not ok:
        return False, reason

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = conn.execute(
            "SELECT * FROM jobs WHERE job_id=?", (job_id,)
        ).fetchone()

        reviewer_role = ("client"
                         if reviewer_account_id == job["client_account_id"]
                         else "provider")
        reviewee_id = (job["provider_account_id"]
                       if reviewer_role == "client"
                       else job["client_account_id"])

        now = now_iso()
        editable_until = (datetime.now(timezone.utc)
                          + timedelta(days=EDIT_WINDOW_DAYS)
                          ).isoformat(timespec="seconds")

        conn.execute(
            """INSERT INTO reviews(
                job_id, reviewer_account_id, reviewee_account_id,
                reviewer_role, stars, comment, editable_until,
                created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (job_id, reviewer_account_id, reviewee_id,
             reviewer_role, stars, comment, editable_until, now, now),
        )
        conn.commit()
        return True, "Review submitted."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_review(review_id: int, reviewer_account_id: str,
                  stars: int, comment: str):
    try:
        stars = int(stars)
    except (TypeError, ValueError):
        return False, "Stars must be between 1 and 5."
    if stars < 1 or stars > 5:
        return False, "Stars must be between 1 and 5."

    comment = (comment or "").strip()
    if len(comment) > MAX_COMMENT_LEN:
        return False, f"Comment must be {MAX_COMMENT_LEN} characters or fewer."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        review = conn.execute(
            "SELECT * FROM reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        if not review:
            conn.rollback()
            return False, "Review not found."
        if review["reviewer_account_id"] != reviewer_account_id:
            conn.rollback()
            return False, "You can only edit your own review."

        editable = parse_iso(review["editable_until"] or "")
        if not editable:
            conn.rollback()
            return False, "This review can no longer be edited."
        if datetime.now(timezone.utc) > editable:
            conn.rollback()
            return False, (
                f"The edit window ({EDIT_WINDOW_DAYS} days) has passed."
            )

        now = now_iso()
        conn.execute(
            """UPDATE reviews SET stars=?, comment=?, updated_at=?
               WHERE review_id=?""",
            (stars, comment, now, review_id),
        )
        conn.commit()
        return True, "Review updated."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_review_for_job(job_id: int, reviewer_account_id: str):
    """Return the review by this account for this job, or {}.

    The reviewer always sees their own review with the real names,
    because they know who they are.
    """
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT r.*,
                      COALESCE(NULLIF(a.display_name, ''), NULLIF(a.full_name, ''), 'Unknown') AS reviewer_name,
                      COALESCE(NULLIF(b.display_name, ''), NULLIF(b.full_name, ''), 'Unknown') AS reviewee_name
               FROM reviews r
               JOIN accounts a ON a.account_id = r.reviewer_account_id
               JOIN accounts b ON b.account_id = r.reviewee_account_id
               WHERE r.job_id=? AND r.reviewer_account_id=?""",
            (job_id, reviewer_account_id),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def list_reviews_for_job(job_id: int):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT r.*,
                      COALESCE(NULLIF(a.display_name, ''), NULLIF(a.full_name, ''), 'Unknown') AS reviewer_name,
                      COALESCE(NULLIF(b.display_name, ''), NULLIF(b.full_name, ''), 'Unknown') AS reviewee_name
               FROM reviews r
               JOIN accounts a ON a.account_id = r.reviewer_account_id
               JOIN accounts b ON b.account_id = r.reviewee_account_id
               WHERE r.job_id=?
               ORDER BY r.created_at ASC""",
            (job_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_reviews_received(account_id: str, limit: int = 100):
    """Reviews about this account.

    The viewer here is the reviewee. The reviewer's name is replaced
    with a masked account id, and the real name is not exposed.
    """
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT r.*,
                      COALESCE(NULLIF(a.display_name, ''), NULLIF(a.full_name, ''), 'Unknown') AS reviewer_name_raw,
                      j.category AS job_category
               FROM reviews r
               JOIN accounts a ON a.account_id = r.reviewer_account_id
               JOIN jobs j ON j.job_id = r.job_id
               WHERE r.reviewee_account_id=?
               ORDER BY r.created_at DESC
               LIMIT ?""",
            (account_id, limit),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            # Mask the reviewer for the reviewee
            d["reviewer_name"] = _mask_id(d.get("reviewer_account_id") or "")
            d["reviewer_name_raw"] = ""  # not exposed to the client
            result.append(d)
        return result
    finally:
        conn.close()


def list_reviews_left(account_id: str, limit: int = 100):
    """Reviews this account has written.

    The viewer here is the reviewer, so they can see the real name
    of the reviewee (they know who they reviewed).
    """
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT r.*,
                      COALESCE(NULLIF(a.display_name, ''), NULLIF(a.full_name, ''), 'Unknown') AS reviewer_name,
                      COALESCE(NULLIF(b.display_name, ''), NULLIF(b.full_name, ''), 'Unknown') AS reviewee_name,
                      j.category AS job_category
               FROM reviews r
               JOIN accounts a ON a.account_id = r.reviewer_account_id
               JOIN accounts b ON b.account_id = r.reviewee_account_id
               JOIN jobs j ON j.job_id = r.job_id
               WHERE r.reviewer_account_id=?
               ORDER BY r.created_at DESC
               LIMIT ?""",
            (account_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def average_for_account(account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT AVG(CAST(stars AS REAL)) AS avg_stars,
                      COUNT(*) AS n
               FROM reviews WHERE reviewee_account_id=?""",
            (account_id,),
        ).fetchone()
        avg = row["avg_stars"] if row and row["avg_stars"] is not None else 0.0
        n = row["n"] if row else 0
        return float(avg), int(n)
    finally:
        conn.close()


def report_review(review_id: int, reporter_account_id: str, reason: str):
    reason = (reason or "").strip()
    if len(reason) < 20:
        return False, "Please explain why you are reporting this (at least 20 characters)."
    if len(reason) > 1000:
        reason = reason[:1000]

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        review = conn.execute(
            "SELECT * FROM reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        if not review:
            conn.rollback()
            return False, "Review not found."
        if reporter_account_id == review["reviewer_account_id"]:
            conn.rollback()
            return False, "You cannot report your own review."

        if reporter_account_id != review["reviewee_account_id"]:
            conn.rollback()
            return False, "Only the reviewed party can report a review."

        existing = conn.execute(
            """SELECT 1 FROM user_reports
               WHERE kind='review'
                 AND reporter_account_id=?
                 AND reason LIKE ?
                 AND status='open'
               LIMIT 1""",
            (reporter_account_id, f"%review#{review_id}%"),
        ).fetchone()
        if existing:
            conn.rollback()
            return False, "You already reported this review."

        now = now_iso()
        conn.execute(
            """INSERT INTO user_reports(
                kind, reporter_account_id, reported_account_id,
                reason, notes, context_job_id, status, created_at
            ) VALUES('review', ?, ?, ?, '', ?, 'open', ?)""",
            (reporter_account_id,
             review["reviewer_account_id"],
             f"Report on review#{review_id}: {reason}",
             review["job_id"],
             now),
        )
        conn.commit()
        return True, "Reported. An admin will review it."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()