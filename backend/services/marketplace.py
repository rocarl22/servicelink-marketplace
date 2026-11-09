"""Marketplace: providers, search, portfolio, provider services, availability, saved."""
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from .. import database as db
from .validation import now_iso


log = logging.getLogger("servicelink.marketplace")


# ------------------------------------------------------------------
# Availability constants
# ------------------------------------------------------------------

AVAILABILITY_MODES = ("available_now", "available_at", "busy_until", "unavailable")

MAX_AVAILABILITY_NOTE_LEN = 120
MAX_AVAILABILITY_AT_LEN = 60

DECAY_HOURS = 12

# Job states where the provider is engaged with a client.
# Terminal states (completed, cancelled, abandoned, disputed) do not
# count as "on a job".
_ACTIVE_JOB_STATES = (
    "accepted",
    "dispatched",
    "arrived",
    "started",
    "client_confirmed",
    "done",
)

_ACTIVE_JOB_SQL = ",".join(f"'{s}'" for s in _ACTIVE_JOB_STATES)


# ------------------------------------------------------------------
# Providers
# ------------------------------------------------------------------

def list_providers(family: str = "", area: str = "", search: str = "",
                   limit: int = 100, caller_account_id: str = ""):
    """List active providers with filters.

    Placeholder order (IMPORTANT):
        1. is_saved subquery: two placeholders for caller_account_id
        2. family filter:     one placeholder
        3. area filter:       one placeholder
        4. search filter:     six placeholders
        5. blocks filter:     one placeholder
    """
    conn = db.get_conn()
    try:
        where = [
            "a.role='provider'",
            "a.setup_complete=1",
            "a.account_status='active'",
        ]
        params = []

        # 1) is_saved placeholders come FIRST because they appear in
        #    the SELECT clause, which precedes the WHERE clause.
        params.append(caller_account_id or "")
        params.append(caller_account_id or "")

        # 2) family
        if family:
            where.append("a.service_family=?")
            params.append(family)

        # 3) area
        if area:
            where.append("a.area=?")
            params.append(area)

        # 4) search — matches name/area/bio, and the provider's service
        #    categories/titles (so custom services like "CAR REPAIR"
        #    are findable by typing the words)
        if search:
            where.append(
                "(a.display_name LIKE ? OR a.full_name LIKE ? "
                "OR a.area LIKE ? OR a.bio LIKE ? "
                "OR EXISTS ("
                "    SELECT 1 FROM provider_services ps "
                "    WHERE ps.provider_account_id = a.account_id "
                "      AND ps.active = 1 "
                "      AND (ps.category LIKE ? OR ps.title LIKE ?)"
                "))"
            )
            like = f"%{search}%"
            params.extend([like, like, like, like, like, like])

        # 5) blocks
        if caller_account_id:
            where.append(
                "NOT EXISTS (SELECT 1 FROM blocks b "
                "WHERE b.blocker_account_id=? "
                "AND b.blocked_account_id=a.account_id)"
            )
            params.append(caller_account_id)

        where_sql = " AND ".join(where)

        rows = conn.execute(
            f"""
            SELECT
                a.account_id,
                COALESCE(NULLIF(a.display_name, ''), a.full_name) AS display_name,
                a.full_name,
                a.area,
                a.bio,
                a.work_photo_path,
                a.service_family,
                a.created_at,
                (SELECT COUNT(*) FROM jobs j
                 WHERE j.provider_account_id = a.account_id
                   AND j.current_state IN ('completed','completed_by_timeout')
                ) AS completed_jobs,
                (SELECT COUNT(*) FROM jobs j
                 WHERE j.provider_account_id = a.account_id
                   AND j.current_state IN ({_ACTIVE_JOB_SQL})
                ) AS active_jobs,
                (SELECT COUNT(*) FROM reviews r
                 WHERE r.reviewee_account_id = a.account_id
                ) AS review_count,
                (SELECT AVG(CAST(r.stars AS REAL)) FROM reviews r
                 WHERE r.reviewee_account_id = a.account_id
                ) AS avg_stars,
                (SELECT COUNT(*) FROM disputes d
                 JOIN jobs j ON j.job_id = d.job_id
                 WHERE j.provider_account_id = a.account_id
                   AND d.status = 'open'
                ) AS open_disputes,
                (SELECT COUNT(*) FROM portfolio p
                 WHERE p.provider_account_id = a.account_id
                   AND p.visible = 1
                ) AS portfolio_count,
                CASE WHEN ? <> '' THEN
                    EXISTS (SELECT 1 FROM saved_providers sp
                            WHERE sp.client_account_id = ?
                              AND sp.provider_account_id = a.account_id)
                ELSE 0 END AS is_saved,
                (SELECT COUNT(*) FROM provider_services ps
                 WHERE ps.provider_account_id = a.account_id
                   AND ps.active = 1
                ) AS service_count,
                COALESCE(
                    (SELECT pa.mode FROM provider_availability pa
                     WHERE pa.provider_account_id = a.account_id),
                    ''
                ) AS availability_mode,
                COALESCE(
                    (SELECT pa.available_at FROM provider_availability pa
                     WHERE pa.provider_account_id = a.account_id),
                    ''
                ) AS availability_at,
                COALESCE(
                    (SELECT pa.updated_at FROM provider_availability pa
                     WHERE pa.provider_account_id = a.account_id),
                    ''
                ) AS availability_updated_at,
                COALESCE(
                    (SELECT MAX(j.updated_at) FROM jobs j
                     WHERE j.provider_account_id = a.account_id),
                    ''
                ) AS last_activity
            FROM accounts a
            WHERE {where_sql}
            """,
            params,
        ).fetchall()

        now_str = db.utcnow_iso()
        cutoff_30d = _days_ago(now_str[:10], 30)

        result = []
        for row in rows:
            d = dict(row)
            recent = False
            if d.get("last_activity"):
                try:
                    recent = d["last_activity"][:10] >= cutoff_30d
                except Exception:
                    recent = False

            d["rank_score"] = _compute_rank(
                completed_jobs=d.get("completed_jobs") or 0,
                review_count=d.get("review_count") or 0,
                avg_stars=d.get("avg_stars") or 0.0,
                has_active_job=(d.get("active_jobs") or 0) > 0,
                has_dispute=(d.get("open_disputes") or 0) > 0,
                recent_activity=recent,
            )

            has_active = (d.get("active_jobs") or 0) > 0
            declared_mode = d.get("availability_mode") or ""
            declared_at = d.get("availability_at") or ""
            declared_updated = d.get("availability_updated_at") or ""

            if has_active:
                effective = {"mode": "on_job", "available_at": "", "note": ""}
            else:
                mode, at = _decay(declared_mode, declared_updated, declared_at)
                if mode == "":
                    mode = "available_now"
                effective = {"mode": mode, "available_at": at, "note": ""}

            d["availability"] = effective
            d["is_saved"] = bool(d.get("is_saved"))

            d.pop("avg_stars", None)
            d.pop("last_activity", None)
            d.pop("availability_mode", None)
            d.pop("availability_at", None)
            d.pop("availability_updated_at", None)
            result.append(d)

        result.sort(key=lambda x: (-x["rank_score"], x.get("display_name") or ""))
        return result[:limit]
    finally:
        conn.close()


def _days_ago(iso_date: str, days: int) -> str:
    try:
        d = datetime.strptime(iso_date, "%Y-%m-%d")
    except ValueError:
        return iso_date
    return (d - timedelta(days=days)).strftime("%Y-%m-%d")


def _compute_rank(completed_jobs: int, review_count: int, avg_stars: float,
                  has_active_job: bool, has_dispute: bool,
                  recent_activity: bool) -> float:
    score = 0.0
    score += min(completed_jobs, 50) * 0.4
    score += min(review_count, 30) * 0.5
    score += avg_stars * 2.0
    if has_active_job:
        score += 0.5
    if recent_activity:
        score += 0.3
    if has_dispute:
        score -= 1.0
    return score


def _decay(mode: str, updated_at: str, available_at: str):
    """Return (effective_mode, effective_available_at) after applying decay.

    Timed statuses (available_at / busy_until) decay to available_now
    if they haven't been touched in DECAY_HOURS.
    """
    if mode not in ("available_at", "busy_until"):
        return mode, available_at
    if not updated_at:
        return "available_now", ""
    try:
        t = datetime.fromisoformat(updated_at)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "available_now", ""
    if datetime.now(timezone.utc) - t > timedelta(hours=DECAY_HOURS):
        return "available_now", ""
    return mode, available_at


def get_provider_profile(provider_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT account_id, role, display_name, full_name, phone,
                      area, bio, work_photo_path, service_family, created_at,
                      setup_complete, account_status
               FROM accounts WHERE account_id=? AND role='provider'""",
            (provider_id,),
        ).fetchone()
        if not row:
            return {}
        d = dict(row)

        d["portfolio"] = portfolio_for_provider(provider_id)

        from .reviews import _mask_id as _mask_reviewer_id
        reviews_rows = conn.execute(
            """SELECT r.stars, r.comment, r.created_at,
                      r.reviewer_account_id
               FROM reviews r
               WHERE r.reviewee_account_id=?
               ORDER BY r.created_at DESC LIMIT 10""",
            (provider_id,),
        ).fetchall()
        d["reviews"] = []
        for r in reviews_rows:
            rr = dict(r)
            rr["reviewer_name"] = _mask_reviewer_id(rr.get("reviewer_account_id") or "")
            rr["reviewer_account_id"] = ""
            d["reviews"].append(rr)

        rrow = conn.execute(
            """SELECT AVG(CAST(stars AS REAL)) AS avg_stars, COUNT(*) AS n
               FROM reviews WHERE reviewee_account_id=?""",
            (provider_id,),
        ).fetchone()
        d["review_count"] = rrow["n"] if rrow else 0
        d["avg_stars"] = float(rrow["avg_stars"]) if rrow and rrow["avg_stars"] is not None else 0.0

        d["completed_jobs"] = conn.execute(
            """SELECT COUNT(*) AS n FROM jobs
               WHERE provider_account_id=?
                 AND current_state IN ('completed','completed_by_timeout')""",
            (provider_id,),
        ).fetchone()["n"]

        d["services"] = list_provider_services(provider_id, include_inactive=False)
        d["availability"] = get_provider_availability(provider_id)

        return d
    finally:
        conn.close()


# ------------------------------------------------------------------
# Availability
# ------------------------------------------------------------------

def _has_active_job_conn(conn, provider_id: str) -> bool:
    placeholders = ",".join("?" * len(_ACTIVE_JOB_STATES))
    row = conn.execute(
        f"""SELECT 1 FROM jobs
            WHERE provider_account_id=?
              AND current_state IN ({placeholders})
            LIMIT 1""",
        (provider_id, *_ACTIVE_JOB_STATES),
    ).fetchone()
    return bool(row)


def get_provider_availability(provider_id: str):
    """Return the provider's effective availability."""
    if not provider_id:
        return {"mode": "available_now", "available_at": "", "note": "", "updated_at": ""}

    conn = db.get_conn()
    try:
        if _has_active_job_conn(conn, provider_id):
            return {"mode": "on_job", "available_at": "", "note": "", "updated_at": ""}

        row = conn.execute(
            """SELECT mode, available_at, note, updated_at
               FROM provider_availability
               WHERE provider_account_id=?""",
            (provider_id,),
        ).fetchone()
        if not row:
            return {"mode": "available_now", "available_at": "", "note": "", "updated_at": ""}

        mode, at = _decay(row["mode"] or "", row["updated_at"] or "",
                          row["available_at"] or "")
        if mode == "":
            mode = "available_now"
        return {
            "mode": mode,
            "available_at": at,
            "note": row["note"] or "",
            "updated_at": row["updated_at"] or "",
        }
    finally:
        conn.close()


def set_provider_availability(provider_account_id: str, mode: str,
                              available_at: str = "", note: str = ""):
    mode = (mode or "").strip()
    available_at = (available_at or "").strip()
    note = (note or "").strip()

    if mode == "on_job":
        return False, "That status is set automatically."

    if mode not in AVAILABILITY_MODES:
        return False, "Invalid availability mode."
    if len(available_at) > MAX_AVAILABILITY_AT_LEN:
        return False, f"Time text must be {MAX_AVAILABILITY_AT_LEN} characters or fewer."
    if len(note) > MAX_AVAILABILITY_NOTE_LEN:
        return False, f"Note must be {MAX_AVAILABILITY_NOTE_LEN} characters or fewer."

    if mode not in ("available_at", "busy_until"):
        available_at = ""

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        prov = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?",
            (provider_account_id,),
        ).fetchone()
        if not prov:
            conn.rollback()
            return False, "Account not found."
        if prov["role"] != "provider":
            conn.rollback()
            return False, "Only providers can set availability."

        now = now_iso()
        conn.execute(
            """INSERT INTO provider_availability(
                provider_account_id, mode, available_at, note, updated_at
            ) VALUES(?,?,?,?,?)
            ON CONFLICT(provider_account_id) DO UPDATE SET
                mode=excluded.mode,
                available_at=excluded.available_at,
                note=excluded.note,
                updated_at=excluded.updated_at""",
            (provider_account_id, mode, available_at, note, now),
        )
        conn.commit()
        return True, "Availability updated."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------
# Portfolio
# ------------------------------------------------------------------

MAX_TITLE_LEN = 80
MAX_DESC_LEN = 300


def portfolio_for_provider(provider_id: str, include_hidden: bool = False):
    conn = db.get_conn()
    try:
        if include_hidden:
            rows = conn.execute(
                """SELECT item_id, provider_account_id, title, description,
                          photo_path, visible, created_at
                   FROM portfolio WHERE provider_account_id=?
                   ORDER BY created_at DESC""",
                (provider_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT item_id, provider_account_id, title, description,
                          photo_path, visible, created_at
                   FROM portfolio WHERE provider_account_id=? AND visible=1
                   ORDER BY created_at DESC""",
                (provider_id,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def portfolio_upload_dir() -> str:
    d = os.path.join(db.DATA_DIR, "portfolio")
    os.makedirs(d, exist_ok=True)
    return d


def add_portfolio_item(provider_account_id: str, src_path: str,
                       title: str, description: str):
    title = (title or "").strip()
    description = (description or "").strip()

    if not title:
        return False, "Give the photo a title."
    if len(title) > MAX_TITLE_LEN:
        return False, f"Title must be {MAX_TITLE_LEN} characters or fewer."
    if len(description) > MAX_DESC_LEN:
        return False, f"Description must be {MAX_DESC_LEN} characters or fewer."

    src_path = (src_path or "").strip()
    if src_path.startswith("file:///"):
        src_path = src_path[8:]
    elif src_path.startswith("file://"):
        src_path = src_path[7:]
    if not src_path or not os.path.exists(src_path):
        return False, "Pick a photo to upload."

    from ..face_screen import prepare_portfolio_image
    upload_dir = portfolio_upload_dir()
    fname = f"{provider_account_id}_{uuid.uuid4().hex[:8]}.jpg"
    dst = os.path.join(upload_dir, fname)
    ok, msg = prepare_portfolio_image(src_path, dst)
    if not ok:
        return False, msg

    conn = db.get_conn()
    try:
        conn.execute(
            """INSERT INTO portfolio(
                provider_account_id, job_id, title, description,
                photo_path, visible, created_at
            ) VALUES(?,NULL,?,?,?,1,?)""",
            (provider_account_id, title, description, dst, now_iso()),
        )
        conn.commit()
        return True, "Photo added to your portfolio."
    except Exception:
        conn.rollback()
        try:
            if os.path.exists(dst):
                os.remove(dst)
        except Exception:
            pass
        raise
    finally:
        conn.close()


def update_portfolio_item(item_id: int, provider_account_id: str,
                          title: str, description: str):
    title = (title or "").strip()
    description = (description or "").strip()
    if not title:
        return False, "Title is required."
    if len(title) > MAX_TITLE_LEN:
        return False, f"Title must be {MAX_TITLE_LEN} characters or fewer."
    if len(description) > MAX_DESC_LEN:
        return False, f"Description must be {MAX_DESC_LEN} characters or fewer."

    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT provider_account_id FROM portfolio WHERE item_id=?",
            (item_id,),
        ).fetchone()
        if not row:
            return False, "Item not found."
        if row["provider_account_id"] != provider_account_id:
            return False, "You can only edit your own photos."

        conn.execute(
            """UPDATE portfolio SET title=?, description=?
               WHERE item_id=?""",
            (title, description, item_id),
        )
        conn.commit()
        return True, "Photo updated."
    finally:
        conn.close()


def delete_portfolio_item(item_id: int, provider_account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT provider_account_id, photo_path FROM portfolio WHERE item_id=?",
            (item_id,),
        ).fetchone()
        if not row:
            return False, "Item not found."
        if row["provider_account_id"] != provider_account_id:
            return False, "You can only delete your own photos."

        path = row["photo_path"]
        conn.execute("DELETE FROM portfolio WHERE item_id=?", (item_id,))
        conn.commit()
    finally:
        conn.close()

    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        log.exception("Could not remove portfolio file")

    return True, "Photo removed."


def toggle_portfolio_visibility(item_id: int, provider_account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT provider_account_id, visible FROM portfolio WHERE item_id=?",
            (item_id,),
        ).fetchone()
        if not row:
            return False, "Item not found."
        if row["provider_account_id"] != provider_account_id:
            return False, "You can only change your own photos."

        new_visible = 0 if row["visible"] else 1
        conn.execute(
            "UPDATE portfolio SET visible=? WHERE item_id=?",
            (new_visible, item_id),
        )
        conn.commit()
        return True, ("Photo hidden." if new_visible == 0 else "Photo visible.")
    finally:
        conn.close()


# ------------------------------------------------------------------
# Provider services
# ------------------------------------------------------------------

MAX_SERVICE_TITLE_LEN = 60
MAX_SERVICE_DESC_LEN = 200
MAX_SERVICE_RATE_LEN = 60
MAX_SERVICES_PER_PROVIDER = 20


def _family_of(category: str):
    from . import categories as cats_mod
    for fam, cats in cats_mod.CATEGORIES.items():
        if category in cats:
            return fam
    return ""


def list_provider_services(provider_id: str, include_inactive: bool = False):
    conn = db.get_conn()
    try:
        if include_inactive:
            rows = conn.execute(
                """SELECT service_id, provider_account_id, title, category,
                          family, description, rate_text, active,
                          created_at, updated_at
                   FROM provider_services
                   WHERE provider_account_id=?
                   ORDER BY family, category, title""",
                (provider_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT service_id, provider_account_id, title, category,
                          family, description, rate_text, active,
                          created_at, updated_at
                   FROM provider_services
                   WHERE provider_account_id=? AND active=1
                   ORDER BY family, category, title""",
                (provider_id,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_provider_service(provider_account_id: str, category: str,
                         title: str, description: str = "",
                         rate_text: str = ""):
    """Add a service. Canonical categories must match the provider's family;
    custom categories inherit the provider's family."""
    category = (category or "").strip()
    title = (title or "").strip()
    description = (description or "").strip()
    rate_text = (rate_text or "").strip()

    if not category:
        return False, "Pick a service category."

    # If the category matches a canonical one, use its declared family.
    # Otherwise treat it as a custom service — the provider's own
    # service_family will be used and validated below.
    family = _family_of(category)

    if not title:
        title = category
    if len(title) > MAX_SERVICE_TITLE_LEN:
        return False, f"Title must be {MAX_SERVICE_TITLE_LEN} characters or fewer."
    if len(description) > MAX_SERVICE_DESC_LEN:
        return False, f"Description must be {MAX_SERVICE_DESC_LEN} characters or fewer."
    if len(rate_text) > MAX_SERVICE_RATE_LEN:
        return False, f"Rate must be {MAX_SERVICE_RATE_LEN} characters or fewer."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        prov = conn.execute(
            "SELECT role, service_family FROM accounts WHERE account_id=?",
            (provider_account_id,),
        ).fetchone()
        if not prov:
            conn.rollback()
            return False, "Account not found."
        if prov["role"] != "provider":
            conn.rollback()
            return False, "Only providers can add services."

        declared_family = prov["service_family"] or ""
        if not family:
            # Custom service — inherit provider's family.
            family = declared_family
            if not family:
                conn.rollback()
                return False, "Your profile has no service family set."
        else:
            # Canonical service — must match the provider's family.
            if declared_family != family:
                conn.rollback()
                return False, (
                    "You can only add services in your registered family "
                    f"({declared_family})."
                )

        existing = conn.execute(
            """SELECT service_id FROM provider_services
               WHERE provider_account_id=?
                 AND category=?
                 AND title=?
               LIMIT 1""",
            (provider_account_id, category, title),
        ).fetchone()
        if existing:
            conn.rollback()
            return False, "You already offer that service."

        count = conn.execute(
            "SELECT COUNT(*) AS n FROM provider_services WHERE provider_account_id=?",
            (provider_account_id,),
        ).fetchone()["n"]
        if count >= MAX_SERVICES_PER_PROVIDER:
            conn.rollback()
            return False, (
                f"You can list at most {MAX_SERVICES_PER_PROVIDER} services."
            )

        now = now_iso()
        conn.execute(
            """INSERT INTO provider_services(
                provider_account_id, title, category, family,
                description, rate_text, active, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,1,?,?)""",
            (provider_account_id, title, category, family,
             description, rate_text, now, now),
        )
        conn.commit()
        return True, "Service added."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_provider_service(service_id: int, provider_account_id: str,
                            title: str, description: str = "",
                            rate_text: str = ""):
    title = (title or "").strip()
    description = (description or "").strip()
    rate_text = (rate_text or "").strip()

    if not title:
        return False, "Title is required."
    if len(title) > MAX_SERVICE_TITLE_LEN:
        return False, f"Title must be {MAX_SERVICE_TITLE_LEN} characters or fewer."
    if len(description) > MAX_SERVICE_DESC_LEN:
        return False, f"Description must be {MAX_SERVICE_DESC_LEN} characters or fewer."
    if len(rate_text) > MAX_SERVICE_RATE_LEN:
        return False, f"Rate must be {MAX_SERVICE_RATE_LEN} characters or fewer."

    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT provider_account_id FROM provider_services WHERE service_id=?",
            (service_id,),
        ).fetchone()
        if not row:
            return False, "Service not found."
        if row["provider_account_id"] != provider_account_id:
            return False, "You can only edit your own services."

        conn.execute(
            """UPDATE provider_services
               SET title=?, description=?, rate_text=?, updated_at=?
               WHERE service_id=?""",
            (title, description, rate_text, now_iso(), service_id),
        )
        conn.commit()
        return True, "Service updated."
    finally:
        conn.close()


def delete_provider_service(service_id: int, provider_account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT provider_account_id FROM provider_services WHERE service_id=?",
            (service_id,),
        ).fetchone()
        if not row:
            return False, "Service not found."
        if row["provider_account_id"] != provider_account_id:
            return False, "You can only delete your own services."

        conn.execute(
            "DELETE FROM provider_services WHERE service_id=?",
            (service_id,),
        )
        conn.commit()
        return True, "Service removed."
    finally:
        conn.close()


def toggle_provider_service(service_id: int, provider_account_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT provider_account_id, active FROM provider_services WHERE service_id=?",
            (service_id,),
        ).fetchone()
        if not row:
            return False, "Service not found."
        if row["provider_account_id"] != provider_account_id:
            return False, "You can only change your own services."

        new_active = 0 if row["active"] else 1
        conn.execute(
            "UPDATE provider_services SET active=?, updated_at=? WHERE service_id=?",
            (new_active, now_iso(), service_id),
        )
        conn.commit()
        return True, ("Service hidden." if new_active == 0 else "Service visible.")
    finally:
        conn.close()


def find_provider_service_by_title(provider_account_id: str, title: str):
    title = (title or "").strip()
    if not title:
        return None
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT service_id, provider_account_id, title, category,
                      family, description, rate_text, active
               FROM provider_services
               WHERE provider_account_id=?
                 AND title=?
                 AND active=1
               LIMIT 1""",
            (provider_account_id, title),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_custom_service_categories(limit: int = 200):
    """Distinct non-canonical service category strings across the platform.

    A "custom" category is any `provider_services.category` value not in
    the canonical `categories.CATEGORIES` list. Only counts services
    belonging to active, setup-complete providers.
    """
    from . import categories as cats_mod

    canonical = set()
    for family_cats in cats_mod.CATEGORIES.values():
        for c in family_cats:
            canonical.add(c)

    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT DISTINCT ps.category
               FROM provider_services ps
               JOIN accounts a ON a.account_id = ps.provider_account_id
               WHERE ps.active = 1
                 AND a.role = 'provider'
                 AND a.account_status = 'active'
                 AND a.setup_complete = 1
                 AND COALESCE(ps.category, '') <> ''
               ORDER BY ps.category"""
        ).fetchall()

        out = []
        for r in rows:
            cat = (r["category"] or "").strip()
            if not cat or cat in canonical:
                continue
            out.append(cat)
            if len(out) >= limit:
                break
        return out
    finally:
        conn.close()


# ------------------------------------------------------------------
# Saved providers
# ------------------------------------------------------------------

def is_saved(client_account_id: str, provider_account_id: str) -> bool:
    if not client_account_id or not provider_account_id:
        return False
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT 1 FROM saved_providers
               WHERE client_account_id=? AND provider_account_id=?
               LIMIT 1""",
            (client_account_id, provider_account_id),
        ).fetchone()
        return bool(row)
    finally:
        conn.close()


def add_saved_provider(client_account_id: str, provider_account_id: str):
    if not client_account_id or not provider_account_id:
        return False, "Missing account."
    if client_account_id == provider_account_id:
        return False, "You cannot save yourself."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        client = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?",
            (client_account_id,),
        ).fetchone()
        if not client or client["role"] != "client":
            conn.rollback()
            return False, "Only clients can save providers."

        prov = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?",
            (provider_account_id,),
        ).fetchone()
        if not prov or prov["role"] != "provider":
            conn.rollback()
            return False, "That account is not a provider."

        existing = conn.execute(
            """SELECT 1 FROM saved_providers
               WHERE client_account_id=? AND provider_account_id=?
               LIMIT 1""",
            (client_account_id, provider_account_id),
        ).fetchone()
        if existing:
            conn.rollback()
            return True, "Already saved."

        conn.execute(
            """INSERT INTO saved_providers(
                client_account_id, provider_account_id, created_at
            ) VALUES(?,?,?)""",
            (client_account_id, provider_account_id, now_iso()),
        )
        conn.commit()
        return True, "Saved."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def remove_saved_provider(client_account_id: str, provider_account_id: str):
    if not client_account_id or not provider_account_id:
        return False, "Missing account."

    conn = db.get_conn()
    try:
        cur = conn.execute(
            """DELETE FROM saved_providers
               WHERE client_account_id=? AND provider_account_id=?""",
            (client_account_id, provider_account_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return False, "Not saved."
        return True, "Removed."
    finally:
        conn.close()


def list_saved_providers(client_account_id: str):
    if not client_account_id:
        return []

    conn = db.get_conn()
    try:
        rows = conn.execute(
            f"""
            SELECT
                a.account_id,
                COALESCE(NULLIF(a.display_name, ''), a.full_name) AS display_name,
                a.full_name,
                a.area,
                a.bio,
                a.work_photo_path,
                a.service_family,
                a.created_at,
                sp.created_at AS saved_at,
                (SELECT COUNT(*) FROM jobs j
                 WHERE j.provider_account_id = a.account_id
                   AND j.current_state IN ('completed','completed_by_timeout')
                ) AS completed_jobs,
                (SELECT COUNT(*) FROM jobs j
                 WHERE j.provider_account_id = a.account_id
                   AND j.current_state IN ({_ACTIVE_JOB_SQL})
                ) AS active_jobs,
                (SELECT COUNT(*) FROM reviews r
                 WHERE r.reviewee_account_id = a.account_id
                ) AS review_count,
                (SELECT AVG(CAST(r.stars AS REAL)) FROM reviews r
                 WHERE r.reviewee_account_id = a.account_id
                ) AS avg_stars,
                (SELECT COUNT(*) FROM disputes d
                 JOIN jobs j ON j.job_id = d.job_id
                 WHERE j.provider_account_id = a.account_id
                   AND d.status = 'open'
                ) AS open_disputes,
                (SELECT COUNT(*) FROM portfolio p
                 WHERE p.provider_account_id = a.account_id
                   AND p.visible = 1
                ) AS portfolio_count,
                (SELECT COUNT(*) FROM provider_services ps
                 WHERE ps.provider_account_id = a.account_id
                   AND ps.active = 1
                ) AS service_count,
                COALESCE(
                    (SELECT pa.mode FROM provider_availability pa
                     WHERE pa.provider_account_id = a.account_id),
                    ''
                ) AS availability_mode,
                COALESCE(
                    (SELECT pa.available_at FROM provider_availability pa
                     WHERE pa.provider_account_id = a.account_id),
                    ''
                ) AS availability_at,
                COALESCE(
                    (SELECT pa.updated_at FROM provider_availability pa
                     WHERE pa.provider_account_id = a.account_id),
                    ''
                ) AS availability_updated_at,
                COALESCE(
                    (SELECT MAX(j.updated_at) FROM jobs j
                     WHERE j.provider_account_id = a.account_id),
                    ''
                ) AS last_activity
            FROM saved_providers sp
            JOIN accounts a ON a.account_id = sp.provider_account_id
            WHERE sp.client_account_id = ?
              AND a.role='provider'
              AND a.setup_complete=1
              AND a.account_status='active'
              AND NOT EXISTS (
                  SELECT 1 FROM blocks b
                  WHERE b.blocker_account_id = sp.client_account_id
                    AND b.blocked_account_id = a.account_id
              )
            ORDER BY sp.created_at DESC
            """,
            (client_account_id,),
        ).fetchall()

        now_str = db.utcnow_iso()
        cutoff_30d = _days_ago(now_str[:10], 30)

        result = []
        for row in rows:
            d = dict(row)
            recent = False
            if d.get("last_activity"):
                try:
                    recent = d["last_activity"][:10] >= cutoff_30d
                except Exception:
                    recent = False

            d["rank_score"] = _compute_rank(
                completed_jobs=d.get("completed_jobs") or 0,
                review_count=d.get("review_count") or 0,
                avg_stars=d.get("avg_stars") or 0.0,
                has_active_job=(d.get("active_jobs") or 0) > 0,
                has_dispute=(d.get("open_disputes") or 0) > 0,
                recent_activity=recent,
            )

            has_active = (d.get("active_jobs") or 0) > 0
            declared_mode = d.get("availability_mode") or ""
            declared_at = d.get("availability_at") or ""
            declared_updated = d.get("availability_updated_at") or ""

            if has_active:
                effective = {"mode": "on_job", "available_at": "", "note": ""}
            else:
                mode, at = _decay(declared_mode, declared_updated, declared_at)
                if mode == "":
                    mode = "available_now"
                effective = {"mode": mode, "available_at": at, "note": ""}

            d["availability"] = effective
            d["is_saved"] = True

            d.pop("avg_stars", None)
            d.pop("last_activity", None)
            d.pop("availability_mode", None)
            d.pop("availability_at", None)
            d.pop("availability_updated_at", None)
            d.pop("saved_at", None)
            result.append(d)

        return result
    finally:
        conn.close()