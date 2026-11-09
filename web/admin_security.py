"""Admin console security. Stricter than the user site on purpose.

- Separate sign-in URL, cookie (Path=/admin, SameSite=Strict) and session table.
- Two-step sign-in: password, then an authenticator-app code. A "pending" session
  grants NOTHING; only a "full" session (after the code) opens admin pages.
- 15 min idle / 2 h absolute; pending sessions last 5 min and allow 5 wrong codes.
- Risky actions also require the admin to re-enter their password.
- Optional IP allow-list (SERVICELINK_ADMIN_ALLOWED_IPS).
"""
import hashlib
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import abort, flash, g, redirect, request, url_for

from backend import database as db
from backend.services import accounts
from backend.services.validation import now_iso, parse_iso

from . import security

STAGE_MFA, STAGE_ENROLL, STAGE_FULL = "pending_mfa", "pending_enroll", "full"
ADMIN_IDLE, ADMIN_ABSOLUTE, PENDING_TTL, MAX_MFA_FAILURES = 15 * 60, 2 * 60 * 60, 5 * 60, 5


def _sha(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()


def cookie_name() -> str:
    return "__Secure-sl_admin" if security.cfg("SECURE_COOKIES") else "sl_admin"


def set_cookie(resp, token):
    resp.set_cookie(cookie_name(), token, httponly=True, path="/admin", secure=security.cfg("SECURE_COOKIES"),
                    samesite="Strict")
    return resp


def clear_cookie(resp):
    resp.set_cookie(cookie_name(), "", expires=0, max_age=0, httponly=True, path="/admin",
                    secure=security.cfg("SECURE_COOKIES"), samesite="Strict")
    return resp


def ip_allowed() -> bool:
    nets = security.cfg("ADMIN_ALLOWED_IPS")
    if not nets:
        return True
    try:
        ip = ipaddress.ip_address(security.client_ip())
        return any(ip in ipaddress.ip_network(n, strict=False) for n in nets)
    except ValueError:
        return False


# ------------------------------------------------------------------ sessions
def create_session(admin_id: str, stage: str) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    ttl = ADMIN_ABSOLUTE if stage == STAGE_FULL else PENDING_TTL
    conn = db.get_conn()
    try:
        conn.execute(
            """INSERT INTO web_admin_sessions(session_hash, admin_id, stage, created_at, last_seen_at,
               expires_at, ip, user_agent) VALUES(?,?,?,?,?,?,?,?)""",
            (_sha(token), admin_id, stage, now_iso(), now_iso(),
             (now + timedelta(seconds=ttl)).isoformat(timespec="seconds"),
             security.client_ip()[:64], (request.headers.get("User-Agent") or "")[:200]))
        conn.commit()
    finally:
        conn.close()
    return token


def load_session(token: str):
    if not token or len(token) > 200:
        return None
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT * FROM web_admin_sessions WHERE session_hash=?", (_sha(token),)).fetchone()
        if not row or row["revoked_at"]:
            return None
        now = datetime.now(timezone.utc)
        expires, seen = parse_iso(row["expires_at"]), parse_iso(row["last_seen_at"])
        idle = ADMIN_IDLE if row["stage"] == STAGE_FULL else PENDING_TTL
        if not expires or not seen or now >= expires or (now - seen).total_seconds() >= idle:
            conn.execute("UPDATE web_admin_sessions SET revoked_at=? WHERE session_hash=?", (now_iso(), row["session_hash"]))
            conn.commit()
            return None
        if row["stage"] == STAGE_FULL:
            conn.execute("UPDATE web_admin_sessions SET last_seen_at=? WHERE session_hash=?", (now_iso(), row["session_hash"]))
            conn.commit()
        return dict(row)
    finally:
        conn.close()


def revoke(session_hash: str):
    conn = db.get_conn()
    try:
        conn.execute("UPDATE web_admin_sessions SET revoked_at=? WHERE session_hash=? AND revoked_at=''", (now_iso(), session_hash))
        conn.commit()
    finally:
        conn.close()


def revoke_all(admin_id: str, keep_hash: str = ""):
    conn = db.get_conn()
    try:
        conn.execute("UPDATE web_admin_sessions SET revoked_at=? WHERE admin_id=? AND revoked_at='' AND session_hash<>?",
                     (now_iso(), admin_id, keep_hash))
        conn.commit()
    finally:
        conn.close()


def upgrade_to_full(old_hash: str, admin_id: str) -> str:
    """Rotate: the pending token dies, a fresh full token is issued."""
    revoke(old_hash)
    return create_session(admin_id, STAGE_FULL)


def record_mfa_failure(session_hash: str) -> int:
    conn = db.get_conn()
    try:
        conn.execute("UPDATE web_admin_sessions SET mfa_failures=mfa_failures+1 WHERE session_hash=?", (session_hash,))
        conn.commit()
        return conn.execute("SELECT mfa_failures FROM web_admin_sessions WHERE session_hash=?", (session_hash,)).fetchone()[0]
    finally:
        conn.close()


def set_pending_totp(session_hash: str, secret: str):
    conn = db.get_conn()
    try:
        conn.execute("UPDATE web_admin_sessions SET pending_totp=? WHERE session_hash=?", (secret, session_hash))
        conn.commit()
    finally:
        conn.close()


def totp_state(admin_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT totp_secret, totp_last_step FROM admin_users WHERE admin_id=?", (admin_id,)).fetchone()
        return (row["totp_secret"] or "", int(row["totp_last_step"] or 0)) if row else ("", 0)
    finally:
        conn.close()


def claim_step(admin_id: str, step: int) -> bool:
    """Atomically record a used code step. False if it was already used (replay)."""
    conn = db.get_conn()
    try:
        cur = conn.execute("UPDATE admin_users SET totp_last_step=? WHERE admin_id=? AND totp_last_step<?", (step, admin_id, step))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def enroll_secret(admin_id: str, secret: str, step: int) -> bool:
    conn = db.get_conn()
    try:
        cur = conn.execute("UPDATE admin_users SET totp_secret=?, totp_last_step=? WHERE admin_id=? AND totp_secret=''",
                           (secret, step, admin_id))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def purge(days: int = 7):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute("DELETE FROM web_admin_sessions WHERE expires_at < ? OR (revoked_at<>'' AND revoked_at < ?)", (cutoff, cutoff))
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------ guards
def admin_required(role=None):
    """Only a fully authenticated admin (password + authenticator code) gets through.
    role='admin' additionally excludes read-mostly 'support' accounts."""
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            sess = g.get("admin_session")
            if not g.get("admin") or not sess or sess["stage"] != STAGE_FULL:
                return redirect(url_for("admin.signin"))
            if role and g.admin["role"] != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return deco


def confirm_password() -> bool:
    """Re-authentication for risky actions. Flashes an error and returns False on failure."""
    security.limit("admin-reauth", g.admin["admin_id"], 8, 600)
    pw = request.form.get("admin_password", "")
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT password_hash FROM admin_users WHERE admin_id=? AND active=1", (g.admin["admin_id"],)).fetchone()
    finally:
        conn.close()
    if row and pw and accounts._check_password(pw, row["password_hash"]):
        return True
    flash("Your password was not correct, so nothing was changed.", "error")
    return False
