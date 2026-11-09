"""Web security layer: server-side sessions, CSRF, headers, rate limiting, safe redirects.

Design rules
- The acting account comes ONLY from the server-side session (never from a form
  field or URL). Resource ids from URLs are always re-checked against that account.
- The session cookie is an opaque random token. Only its SHA-256 is stored, so a
  database leak does not yield usable sessions.
- No inline scripts or styles anywhere, so the CSP can be strict (no nonces needed).
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, current_app, g, redirect, request, url_for

from backend import database as db
from backend.services import netutil, ratelimit
from backend.services.validation import now_iso, parse_iso

TOUCH_INTERVAL_SECONDS = 60          # limit "last seen" writes
MEDIA_ENDPOINTS = ("media.avatar", "media.portfolio_image", "media.evidence", "admin.evidence_file")
UPLOAD_ENDPOINTS = ("media.photo_set", "media.portfolio_add", "app.dispute_reply")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ config helpers
def cfg(name):
    return current_app.config[name]


def cookie_name(kind: str) -> str:
    # __Host- prefix: browser enforces Secure, Path=/, and no Domain attribute.
    return ("__Host-sl_" if cfg("SECURE_COOKIES") else "sl_") + kind


def client_ip() -> str:
    ip = netutil.client_ip(request.remote_addr or "", request.headers.get("X-Forwarded-For"),
                           cfg("TRUSTED_PROXIES"))
    return ip or "0.0.0.0"


# ------------------------------------------------------------------ sessions (DB-backed)
def create_session(account_id: str) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    conn = db.get_conn()
    try:
        conn.execute(
            """INSERT INTO web_sessions(session_hash, account_id, created_at, last_seen_at,
               expires_at, ip, user_agent) VALUES(?,?,?,?,?,?,?)""",
            (_sha(token), account_id, now_iso(), now_iso(),
             (now + timedelta(seconds=cfg("ABSOLUTE_TIMEOUT"))).isoformat(timespec="seconds"),
             client_ip()[:64], (request.headers.get("User-Agent") or "")[:200]))
        conn.commit()
    finally:
        conn.close()
    return token


def load_session(token: str):
    """Return the session row (dict) if valid, else None. Enforces idle + absolute expiry."""
    if not token or len(token) > 200:
        return None
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT * FROM web_sessions WHERE session_hash=?", (_sha(token),)).fetchone()
        if not row or row["revoked_at"]:
            return None
        now = datetime.now(timezone.utc)
        expires = parse_iso(row["expires_at"])
        last_seen = parse_iso(row["last_seen_at"])
        if not expires or not last_seen or now >= expires or (now - last_seen).total_seconds() >= cfg("IDLE_TIMEOUT"):
            conn.execute("UPDATE web_sessions SET revoked_at=? WHERE session_hash=?", (now_iso(), row["session_hash"]))
            conn.commit()
            return None
        if (now - last_seen).total_seconds() >= TOUCH_INTERVAL_SECONDS:
            conn.execute("UPDATE web_sessions SET last_seen_at=? WHERE session_hash=?", (now_iso(), row["session_hash"]))
            conn.commit()
        return dict(row)
    finally:
        conn.close()


def revoke_session(session_hash: str, account_id: str = ""):
    conn = db.get_conn()
    try:
        if account_id:     # only ever revoke your own sessions
            conn.execute("UPDATE web_sessions SET revoked_at=? WHERE session_hash=? AND account_id=? AND revoked_at=''",
                         (now_iso(), session_hash, account_id))
        else:
            conn.execute("UPDATE web_sessions SET revoked_at=? WHERE session_hash=? AND revoked_at=''",
                         (now_iso(), session_hash))
        conn.commit()
    finally:
        conn.close()


def revoke_all_sessions(account_id: str, keep_hash: str = ""):
    conn = db.get_conn()
    try:
        conn.execute("UPDATE web_sessions SET revoked_at=? WHERE account_id=? AND revoked_at='' AND session_hash<>?",
                     (now_iso(), account_id, keep_hash))
        conn.commit()
    finally:
        conn.close()


def list_sessions(account_id: str):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            """SELECT session_hash, created_at, last_seen_at, expires_at, ip, user_agent
               FROM web_sessions WHERE account_id=? AND revoked_at='' ORDER BY last_seen_at DESC""",
            (account_id,)).fetchall()
        now = datetime.now(timezone.utc)
        out = []
        for r in rows:
            exp, seen = parse_iso(r["expires_at"]), parse_iso(r["last_seen_at"])
            if exp and now < exp and seen and (now - seen).total_seconds() < cfg("IDLE_TIMEOUT"):
                out.append(dict(r))
        return out
    finally:
        conn.close()


def purge_sessions(days: int = 7):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute("DELETE FROM web_sessions WHERE expires_at < ? OR (revoked_at<>'' AND revoked_at < ?)",
                     (cutoff, cutoff))
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------ CSRF (HMAC bound to the session/anon cookie)
def _bound_token() -> str:
    """The session token the CSRF token is tied to (admin pages use the admin session)."""
    if request.path.startswith("/admin"):
        return g.get("admin_token") or ""
    return g.get("session_token") or ""


def _csrf_binding() -> str:
    if _bound_token():
        return "s:" + _bound_token()
    anon = request.cookies.get(cookie_name("anon"), "")
    if not anon or len(anon) > 100:
        anon = g.get("new_anon") or secrets.token_urlsafe(16)
        g.new_anon = anon                      # after_request will set the cookie
    return "a:" + anon


def csrf_token() -> str:
    return hmac.new(cfg("SECRET_KEY").encode(), ("csrf|" + _csrf_binding()).encode(), hashlib.sha256).hexdigest()


def _check_origin():
    """Reject cross-site form posts: Origin (or Referer) host must match this host."""
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if not source:
        return                                   # same-site navigations from old browsers; CSRF token still required
    if source == "null":
        abort(403)
    host = urlsplit(source).netloc.lower()
    allowed = {request.host.lower()} | set(cfg("ALLOWED_ORIGINS"))
    if host not in allowed:
        abort(403)


def enforce_csrf():
    _check_origin()
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    binding_cookie = _bound_token() or request.cookies.get(cookie_name("anon"), "")
    if not binding_cookie or not submitted or not hmac.compare_digest(submitted, csrf_token()):
        abort(403)


# ------------------------------------------------------------------ rate limiting
def limit(name: str, subject: str, max_count: int, window_seconds: int):
    """Abort with 429 when `subject` has exceeded max_count in the sliding window."""
    allowed, _ = ratelimit.consume(netutil.rate_key(f"web:{name}", subject), max_count, window_seconds)
    if not allowed:
        abort(429)


def limit_ip(name: str, max_count: int, window_seconds: int):
    limit(name, netutil.rate_bucket_ip(client_ip()), max_count, window_seconds)


# ------------------------------------------------------------------ helpers / decorators
def safe_next(target: str, default: str = "/dashboard") -> str:
    """Only same-site absolute paths: blocks open redirects (//evil.com, https://..., \\evil)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return default
    if any(ord(c) < 32 for c in target):
        return default
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return default
    return target


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.get("account"):
            return redirect(url_for("auth.signin", next=request.full_path.rstrip("?")))
        if g.account.get("password_upgrade_required") and request.endpoint not in ("auth.password_required", "auth.signout"):
            return redirect(url_for("auth.password_required"))      # e.g. after an administrator reset
        if not g.account.get("setup_complete") and request.endpoint not in ("auth.complete_profile", "auth.signout"):
            return redirect(url_for("auth.complete_profile"))
        return view(*args, **kwargs)
    return wrapper


def role_required(role: str, verified: bool = False):
    """verified=True also needs a confirmed phone number (when verification is switched on)."""
    def deco(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if g.account.get("role") != role:
                abort(403)
            if verified and cfg("REQUIRE_PHONE_VERIFICATION") and not g.account.get("phone_verified_at"):
                from flask import flash
                flash("Please verify your phone number first. It keeps everyone on ServiceLink safe.", "error")
                return redirect(url_for("auth.verify_phone", next=request.path))
            return view(*args, **kwargs)
        return wrapper
    return deco


def apply_security_headers(response):
    h = response.headers
    own_csp = h.get("Content-Security-Policy")
    own_cache = h.get("Cache-Control") if request.endpoint in MEDIA_ENDPOINTS else None
    h["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests" if cfg("SECURE_COOKIES") else
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'")
    if own_csp:
        h["Content-Security-Policy"] = own_csp               # e.g. the "sandbox" policy on served files
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["X-Frame-Options"] = "DENY"
    h["Server"] = "ServiceLink"
    if request.path.startswith("/admin"):
        h["X-Robots-Tag"] = "noindex, nofollow"
    if cfg("SECURE_COOKIES"):
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if request.path.startswith("/static/"):
        h["Cache-Control"] = "public, max-age=86400"
    elif own_cache:
        h["Cache-Control"] = own_cache
    else:
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
    return response
