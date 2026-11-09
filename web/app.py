"""Application factory for the ServiceLink website."""
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, g, render_template, request
from markupsafe import Markup, escape

from backend import database as db
from backend.services import accounts, chat, money, notifications
from backend.services import admin as admin_svc

from . import security

log = logging.getLogger("servicelink.web")
EAT = timezone(timedelta(hours=3))          # Kenya: UTC+3, no daylight saving

STATE_LABELS = {
    "accepted": ("Accepted", "info"), "dispatched": ("On the way", "info"),
    "arrived": ("Arrived", "info"), "started": ("In progress", "warn"),
    "client_confirmed": ("Awaiting provider", "warn"), "done": ("Awaiting your confirmation", "warn"),
    "completed": ("Completed", "ok"), "completed_by_timeout": ("Completed", "ok"),
    "disputed": ("In dispute", "bad"), "abandoned": ("Abandoned", "bad"), "cancelled": ("Cancelled", "muted"),
    "pending": ("Pending", "warn"), "declined": ("Declined", "muted"), "expired": ("Expired", "muted"),
    "open": ("Open", "info"),
}

CATEGORY_ICONS = {
    "Plumbing": "wrench", "Electrical": "zap", "Cleaning": "house", "Carpentry": "wrench",
    "Painting": "paint-roller", "Appliance Repair": "settings", "Gardening": "house", "Moving": "briefcase",
    "Hair": "palette", "Makeup": "palette", "Tailoring": "briefcase", "Spa": "heart", "Photography": "camera",
}


def _env_bool(name, default):
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in ("1", "true", "yes", "on")


def _env_list(name):
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def _load_secret_key() -> str:
    """SERVICELINK_SECRET_KEY if set; otherwise generate once and keep it (0600) in the data dir."""
    env = os.environ.get("SERVICELINK_SECRET_KEY", "")
    if len(env) >= 32:
        return env
    path = os.path.join(db.DATA_DIR, ".web_secret")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
            if len(value) >= 32:
                return value
    except OSError:
        pass
    value = secrets.token_urlsafe(48)
    os.makedirs(db.DATA_DIR, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value)
    log.warning("Generated a new web secret key at %s (set SERVICELINK_SECRET_KEY to manage it yourself).", path)
    return value


def create_app(overrides=None):
    app = Flask(__name__, static_folder="static", template_folder="templates")
    production = os.environ.get("SERVICELINK_ENV", "development").lower() == "production"
    app.config.update(
        ENV_NAME="production" if production else "development",
        SECURE_COOKIES=_env_bool("SERVICELINK_SECURE_COOKIES", production),
        IDLE_TIMEOUT=30 * 60,
        ABSOLUTE_TIMEOUT=8 * 60 * 60,
        TRUSTED_PROXIES=_env_list("SERVICELINK_TRUSTED_PROXIES"),
        ALLOWED_ORIGINS=_env_list("SERVICELINK_ALLOWED_ORIGINS"),
        ADMIN_ALLOWED_IPS=_env_list("SERVICELINK_ADMIN_ALLOWED_IPS"),
        SMS_BACKEND=os.environ.get("SERVICELINK_SMS_BACKEND", "none" if production else "console").strip().lower(),
        AT_USERNAME=os.environ.get("AT_USERNAME", ""), AT_API_KEY=os.environ.get("AT_API_KEY", ""),
        AT_SENDER_ID=os.environ.get("AT_SENDER_ID", ""), AT_SANDBOX=_env_bool("AT_SANDBOX", False),
        SMS_ASYNC=True,
        ALLOW_PDF_EVIDENCE=_env_bool("SERVICELINK_ALLOW_PDF_EVIDENCE", False),
        MAX_CONTENT_LENGTH=256 * 1024,            # no uploads yet; small forms only
        JSON_SORT_KEYS=False,
        TEMPLATES_AUTO_RELOAD=False,
        SKIP_DB_INIT=False,
        RATE_LIMITS_ENABLED=True,
    )
    app.config["REQUIRE_PHONE_VERIFICATION"] = _env_bool("SERVICELINK_REQUIRE_PHONE_VERIFICATION",
                                                         app.config["SMS_BACKEND"] != "none")
    hosts = _env_list("SERVICELINK_ALLOWED_HOSTS")
    if hosts:
        app.config["TRUSTED_HOSTS"] = hosts
    if overrides:
        app.config.update(overrides)
        if "REQUIRE_PHONE_VERIFICATION" not in overrides:
            app.config["REQUIRE_PHONE_VERIFICATION"] = app.config["SMS_BACKEND"] != "none"
    # Flask's signed "flash" cookie (messages only) follows the same cookie policy.
    app.config.update(
        SESSION_COOKIE_NAME=("__Host-sl_flash" if app.config["SECURE_COOKIES"] else "sl_flash"),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=app.config["SECURE_COOKIES"],
    )

    if not app.config["SKIP_DB_INIT"]:
        db.init_db()
    app.config.setdefault("SECRET_KEY", None)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_secret_key()
    security.purge_sessions()
    app.config.setdefault("RUN_SWEEPER", not app.config.get("TESTING", False))
    if app.config["RUN_SWEEPER"]:
        from . import sweeper
        sweeper.run_once()                     # like the desktop app: sweep at start-up...
        sweeper.start()                        # ...and every 5 minutes after that
    from . import admin_security
    admin_security.purge()
    from backend.services import otp as otp_svc
    otp_svc.purge()

    # ------------------------------------------------------------ request hooks
    @app.before_request
    def _before():
        g.session_token = None
        g.session = None
        g.account = None
        g.new_anon = None
        g.admin = g.admin_session = g.admin_token = None
        if request.path.startswith("/static/"):
            return
        if app.config["RATE_LIMITS_ENABLED"]:
            security.limit_ip("req", 600, 300)
        token = request.cookies.get(security.cookie_name("session"), "")
        sess = security.load_session(token) if token else None
        if sess:
            acct = accounts.get_account(sess["account_id"])
            if acct and acct.get("account_status") not in ("suspended", "closed"):
                g.session_token, g.session, g.account = token, sess, acct
            else:
                security.revoke_session(sess["session_hash"])
        if request.path.startswith("/admin"):
            from . import admin_security as adm
            if not adm.ip_allowed():
                abort(404)                              # the console simply does not exist for other networks
            atoken = request.cookies.get(adm.cookie_name(), "")
            asess = adm.load_session(atoken) if atoken else None
            if asess:
                admin_row = admin_svc.get_admin(asess["admin_id"])
                if admin_row and admin_row.get("active"):
                    g.admin, g.admin_session, g.admin_token = admin_row, asess, atoken
                else:
                    adm.revoke(asess["session_hash"])
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.endpoint in security.UPLOAD_ENDPOINTS:
                from . import uploads
                request.max_content_length = uploads.REQUEST_LIMIT_BYTES     # only these routes may take big bodies
            if app.config["RATE_LIMITS_ENABLED"]:
                security.limit_ip("post", 120, 60)
            security.enforce_csrf()

    @app.after_request
    def _after(response):
        if g.get("new_anon") and not request.cookies.get(security.cookie_name("anon")):
            response.set_cookie(security.cookie_name("anon"), g.new_anon, httponly=True, path="/",
                                secure=app.config["SECURE_COOKIES"], samesite="Lax")
        return security.apply_security_headers(response)

    # ------------------------------------------------------------ template helpers
    ICON_DIR = os.path.join(app.static_folder, "icons")
    icon_cache = {}

    def icon(name, cls=""):
        if not re.fullmatch(r"[a-z0-9\-]{1,40}", name or ""):
            return Markup("")
        if name not in icon_cache:
            try:
                with open(os.path.join(ICON_DIR, name + ".svg"), "r", encoding="utf-8") as fh:
                    svg = fh.read()
                svg = re.sub(r'\s(width|height)="[^"]*"', "", svg, count=2)
                svg = re.sub(r'class="[^"]*"', 'class="icon"', svg, count=1)
                icon_cache[name] = svg
            except OSError:
                icon_cache[name] = ""
        svg = icon_cache[name]
        if svg and cls:
            svg = svg.replace('class="icon"', f'class="icon {escape(cls)}" aria-hidden="true"', 1)
        elif svg:
            svg = svg.replace('class="icon"', 'class="icon" aria-hidden="true"', 1)
        return Markup(svg)

    def fmt_dt(value, fmt="%d %b %Y, %H:%M"):
        try:
            dt = datetime.fromisoformat(str(value))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(EAT).strftime(fmt)
        except (ValueError, TypeError):
            return ""

    def fmt_ago(value):
        try:
            dt = datetime.fromisoformat(str(value))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            secs = (datetime.now(timezone.utc) - dt).total_seconds()
        except (ValueError, TypeError):
            return ""
        if secs < 60: return "just now"
        if secs < 3600: return f"{int(secs // 60)} min ago"
        if secs < 86400: return f"{int(secs // 3600)} h ago"
        if secs < 7 * 86400: return f"{int(secs // 86400)} d ago"
        return fmt_dt(value, "%d %b %Y")

    def initials(name):
        parts = [p for p in re.split(r"\s+", (name or "").strip()) if p]
        return ("".join(p[0] for p in parts[:2]) or "?").upper()

    def nl2br(text):
        return Markup(str(escape(text or "")).replace("\n", "<br>"))

    def avail_label(av):
        av = av if isinstance(av, dict) else {"mode": str(av or "")}
        mode, when = av.get("mode", ""), (av.get("available_at") or "").strip()
        return {"available_now": ("Available now", "ok"), "on_job": ("On a job", "info"),
                "available_at": (f"Available from {when}" if when else "Available later", "info"),
                "busy_until": (f"Busy until {when}" if when else "Busy", "warn"),
                "unavailable": ("Unavailable", "muted")}.get(mode, ("Available now", "ok"))

    def state_label(state):
        return STATE_LABELS.get(state, (str(state or "").replace("_", " ").title(), "muted"))

    def photo_url(account_id, stored_path):
        """Address of someone's profile photo (never the file path), or '' if they have none."""
        if not stored_path:
            return ""
        from .views_media import photo_version
        return f"/media/avatar/{account_id}?v={photo_version(stored_path)}"

    app.jinja_env.globals.update(photo_url=photo_url, now_year=datetime.now().year, icon=icon, csrf_token=security.csrf_token,
                                 category_icon=lambda c: CATEGORY_ICONS.get(c, "briefcase"))
    app.jinja_env.filters.update(dt=fmt_dt, ago=fmt_ago, initials=initials, nl2br=nl2br,
                                 state_label=state_label, avail=avail_label,
                                 kes=lambda minor_or_text: money.format_kes(minor_or_text) if isinstance(minor_or_text, int) else (minor_or_text or ""))

    @app.context_processor
    def _inject():
        acct = g.get("account")
        ctx = {"current_account": acct, "unread_messages": 0, "unread_notifications": 0,
               "needs_verify": bool(acct and app.config["REQUIRE_PHONE_VERIFICATION"] and not acct.get("phone_verified_at"))}
        if acct:
            try:
                ctx["unread_messages"] = chat.unread_count(acct["account_id"])
                ctx["unread_notifications"] = notifications.unread_count(acct["account_id"])
            except Exception:
                log.exception("badge counts failed")
        return ctx

    # ------------------------------------------------------------ errors (never leak internals)
    def _error(code, title, message):
        return render_template("error.html", code=code, title=title, message=message), code

    app.register_error_handler(400, lambda e: _error(400, "Bad request", "That request couldn't be understood."))
    app.register_error_handler(403, lambda e: _error(403, "Not allowed", "You don't have permission to do that, or your session expired. Please go back and try again."))
    app.register_error_handler(404, lambda e: _error(404, "Page not found", "We couldn't find what you were looking for."))
    app.register_error_handler(405, lambda e: _error(405, "Not allowed", "That action isn't supported here."))
    app.register_error_handler(413, lambda e: _error(413, "Too large", "That request was too large."))
    app.register_error_handler(429, lambda e: _error(429, "Slow down", "Too many requests. Please wait a moment and try again."))

    @app.errorhandler(Exception)
    def _unhandled(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return _error(exc.code or 500, exc.name, "Something went wrong.")
        log.exception("Unhandled error on %s %s", request.method, request.path)
        return _error(500, "Something went wrong", "An unexpected error occurred. Nothing was changed. Please try again.")

    # ------------------------------------------------------------ blueprints
    from .views_public import bp as public_bp
    from .views_auth import bp as auth_bp
    from .views_app import bp as app_bp
    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(app_bp)
    from .views_media import bp as media_bp
    app.register_blueprint(media_bp)
    from .views_admin import bp as admin_bp
    app.register_blueprint(admin_bp)
    return app
