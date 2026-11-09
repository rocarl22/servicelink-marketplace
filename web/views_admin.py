"""Admin console (/admin). See admin_security.py for the protection model."""
import re

from flask import (Blueprint, abort, flash, g, make_response, redirect, render_template, request, url_for)

from backend.services import admin as admin_svc
from backend.services.validation import clean_text

from . import admin_security as adm
from . import security, totp

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _text(name, maxlen=1000):
    return clean_text(request.form.get(name, "")).strip()[:maxlen]


def _go_full(admin_id):
    token = adm.upgrade_to_full(g.admin_session["session_hash"], admin_id)
    return adm.set_cookie(make_response(redirect(url_for("admin.dashboard"))), token)


def _need_stage(stage):
    sess = g.get("admin_session")
    return bool(sess and sess["stage"] == stage)


# ------------------------------------------------------------------ sign in / MFA
@bp.route("/signin", methods=["GET", "POST"])
def signin():
    if g.get("admin_session") and g.admin_session["stage"] == adm.STAGE_FULL:
        return redirect(url_for("admin.dashboard"))
    if request.method == "POST":
        security.limit_ip("admin-signin", 10, 600)
        ok, result = admin_svc.admin_login(_text("username", 60), request.form.get("password", ""))
        if not ok:
            flash(result, "error")
        else:
            if g.get("admin_session"):
                adm.revoke(g.admin_session["session_hash"])
            secret, _ = adm.totp_state(result)
            stage = adm.STAGE_MFA if secret else adm.STAGE_ENROLL
            token = adm.create_session(result, stage)
            target = "admin.mfa" if secret else "admin.mfa_setup"
            return adm.set_cookie(make_response(redirect(url_for(target))), token)
    return render_template("admin/signin.html")


@bp.route("/mfa", methods=["GET", "POST"])
def mfa():
    if not _need_stage(adm.STAGE_MFA):
        return redirect(url_for("admin.signin"))
    admin_id = g.admin["admin_id"]
    if request.method == "POST":
        security.limit("admin-mfa", admin_id, 10, 900)
        secret, last = adm.totp_state(admin_id)
        step = totp.verify(secret, request.form.get("code", ""), last)
        if step is not None and adm.claim_step(admin_id, step):
            return _go_full(admin_id)
        if adm.record_mfa_failure(g.admin_session["session_hash"]) >= adm.MAX_MFA_FAILURES:
            adm.revoke(g.admin_session["session_hash"])
            flash("Too many wrong codes. Please sign in again.", "error")
            return adm.clear_cookie(make_response(redirect(url_for("admin.signin"))))
        flash("That code wasn't right. Check the code in your authenticator app and try again.", "error")
        return redirect(url_for("admin.mfa"))
    return render_template("admin/mfa.html")


@bp.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    if not _need_stage(adm.STAGE_ENROLL):
        return redirect(url_for("admin.signin"))
    sess = g.admin_session
    secret = sess.get("pending_totp") or ""
    if not secret:
        secret = totp.new_secret()
        adm.set_pending_totp(sess["session_hash"], secret)
    if request.method == "POST":
        security.limit("admin-mfa", g.admin["admin_id"], 10, 900)
        step = totp.verify(secret, request.form.get("code", ""), 0)
        if step is not None and adm.enroll_secret(g.admin["admin_id"], secret, step):
            flash("Two-step sign-in is now on for your account.", "ok")
            return _go_full(g.admin["admin_id"])
        if adm.record_mfa_failure(sess["session_hash"]) >= adm.MAX_MFA_FAILURES:
            adm.revoke(sess["session_hash"])
            flash("Too many wrong codes. Please sign in again.", "error")
            return adm.clear_cookie(make_response(redirect(url_for("admin.signin"))))
        flash("That code wasn't right. Make sure the app shows this account, then try again.", "error")
        return redirect(url_for("admin.mfa_setup"))
    return render_template("admin/mfa_setup.html", secret=totp.group(secret),
                           uri=totp.otpauth_uri(secret, g.admin["username"]))


@bp.post("/signout")
def signout():
    if g.get("admin_session"):
        adm.revoke(g.admin_session["session_hash"])
    return adm.clear_cookie(make_response(redirect(url_for("admin.signin"))))


# ------------------------------------------------------------------ dashboard / audit
@bp.get("/")
@adm.admin_required()
def dashboard():
    return render_template("admin/dashboard.html", stats=admin_svc.get_dashboard_stats(),
                           actions=admin_svc.list_admin_actions(limit=8))


@bp.get("/audit")
@adm.admin_required()
def audit():
    kind = re.sub(r"[^a-z_]", "", request.args.get("type", ""))[:40]
    return render_template("admin/audit.html", actions=admin_svc.list_admin_actions(limit=200, action_type=kind), kind=kind)


# ------------------------------------------------------------------ accounts
ACCOUNT_ID = re.compile(r"^[CP]-[A-F0-9]{10}$")


@bp.get("/accounts")
@adm.admin_required()
def accounts():
    q = clean_text(request.args.get("q", "")).strip()[:60]
    role = request.args.get("role", "")
    role = role if role in ("client", "provider") else ""
    return render_template("admin/accounts.html", items=admin_svc.search_accounts(q, role, 100), q=q, role=role)


def _account_or_404(account_id):
    if not ACCOUNT_ID.match(account_id):
        abort(404)
    detail = admin_svc.get_account_detail(account_id)
    if not detail:
        abort(404)
    return detail


@bp.get("/accounts/<account_id>")
@adm.admin_required()
def account_detail(account_id):
    from backend.services import accounts as accounts_svc
    return render_template("admin/account_detail.html", a=_account_or_404(account_id), statuses=admin_svc.VALID_STATUSES,
                           phone_verified=bool(accounts_svc.verified_ids([account_id])))


@bp.post("/accounts/<account_id>/status")
@adm.admin_required("admin")
def account_status(account_id):
    _account_or_404(account_id)
    if adm.confirm_password():
        ok, msg = admin_svc.set_account_status(g.admin["admin_id"], account_id, request.form.get("new_status", ""), _text("reason", 500))
        flash(msg if not ok else "Account status updated.", "ok" if ok else "error")
    return redirect(url_for("admin.account_detail", account_id=account_id))


@bp.post("/accounts/<account_id>/reset-password")
@adm.admin_required("admin")
def account_reset(account_id):
    a = _account_or_404(account_id)
    if not adm.confirm_password():
        return redirect(url_for("admin.account_detail", account_id=account_id))
    ok, result = admin_svc.issue_password_reset(g.admin["admin_id"], account_id, _text("reason", 500))
    if not ok:
        flash(result, "error")
        return redirect(url_for("admin.account_detail", account_id=account_id))
    from backend.services.validation import normalize_ke_phone
    from .views_auth import notify
    ok_phone, phone07 = normalize_ke_phone(a.get("phone", ""))
    if ok_phone:
        notify(phone07, "ServiceLink: an administrator reset your password. If you did not ask for this, contact support.")
    return render_template("admin/reset_result.html", a=a, temp_password=result)     # shown once, never stored in a URL


# ------------------------------------------------------------------ disputes
@bp.get("/disputes")
@adm.admin_required()
def disputes():
    return render_template("admin/disputes.html", items=admin_svc.list_open_disputes())


def _dispute_or_404(dispute_id):
    ctx = admin_svc.get_dispute_context(dispute_id)
    if not ctx:
        abort(404)
    return ctx


@bp.get("/disputes/<int:dispute_id>")
@adm.admin_required()
def dispute_detail(dispute_id):
    ctx = _dispute_or_404(dispute_id)
    for party in (ctx["client"].get("account_id"), ctx["provider"].get("account_id")):
        if party:
            admin_svc.mark_thread_read_by_admin(dispute_id, party)
    return render_template("admin/dispute_detail.html", ctx=ctx)


@bp.get("/media/evidence/<int:evidence_id>")
@adm.admin_required()
def evidence_file(evidence_id):
    from .views_media import evidence_row, serve_evidence
    row = evidence_row(evidence_id)
    if not row:
        abort(404)
    return serve_evidence(row)


@bp.post("/disputes/<int:dispute_id>/message")
@adm.admin_required()
def dispute_message(dispute_id):
    _dispute_or_404(dispute_id)
    ok, msg = admin_svc.post_dispute_message(g.admin["admin_id"], dispute_id, _text("body", 1000),
                                             request.form.get("kind", "question"), request.form.get("target", "both"))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("admin.dispute_detail", dispute_id=dispute_id))


@bp.post("/disputes/<int:dispute_id>/hold")
@adm.admin_required()
def dispute_hold(dispute_id):
    _dispute_or_404(dispute_id)
    ok, msg = admin_svc.hold_dispute(g.admin["admin_id"], dispute_id, _text("reason", 500))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("admin.dispute_detail", dispute_id=dispute_id))


@bp.post("/disputes/<int:dispute_id>/resolve")
@adm.admin_required("admin")
def dispute_resolve(dispute_id):
    _dispute_or_404(dispute_id)
    if adm.confirm_password():
        ok, msg = admin_svc.resolve_dispute(g.admin["admin_id"], dispute_id, request.form.get("outcome", ""), _text("reason", 500))
        flash(msg, "ok" if ok else "error")
        if ok:
            return redirect(url_for("admin.disputes"))
    return redirect(url_for("admin.dispute_detail", dispute_id=dispute_id))


# ------------------------------------------------------------------ reports
@bp.get("/reports")
@adm.admin_required()
def reports():
    return render_template("admin/reports.html", items=admin_svc.list_open_reports())


@bp.post("/reports/<int:report_id>/dismiss")
@adm.admin_required()
def report_dismiss(report_id):
    ok, msg = admin_svc.dismiss_report(g.admin["admin_id"], report_id, _text("reason", 500))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("admin.reports"))


# ------------------------------------------------------------------ my account
@bp.get("/me")
@adm.admin_required()
def me():
    return render_template("admin/me.html")


@bp.post("/me/username")
@adm.admin_required()
def me_username():
    ok, msg = admin_svc.change_own_username(g.admin["admin_id"], _text("new_username", 60), request.form.get("password", ""))
    flash("Username changed." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("admin.me"))


@bp.post("/me/password")
@adm.admin_required()
def me_password():
    ok, msg = admin_svc.change_own_password(g.admin["admin_id"], request.form.get("current_password", ""),
                                            request.form.get("new_password", ""), request.form.get("confirm_password", ""))
    if not ok:
        flash(msg, "error")
        return redirect(url_for("admin.me"))
    adm.revoke_all(g.admin["admin_id"])                       # every admin session, including this one
    flash("Password changed. Please sign in again.", "ok")
    return adm.clear_cookie(make_response(redirect(url_for("admin.signin"))))
