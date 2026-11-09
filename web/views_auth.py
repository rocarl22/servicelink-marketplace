"""Sign up, sign in, sign out and first-time profile completion."""
import re

from flask import (Blueprint, flash, g, make_response, redirect, render_template, request, url_for)

from backend.services import accounts, categories
from backend.services import otp as otp_svc
from backend.services import passwords as passwords_svc
from backend.services.validation import clean_text, normalize_ke_phone

from . import security, sms

bp = Blueprint("auth", __name__)


def _set_session_cookie(resp, token):
    resp.set_cookie(security.cookie_name("session"), token, httponly=True, path="/",
                    secure=security.cfg("SECURE_COOKIES"), samesite="Lax")
    return resp


def _clear_session_cookie(resp):
    resp.set_cookie(security.cookie_name("session"), "", expires=0, max_age=0, httponly=True, path="/",
                    secure=security.cfg("SECURE_COOKIES"), samesite="Lax")
    return resp


def _start_session_and_redirect(account_id, destination):
    """Session fixation defence: always mint a brand-new token on authentication."""
    if g.get("session"):
        security.revoke_session(g.session["session_hash"])
    token = security.create_session(account_id)
    return _set_session_cookie(make_response(redirect(destination)), token)


@bp.route("/signup", methods=["GET", "POST"])
def signup():
    if g.get("account"):
        return redirect(url_for("app.dashboard"))
    families = {k for k, _ in categories.SERVICE_FAMILIES}
    form = {"role": request.values.get("role", "client")}
    if request.method == "POST":
        security.limit_ip("signup", 8, 3600)
        form = {k: clean_text(request.form.get(k, "")).strip() for k in
                ("role", "full_name", "phone", "email", "service_family")}
        password, confirm = request.form.get("password", ""), request.form.get("password_confirm", "")
        role = form["role"] if form["role"] in ("client", "provider") else ""
        family = form["service_family"] if form["service_family"] in families else ""
        if not role:
            flash("Choose whether you are a client or a provider.", "error")
        elif role == "provider" and not family:
            flash("Choose the type of services you provide.", "error")
        else:
            ok, result = accounts.create_account(
                role=role, full_name=form["full_name"], phone=form["phone"], email=form["email"],
                password=password, password_confirm=confirm,
                terms_accepted=bool(request.form.get("terms")), role_locked=True,
                service_family=family if role == "provider" else "", device_key="web")
            if ok:
                return _start_session_and_redirect(result, url_for("auth.complete_profile"))
            flash(result, "error")
    return render_template("signup.html", form=form, families=categories.SERVICE_FAMILIES)


@bp.route("/signin", methods=["GET", "POST"])
def signin():
    if g.get("account"):
        return redirect(url_for("app.dashboard"))
    nxt = request.values.get("next", "")
    if request.method == "POST":
        security.limit_ip("signin", 20, 600)
        phone = clean_text(request.form.get("phone", "")).strip()
        digits = re.sub(r"\D", "", phone)[-9:]
        security.limit("signin-account", digits or "none", 10, 600)    # slows guessing against one account
        ok, result = accounts.sign_in(phone, request.form.get("password", ""), "web")
        if ok:
            return _start_session_and_redirect(result, security.safe_next(nxt))
        flash(result, "error")
    return render_template("signin.html", next=security.safe_next(nxt, ""), reset_available=sms.enabled(sms_settings()))


@bp.post("/signout")
def signout():
    if g.get("session"):
        security.revoke_session(g.session["session_hash"])
    flash("You have been signed out.", "ok")
    return _clear_session_cookie(make_response(redirect(url_for("public.landing"))))


@bp.route("/complete-profile", methods=["GET", "POST"])
@security.login_required
def complete_profile():
    acct = g.account
    if acct.get("setup_complete"):
        return redirect(url_for("app.dashboard"))
    if request.method == "POST":
        display_name = clean_text(request.form.get("display_name", "")).strip()
        area = request.form.get("area", "")
        bio = clean_text(request.form.get("bio", "")).strip()
        if area not in categories.OPERATING_AREAS:
            flash("Choose the area you are in.", "error")
        else:
            from backend.services import scam_shield
            bio = scam_shield.screen(bio).text
            ok, msg = accounts.complete_profile(acct["account_id"], display_name, area, bio, "",
                                                acct["role"], acct.get("service_family", ""))
            if ok:
                flash("Welcome to ServiceLink!", "ok")
                return redirect(url_for("app.settings") + "#services" if acct["role"] == "provider"
                                else url_for("app.dashboard"))
            flash(msg, "error")
    return render_template("complete_profile.html", areas=categories.OPERATING_AREAS)


# ------------------------------------------------------------------ phone codes, password reset, forced change
CODE_TEXT = {
    "verify_phone": "ServiceLink: your verification code is {code}. It expires in 10 minutes. Never share this code.",
    "reset_password": "ServiceLink: your password reset code is {code}. It expires in 10 minutes. "
                      "If you did not ask for this, ignore this message.",
}
RESETTABLE = ("active", "under_review", "restricted", "on_hold")


def sms_settings():
    return {k: security.cfg(k) for k in ("SMS_BACKEND", "AT_USERNAME", "AT_API_KEY", "AT_SENDER_ID", "AT_SANDBOX", "SMS_ASYNC")}


def notify(phone07, text):
    """Best-effort security notice by text message; never blocks or fails the request."""
    if sms.enabled(sms_settings()):
        try:
            sms.send_async(phone07, text, sms_settings())
        except Exception:
            pass


def _issue_and_send(account, purpose):
    ok, result = otp_svc.issue(account["account_id"], purpose, account["phone"], pepper=security.cfg("SECRET_KEY"))
    if not ok:
        return False, result
    sms.send_async(account["phone"], CODE_TEXT[purpose].format(code=result), sms_settings())
    return True, ""


@bp.route("/verify-phone", methods=["GET", "POST"])
@security.login_required
def verify_phone():
    acct = g.account
    nxt = security.safe_next(request.values.get("next", ""), "")
    if acct.get("phone_verified_at"):
        return redirect(nxt or url_for("app.dashboard"))
    if request.method == "POST":
        security.limit("otp-verify", acct["account_id"], 10, 900)
        ok, msg = otp_svc.verify(acct["account_id"], "verify_phone", request.form.get("code", ""),
                                 pepper=security.cfg("SECRET_KEY"))
        if ok:
            accounts.mark_phone_verified(acct["account_id"])
            flash("Phone number verified. Thank you!", "ok")
            return redirect(nxt or url_for("app.dashboard"))
        flash(msg, "error")
    return render_template("verify_phone.html", masked=sms.mask(acct["phone"]), next=nxt,
                           sms_on=sms.enabled(sms_settings()))


@bp.post("/verify-phone/send")
@security.login_required
def verify_phone_send():
    acct = g.account
    if acct.get("phone_verified_at") or not sms.enabled(sms_settings()):
        return redirect(url_for("app.dashboard"))
    security.limit_ip("otp-send", 10, 3600)
    ok, msg = _issue_and_send(acct, "verify_phone")
    flash(f"We sent a code to {sms.mask(acct['phone'])}." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("auth.verify_phone", next=security.safe_next(request.form.get("next", ""), "")))


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if g.get("account"):
        return redirect(url_for("app.settings") + "#security")
    on = sms.enabled(sms_settings())
    if request.method == "POST" and on:
        security.limit_ip("forgot", 6, 3600)
        phone = clean_text(request.form.get("phone", "")).strip()[:30]
        ok_phone, normalized = normalize_ke_phone(phone)
        digits = normalized[-9:] if ok_phone else "invalid"
        security.limit("forgot-phone", digits, 5, 3600)
        acct = accounts.get_account_by_phone(phone) if ok_phone else {}
        if acct and acct.get("account_status") in RESETTABLE:
            _issue_and_send(acct, "reset_password")
        # The same page and wording whether or not the number has an account (no enumeration).
        flash("If that number belongs to an account, we've sent a code to it.", "ok")
        return render_template("reset_password.html", phone=normalized if ok_phone else phone)
    return render_template("forgot_password.html", sms_on=on)


@bp.post("/reset-password")
def reset_password():
    if not sms.enabled(sms_settings()):
        return redirect(url_for("auth.forgot_password"))
    security.limit_ip("reset", 20, 3600)
    phone = clean_text(request.form.get("phone", "")).strip()[:30]
    ok_phone, normalized = normalize_ke_phone(phone)
    security.limit("reset-phone", normalized[-9:] if ok_phone else "invalid", 10, 900)
    new_pw, confirm = request.form.get("new_password", ""), request.form.get("confirm_password", "")
    acct = accounts.get_account_by_phone(phone) if ok_phone else {}

    def again(message):
        flash(message, "error")
        return render_template("reset_password.html", phone=normalized if ok_phone else phone)

    # Check the new password BEFORE spending the one-time code, so a typo or weak password doesn't burn it.
    if new_pw != confirm:
        return again("The two passwords do not match.")
    ok, msg = passwords_svc.validate_password(new_pw, context=(acct.get("full_name"), acct.get("phone"), acct.get("email")) if acct else (phone,))
    if not ok:
        return again(msg)
    if not acct or acct.get("account_status") not in RESETTABLE:
        return again(otp_svc.GENERIC_FAIL)
    ok, msg = otp_svc.verify(acct["account_id"], "reset_password", request.form.get("code", ""), pepper=security.cfg("SECRET_KEY"))
    if not ok:
        return again(msg)
    ok, msg = accounts.reset_password(acct["account_id"], new_pw, confirm)
    if not ok:
        return again(msg)
    security.revoke_all_sessions(acct["account_id"])              # a reset signs out every device
    notify(acct["phone"], "ServiceLink: your password was just changed. If this wasn't you, contact support now.")
    flash("Your password has been changed. Please sign in.", "ok")
    return redirect(url_for("auth.signin"))


@bp.route("/password-required", methods=["GET", "POST"])
@security.login_required
def password_required():
    """Shown after an administrator issued a temporary password: choose your own before anything else."""
    acct = g.account
    if not acct.get("password_upgrade_required"):
        return redirect(url_for("app.dashboard"))
    if request.method == "POST":
        ok, msg = accounts.change_password(acct["account_id"], request.form.get("current_password", ""),
                                           request.form.get("new_password", ""), request.form.get("confirm_password", ""))
        if ok:
            security.revoke_all_sessions(acct["account_id"])
            token = security.create_session(acct["account_id"])
            flash("Your new password is set.", "ok")
            return _set_session_cookie(make_response(redirect(url_for("app.dashboard"))), token)
        flash(msg, "error")
    return render_template("password_required.html")
