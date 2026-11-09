"""Signed-in pages: dashboard, requests, jobs, messages, notifications, settings."""
import json
import re
from datetime import datetime, timezone

from flask import (Blueprint, Response, abort, flash, g, make_response, redirect, render_template,
                   request, url_for)

from backend import database as dbmod
from backend.services import (accounts, blocks, categories, chat, data_export, jobs, marketplace, notifications,
                              requests as requests_svc, reviews, scam_shield)
from backend.services import admin as admin_svc
from backend.services.validation import clean_text, parse_iso

from . import security, uploads
from .security import login_required, role_required
from .views_public import annotate_verified

bp = Blueprint("app", __name__)

PROVIDER_ID = re.compile(r"^P-[A-F0-9]{10}$")
ACCOUNT_ID = re.compile(r"^[CP]-[A-F0-9]{10}$")


def me() -> str:
    """The acting account id - from the server-side session only."""
    return g.account["account_id"]


def _text(name, maxlen=2000):
    return clean_text(request.form.get(name, "")).strip()[:maxlen]


def _all_categories():
    return [c for cats in categories.CATEGORIES.values() for c in cats]


def _job_or_404(job_id):
    job = jobs.get_job(job_id, me())          # returns {} unless the viewer is the client or provider
    if not job:
        abort(404)
    return job


# ------------------------------------------------------------------ dashboard
@bp.get("/dashboard")
@login_required
def dashboard():
    acct = g.account
    all_jobs = jobs.list_my_jobs(me())
    active = [j for j in all_jobs if j["current_state"] not in jobs.TERMINAL_STATES]
    recent = [j for j in all_jobs if j["current_state"] in jobs.TERMINAL_STATES][:5]
    summary = accounts.get_account_summary(me())
    ctx = dict(active=active, recent=recent, summary=summary)
    if acct["role"] == "provider":
        ctx["incoming"] = requests_svc.list_open_requests_for_provider(me())
        ctx["availability"] = marketplace.get_provider_availability(me())
    else:
        ctx["my_requests"] = [r for r in requests_svc.list_client_requests(me()) if r["status"] == "open"]
        ctx["featured"] = annotate_verified(marketplace.list_providers(limit=4, caller_account_id=me()))
    return render_template("dashboard.html", **ctx)


@bp.post("/availability")
@role_required("provider")
def availability_set():
    ok, msg = marketplace.set_provider_availability(me(), request.form.get("mode", ""), _text("when", 60), _text("note", 120))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.dashboard"))


# ------------------------------------------------------------------ reviews
@bp.get("/reviews")
@login_required
def reviews_page():
    tab = "given" if request.args.get("tab") == "given" else "received"
    avg, count = reviews.average_for_account(me())
    items = reviews.list_reviews_left(me()) if tab == "given" else reviews.list_reviews_received(me())
    return render_template("reviews.html", tab=tab, items=items, avg=avg, count=count)


# ------------------------------------------------------------------ saved providers (clients)
@bp.get("/saved")
@role_required("client")
def saved():
    return render_template("saved.html", providers=annotate_verified(marketplace.list_saved_providers(me())))


@bp.post("/providers/<provider_id>/save")
@role_required("client")
def toggle_save(provider_id):
    if not PROVIDER_ID.match(provider_id):
        abort(404)
    if marketplace.is_saved(me(), provider_id):
        marketplace.remove_saved_provider(me(), provider_id)
        flash("Removed from saved providers.", "ok")
    else:
        ok, msg = marketplace.add_saved_provider(me(), provider_id)
        flash("Saved." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("public.provider_detail", provider_id=provider_id))


# ------------------------------------------------------------------ requests
@bp.route("/request/new", methods=["GET", "POST"])
@role_required("client", verified=True)
def request_new():
    provider_id = (request.values.get("provider") or "").strip()
    provider = None
    if provider_id:
        if not PROVIDER_ID.match(provider_id):
            abort(404)
        provider = marketplace.get_provider_profile(provider_id)
        if not provider or provider.get("account_status") != "active" or not provider.get("setup_complete"):
            abort(404)
        provider.pop("phone", None)
    cats = _all_categories()
    customs = [c["category"] if isinstance(c, dict) else str(c) for c in marketplace.list_custom_service_categories()]
    cats = sorted(set(cats) | set(customs))
    if provider:
        cats = sorted(set(cats) | {s["category"] for s in provider.get("services", []) if s.get("category")})
    if request.method == "POST":
        category, area = _text("category", 80), request.form.get("area", "")
        if category == "__custom__":                                  # the desktop's "Custom service"
            category = _text("custom_category", 60)
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 &'/\-]{2,59}", category):
                flash("Describe the service in 3-60 letters or numbers, e.g. Sofa cleaning.", "error")
                return render_template("request_new.html", provider=provider, cats=cats, areas=categories.OPERATING_AREAS,
                                       form={"category": "__custom__", "area": area, "custom": category})
            cats = cats + [category]
        description = scam_shield.screen(_text("description", 1000)).text      # same protection as chat
        if category not in cats:
            flash("Choose a service category.", "error")
        elif area not in categories.OPERATING_AREAS:
            flash("Choose your area.", "error")
        else:
            ok, result = requests_svc.create_request(
                me(), category, description, area, _text("preferred_time", 80),
                provider_id if provider else "", "direct" if provider else "open")
            if ok:
                flash("Request sent. You'll see replies in your messages." if provider
                      else "Your request is open to matching providers.", "ok")
                return redirect(url_for("app.requests_list"))
            flash(result, "error")
    return render_template("request_new.html", provider=provider, cats=cats, areas=categories.OPERATING_AREAS,
                           form={"custom": "", "category": request.values.get("category", ""),
                                 "area": request.values.get("area", g.account.get("area", ""))})


@bp.get("/requests")
@role_required("client")
def requests_list():
    return render_template("requests.html", items=requests_svc.list_client_requests(me()))


@bp.post("/requests/<int:request_id>/cancel")
@role_required("client")
def request_cancel(request_id):
    ok, msg = requests_svc.cancel_request(me(), request_id, _text("reason", 200))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.requests_list"))


@bp.get("/requests/available")
@role_required("provider")
def requests_available():
    return render_template("available.html", items=requests_svc.list_open_requests_for_provider(me()))


@bp.post("/requests/<int:request_id>/accept")
@role_required("provider", verified=True)
def request_accept(request_id):
    ok, result = jobs.accept_request(me(), request_id)
    if ok:
        flash("Request accepted. Agree the price with your client in the job.", "ok")
        return redirect(url_for("app.job_detail", job_id=int(result)))
    flash(result, "error")
    return redirect(url_for("app.requests_available"))


@bp.post("/requests/<int:request_id>/decline")
@role_required("provider")
def request_decline(request_id):
    ok, msg = requests_svc.decline_request(me(), request_id, _text("reason", 200))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.requests_available"))


# ------------------------------------------------------------------ jobs
STAGES = [("accepted", "Job accepted"), ("dispatched", "Provider on the way"), ("arrived", "Provider arrived"),
          ("started", "Work started"), ("client_confirmed", "Client confirmed the start"), ("done", "Work marked done")]
JOB_DONE_STATES = ("completed", "completed_by_timeout")
JOB_CANCELLED_STATES = ("cancelled", "abandoned")
JOB_ENDED_STATES = JOB_DONE_STATES + JOB_CANCELLED_STATES


def job_stages(job):
    """Every stage of the job - finished ones ticked, the next one highlighted, upcoming ones greyed -
    like the desktop app's tracker. Cancelled/abandoned/disputed jobs end in a red marker."""
    state = job["current_state"]
    by_state = {}
    for ev in job["events"]:
        by_state[ev["to_state"]] = ev
    out = [dict(key=k, label=lbl, done=k in by_state, kind="ok",
                time=(by_state[k]["created_at"] if k in by_state else ""),
                actor=(by_state[k].get("actor_name") or "") if k in by_state else "",
                note=(by_state[k].get("note") or "") if k in by_state else "") for k, lbl in STAGES]
    if state in JOB_DONE_STATES:
        closing = by_state.get(state) or {}
        out.append(dict(key="closed", label="Job closed" if state == "completed" else "Job completed automatically",
                        done=True, kind="ok", time=job.get("closed_at") or closing.get("created_at", ""),
                        actor=closing.get("actor_name") or "", note=closing.get("note") or ""))
    elif state in JOB_CANCELLED_STATES:
        out.append(dict(key=state, label="Job cancelled" if state == "cancelled" else "Job abandoned", done=True, kind="bad",
                        time=job.get("closed_at") or "", actor="", note=job.get("cancellation_reason") or ""))
    elif state == "disputed":
        ev = by_state.get("disputed") or {}
        out.append(dict(key="disputed", label="Dispute opened", done=True, kind="bad", time=ev.get("created_at", ""),
                        actor=ev.get("actor_name") or "", note=ev.get("note") or ""))
    else:
        out.append(dict(key="closed", label="Job closed", done=False, kind="ok", time="", actor="", note=""))
    first_pending = next((s for s in out if not s["done"]), None)
    for s_ in out:
        s_["current"] = s_ is first_pending
    return out


def waiting_message(job, is_provider):
    s = job["current_state"]
    fixed = {"completed": "This job is complete. No further actions.",
             "completed_by_timeout": "This job completed automatically. No further actions.",
             "cancelled": "This job has been cancelled. No further actions.",
             "abandoned": "This job was abandoned. No further actions."}
    if s in fixed:
        return fixed[s]
    if not is_provider:
        return {"accepted": "Waiting for the provider to set off.", "dispatched": "Waiting for the provider to arrive.",
                "arrived": "Waiting for the provider to start work.",
                "client_confirmed": "Waiting for the provider to mark the work done."}.get(s, "")
    return {"started": "Waiting for the client to confirm the work has started.",
            "done": "Waiting for the client to confirm the job is complete."}.get(s, "")


def _next_actions(job):
    state, is_provider = job["current_state"], me() == job["provider_account_id"]
    if is_provider:
        table = {"accepted": ("dispatched", "I'm on my way"), "dispatched": ("arrived", "I've arrived"),
                 "arrived": ("started", "Start the work"), "client_confirmed": ("done", "Mark work complete")}
    else:
        table = {"started": ("client_confirmed", "The work is finished"),
                 "done": ("close", "Confirm and close this job")}
    return [table[state]] if state in table else []


@bp.get("/jobs")
@login_required
def jobs_list():
    all_jobs = jobs.list_my_jobs(me())
    tabs = {"active": [j for j in all_jobs if j["current_state"] not in JOB_ENDED_STATES],
            "completed": [j for j in all_jobs if j["current_state"] in JOB_DONE_STATES],
            "cancelled": [j for j in all_jobs if j["current_state"] in JOB_CANCELLED_STATES]}
    tab = request.args.get("tab", "active")
    tab = tab if tab in tabs else "active"
    return render_template("jobs.html", tab=tab, items=tabs[tab], counts={k: len(v) for k, v in tabs.items()})


@bp.get("/jobs/<int:job_id>")
@login_required
def job_detail(job_id):
    job = _job_or_404(job_id)
    is_provider = me() == job["provider_account_id"]
    state = job["current_state"]
    terminal = state in JOB_ENDED_STATES or state == "disputed"
    can_rev, _ = reviews.can_review(job_id, me())
    dispute = jobs.get_dispute_for_job(job_id) if state == "disputed" else None
    my_review = reviews.get_review_for_job(job_id, me()) or None
    editable_until = parse_iso(my_review["editable_until"]) if my_review else None
    can_edit_review = bool(editable_until and editable_until > datetime.now(timezone.utc))
    try:
        conv_id = chat.ensure_conversation(job["client_account_id"], job["provider_account_id"])
    except Exception:
        conv_id = None
    incidents = dbmod.INCIDENT_TYPES_PROVIDER if is_provider else dbmod.INCIDENT_TYPES_CLIENT
    return render_template("job_detail.html", job=job, is_provider=is_provider, terminal=terminal, incidents=incidents,
                           stages=job_stages(job), waiting=waiting_message(job, is_provider) if not _next_actions(job) else "",
                           dispute=dispute, i_raised=bool(dispute and dispute["opened_by_account_id"] == me()),
                           my_review=my_review, can_edit_review=can_edit_review,
                           actions=_next_actions(job), can_review=can_rev, conv_id=conv_id,
                           job_reviews=reviews.list_reviews_for_job(job_id))


@bp.post("/jobs/<int:job_id>/advance")
@login_required
def job_advance(job_id):
    job = _job_or_404(job_id)
    action = request.form.get("action", "")
    if action not in {a for a, _ in _next_actions(job)}:       # server decides what is possible
        abort(400)
    if action == "close":
        ok, msg = jobs.close_job(job_id, me(), "client_confirmed")
    else:
        ok, msg = jobs.advance(job_id, me(), action)
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/price")
@role_required("provider")
def job_price(job_id):
    _job_or_404(job_id)
    ok, msg = jobs.set_agreed_price(job_id, me(), _text("price", 60))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/cancel")
@login_required
def job_cancel(job_id):
    _job_or_404(job_id)
    ok, msg = jobs.cancel_job(job_id, me(), _text("reason", 300))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/review")
@login_required
def job_review(job_id):
    _job_or_404(job_id)
    comment = scam_shield.screen(_text("comment", 600)).text
    ok, msg = reviews.create_review(job_id, me(), request.form.get("stars", "0"), comment)
    flash("Thanks for your review." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/dispute")
@login_required
def job_dispute(job_id):
    job = _job_or_404(job_id)
    allowed = dbmod.INCIDENT_TYPES_PROVIDER if me() == job["provider_account_id"] else dbmod.INCIDENT_TYPES_CLIENT
    category = _text("category", 80)
    if category not in allowed:
        abort(400)
    ok, msg = jobs.open_dispute(job_id, me(), category, _text("description", 1000), bool(request.form.get("anonymous")))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.disputes_page") if ok else url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/dispute/withdraw")
@login_required
def dispute_withdraw(job_id):
    _job_or_404(job_id)
    ok, msg = jobs.withdraw_dispute(job_id, me())
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/dispute/accept")
@login_required
def dispute_accept(job_id):
    _job_or_404(job_id)
    ok, msg = jobs.accept_dispute(job_id, me(), _text("note", 300))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/review/edit")
@login_required
def job_review_edit(job_id):
    _job_or_404(job_id)
    mine = reviews.get_review_for_job(job_id, me())
    if not mine:
        abort(404)
    comment = scam_shield.screen(_text("comment", 600)).text
    ok, msg = reviews.update_review(mine["review_id"], me(), request.form.get("stars", "0"), comment)
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


@bp.post("/jobs/<int:job_id>/block")
@login_required
def job_block(job_id):
    job = _job_or_404(job_id)
    other = job["client_account_id"] if me() == job["provider_account_id"] else job["provider_account_id"]
    ok, msg = blocks.block_user(me(), other, _text("reason", 300), job_id)
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.job_detail", job_id=job_id))


# ------------------------------------------------------------------ disputes (messages with the administrator)
@bp.get("/disputes")
@login_required
def disputes_page():
    threads = admin_svc.list_party_thread(me())
    for t in threads:
        if t.get("unread"):
            admin_svc.mark_thread_read(me(), t["dispute_id"])
    return render_template("disputes.html", threads=threads)


@bp.post("/disputes/<int:dispute_id>/reply")
@login_required
def dispute_reply(dispute_id):
    body = _text("body", 1000)
    upload = request.files.get("evidence")
    if upload and upload.filename:
        security.limit("upload", me(), 20, 3600)
        with uploads.staged(upload, uploads.MAX_EVIDENCE_BYTES, allow_pdf=security.cfg("ALLOW_PDF_EVIDENCE")) as up:
            if not up.ok:
                flash(up.error, "error")
            else:
                ok, msg = admin_svc.send_party_message(me(), dispute_id, body or "Evidence attached.", up.path)
                flash(msg, "ok" if ok else "error")
    else:
        ok, msg = admin_svc.send_party_message(me(), dispute_id, body)
        flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.disputes_page") + f"#d{dispute_id}")


# ------------------------------------------------------------------ messages
@bp.get("/messages")
@login_required
def messages():
    return render_template("messages.html", conversations=chat.list_conversations(me()))


@bp.route("/messages/<int:conversation_id>", methods=["GET", "POST"])
@login_required
def thread(conversation_id):
    conv = chat.get_conversation(conversation_id, me())      # {} unless you are a participant
    if not conv:
        abort(404)
    if request.method == "POST":
        ok, msg = chat.send_message(conversation_id, me(), request.form.get("body", ""))
        if not ok:
            flash(msg, "error")
        return redirect(url_for("app.thread", conversation_id=conversation_id) + "#end")
    chat.mark_read(conversation_id, me())
    other = conv["provider_name"] if me() == conv["client_account_id"] else conv["client_name"]
    pair = (conv["client_account_id"], conv["provider_account_id"])
    return render_template("thread.html", conv=conv, other=other, is_provider=me() == conv["provider_account_id"],
                           open_requests=requests_svc.list_open_requests_between(*pair),
                           open_dispute=jobs.get_open_dispute_between(pair[0], pair[1], me()),
                           msgs=chat.list_messages(conversation_id, me()), live=chat.is_chat_live(conversation_id))


# ------------------------------------------------------------------ notifications
@bp.get("/notifications")
@login_required
def notifications_page():
    items = notifications.list_for_account(me())
    return render_template("notifications.html", items=items)


@bp.post("/notifications/seen")
@login_required
def notifications_seen():
    keys = [n["key"] for n in notifications.list_for_account(me()) if not n.get("seen")]
    if keys:
        notifications.mark_seen(me(), keys)
    return redirect(url_for("app.notifications_page"))


# ------------------------------------------------------------------ settings
@bp.get("/settings")
@login_required
def settings():
    services = marketplace.list_provider_services(me(), include_inactive=True) if g.account["role"] == "provider" else []
    cats = categories.CATEGORIES.get(g.account.get("service_family", ""), [])
    portfolio = marketplace.portfolio_for_provider(me(), include_hidden=True) if g.account["role"] == "provider" else []
    return render_template("settings.html", portfolio=portfolio, summary=accounts.get_account_summary(me()), blocked=blocks.list_blocked_by(me()), sessions=security.list_sessions(me()),
                           current_hash=g.session["session_hash"], services=services, cats=cats,
                           areas=categories.OPERATING_AREAS)


@bp.post("/settings/profile")
@login_required
def settings_profile():
    area = request.form.get("area", "")
    if area not in categories.OPERATING_AREAS:
        flash("Choose your area.", "error")
    else:
        bio = scam_shield.screen(_text("bio", 500)).text
        ok, msg = accounts.update_profile(me(), _text("display_name", 60), area, bio,
                                          g.account.get("work_photo_path", ""))
        flash("Profile updated." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("app.settings"))


@bp.post("/settings/password")
@login_required
def settings_password():
    ok, msg = accounts.change_password(me(), request.form.get("current_password", ""),
                                       request.form.get("new_password", ""), request.form.get("confirm_password", ""))
    if not ok:
        flash(msg, "error")
        return redirect(url_for("app.settings"))
    # Changing a password signs out every other device and rotates this session.
    security.revoke_all_sessions(me())
    token = security.create_session(me())
    from .views_auth import notify
    notify(g.account["phone"], "ServiceLink: your password was just changed. If this wasn't you, contact support now.")
    flash("Password changed. Other devices were signed out.", "ok")
    resp = make_response(redirect(url_for("app.settings")))
    resp.set_cookie(security.cookie_name("session"), token, httponly=True, path="/",
                    secure=security.cfg("SECURE_COOKIES"), samesite="Lax")
    return resp


@bp.post("/settings/sessions/revoke")
@login_required
def sessions_revoke():
    target = request.form.get("session", "")
    if re.fullmatch(r"[a-f0-9]{64}", target) and target != g.session["session_hash"]:
        security.revoke_session(target, account_id=me())          # only your own sessions
        flash("That device was signed out.", "ok")
    return redirect(url_for("app.settings") + "#security")


@bp.post("/settings/sessions/revoke-others")
@login_required
def sessions_revoke_others():
    security.revoke_all_sessions(me(), keep_hash=g.session["session_hash"])
    flash("All other devices were signed out.", "ok")
    return redirect(url_for("app.settings") + "#security")


@bp.post("/settings/blocked/unblock")
@login_required
def unblock():
    target = request.form.get("account_id", "")
    if ACCOUNT_ID.match(target):
        ok, msg = blocks.unblock_user(me(), target)
        flash(msg if not ok else "Unblocked.", "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#blocked")


@bp.post("/settings/services/add")
@role_required("provider")
def service_add():
    ok, msg = marketplace.add_provider_service(me(), _text("category", 80), _text("title", 80),
                                               scam_shield.screen(_text("description", 300)).text,
                                               _text("rate_text", 60))
    flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#services")


@bp.post("/settings/services/<int:service_id>/edit")
@role_required("provider")
def service_edit(service_id):
    ok, msg = marketplace.update_provider_service(service_id, me(), _text("title", 80),
                                                  scam_shield.screen(_text("description", 300)).text, _text("rate_text", 60))
    flash("Service updated." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#services")


@bp.post("/settings/services/<int:service_id>/toggle")
@role_required("provider")
def service_toggle(service_id):
    ok, msg = marketplace.toggle_provider_service(service_id, me())
    flash(msg if not ok else "Service updated.", "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#services")


@bp.post("/settings/services/<int:service_id>/delete")
@role_required("provider")
def service_delete(service_id):
    ok, msg = marketplace.delete_provider_service(service_id, me())
    flash(msg if not ok else "Service removed.", "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#services")


@bp.post("/settings/export")
@login_required
def export_data():
    payload = json.dumps(data_export.export_account_data(me()), indent=2, ensure_ascii=False)
    resp = Response(payload, mimetype="application/json")
    resp.headers["Content-Disposition"] = 'attachment; filename="servicelink-my-data.json"'
    return resp
