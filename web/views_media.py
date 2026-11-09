"""Photo uploads (profile photo, portfolio) and the access-checked routes that serve them.

Stored files are never reachable by URL path. Each image is served by id after checking who is asking:
  /media/avatar/<account>   providers' photos are public; a client's photo only to people they deal with
  /media/portfolio/<item>   public while visible; hidden items only to their owner
  /media/evidence/<id>      only the person who attached it (their private thread with the administrator)
  /admin/media/evidence/<id>  signed-in administrators (see views_admin.py)
The database stores server file paths, so every path is re-checked to lie inside the expected folder.
"""
import hashlib
import os
import re

from flask import Blueprint, abort, flash, g, make_response, redirect, request, send_file, url_for

from backend import database as db
from backend.services import accounts, marketplace, scam_shield
from backend.services.validation import clean_text

from . import security, uploads
from .security import login_required, role_required

bp = Blueprint("media", __name__)
ACCOUNT_ID = re.compile(r"^[CP]-[A-F0-9]{10}$")
ALLOWED_MIME = {"image/jpeg": "inline", "application/pdf": "attachment"}


def me() -> str:
    return g.account["account_id"]


def _text(name, maxlen=300):
    return clean_text(request.form.get(name, "")).strip()[:maxlen]


def photo_version(path: str) -> str:
    """Changes whenever the photo changes, so browsers refresh their cached copy."""
    return hashlib.sha1(os.path.basename(path or "").encode()).hexdigest()[:8]


# ------------------------------------------------------------------ safe file serving
def safe_path(stored_path: str, folder: str):
    """The real path if `stored_path` is a regular file inside DATA_DIR/<folder>, else None."""
    if not stored_path:
        return None
    root = os.path.realpath(os.path.join(db.DATA_DIR, folder))
    real = os.path.realpath(stored_path)
    if os.path.commonpath([root, real]) != root or not os.path.isfile(real):
        return None
    return real


def serve(path: str, mimetype: str, cache: str):
    if mimetype not in ALLOWED_MIME:
        abort(404)
    resp = send_file(path, mimetype=mimetype, conditional=True, max_age=None)
    resp.headers["Content-Disposition"] = (f'{ALLOWED_MIME[mimetype]}; filename="'
                                           f'{"document.pdf" if mimetype == "application/pdf" else "photo.jpg"}"')
    resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"      # never executes, whatever it is
    resp.headers["Cache-Control"] = cache
    return resp


def _related(viewer: str, target: str) -> bool:
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT 1 FROM conversations WHERE (client_account_id=? AND provider_account_id=?)
                                              OR (client_account_id=? AND provider_account_id=?) LIMIT 1""",
            (viewer, target, target, viewer)).fetchone()
        return bool(row)
    finally:
        conn.close()


@bp.get("/media/avatar/<account_id>")
def avatar(account_id):
    if not ACCOUNT_ID.match(account_id):
        abort(404)
    acct = accounts.get_account(account_id)
    path = safe_path(acct.get("work_photo_path", "") if acct else "", "profile_photos")
    if not path:
        abort(404)
    public = acct["role"] == "provider" and acct.get("account_status") == "active" and acct.get("setup_complete")
    viewer = g.account["account_id"] if g.get("account") else ""
    if not (public or (viewer and (viewer == account_id or _related(viewer, account_id)))):
        abort(404)
    return serve(path, "image/jpeg", "public, max-age=600" if public else "private, max-age=600")


@bp.get("/media/portfolio/<int:item_id>")
def portfolio_image(item_id):
    conn = db.get_conn()
    try:
        row = conn.execute("""SELECT p.photo_path, p.visible, p.provider_account_id, a.account_status
                              FROM portfolio p JOIN accounts a ON a.account_id=p.provider_account_id
                              WHERE p.item_id=?""", (item_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        abort(404)
    owner = g.get("account") and g.account["account_id"] == row["provider_account_id"]
    if not owner and not (row["visible"] and row["account_status"] == "active"):
        abort(404)
    path = safe_path(row["photo_path"], "portfolio")
    if not path:
        abort(404)
    return serve(path, "image/jpeg", "public, max-age=600" if row["visible"] else "private, no-store")


def evidence_row(evidence_id: int):
    conn = db.get_conn()
    try:
        return conn.execute("""SELECT e.file_path, e.mime_type, m.party_account_id
                               FROM dispute_evidence e JOIN admin_party_messages m ON m.message_id=e.message_id
                               WHERE e.evidence_id=?""", (evidence_id,)).fetchone()
    finally:
        conn.close()


def serve_evidence(row):
    path = safe_path(row["file_path"], "dispute_evidence") if row else None
    if not path or row["mime_type"] not in ALLOWED_MIME:
        abort(404)
    return serve(path, row["mime_type"], "private, no-store")


@bp.get("/media/evidence/<int:evidence_id>")
@login_required
def evidence(evidence_id):
    row = evidence_row(evidence_id)
    if not row or row["party_account_id"] != me():          # only the person who attached it
        abort(404)
    return serve_evidence(row)


# ------------------------------------------------------------------ profile photo
@bp.post("/settings/photo")
@login_required
def photo_set():
    security.limit("upload", me(), 20, 3600)
    with uploads.staged(request.files.get("photo"), uploads.MAX_IMAGE_BYTES) as up:
        if not up.ok:
            flash(up.error, "error")
        else:
            ok, msg = accounts.set_work_photo(me(), up.path)
            flash("Profile photo updated." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#profile")


@bp.post("/settings/photo/remove")
@login_required
def photo_remove():
    ok, msg = accounts.remove_work_photo(me())
    flash("Profile photo removed." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#profile")


# ------------------------------------------------------------------ portfolio (providers)
@bp.post("/settings/portfolio/add")
@role_required("provider")
def portfolio_add():
    security.limit("upload", me(), 20, 3600)
    with uploads.staged(request.files.get("photo"), uploads.MAX_IMAGE_BYTES) as up:
        if not up.ok:
            flash(up.error, "error")
        else:
            ok, msg = marketplace.add_portfolio_item(me(), up.path, _text("title", 60),
                                                     scam_shield.screen(_text("description", 300)).text)
            flash(msg, "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#portfolio")


@bp.post("/settings/portfolio/<int:item_id>/edit")
@role_required("provider")
def portfolio_edit(item_id):
    ok, msg = marketplace.update_portfolio_item(item_id, me(), _text("title", 60),
                                                scam_shield.screen(_text("description", 300)).text)
    flash("Saved." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#portfolio")


@bp.post("/settings/portfolio/<int:item_id>/toggle")
@role_required("provider")
def portfolio_toggle(item_id):
    ok, msg = marketplace.toggle_portfolio_visibility(item_id, me())
    flash(msg if not ok else "Visibility changed.", "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#portfolio")


@bp.post("/settings/portfolio/<int:item_id>/delete")
@role_required("provider")
def portfolio_delete(item_id):
    ok, msg = marketplace.delete_portfolio_item(item_id, me())
    flash("Photo deleted." if ok else msg, "ok" if ok else "error")
    return redirect(url_for("app.settings") + "#portfolio")
