"""Public pages: landing, provider browsing, provider profile, health, safety."""
import re

from flask import Blueprint, abort, g, jsonify, render_template, request

from backend import database as db
from backend.services import accounts, categories, marketplace
from backend.services.validation import clean_text

bp = Blueprint("public", __name__)

PROVIDER_ID = re.compile(r"^P-[A-F0-9]{10}$")


def annotate_verified(providers):
    ids = accounts.verified_ids([p["account_id"] for p in providers])
    for p in providers:
        p["verified"] = p["account_id"] in ids
    return providers


def _family_keys():
    return {k for k, _ in categories.SERVICE_FAMILIES}


@bp.get("/")
def landing():
    viewer = g.account["account_id"] if g.get("account") else ""
    featured = annotate_verified(marketplace.list_providers(limit=6, caller_account_id=viewer))
    return render_template("landing.html", featured=featured, families=categories.SERVICE_FAMILIES,
                           categories=categories.CATEGORIES)


@bp.get("/providers")
def providers():
    family = request.args.get("family", "")
    area = request.args.get("area", "")
    q = clean_text(request.args.get("q", "")).strip()[:60]
    family = family if family in _family_keys() else ""
    area = area if area in categories.OPERATING_AREAS else ""
    viewer = g.account["account_id"] if g.get("account") else ""
    results = annotate_verified(marketplace.list_providers(family=family, area=area, search=q, limit=60, caller_account_id=viewer))
    return render_template("providers.html", providers=results, family=family, area=area, q=q,
                           families=categories.SERVICE_FAMILIES, areas=categories.OPERATING_AREAS)


@bp.get("/providers/<provider_id>")
def provider_detail(provider_id):
    if not PROVIDER_ID.match(provider_id):
        abort(404)
    profile = marketplace.get_provider_profile(provider_id)
    if not profile or not profile.get("setup_complete") or profile.get("account_status") != "active":
        abort(404)
    profile.pop("phone", None)            # contact details stay on-platform
    profile["verified"] = bool(accounts.verified_ids([provider_id]))
    saved = False
    if g.get("account") and g.account["role"] == "client":
        saved = marketplace.is_saved(g.account["account_id"], provider_id)
    return render_template("provider_detail.html", p=profile, saved=saved,
                           portfolio=marketplace.portfolio_for_provider(provider_id))


@bp.get("/safety")
def safety():
    return render_template("safety.html")


@bp.get("/legal")
def legal():
    return render_template("legal.html")


@bp.get("/healthz")
def healthz():
    conn = db.get_conn()
    try:
        conn.execute("SELECT 1").fetchone()
    finally:
        conn.close()
    return jsonify(status="ok")
