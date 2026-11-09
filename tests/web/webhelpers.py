"""Shared helpers for the website tests."""
import re
from datetime import datetime, timedelta, timezone

from web.app import create_app

PW = "amber-falcon-river-lamp"


def make_app(isolated_database, **cfg):
    base = {"TESTING": True, "RATE_LIMITS_ENABLED": False, "SECRET_KEY": "k" * 48, "SKIP_DB_INIT": True,
            "SMS_BACKEND": "none", "SMS_ASYNC": False}
    base.update(cfg)
    return create_app(base)


def csrf_from(html):
    m = re.search(r'name="csrf_token" value="([a-f0-9]+)"', html)
    assert m, "no csrf token on page"
    return m.group(1)


def token_for(client, path="/signin"):
    return csrf_from(client.get(path).get_data(as_text=True))


def register(app, role, name, phone, family=""):
    c = app.test_client()
    tok = token_for(c, "/signup")
    r = c.post("/signup", data={"csrf_token": tok, "role": role, "full_name": name, "phone": phone, "email": "",
                                "service_family": family, "password": PW, "password_confirm": PW, "terms": "1"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/complete-profile"), r.get_data(as_text=True)[:400]
    tok = token_for(c, "/complete-profile")
    r = c.post("/complete-profile", data={"csrf_token": tok, "display_name": name.split()[0], "area": "Westlands",
                                          "bio": "I do good work."})
    assert r.status_code == 302
    return c


def post(client, path, page, **data):
    """POST with a valid CSRF token taken from `page`."""
    data["csrf_token"] = token_for(client, page)
    return client.post(path, data=data)


def sign_in(app, phone):
    c = app.test_client()
    r = c.post("/signin", data={"csrf_token": token_for(c), "phone": phone, "password": PW})
    assert r.status_code == 302, r.get_data(as_text=True)[:300]
    return c


def setup_marketplace(app):
    client = register(app, "client", "Ann Mwangi", "0712345601")
    provider = register(app, "provider", "Ben Otieno", "0712345602", "home")
    r = post(provider, "/settings/services/add", "/settings", category="Plumbing", title="Leak repairs",
             rate_text="From KSh 1,500", description="Pipes and taps")
    assert r.status_code == 302
    return client, provider


def provider_id(isolated_database):
    conn = isolated_database.get_conn()
    try:
        return conn.execute("SELECT account_id FROM accounts WHERE role='provider'").fetchone()[0]
    finally:
        conn.close()


def make_job(app, isolated_database, client, provider):
    pid = provider_id(isolated_database)
    r = post(client, "/request/new", f"/request/new?provider={pid}", provider=pid, category="Plumbing", area="Westlands",
             description="Kitchen tap is leaking badly, please fix it", preferred_time="Tomorrow")
    assert r.status_code == 302
    conn = isolated_database.get_conn()
    try:
        rid = conn.execute("SELECT request_id FROM service_requests").fetchone()[0]
    finally:
        conn.close()
    r = post(provider, f"/requests/{rid}/accept", "/requests/available")
    assert r.status_code == 302 and "/jobs/" in r.headers["Location"], r.headers.get("Location")
    return int(r.headers["Location"].rsplit("/", 1)[1])


