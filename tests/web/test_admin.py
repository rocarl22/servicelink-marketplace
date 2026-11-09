"""Admin console: two-step sign-in, authorization, re-authentication, disputes and reports."""
import html as htmllib
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
import webhelpers as H                                       # noqa: E402
from backend import database as dbmod                        # noqa: E402
from backend.services import accounts, admin                 # noqa: E402
from web import admin_cli, totp                              # noqa: E402

ADMIN_PW = "violet-harbor-lantern-42"


def mk_admin(role="admin", username="owner"):
    if role == "admin":
        ok, msg = admin.create_initial_admin(username, ADMIN_PW, ADMIN_PW)
        assert ok, msg
        return
    conn = dbmod.get_conn()
    conn.execute("INSERT INTO admin_users(admin_id, username, password_hash, role, active, created_at) VALUES(?,?,?,?,1,?)",
                 ("A-SUPPORT001", username, accounts._hash_password(ADMIN_PW), role, "2026-01-01T00:00:00+00:00"))
    conn.commit(); conn.close()


def step_now(offset=0):
    return int(time.time() // 30) + offset


def code(secret, offset=0):
    return totp._code_for_step(secret, step_now(offset))


def pending_secret():
    conn = dbmod.get_conn()
    try:
        return conn.execute("SELECT pending_totp FROM web_admin_sessions WHERE revoked_at='' ORDER BY created_at DESC").fetchone()[0]
    finally:
        conn.close()


def stored_secret(username="owner"):
    conn = dbmod.get_conn()
    try:
        return conn.execute("SELECT totp_secret FROM admin_users WHERE username=?", (username,)).fetchone()[0]
    finally:
        conn.close()


def password_step(app, username="owner", password=ADMIN_PW):
    c = app.test_client()
    r = c.post("/admin/signin", data={"csrf_token": H.csrf_from(c.get("/admin/signin").get_data(as_text=True)),
                                      "username": username, "password": password})
    return c, r


def enrolled_admin_client(app, username="owner"):
    """Full sign-in including first-time authenticator enrolment."""
    c, r = password_step(app, username)
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin/mfa/setup"), r.headers.get("Location")
    page = c.get("/admin/mfa/setup").get_data(as_text=True)
    secret = pending_secret()
    assert totp.group(secret) in page
    r = c.post("/admin/mfa/setup", data={"csrf_token": H.csrf_from(page), "code": code(secret)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin/"), r.headers.get("Location")
    return c, secret


def mfa_login(app, secret, offset=1, username="owner"):
    c, r = password_step(app, username)
    assert r.headers["Location"].endswith("/admin/mfa")
    tok = H.csrf_from(c.get("/admin/mfa").get_data(as_text=True))
    return c, c.post("/admin/mfa", data={"csrf_token": tok, "code": code(secret, offset)}), tok


def apost(c, path, page, **data):
    data["csrf_token"] = H.csrf_from(c.get(page).get_data(as_text=True))
    return c.post(path, data=data)


# ------------------------------------------------------------------ sign-in
def test_admin_area_is_closed_until_fully_signed_in(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c = app.test_client()
    for path in ("/admin/", "/admin/accounts", "/admin/disputes", "/admin/reports", "/admin/audit", "/admin/me"):
        r = c.get(path)
        assert r.status_code == 302 and r.headers["Location"].endswith("/admin/signin"), path
    r = c.get("/admin/signin")
    assert r.status_code == 200 and "noindex" in r.headers["X-Robots-Tag"]
    assert "unsafe-inline" not in r.headers["Content-Security-Policy"]


def test_password_alone_grants_nothing(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c, r = password_step(app)
    assert r.status_code == 302
    cookie = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("sl_admin=")][0]
    assert "Path=/admin" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    for path in ("/admin/", "/admin/accounts", "/admin/audit", "/admin/me", "/admin/disputes"):
        r = c.get(path)
        assert r.status_code == 302 and r.headers["Location"].endswith("/admin/signin"), path
    assert c.get("/admin/mfa/setup").status_code == 200          # only the enrolment page is reachable


def test_enrolment_then_login_with_authenticator_code(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c, secret = enrolled_admin_client(app)
    assert stored_secret() == secret
    page = c.get("/admin/").get_data(as_text=True)
    assert "Overview" in page and "Open disputes" in page
    c2, r, _ = mfa_login(app, secret)
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin/")
    assert c2.get("/admin/accounts").status_code == 200


def test_wrong_codes_replays_and_lockout(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c, secret = enrolled_admin_client(app)
    c.post("/admin/signout", data={"csrf_token": H.csrf_from(c.get("/admin/me").get_data(as_text=True))})
    # replay: the code used at enrolment (current step) must never work again
    c2, r = password_step(app)
    tok = H.csrf_from(c2.get("/admin/mfa").get_data(as_text=True))
    assert c2.post("/admin/mfa", data={"csrf_token": tok, "code": code(secret, 0)}).headers["Location"].endswith("/admin/mfa")
    assert c2.get("/admin/").status_code == 302
    # five wrong codes in total kills the pending session
    for _ in range(4):
        r = c2.post("/admin/mfa", data={"csrf_token": H.csrf_from(c2.get("/admin/mfa").get_data(as_text=True)), "code": "000000"})
    assert r.headers["Location"].endswith("/admin/signin")
    assert c2.get("/admin/mfa").status_code == 302                  # pending session is gone
    # a fresh sign-in with a valid next-step code still works, and that code cannot be reused
    c3, r, tok3 = mfa_login(app, secret, offset=1)
    assert r.headers["Location"].endswith("/admin/")
    c3.post("/admin/signout", data={"csrf_token": tok3})
    c4, r4 = password_step(app)
    r4 = c4.post("/admin/mfa", data={"csrf_token": H.csrf_from(c4.get("/admin/mfa").get_data(as_text=True)), "code": code(secret, 1)})
    assert r4.headers["Location"].endswith("/admin/mfa")


def test_pending_session_expires_after_five_minutes(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c, _ = password_step(app)
    old = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(timespec="seconds")
    conn = dbmod.get_conn(); conn.execute("UPDATE web_admin_sessions SET last_seen_at=?", (old,)); conn.commit(); conn.close()
    assert c.get("/admin/mfa/setup").status_code == 302


def test_wrong_password_and_unknown_user_look_the_same(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    a = password_step(app, "owner", "wrong-password-here!")[1]
    b = password_step(app, "nobody", "wrong-password-here!")[1]
    assert a.status_code == b.status_code == 200 and "incorrect" in a.get_data(as_text=True) and "incorrect" in b.get_data(as_text=True)


def test_admin_idle_and_absolute_expiry(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c, _ = enrolled_admin_client(app)
    old = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat(timespec="seconds")
    conn = dbmod.get_conn(); conn.execute("UPDATE web_admin_sessions SET last_seen_at=? WHERE stage='full'", (old,)); conn.commit(); conn.close()
    assert c.get("/admin/").status_code == 302


def test_user_sessions_and_admin_sessions_do_not_mix(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    client = H.register(app, "client", "Ann Mwangi", "0712345601")
    assert client.get("/admin/").status_code == 302 and client.get("/admin/accounts").status_code == 302
    adm, _ = enrolled_admin_client(app)
    assert adm.get("/dashboard").status_code == 302                 # an admin is not automatically a site user


def test_ip_allow_list_hides_the_console(isolated_database):
    app = H.make_app(isolated_database, ADMIN_ALLOWED_IPS=["10.0.0.0/8"])
    mk_admin()
    c = app.test_client()
    assert c.get("/admin/signin").status_code == 404
    assert c.post("/admin/signin", data={}).status_code == 404
    assert c.get("/admin/signin", environ_overrides={"REMOTE_ADDR": "10.1.2.3"}).status_code == 200
    assert c.get("/admin/signin", environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
                 headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 200


def test_admin_sign_in_is_rate_limited(isolated_database):
    app = H.make_app(isolated_database, RATE_LIMITS_ENABLED=True)
    mk_admin()
    codes = [password_step(app, "owner", "wrong-password-here!")[1].status_code for _ in range(14)]
    assert 429 in codes


# ------------------------------------------------------------------ CSRF / re-auth / roles
def test_admin_csrf_is_bound_to_the_admin_session(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c, _ = enrolled_admin_client(app)
    assert c.post("/admin/signout", data={}).status_code == 403
    anon_token = H.csrf_from(app.test_client().get("/signin").get_data(as_text=True))         # token from another context
    assert c.post("/admin/signout", data={"csrf_token": anon_token}).status_code == 403
    assert c.post("/admin/signout", data={"csrf_token": H.csrf_from(c.get("/admin/me").get_data(as_text=True))},
                  headers={"Origin": "https://evil.example"}).status_code == 403


def test_status_change_needs_password_reason_and_is_audited(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    user = H.register(app, "client", "Ann Mwangi", "0712345601")
    conn = dbmod.get_conn(); uid = conn.execute("SELECT account_id FROM accounts").fetchone()[0]; conn.close()
    c, _ = enrolled_admin_client(app)
    page = f"/admin/accounts/{uid}"
    assert "Change status" in c.get(page).get_data(as_text=True)
    apost(c, f"{page}/status", page, new_status="restricted", reason="Repeated complaints from providers", admin_password="wrong-password!")
    assert admin.get_account_detail(uid)["account_status"] == "active"                       # wrong password: nothing changed
    apost(c, f"{page}/status", page, new_status="restricted", reason="short", admin_password=ADMIN_PW)
    assert admin.get_account_detail(uid)["account_status"] == "active"                       # reason too short
    apost(c, f"{page}/status", page, new_status="restricted", reason="Repeated complaints from providers", admin_password=ADMIN_PW)
    assert admin.get_account_detail(uid)["account_status"] == "restricted"
    audit = c.get("/admin/audit").get_data(as_text=True)
    assert "restricted" in audit and "Repeated complaints" in audit
    assert c.get("/admin/accounts?q=Ann").status_code == 200 and c.get("/admin/accounts/not-an-id").status_code == 404


def test_password_reset_is_shown_once_and_works(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    H.register(app, "client", "Ann Mwangi", "0712345601")
    conn = dbmod.get_conn(); uid = conn.execute("SELECT account_id FROM accounts").fetchone()[0]; conn.close()
    c, _ = enrolled_admin_client(app)
    page = f"/admin/accounts/{uid}"
    r = apost(c, f"{page}/reset-password", page, reason="Identity checked by phone call", admin_password="wrong-password!")
    assert r.status_code == 302 and "Temporary password" not in r.get_data(as_text=True)
    r = apost(c, f"{page}/reset-password", page, reason="Identity checked by phone call", admin_password=ADMIN_PW)
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    temp = htmllib.unescape(re.search(r'class="keybox">([^<]+)<', html).group(1))    # the page escapes & < > for HTML
    u = H.make_app(isolated_database).test_client()
    ok = u.post("/signin", data={"csrf_token": H.token_for(u), "phone": "0712345601", "password": temp})
    assert ok.status_code == 302 and ok.headers["Location"] == "/dashboard"
    u2 = app.test_client()
    assert u2.post("/signin", data={"csrf_token": H.token_for(u2), "phone": "0712345601", "password": H.PW}).status_code == 200   # old password dead


def test_support_role_can_look_but_not_change(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin("support", "helper")
    H.register(app, "client", "Ann Mwangi", "0712345601")
    conn = dbmod.get_conn(); uid = conn.execute("SELECT account_id FROM accounts").fetchone()[0]; conn.close()
    c, _ = enrolled_admin_client(app, "helper")
    page = f"/admin/accounts/{uid}"
    html = c.get(page).get_data(as_text=True)
    assert "not change them" in html and "Create temporary password" not in html
    assert apost(c, f"{page}/status", "/admin/me", new_status="suspended", reason="Trying to suspend", admin_password=ADMIN_PW).status_code == 403
    assert apost(c, f"{page}/reset-password", "/admin/me", reason="Trying to reset it", admin_password=ADMIN_PW).status_code == 403
    assert admin.get_account_detail(uid)["account_status"] == "active"


def test_changing_admin_password_ends_all_admin_sessions(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    c, secret = enrolled_admin_client(app)
    other, _, _ = mfa_login(app, secret)
    new = "copper-meadow-violin-99"
    r = apost(c, "/admin/me/password", "/admin/me", current_password=ADMIN_PW, new_password=new, confirm_password=new)
    assert r.status_code == 302 and c.get("/admin/").status_code == 302 and other.get("/admin/").status_code == 302


# ------------------------------------------------------------------ user safety -> admin workflow
def start_dispute(app, isolated_database):
    client, provider = H.setup_marketplace(app)
    job = H.make_job(app, isolated_database, client, provider)
    H.post(provider, f"/jobs/{job}/advance", f"/jobs/{job}", action="dispatched")
    H.post(provider, f"/jobs/{job}/advance", f"/jobs/{job}", action="arrived")
    cat = dbmod.INCIDENT_TYPES_CLIENT[0]
    r = H.post(client, f"/jobs/{job}/dispute", f"/jobs/{job}", category=cat,
               description="The provider arrived but refused to fix the pipe <script>alert(1)</script> properly.")
    assert r.status_code == 302
    return client, provider, job


def test_dispute_workflow_end_to_end(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    client, provider, job = start_dispute(app, isolated_database)
    c, _ = enrolled_admin_client(app)
    listing = c.get("/admin/disputes").get_data(as_text=True)
    assert "Provider didn" in listing or "didn&#39;t" in listing
    did = int(re.search(r"/admin/disputes/(\d+)", listing).group(1))
    detail = c.get(f"/admin/disputes/{did}").get_data(as_text=True)
    assert "&lt;script&gt;" in detail and "<script>alert" not in detail                   # user text escaped for admins too
    assert not re.search(r"\sstyle=|\sonclick=|<script(?![^>]*\bsrc=)", detail)
    apost(c, f"/admin/disputes/{did}/message", f"/admin/disputes/{did}", body="Please say what was left unfinished.", kind="question", target="both")
    assert "unfinished" in client.get("/disputes").get_data(as_text=True)
    assert "unfinished" in provider.get("/disputes").get_data(as_text=True)
    H.post(client, f"/disputes/{did}/reply", "/disputes", body="The tap is still leaking, nothing was fixed.")
    assert "still leaking" in c.get(f"/admin/disputes/{did}").get_data(as_text=True)
    # strangers cannot reply into someone else's dispute
    intruder = H.register(app, "client", "Mallory Kip", "0712345609")
    before = dbmod.get_conn().execute("SELECT COUNT(*) FROM admin_party_messages").fetchone()[0]
    H.post(intruder, f"/disputes/{did}/reply", "/settings", body="I am not part of this dispute")
    assert dbmod.get_conn().execute("SELECT COUNT(*) FROM admin_party_messages").fetchone()[0] == before
    assert "not part of" not in c.get(f"/admin/disputes/{did}").get_data(as_text=True)
    # resolving needs the password and the full admin role
    page = f"/admin/disputes/{did}"
    apost(c, f"{page}/resolve", page, outcome="cancel", reason="Provider did not complete the work", admin_password="nope-nope-nope")
    assert "Open disputes" in c.get("/admin/disputes").get_data(as_text=True) and f"/admin/disputes/{did}" in c.get("/admin/disputes").get_data(as_text=True)
    apost(c, f"{page}/resolve", page, outcome="cancel", reason="Provider did not complete the work", admin_password=ADMIN_PW)
    assert f"/admin/disputes/{did}" not in c.get("/admin/disputes").get_data(as_text=True)
    assert "Cancelled" in client.get(f"/jobs/{job}").get_data(as_text=True)
    assert "Provider did not complete the work" in client.get("/disputes").get_data(as_text=True)


def test_dispute_category_is_validated(isolated_database):
    app = H.make_app(isolated_database)
    client, provider = H.setup_marketplace(app)
    job = H.make_job(app, isolated_database, client, provider)
    r = H.post(client, f"/jobs/{job}/dispute", f"/jobs/{job}", category="Made-up reason", description="x" * 40)
    assert r.status_code == 400


def test_block_user_creates_a_report_the_admin_can_dismiss(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    client, provider = H.setup_marketplace(app)
    job = H.make_job(app, isolated_database, client, provider)
    assert H.post(client, f"/jobs/{job}/block", f"/jobs/{job}", reason="Rude and unprofessional during the visit").status_code == 302
    assert "Ben" in client.get("/settings").get_data(as_text=True) and "Rude and unprofessional" in client.get("/settings").get_data(as_text=True)
    c, _ = enrolled_admin_client(app)
    reports = c.get("/admin/reports").get_data(as_text=True)
    rid = int(re.search(r"/admin/reports/(\d+)/dismiss", reports).group(1))
    apost(c, f"/admin/reports/{rid}/dismiss", "/admin/reports", reason="Reviewed, no further action needed")
    assert f"/admin/reports/{rid}/dismiss" not in c.get("/admin/reports").get_data(as_text=True)
    pid = H.provider_id(isolated_database)
    H.post(client, "/settings/blocked/unblock", "/settings", account_id=pid)
    assert "You haven&#39;t blocked anyone" in client.get("/settings").get_data(as_text=True) or "haven't blocked anyone" in client.get("/settings").get_data(as_text=True)


def test_admin_pages_have_no_inline_scripts_or_styles(isolated_database):
    app = H.make_app(isolated_database)
    mk_admin()
    H.register(app, "client", "Ann Mwangi", "0712345601")
    conn = dbmod.get_conn(); uid = conn.execute("SELECT account_id FROM accounts").fetchone()[0]; conn.close()
    c, _ = enrolled_admin_client(app)
    for path in ("/admin/", "/admin/accounts", f"/admin/accounts/{uid}", "/admin/disputes", "/admin/reports", "/admin/audit", "/admin/me"):
        html = c.get(path).get_data(as_text=True)
        assert c.get(path).status_code == 200, path
        assert not re.search(r"<script(?![^>]*\bsrc=)", html) and not re.search(r"\sstyle=|\sonclick=", html), path


# ------------------------------------------------------------------ TOTP + CLI
def test_totp_matches_the_rfc_6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                 # ASCII "12345678901234567890"
    assert totp._code_for_step(secret, 59 // 30) == "287082"
    assert totp.verify(secret, "287082", 0, now=59) == 1
    assert totp.verify(secret, "287082", 1, now=59) is None       # replay refused
    assert totp.verify(secret, "28 70 82", 0, now=59) == 1       # spaces tolerated
    assert totp.verify(secret, "12345", 0, now=59) is None and totp.verify(secret, "abcdef", 0, now=59) is None
    assert totp.verify(secret, "287082", 0, now=59 + 120) is None   # outside the +/-1 step window


def test_cli_create_list_and_reset(isolated_database, monkeypatch):
    import getpass
    monkeypatch.setattr("builtins.input", lambda prompt="": "boss")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": ADMIN_PW)
    assert admin_cli.main(["create-admin"]) == 0
    assert admin_cli.main(["create-admin"]) == 1                    # only one initial admin
    app = H.make_app(isolated_database)
    c, secret = enrolled_admin_client(app, "boss")
    assert c.get("/admin/").status_code == 200
    assert admin_cli.main(["reset-mfa", "boss"]) == 0
    assert c.get("/admin/").status_code == 302                      # sessions ended
    assert stored_secret("boss") == ""
    _, r = password_step(app, "boss")
    assert r.headers["Location"].endswith("/admin/mfa/setup")        # must enrol again
    assert admin_cli.main(["reset-mfa", "nobody"]) == 1 and admin_cli.main(["list"]) == 0 and admin_cli.main([]) == 2
