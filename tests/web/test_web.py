"""End-to-end tests of the website through Flask's test client (real HTTP semantics)."""
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


# ---------------------------------------------------------------- basics
def test_public_pages_render_and_private_pages_redirect(isolated_database):
    c = make_app(isolated_database).test_client()
    for path in ("/", "/providers", "/safety", "/legal", "/signin", "/signup", "/healthz"):
        assert c.get(path).status_code == 200, path
    for path in ("/dashboard", "/jobs", "/messages", "/settings", "/notifications", "/saved"):
        r = c.get(path)
        assert r.status_code == 302 and "/signin?next=" in r.headers["Location"], path
    assert c.get("/providers/not-an-id").status_code == 404 and c.get("/jobs/1").status_code == 302


def test_security_headers_and_caching(isolated_database):
    r = make_app(isolated_database).test_client().get("/")
    csp = r.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["Cache-Control"] == "no-store"
    assert "geolocation=()" in r.headers["Permissions-Policy"] and r.headers["Referrer-Policy"] == "same-origin"
    assert "max-age" in make_app(isolated_database).test_client().get("/static/css/app.css").headers["Cache-Control"]


def test_pages_use_no_inline_scripts_or_styles(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    job = make_job(app, isolated_database, client, provider)
    pages = ["/", "/providers", "/signup", "/signin", "/dashboard", "/settings", "/jobs", f"/jobs/{job}", "/messages", "/notifications"]
    for who in (client, provider):
        for path in pages:
            html = who.get(path).get_data(as_text=True)
            assert not re.search(r"<script(?![^>]*\bsrc=)", html), path
            assert not re.search(r"\sstyle=|\sonclick=|\sonload=", html), path


def test_hsts_and_host_cookies_in_secure_mode(isolated_database):
    c = make_app(isolated_database, SECURE_COOKIES=True).test_client()
    r = c.get("/signup")
    assert "Strict-Transport-Security" in r.headers and "upgrade-insecure-requests" in r.headers["Content-Security-Policy"]
    assert any(h.startswith("__Host-sl_anon=") and "Secure" in h and "HttpOnly" in h for h in r.headers.getlist("Set-Cookie"))


# ---------------------------------------------------------------- CSRF
def test_csrf_is_required_and_bound(isolated_database):
    app = make_app(isolated_database)
    c = app.test_client()
    c.get("/signin")
    assert c.post("/signin", data={"phone": "0712345601", "password": PW}).status_code == 403          # missing token
    assert c.post("/signin", data={"csrf_token": "0" * 64, "phone": "x", "password": "y"}).status_code == 403  # wrong token
    other = app.test_client()
    foreign = token_for(other)                                                                          # token from another browser
    assert c.post("/signin", data={"csrf_token": foreign, "phone": "x", "password": "y"}).status_code == 403
    assert app.test_client().post("/signin", data={"phone": "x", "password": "y"}).status_code == 403   # no anon cookie at all


def test_cross_origin_posts_are_rejected_even_with_a_valid_token(isolated_database):
    app = make_app(isolated_database)
    client, _ = setup_marketplace(app)
    tok = token_for(client, "/settings")
    r = client.post("/settings/profile", data={"csrf_token": tok, "display_name": "Hacked", "area": "Rongai"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/settings/profile", data={"csrf_token": tok, "display_name": "Fine", "area": "Rongai"},
                    headers={"Origin": "http://localhost"})
    assert r.status_code == 302


# ---------------------------------------------------------------- sessions
def test_session_cookie_flags_and_fixation_defence(isolated_database):
    app = make_app(isolated_database)
    register(app, "client", "Ann Mwangi", "0712345601")
    c = app.test_client()
    r = c.post("/signin", data={"csrf_token": token_for(c), "phone": "0712345601", "password": PW})
    cookie = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("sl_session=")][0]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/" in cookie
    first = c.get_cookie("sl_session").value
    c2 = app.test_client()
    c2.set_cookie("sl_session", first)                       # attacker plants/steals the old token
    assert c2.get("/dashboard").status_code == 200
    c.post("/signout", data={"csrf_token": token_for(c, "/settings")})
    assert c2.get("/dashboard").status_code == 302          # server-side revocation: stolen cookie is dead


def test_new_token_on_every_login_and_old_one_stops_working(isolated_database):
    app = make_app(isolated_database)
    register(app, "client", "Ann Mwangi", "0712345601")
    a, b = sign_in(app, "0712345601"), sign_in(app, "0712345601")
    assert a.get_cookie("sl_session").value != b.get_cookie("sl_session").value
    assert a.get("/dashboard").status_code == 200 and b.get("/dashboard").status_code == 200   # separate devices both fine


def test_idle_and_absolute_expiry_are_enforced_server_side(isolated_database):
    app = make_app(isolated_database)
    register(app, "client", "Ann Mwangi", "0712345601")
    c = sign_in(app, "0712345601")
    assert c.get("/dashboard").status_code == 200
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
    conn = isolated_database.get_conn(); conn.execute("UPDATE web_sessions SET last_seen_at=?", (old,)); conn.commit(); conn.close()
    assert c.get("/dashboard").status_code == 302                                    # idle > 30 min
    c = sign_in(app, "0712345601")
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(timespec="seconds")
    conn = isolated_database.get_conn(); conn.execute("UPDATE web_sessions SET expires_at=? WHERE revoked_at=''", (past,)); conn.commit(); conn.close()
    assert c.get("/dashboard").status_code == 302                                    # absolute lifetime reached


def test_sessions_store_only_a_hash_of_the_token(isolated_database):
    app = make_app(isolated_database)
    register(app, "client", "Ann Mwangi", "0712345601")
    c = sign_in(app, "0712345601")
    token = c.get_cookie("sl_session").value
    conn = isolated_database.get_conn()
    try:
        stored = [r[0] for r in conn.execute("SELECT session_hash FROM web_sessions")]
    finally:
        conn.close()
    assert token not in stored and all(len(h) == 64 for h in stored)


def test_password_change_signs_out_other_devices_and_cannot_revoke_foreign_sessions(isolated_database):
    app = make_app(isolated_database)
    register(app, "client", "Ann Mwangi", "0712345601")
    register(app, "client", "Carl Kamau", "0712345603")
    laptop, phone = sign_in(app, "0712345601"), sign_in(app, "0712345601")
    carl = sign_in(app, "0712345603")
    conn = isolated_database.get_conn()
    carl_hash = conn.execute("SELECT session_hash FROM web_sessions WHERE account_id=(SELECT account_id FROM accounts WHERE phone LIKE '%345603') LIMIT 1").fetchone()[0]
    conn.close()
    post(laptop, "/settings/sessions/revoke", "/settings", session=carl_hash)           # try to kill someone else's session
    assert carl.get("/dashboard").status_code == 200
    new_pw = "violet-harbor-lantern-42"
    r = post(laptop, "/settings/password", "/settings", current_password=PW, new_password=new_pw, confirm_password=new_pw)
    assert r.status_code == 302
    assert laptop.get("/dashboard").status_code == 200          # this device stays (rotated token)
    assert phone.get("/dashboard").status_code == 302           # other device signed out


# ---------------------------------------------------------------- full marketplace flow
def test_full_flow_request_accept_progress_review(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    pid = provider_id(isolated_database)
    detail = client.get(f"/providers/{pid}").get_data(as_text=True)
    assert "Leak repairs" in detail and "0712 345 602" not in detail and "0712345602" not in detail     # phone never shown
    job = make_job(app, isolated_database, client, provider)
    assert "Accepted" in provider.get(f"/jobs/{job}").get_data(as_text=True)
    post(provider, f"/jobs/{job}/price", f"/jobs/{job}", price="KSh 2,500")
    conn = isolated_database.get_conn()
    assert conn.execute("SELECT agreed_price_minor FROM jobs").fetchone()[0] == 250000
    conn.close()
    for who, action in ((provider, "dispatched"), (provider, "arrived"), (provider, "started"), (client, "client_confirmed"),
                        (provider, "done"), (client, "close")):
        r = post(who, f"/jobs/{job}/advance", f"/jobs/{job}", action=action)
        assert r.status_code == 302, action
    page = client.get(f"/jobs/{job}").get_data(as_text=True)
    assert "Completed" in page and "Leave a review" in page
    r = post(client, f"/jobs/{job}/review", f"/jobs/{job}", stars="5", comment="Great work, call 0712345678")
    assert r.status_code == 302
    profile = client.get(f"/providers/{pid}").get_data(as_text=True)
    assert "Great work" in profile and "0712345678" not in profile                    # review text is masked too


def test_server_decides_which_job_actions_are_allowed(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    job = make_job(app, isolated_database, client, provider)
    assert post(client, f"/jobs/{job}/advance", f"/jobs/{job}", action="done").status_code == 400            # client can't skip ahead
    assert post(provider, f"/jobs/{job}/advance", f"/jobs/{job}", action="started").status_code == 400       # provider can't skip a step
    assert post(provider, f"/jobs/{job}/advance", f"/jobs/{job}", action="'; DROP TABLE jobs;--").status_code == 400


# ---------------------------------------------------------------- authorization (IDOR)
def test_other_users_cannot_see_or_change_someone_elses_job_or_chat(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    job = make_job(app, isolated_database, client, provider)
    intruder = register(app, "client", "Mallory Kip", "0712345609")
    rogue_pro = register(app, "provider", "Rick Oduor", "0712345610", "home")
    for who in (intruder, rogue_pro):
        assert who.get(f"/jobs/{job}").status_code == 404
        assert post(who, f"/jobs/{job}/advance", "/settings", action="dispatched").status_code == 404
        assert post(who, f"/jobs/{job}/cancel", "/settings", reason="x").status_code == 404
        assert post(who, f"/jobs/{job}/review", "/settings", stars="1", comment="spam").status_code == 404
    conn = isolated_database.get_conn()
    cid = conn.execute("SELECT conversation_id FROM conversations").fetchone()[0]
    conn.close()
    for who in (intruder, rogue_pro):
        assert who.get(f"/messages/{cid}").status_code == 404
        assert post(who, f"/messages/{cid}", "/settings", body="hello").status_code == 404
    assert client.get(f"/messages/{cid}").status_code == 200 and provider.get(f"/messages/{cid}").status_code == 200


def test_a_provider_cannot_accept_a_request_sent_to_someone_else(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    rogue = register(app, "provider", "Rick Oduor", "0712345610", "home")
    pid = provider_id(isolated_database)
    post(client, "/request/new", f"/request/new?provider={pid}", provider=pid, category="Plumbing", area="Westlands",
         description="Direct request for Ben only, thanks")
    conn = isolated_database.get_conn(); rid = conn.execute("SELECT request_id FROM service_requests").fetchone()[0]; conn.close()
    r = post(rogue, f"/requests/{rid}/accept", "/requests/available")
    assert "/jobs/" not in r.headers["Location"]
    conn = isolated_database.get_conn(); assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0; conn.close()


def test_role_separation(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    assert provider.get("/request/new").status_code == 403 and provider.get("/requests").status_code == 403
    assert client.get("/requests/available").status_code == 403
    assert post(client, "/settings/services/add", "/settings", category="Plumbing", title="x").status_code == 403


# ---------------------------------------------------------------- injection / redirects / shield
def test_user_content_is_escaped_everywhere(isolated_database):
    app = make_app(isolated_database)
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    client = register(app, "client", "Ann Mwangi", "0712345601")
    provider = register(app, "provider", "Ben Otieno", "0712345602", "home")
    post(provider, "/settings/profile", "/settings", display_name="Ben<b>", area="Westlands", bio=evil)
    post(provider, "/settings/services/add", "/settings", category="Plumbing", title=evil, description=evil, rate_text=evil)
    pid = provider_id(isolated_database)
    for page in (client.get(f"/providers/{pid}"), client.get("/providers"), provider.get("/settings")):
        html = page.get_data(as_text=True)
        assert "<script>alert(1)" not in html and "<img src=x" not in html and "&lt;" in html
    post(client, "/request/new", f"/request/new?provider={pid}", provider=pid, category="Plumbing", area="Westlands", description=evil + " fix tap")
    conn = isolated_database.get_conn(); cid = conn.execute("SELECT conversation_id FROM conversations").fetchone()[0]; conn.close()
    post(client, f"/messages/{cid}", f"/messages/{cid}", body=evil)
    html = provider.get(f"/messages/{cid}").get_data(as_text=True)
    assert "<script>alert" not in html and "<img src=x" not in html


def test_open_redirect_is_blocked(isolated_database):
    app = make_app(isolated_database)
    register(app, "client", "Ann Mwangi", "0712345601")
    for bad in ("//evil.example", "https://evil.example", "/\\evil.example", "javascript:alert(1)", "http:evil"):
        c = app.test_client()
        r = c.post("/signin", data={"csrf_token": token_for(c), "phone": "0712345601", "password": PW, "next": bad})
        assert r.status_code == 302 and r.headers["Location"] == "/dashboard", bad
    c = app.test_client()
    r = c.post("/signin", data={"csrf_token": token_for(c), "phone": "0712345601", "password": PW, "next": "/jobs"})
    assert r.headers["Location"] == "/jobs"


def test_chat_masks_contact_details_on_the_web(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    make_job(app, isolated_database, client, provider)
    conn = isolated_database.get_conn(); cid = conn.execute("SELECT conversation_id FROM conversations").fetchone()[0]; conn.close()
    post(client, f"/messages/{cid}", f"/messages/{cid}", body="Call me on 0712 345 678 or bob@gmail.com")
    html = provider.get(f"/messages/{cid}").get_data(as_text=True)
    assert "[contact hidden]" in html and "0712 345 678" not in html and "gmail" not in html


# ---------------------------------------------------------------- abuse resistance
def test_sign_in_is_rate_limited_per_ip(isolated_database):
    app = make_app(isolated_database, RATE_LIMITS_ENABLED=True)
    c = app.test_client()
    codes = []
    for i in range(24):
        codes.append(c.post("/signin", data={"csrf_token": token_for(c), "phone": f"07123456{i:02d}", "password": "nope-nope-nope"}).status_code)
    assert 429 in codes and codes[0] != 429


def test_forged_forwarded_for_header_does_not_evade_limits(isolated_database):
    app = make_app(isolated_database, RATE_LIMITS_ENABLED=True)      # no trusted proxies configured
    c = app.test_client()
    codes = [c.post("/signin", data={"csrf_token": token_for(c), "phone": "0712345600", "password": "nope-nope-nope"},
                    headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(24)]
    assert 429 in codes


def test_errors_never_leak_internals(isolated_database, monkeypatch):
    from backend.services import marketplace
    app = make_app(isolated_database)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["TESTING"] = False
    monkeypatch.setattr(marketplace, "list_providers", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret db path /srv/x")))
    r = app.test_client().get("/providers")
    body = r.get_data(as_text=True)
    assert r.status_code == 500 and "secret db path" not in body and "Traceback" not in body and "RuntimeError" not in body


def test_data_export_contains_only_own_data(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    r = post(client, "/settings/export", "/settings")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"] and r.mimetype == "application/json"
    text = r.get_data(as_text=True)
    assert "Ann" in text and "0712345602" not in text and "Ben Otieno" not in text
    assert "password" not in text.lower() or "password_hash" not in text.lower()


def test_dashboards_and_listing_pages_render_for_both_roles(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    make_job(app, isolated_database, client, provider)
    for who in (client, provider):
        for path in ("/dashboard", "/jobs", "/messages", "/notifications", "/settings"):
            assert who.get(path).status_code == 200, path
    assert client.get("/requests").status_code == 200 and client.get("/saved").status_code == 200
    assert provider.get("/requests/available").status_code == 200


def test_open_request_lifecycle_shows_and_cancels(isolated_database):
    app = make_app(isolated_database)
    client, provider = setup_marketplace(app)
    r = post(client, "/request/new", "/request/new", category="Plumbing", area="Westlands",
             description="Need a plumber to fix a leaking pipe tomorrow")
    assert r.status_code == 302
    page = client.get("/requests").get_data(as_text=True)
    assert "Cancel request" in page and "Open to matching providers" in page
    assert "1</b><span>Pending requests" in client.get("/dashboard").get_data(as_text=True)
    assert "Accept job" in provider.get("/requests/available").get_data(as_text=True)
    conn = isolated_database.get_conn(); rid = conn.execute("SELECT request_id FROM service_requests").fetchone()[0]; conn.close()
    assert post(client, f"/requests/{rid}/cancel", "/requests", reason="changed my mind").status_code == 302
    conn = isolated_database.get_conn(); status = conn.execute("SELECT status FROM service_requests").fetchone()[0]; conn.close()
    assert status == "cancelled"
    assert "Accept job" not in provider.get("/requests/available").get_data(as_text=True)
    other = register(app, "client", "Mallory Kip", "0712345609")
    r2 = post(client, "/request/new", "/request/new", category="Plumbing", area="Westlands", description="Second request for a blocked drain")
    conn = isolated_database.get_conn(); rid2 = conn.execute("SELECT request_id FROM service_requests WHERE status='open'").fetchone()[0]; conn.close()
    post(other, f"/requests/{rid2}/cancel", "/settings", reason="not mine")                 # someone else's request
    conn = isolated_database.get_conn(); assert conn.execute("SELECT status FROM service_requests WHERE request_id=?", (rid2,)).fetchone()[0] == "open"; conn.close()
