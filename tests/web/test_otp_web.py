"""Phone verification, self-service password reset, forced password change, SMS adapters."""
import logging
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import webhelpers as H                                          # noqa: E402
import test_admin as A                                          # noqa: E402
from backend import database as dbmod                           # noqa: E402
from backend.services import accounts, admin                    # noqa: E402
from web import __main__ as web_main, sms                       # noqa: E402

NEW_PW = "violet-harbor-lantern-42"


def sms_app(isolated_database, **cfg):
    sms.outbox.clear()
    return H.make_app(isolated_database, SMS_BACKEND="memory", SMS_ASYNC=False, **cfg)


def last_code(phone=None):
    msgs = [m for m in sms.outbox if phone is None or m[0] == phone]
    assert msgs, "no SMS was sent"
    return re.search(r"\b(\d{6})\b", msgs[-1][1]).group(1)


def send_code(client, next_url=""):
    return H.post(client, "/verify-phone/send", "/verify-phone", next=next_url)


def verify_now(client, phone):
    send_code(client)
    r = H.post(client, "/verify-phone", "/verify-phone", code=last_code(phone))
    assert r.status_code == 302, r.get_data(as_text=True)[:300]


def setup_pair(app):
    client, provider = H.setup_marketplace(app)
    return client, provider, "0712345601", "0712345602"


# ------------------------------------------------------------------ phone verification
def test_unverified_users_are_sent_to_verify_before_requesting(isolated_database):
    app = sms_app(isolated_database)
    client, provider, cphone, _ = setup_pair(app)
    assert "Verify your phone number" in client.get("/dashboard").get_data(as_text=True)
    pid = H.provider_id(isolated_database)
    r = client.get(f"/request/new?provider={pid}")
    assert r.status_code == 302 and "/verify-phone" in r.headers["Location"]
    r = H.post(client, "/request/new", "/settings", provider=pid, category="Plumbing", area="Westlands", description="Fix my kitchen tap please")
    assert r.status_code == 302 and "/verify-phone" in r.headers["Location"]
    conn = isolated_database.get_conn(); assert conn.execute("SELECT COUNT(*) FROM service_requests").fetchone()[0] == 0; conn.close()
    send_code(client)
    assert sms.outbox[-1][0] == cphone and "verification code" in sms.outbox[-1][1]
    wrong = "000000" if last_code() != "000000" else "111111"
    r = H.post(client, "/verify-phone", "/verify-phone", code=wrong)
    assert r.status_code == 200 and "isn&#39;t right" in r.get_data(as_text=True)
    assert not accounts.verified_ids([accounts.get_account_by_phone(cphone)["account_id"]])
    r = H.post(client, "/verify-phone", "/verify-phone", code=last_code(cphone))
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert accounts.verified_ids([accounts.get_account_by_phone(cphone)["account_id"]])
    assert client.get(f"/request/new?provider={pid}").status_code == 200
    assert "Verify your phone number" not in client.get("/dashboard").get_data(as_text=True)


def test_unverified_provider_cannot_accept_until_verified(isolated_database):
    app = sms_app(isolated_database)
    client, provider, cphone, pphone = setup_pair(app)
    verify_now(client, cphone)
    pid = H.provider_id(isolated_database)
    H.post(client, "/request/new", f"/request/new?provider={pid}", provider=pid, category="Plumbing", area="Westlands", description="Fix my kitchen tap please")
    conn = isolated_database.get_conn(); rid = conn.execute("SELECT request_id FROM service_requests").fetchone()[0]; conn.close()
    r = H.post(provider, f"/requests/{rid}/accept", "/requests/available")
    assert "/verify-phone" in r.headers["Location"]
    conn = isolated_database.get_conn(); assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0; conn.close()
    verify_now(provider, pphone)
    r = H.post(provider, f"/requests/{rid}/accept", "/requests/available")
    assert "/jobs/" in r.headers["Location"]


def test_resend_cooldown_and_verified_badge(isolated_database):
    app = sms_app(isolated_database)
    client, provider, cphone, pphone = setup_pair(app)
    send_code(provider); sms.outbox.clear()
    r = send_code(provider)
    assert not sms.outbox                                                    # cooldown: no second text
    assert "wait a minute" in provider.get("/verify-phone").get_data(as_text=True)
    pid = H.provider_id(isolated_database)
    assert "Phone verified" not in client.get(f"/providers/{pid}").get_data(as_text=True)
    verify_now_after = H.post(provider, "/verify-phone", "/verify-phone", code=last_code.__call__() if False else "000000")
    conn = isolated_database.get_conn()
    conn.execute("UPDATE otp_codes SET created_at='2020-01-01T00:00:00+00:00'"); conn.commit(); conn.close()
    verify_now(provider, pphone)
    assert "Phone verified" in client.get(f"/providers/{pid}").get_data(as_text=True)
    assert "Verified" in client.get("/providers").get_data(as_text=True)


def test_sms_none_turns_the_features_off_gracefully(isolated_database):
    sms.outbox.clear()
    app = H.make_app(isolated_database)                                      # default helper config: SMS_BACKEND none
    client, provider, *_ = setup_pair(app)
    pid = H.provider_id(isolated_database)
    assert client.get(f"/request/new?provider={pid}").status_code == 200       # no verification demanded
    c = app.test_client()
    page = c.get("/forgot-password").get_data(as_text=True)
    assert "available on this site" in page and "name=\"phone\"" not in page      # no form is offered
    assert c.post("/forgot-password", data={"phone": "0712345601"}).status_code == 403
    assert not sms.outbox
    assert "Ask an administrator" in app.test_client().get("/signin").get_data(as_text=True)


# ------------------------------------------------------------------ forgot / reset password
def reset_request(app, phone):
    c = app.test_client()
    tok = H.csrf_from(c.get("/forgot-password").get_data(as_text=True))
    return c, c.post("/forgot-password", data={"csrf_token": tok, "phone": phone})


def reset_submit(c, page_html, phone, code, pw, confirm=None):
    return c.post("/reset-password", data={"csrf_token": H.csrf_from(page_html), "phone": phone, "code": code,
                                           "new_password": pw, "confirm_password": confirm or pw})


def test_reset_flow_end_to_end_and_side_effects(isolated_database):
    app = sms_app(isolated_database)
    H.register(app, "client", "Ann Mwangi", "0712345601")
    other_device = H.sign_in(app, "0712345601")
    assert other_device.get("/dashboard").status_code == 200
    aid = accounts.get_account_by_phone("0712345601")["account_id"]
    conn = isolated_database.get_conn()
    conn.execute("UPDATE accounts SET failed_login_count=5, locked_until='2999-01-01T00:00:00+00:00' WHERE account_id=?", (aid,)); conn.commit(); conn.close()
    c, r = reset_request(app, "0712 345 601")
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "If that number belongs to an account" in page
    code = last_code("0712345601")
    assert "password reset code" in sms.outbox[-1][1]
    bad = reset_submit(c, page, "0712345601", "000000" if code != "000000" else "111111", NEW_PW)
    assert "isn&#39;t right" in bad.get_data(as_text=True) and bad.status_code == 200
    weak = reset_submit(c, bad.get_data(as_text=True), "0712345601", code, "password1234")
    assert weak.status_code == 200 and "easy to guess" in weak.get_data(as_text=True)          # weak password...
    mism = reset_submit(c, weak.get_data(as_text=True), "0712345601", code, NEW_PW, "something-else-entirely")
    assert "do not match" in mism.get_data(as_text=True)
    ok = reset_submit(c, mism.get_data(as_text=True), "0712345601", code, NEW_PW)           # ...did not burn the code
    assert ok.status_code == 302 and ok.headers["Location"].endswith("/signin")
    assert "was just changed" in sms.outbox[-1][1]
    assert other_device.get("/dashboard").status_code == 302                                  # every device signed out
    old = app.test_client()
    assert old.post("/signin", data={"csrf_token": H.token_for(old), "phone": "0712345601", "password": H.PW}).status_code == 200
    new = app.test_client()
    r = new.post("/signin", data={"csrf_token": H.token_for(new), "phone": "0712345601", "password": NEW_PW})
    assert r.status_code == 302 and r.headers["Location"] == "/dashboard"                    # lockout cleared too
    again = reset_submit(c, page, "0712345601", code, "copper-meadow-violin-99")
    assert again.status_code == 200 and "isn&#39;t right" in again.get_data(as_text=True)    # code is single use


def test_unknown_and_known_numbers_get_identical_responses(isolated_database):
    app = sms_app(isolated_database)
    H.register(app, "client", "Ann Mwangi", "0712345601")
    sms.outbox.clear()
    c1, known = reset_request(app, "0712345601")
    n_known = len(sms.outbox)
    c2, unknown = reset_request(app, "0799999999")
    norm = lambda html: re.sub(r'value="[a-f0-9]{64}"|name="phone" value="[^"]*"', "", html)    # noqa: E731
    assert known.status_code == unknown.status_code == 200
    assert norm(known.get_data(as_text=True)) == norm(unknown.get_data(as_text=True))
    assert n_known == 1 and len(sms.outbox) == 1                                              # nothing sent to the unknown number
    c3, bad = reset_request(app, "not a phone")
    assert bad.status_code == 200 and len(sms.outbox) == 1
    wrong_user = reset_submit(c2, unknown.get_data(as_text=True), "0799999999", "123456", NEW_PW)
    assert wrong_user.status_code == 200 and "isn&#39;t right" in wrong_user.get_data(as_text=True)


def test_suspended_accounts_cannot_use_the_reset_path(isolated_database):
    app = sms_app(isolated_database)
    H.register(app, "client", "Ann Mwangi", "0712345601")
    conn = isolated_database.get_conn(); conn.execute("UPDATE accounts SET account_status='suspended'"); conn.commit(); conn.close()
    sms.outbox.clear()
    reset_request(app, "0712345601")
    assert not sms.outbox


def test_reset_endpoints_are_rate_limited(isolated_database):
    app = sms_app(isolated_database, RATE_LIMITS_ENABLED=True)
    codes = []
    for i in range(10):
        c = app.test_client()
        tok = H.csrf_from(c.get("/forgot-password").get_data(as_text=True))
        codes.append(c.post("/forgot-password", data={"csrf_token": tok, "phone": f"07123456{i:02d}"}).status_code)
    assert 429 in codes and codes[0] == 200
    assert len(sms.outbox) == 0                                                               # unknown numbers: no texts, no cost


def test_per_phone_limit_stops_hammering_one_number(isolated_database):
    app = sms_app(isolated_database, RATE_LIMITS_ENABLED=True)
    H.register(app, "client", "Ann Mwangi", "0712345601")
    sms.outbox.clear()
    statuses = []
    for _ in range(7):
        c = app.test_client()
        tok = H.csrf_from(c.get("/forgot-password").get_data(as_text=True))
        statuses.append(c.post("/forgot-password", data={"csrf_token": tok, "phone": "0712345601"}).status_code)
    assert len(sms.outbox) <= 1                                                               # 60 s cooldown inside the service


# ------------------------------------------------------------------ forced password change
def test_temporary_password_forces_a_new_one(isolated_database):
    app = sms_app(isolated_database)
    H.register(app, "client", "Ann Mwangi", "0712345601")
    A.mk_admin()
    aid = accounts.get_account_by_phone("0712345601")["account_id"]
    adm_id = admin.admin_login("owner", A.ADMIN_PW)[1]
    ok, temp = admin.issue_password_reset(adm_id, aid, "Identity checked by phone call")
    assert ok
    u = app.test_client()
    r = u.post("/signin", data={"csrf_token": H.token_for(u), "phone": "0712345601", "password": temp})
    assert r.status_code == 302
    for path in ("/dashboard", "/jobs", "/messages", "/settings", "/providers/P-AAAAAAAAAA"):
        r = u.get(path)
        if path.startswith("/providers"):
            continue                                                                         # public pages stay public
        assert r.status_code == 302 and r.headers["Location"].endswith("/password-required"), path
    page = u.get("/password-required").get_data(as_text=True)
    weak = u.post("/password-required", data={"csrf_token": H.csrf_from(page), "current_password": temp, "new_password": "short", "confirm_password": "short"})
    assert weak.status_code == 200 and u.get("/dashboard").status_code == 302
    r = u.post("/password-required", data={"csrf_token": H.csrf_from(page), "current_password": temp, "new_password": NEW_PW, "confirm_password": NEW_PW})
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert u.get("/dashboard").status_code == 200


def test_admin_reset_texts_the_user(isolated_database):
    app = sms_app(isolated_database)
    H.register(app, "client", "Ann Mwangi", "0712345601")
    A.mk_admin()
    uid = accounts.get_account_by_phone("0712345601")["account_id"]
    c, _ = A.enrolled_admin_client(app)
    page = f"/admin/accounts/{uid}"
    assert "not verified" in c.get(page).get_data(as_text=True)
    sms.outbox.clear()
    A.apost(c, f"{page}/reset-password", page, reason="Identity checked by phone call", admin_password=A.ADMIN_PW)
    assert sms.outbox and sms.outbox[-1][0] == "0712345601" and "administrator reset your password" in sms.outbox[-1][1]


# ------------------------------------------------------------------ adapters / guards
def test_africastalking_request_format_and_failure_handling(monkeypatch):
    seen = {}

    def fake(url, headers, data, timeout=8):
        seen.update(url=url, headers=headers, data=data)
        return 201, '{"SMSMessageData":{"Recipients":[{"statusCode":101,"status":"Success","number":"+254712345601"}]}}'
    monkeypatch.setattr(sms, "_http_post", fake)
    cfg = {"SMS_BACKEND": "africastalking", "AT_USERNAME": "acme", "AT_API_KEY": "SECRETKEY123", "AT_SENDER_ID": "SvcLink", "AT_SANDBOX": False}
    logs = []
    class H_(logging.Handler):
        def emit(self, rec): logs.append(rec.getMessage())
    h = H_(); logging.getLogger("servicelink.sms").addHandler(h)
    try:
        assert sms.send("0712345601", "hello", cfg) is True
        assert seen["url"] == sms.AT_LIVE and seen["headers"]["apiKey"] == "SECRETKEY123"
        assert seen["data"] == {"username": "acme", "to": "+254712345601", "message": "hello", "from": "SvcLink"}
        sms.send("0712345601", "x", dict(cfg, AT_SANDBOX=True)); assert seen["url"] == sms.AT_SANDBOX
        monkeypatch.setattr(sms, "_http_post", lambda *a, **k: (400, '{"SMSMessageData":{"Recipients":[{"statusCode":403,"status":"InvalidPhoneNumber"}]}}'))
        assert sms.send("0712345601", "x", cfg) is False
        monkeypatch.setattr(sms, "_http_post", lambda *a, **k: (_ for _ in ()).throw(OSError("network down")))
        assert sms.send("0712345601", "x", cfg) is False
        assert sms.send("0712345601", "x", dict(cfg, AT_API_KEY="")) is False
    finally:
        logging.getLogger("servicelink.sms").removeHandler(h)
    assert not any("SECRETKEY123" in m for m in logs)                                          # keys never reach the logs


def test_async_sending_does_not_block_the_request(isolated_database):
    sms.outbox.clear()
    settings = {"SMS_BACKEND": "memory", "SMS_ASYNC": True}
    sms.send_async("0712345601", "hi", settings)
    for _ in range(40):
        if sms.outbox:
            break
        time.sleep(0.05)
    assert sms.outbox == [("0712345601", "hi")]


def test_production_start_guard_covers_sms(isolated_database):
    base = {"SECURE_COOKIES": True, "TRUSTED_HOSTS": ["x.example"], "SMS_BACKEND": "none", "AT_USERNAME": "", "AT_API_KEY": ""}
    class Fake: config = base
    assert web_main.production_problems(Fake) == []
    for backend in ("console", "memory"):
        base["SMS_BACKEND"] = backend
        assert any("one-time codes" in p for p in web_main.production_problems(Fake))
    base["SMS_BACKEND"] = "africastalking"
    assert any("AT_USERNAME" in p for p in web_main.production_problems(Fake))
    base.update(AT_USERNAME="u", AT_API_KEY="k")
    assert web_main.production_problems(Fake) == []
