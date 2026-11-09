from datetime import datetime, timedelta, timezone

from backend.services import accounts, otp


def make_account(isolated_database, phone="0712345601", name="Ann Mwangi"):
    ok, aid = accounts.create_account("client", name, phone, "", "amber-falcon-river-lamp", "amber-falcon-river-lamp",
                                      True, True, "", "pytest")
    assert ok, aid
    return aid


def clock(monkeypatch, start=None):
    state = {"t": start or datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)}
    monkeypatch.setattr(otp, "_now", lambda: state["t"])
    return state


def test_correct_code_works_once_and_other_purposes_are_separate(isolated_database, monkeypatch):
    clock(monkeypatch)
    aid = make_account(isolated_database)
    ok, code = otp.issue(aid, "verify_phone", "0712345601")
    assert ok and len(code) == 6 and code.isdigit()
    assert otp.verify(aid, "reset_password", code)[0] is False            # a phone-verify code can't reset a password
    assert otp.verify(aid, "verify_phone", " " + code[:3] + " " + code[3:])[0] is True      # spaces tolerated
    assert otp.verify(aid, "verify_phone", code)[0] is False              # single use


def test_five_wrong_guesses_lock_the_code_even_for_the_right_answer(isolated_database, monkeypatch):
    clock(monkeypatch)
    aid = make_account(isolated_database)
    ok, code = otp.issue(aid, "verify_phone", "0712345601")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert otp.verify(aid, "verify_phone", wrong)[0] is False
    assert otp.verify(aid, "verify_phone", code)[0] is False


def test_codes_expire_after_ten_minutes(isolated_database, monkeypatch):
    st = clock(monkeypatch)
    aid = make_account(isolated_database)
    _, code = otp.issue(aid, "verify_phone", "0712345601")
    st["t"] += timedelta(minutes=9, seconds=59)
    assert otp.verify(aid, "verify_phone", code)[0] is True
    _, code2 = otp.issue(aid, "reset_password", "0712345601")
    st["t"] += timedelta(minutes=10, seconds=1)
    assert otp.verify(aid, "reset_password", code2)[0] is False


def test_cooldown_hourly_cap_and_new_code_replaces_old(isolated_database, monkeypatch):
    st = clock(monkeypatch)
    aid = make_account(isolated_database)
    ok, first = otp.issue(aid, "verify_phone", "0712345601")
    assert ok
    assert otp.issue(aid, "verify_phone", "0712345601")[0] is False                  # 60 s cooldown
    st["t"] += timedelta(seconds=61)
    ok, second = otp.issue(aid, "verify_phone", "0712345601")
    assert ok and (first == second or otp.verify(aid, "verify_phone", first)[0] is False)
    if first != second:
        assert otp.verify(aid, "verify_phone", second)[0] is True
    sent = 2
    while True:                                                                      # hit the 5 per hour cap
        st["t"] += timedelta(seconds=61)
        ok, msg = otp.issue(aid, "verify_phone", "0712345601")
        if not ok:
            break
        sent += 1
        assert sent <= 5
    assert "Too many" in msg and sent == 5
    st["t"] += timedelta(hours=1, minutes=1)
    assert otp.issue(aid, "verify_phone", "0712345601")[0] is True                   # allowed again later


def test_codes_are_stored_hashed_and_depend_on_the_pepper(isolated_database, monkeypatch):
    clock(monkeypatch)
    aid = make_account(isolated_database)
    _, code = otp.issue(aid, "verify_phone", "0712345601", pepper="server-secret")
    conn = isolated_database.get_conn()
    row = conn.execute("SELECT * FROM otp_codes").fetchone(); conn.close()
    assert code not in " ".join(str(v) for v in dict(row).values()) and len(row["code_hash"]) == 64
    assert otp.verify(aid, "verify_phone", code, pepper="other-secret")[0] is False
    _, code2 = otp.issue(aid, "reset_password", "0712345601", pepper="server-secret")
    assert otp.verify(aid, "reset_password", code2, pepper="server-secret")[0] is True


def test_no_code_means_failure_and_wrong_account_cannot_use_it(isolated_database, monkeypatch):
    clock(monkeypatch)
    a, b = make_account(isolated_database), make_account(isolated_database, "0712345602", "Ben Otieno")
    assert otp.verify(a, "verify_phone", "123456")[0] is False
    _, code = otp.issue(a, "verify_phone", "0712345601")
    assert otp.verify(b, "verify_phone", code)[0] is False
    assert otp.verify(a, "verify_phone", "abcdef")[0] is False and otp.verify(a, "verify_phone", "")[0] is False
