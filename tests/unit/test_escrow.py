"""Escrow accounting. After every scenario the books must still balance (integrity_report)."""
import itertools
import threading
from datetime import timedelta

from backend import database as dbmod
from backend.services import accounts, admin, escrow, jobs, marketplace, requests as rq

PW = "amber-falcon-river-lamp"
_counter = itertools.count(1)


def make_job(isolated_database, price="KSh 1,000", advance_to=None):
    n = next(_counter)
    ok, cid = accounts.create_account("client", f"Client{n} Wanjiku", f"07120{n:05d}", "", PW, PW, True, True, "", "t"); assert ok, cid
    ok, pid = accounts.create_account("provider", f"Provider{n} Otieno", f"07130{n:05d}", "", PW, PW, True, True, "home", "t"); assert ok, pid
    accounts.complete_profile(cid, f"Client{n}", "Westlands", "", "", "client", "")
    accounts.complete_profile(pid, f"Provider{n}", "Westlands", "bio text here", "", "provider", "home")
    rq.create_request(cid, "Plumbing", "Kitchen tap leaking badly please fix it", "Westlands", "", pid, "direct")
    rid = [r for r in rq.list_client_requests(cid) if r["status"] == "open"][0]["request_id"]
    jid = int(jobs.accept_request(pid, rid)[1])
    if price:
        assert jobs.set_agreed_price(jid, pid, price)[0]
    if advance_to:
        walk(jid, cid, pid, advance_to)
    return cid, pid, jid


def walk(jid, cid, pid, target):
    steps = [(pid, "dispatched"), (pid, "arrived"), (pid, "started"), (cid, "client_confirmed"), (pid, "done")]
    for who, action in steps:
        jobs.advance(jid, who, action)
        if action == target:
            return


def complete(jid, cid, pid):
    walk(jid, cid, pid, "done"); assert jobs.close_job(jid, cid, "client_confirmed")[0]


def fund(cid, jid, checkout="CO-1", phone="0712345678", receipt="QGH7XYZ123"):
    ok, info = escrow.start_payment(cid, jid, phone, "simulated"); assert ok, info
    escrow.attach_checkout(info["attempt_id"], checkout)
    ok, msg = escrow.record_result(checkout, True, receipt=receipt, amount_minor=info["amount_minor"], result_code="0")
    assert ok, msg
    return info


def books_ok():
    rep = escrow.integrity_report()
    assert rep["ok"], rep["problems"]
    return rep["balances"]


def admin_id():
    ok, msg = admin.create_initial_admin("owner", "violet-harbor-lantern-42", "violet-harbor-lantern-42")
    return admin.admin_login("owner", "violet-harbor-lantern-42")[1]


# ------------------------------------------------------------------ fees and validation
def test_fee_rounds_down_to_whole_shillings():
    assert escrow.compute_fee(100_000, 250) == 2_500            # KSh 1,000 at 2.5% = KSh 25
    assert escrow.compute_fee(33_300, 250) == 800               # KSh 333 at 2.5% = 8.32 -> KSh 8
    assert escrow.compute_fee(100_000, 0) == 0 and escrow.compute_fee(5_000, 100) == 0


def test_payment_start_validation(isolated_database):
    cid, pid, jid = make_job(isolated_database, price="")
    assert "price" in escrow.start_payment(cid, jid, "0712345678", "simulated")[1]
    jobs.set_agreed_price(jid, pid, "KSh 2,500.50")
    assert "whole shilling" in escrow.start_payment(cid, jid, "0712345678", "simulated")[1]
    jobs.set_agreed_price(jid, pid, "KSh 5")
    assert "between" in escrow.start_payment(cid, jid, "0712345678", "simulated")[1]
    jobs.set_agreed_price(jid, pid, "KSh 900,000")
    assert "between" in escrow.start_payment(cid, jid, "0712345678", "simulated")[1]
    jobs.set_agreed_price(jid, pid, "KSh 1,000")
    assert "valid Kenyan" in escrow.start_payment(cid, jid, "not a phone", "simulated")[1]
    assert escrow.start_payment(pid, jid, "0712345678", "simulated") == (False, "Job not found.")      # provider can't pay
    other = make_job(isolated_database)
    assert escrow.start_payment(other[0], jid, "0712345678", "simulated")[1] == "Job not found."          # someone else's job
    assert escrow.start_payment(cid, 99999, "0712345678", "simulated")[1] == "Job not found."
    assert escrow.get_for_job(jid) is None
    books_ok()


def test_cannot_pay_for_finished_jobs_or_twice(isolated_database):
    cid, pid, jid = make_job(isolated_database)
    fund(cid, jid)
    assert "already been paid" in escrow.start_payment(cid, jid, "0712345678", "simulated")[1]
    c2, p2, j2 = make_job(isolated_database, advance_to="arrived")
    jobs.cancel_job(j2, c2, "Plans changed completely")
    assert "no longer" in escrow.start_payment(c2, j2, "0712345678", "simulated")[1]
    books_ok()


def test_only_one_live_payment_request_and_old_ones_expire(isolated_database, monkeypatch):
    cid, pid, jid = make_job(isolated_database)
    ok, a = escrow.start_payment(cid, jid, "0712345678", "simulated"); assert ok
    ok, msg = escrow.start_payment(cid, jid, "0712345678", "simulated")
    assert not ok and "already waiting" in msg
    later = escrow._now() + timedelta(minutes=11)
    monkeypatch.setattr(escrow, "_now", lambda: later)
    ok, b = escrow.start_payment(cid, jid, "0712345678", "simulated"); assert ok and b["attempt_id"] != a["attempt_id"]
    conn = dbmod.get_conn(); old = conn.execute("SELECT status FROM payment_attempts WHERE attempt_id=?", (a["attempt_id"],)).fetchone()[0]; conn.close()
    assert old == "timeout"


def test_price_change_before_payment_updates_the_amount(isolated_database):
    cid, pid, jid = make_job(isolated_database, price="KSh 1,000")
    escrow.start_payment(cid, jid, "0712345678", "simulated")
    jobs.set_agreed_price(jid, pid, "KSh 1,500")
    conn = dbmod.get_conn(); conn.execute("UPDATE payment_attempts SET status='timeout'"); conn.commit(); conn.close()
    ok, info = escrow.start_payment(cid, jid, "0712345678", "simulated")
    assert ok and info["amount_minor"] == 150_000 and escrow.get_for_job(jid)["amount_minor"] == 150_000


# ------------------------------------------------------------------ paying in
def test_confirmed_payment_is_held_and_replays_change_nothing(isolated_database):
    cid, pid, jid = make_job(isolated_database)
    info = fund(cid, jid)
    b = books_ok()
    assert b[escrow.EXTERNAL] == -100_000 and b[escrow.HELD] == 100_000
    assert escrow.get_for_job(jid)["status"] == "held"
    for _ in range(3):
        assert escrow.record_result("CO-1", True, receipt="QGH7XYZ123", amount_minor=100_000, result_code="0")[0]
    assert books_ok() == b
    conn = dbmod.get_conn(); assert conn.execute("SELECT COUNT(*) FROM ledger_entries").fetchone()[0] == 2; conn.close()


def test_failed_cancelled_and_timed_out_payments(isolated_database):
    cid, pid, jid = make_job(isolated_database)
    ok, a = escrow.start_payment(cid, jid, "0712345678", "simulated"); escrow.attach_checkout(a["attempt_id"], "CO-A")
    assert escrow.record_result("CO-A", False, result_code="1032", result_desc="Request cancelled by user")[0]
    assert escrow.get_for_job(jid)["status"] == "awaiting_payment" and escrow.get_for_job(jid)["attempts"][0]["status"] == "cancelled"
    assert escrow.record_result("CO-A", True, receipt="QGH7AAAAAA", amount_minor=100_000)[0]           # final: a replayed success is ignored
    assert escrow.get_for_job(jid)["status"] == "awaiting_payment"
    ok, b = escrow.start_payment(cid, jid, "0712345678", "simulated"); escrow.attach_checkout(b["attempt_id"], "CO-B")
    escrow.record_result("CO-B", False, result_code="1037")
    assert escrow.get_for_job(jid)["attempts"][0]["status"] == "timeout"
    assert escrow.record_result("CO-B", True, receipt="QGH7BBBBBB", amount_minor=100_000, result_code="0")[0]   # money did arrive late
    assert escrow.get_for_job(jid)["status"] == "held"
    assert escrow.record_result("NOPE", True)[0] is False
    books_ok()


def test_wrong_amount_is_never_credited(isolated_database):
    cid, pid, jid = make_job(isolated_database)
    ok, a = escrow.start_payment(cid, jid, "0712345678", "simulated"); escrow.attach_checkout(a["attempt_id"], "CO-X")
    ok, msg = escrow.record_result("CO-X", True, receipt="QGH7XXXXXX", amount_minor=50_000, result_code="0")
    assert ok is False and "review" in msg
    assert escrow.get_for_job(jid)["status"] == "awaiting_payment" and escrow.get_for_job(jid)["attempts"][0]["status"] == "mismatch"
    conn = dbmod.get_conn(); assert conn.execute("SELECT COUNT(*) FROM ledger_entries").fetchone()[0] == 0; conn.close()
    books_ok()


def test_reused_receipt_is_refused(isolated_database):
    c1, p1, j1 = make_job(isolated_database); fund(c1, j1, "CO-1", receipt="QGH7SAME01")
    c2, p2, j2 = make_job(isolated_database)
    ok, a = escrow.start_payment(c2, j2, "0712345678", "simulated"); escrow.attach_checkout(a["attempt_id"], "CO-2")
    ok, msg = escrow.record_result("CO-2", True, receipt="QGH7SAME01", amount_minor=100_000, result_code="0")
    assert ok is False and "already used" in msg and escrow.get_for_job(j2)["status"] == "awaiting_payment"
    books_ok()


def test_duplicate_payment_is_booked_as_a_refund_owed(isolated_database):
    cid, pid, jid = make_job(isolated_database)
    fund(cid, jid, "CO-1", receipt="QGH7FIRST1")
    ok, a = escrow.start_payment(cid, jid, "0712345678", "simulated")
    assert not ok                                                                                    # normal path refuses a second payment
    # but a stray second confirmation (e.g. user paid the same prompt twice) must not be kept:
    conn = dbmod.get_conn()
    eid = escrow.get_for_job(jid)["escrow_id"]
    conn.execute("INSERT INTO payment_attempts(escrow_id,gateway,checkout_id,phone,amount_minor,status,created_at) VALUES(?,?,?,?,?,'pending','2026-01-01T00:00:00+00:00')",
                 (eid, "simulated", "CO-DUP", "0712345678", 100_000)); conn.commit(); conn.close()
    assert escrow.record_result("CO-DUP", True, receipt="QGH7DUPLI1", amount_minor=100_000, result_code="0") == (True, "Extra payment will be refunded.")
    b = books_ok()
    assert b[escrow.HELD] == 100_000 and b[escrow.REFUNDABLE] == 100_000
    [p] = [x for x in escrow.list_payouts("pending") if x["kind"] == "refund"]
    assert p["amount_minor"] == 100_000 and p["to_account_id"] == cid
    assert escrow.mark_payout_paid(p["payout_id"], "QGH7REFUN1", "admin")[0]
    assert books_ok()[escrow.REFUNDABLE] == 0


def test_late_payment_after_the_job_was_cancelled_is_refunded(isolated_database):
    cid, pid, jid = make_job(isolated_database, advance_to="arrived")
    ok, a = escrow.start_payment(cid, jid, "0712345678", "simulated"); escrow.attach_checkout(a["attempt_id"], "CO-L")
    jobs.cancel_job(jid, cid, "Plans changed completely")
    assert escrow.reconcile()["voided"] == 1
    assert escrow.record_result("CO-L", True, receipt="QGH7LATE01", amount_minor=100_000, result_code="0")[0]
    assert escrow.get_for_job(jid)["status"] == "void"
    [p] = escrow.list_payouts("pending")
    assert p["kind"] == "refund" and p["amount_minor"] == 100_000 and p["phone"] == "0712345678"
    books_ok()


# ------------------------------------------------------------------ release / refund
def test_release_after_completion_pays_the_provider_minus_commission(isolated_database):
    aid = admin_id(); assert escrow.set_fee_bps(aid, 250, "Launch pricing for the first year")[0]
    cid, pid, jid = make_job(isolated_database, price="KSh 1,000")
    fund(cid, jid)
    assert escrow.reconcile(jid) == {"released": 0, "refunded": 0, "voided": 0}                     # job still running: nothing moves
    complete(jid, cid, pid)
    assert escrow.reconcile(jid)["released"] == 1
    e = escrow.get_for_job(jid)
    assert e["status"] == "released" and e["fee_minor"] == 2_500 and e["net_minor"] == 97_500
    [p] = e["payouts"]
    assert p["kind"] == "release" and p["to_account_id"] == pid and p["amount_minor"] == 97_500 and p["phone"] == accounts.get_account(pid)["phone"]
    b = books_ok()
    assert b[escrow.HELD] == 0 and b[escrow.PAYABLE] == 97_500 and b[escrow.FEES] == 2_500
    snap = dict(b)
    assert escrow.reconcile(jid) == {"released": 0, "refunded": 0, "voided": 0} and books_ok() == snap       # idempotent
    assert escrow.mark_payout_paid(p["payout_id"], "QGH7PAID01", "admin")[0]
    b = books_ok()
    assert b[escrow.PAYABLE] == 0 and b[escrow.EXTERNAL] == -2_500                                         # the platform kept exactly its fee


def test_zero_commission_by_default(isolated_database):
    assert escrow.fee_bps() == 0
    cid, pid, jid = make_job(isolated_database); fund(cid, jid); complete(jid, cid, pid); escrow.reconcile()
    e = escrow.get_for_job(jid)
    assert e["fee_minor"] == 0 and e["payouts"][0]["amount_minor"] == 100_000 and books_ok()[escrow.FEES] == 0


def test_cancellation_refunds_the_payer_phone(isolated_database):
    cid, pid, jid = make_job(isolated_database, advance_to="dispatched")
    fund(cid, jid, phone="0799888777")
    jobs.cancel_job(jid, cid, "Plans changed completely")
    assert escrow.reconcile(jid)["refunded"] == 1
    e = escrow.get_for_job(jid)
    [p] = e["payouts"]
    assert e["status"] == "refunded" and p["kind"] == "refund" and p["amount_minor"] == 100_000 and p["phone"] == "0799888777" and p["to_account_id"] == cid
    assert books_ok()[escrow.REFUNDABLE] == 100_000
    escrow.mark_payout_paid(p["payout_id"], "QGH7BACK01", "admin")
    b = books_ok(); assert b[escrow.EXTERNAL] == 0 and b[escrow.REFUNDABLE] == 0


def test_disputed_jobs_are_frozen_until_settled(isolated_database):
    aid = admin_id(); escrow.set_fee_bps(aid, 1000, "Ten percent commission for testing")
    cid, pid, jid = make_job(isolated_database, price="KSh 1,000", advance_to="arrived")
    fund(cid, jid)
    assert jobs.open_dispute(jid, cid, dbmod.INCIDENT_TYPES_CLIENT[0], "The provider did not do the agreed work at all today.")[0]
    assert escrow.reconcile(jid)["released"] == 0 and escrow.get_for_job(jid)["status"] == "held"
    e = escrow.get_for_job(jid)
    assert escrow.admin_settle(aid, e["escrow_id"], 60_000, "short")[0] is False                    # needs a real reason
    assert escrow.admin_settle(aid, e["escrow_id"], 60_050, "Partial work was done, split 60/40")[0] is False   # whole shillings only
    assert escrow.admin_settle(aid, e["escrow_id"], 100_100, "Partial work was done, split 60/40")[0] is False  # more than held
    ok, msg = escrow.admin_settle(aid, e["escrow_id"], 60_000, "Partial work was done, split 60/40")
    assert ok, msg
    e = escrow.get_for_job(jid)
    by = {p["kind"]: p for p in e["payouts"]}
    assert e["status"] == "settled" and by["release"]["amount_minor"] == 54_000 and by["refund"]["amount_minor"] == 40_000     # 60,000 less 6,000 commission
    b = books_ok(); assert b[escrow.FEES] == 6_000 and b[escrow.PAYABLE] == 54_000 and b[escrow.REFUNDABLE] == 40_000 and b[escrow.HELD] == 0
    assert escrow.admin_settle(aid, e["escrow_id"], 0, "Trying to settle the same money twice")[0] is False
    conn = dbmod.get_conn(); row = conn.execute("SELECT action_type, reason FROM admin_actions WHERE action_type='settle_escrow'").fetchone(); conn.close()
    assert row and "60/40" in row["reason"]


def test_settle_rules(isolated_database):
    aid = admin_id()
    cid, pid, jid = make_job(isolated_database, advance_to="dispatched")
    fund(cid, jid)
    eid = escrow.get_for_job(jid)["escrow_id"]
    assert "disputed or finished" in escrow.admin_settle(aid, eid, 0, "Job is still running normally")[1]
    c2, p2, j2 = make_job(isolated_database)
    ok, a = escrow.start_payment(c2, j2, "0712345678", "simulated")
    assert "currently held" in escrow.admin_settle(aid, escrow.get_for_job(j2)["escrow_id"], 0, "Nothing has been paid yet")[1]
    assert escrow.admin_settle(aid, 99999, 0, "No such escrow exists at all")[0] is False


def test_full_refund_through_settle_on_a_completed_job(isolated_database):
    aid = admin_id()
    cid, pid, jid = make_job(isolated_database); fund(cid, jid); complete(jid, cid, pid)
    eid = escrow.get_for_job(jid)["escrow_id"]
    assert escrow.admin_settle(aid, eid, 0, "Client proved the work was never done")[0]       # beats the automatic release
    e = escrow.get_for_job(jid); assert [p["kind"] for p in e["payouts"]] == ["refund"] and e["payouts"][0]["amount_minor"] == 100_000
    assert escrow.reconcile(jid)["released"] == 0
    books_ok()


# ------------------------------------------------------------------ payouts
def test_payout_marking_is_idempotent_and_validated(isolated_database):
    cid, pid, jid = make_job(isolated_database); fund(cid, jid); complete(jid, cid, pid); escrow.reconcile()
    [p] = escrow.get_for_job(jid)["payouts"]
    assert escrow.mark_payout_paid(p["payout_id"], "ab", "admin")[0] is False                       # too short
    assert escrow.mark_payout_paid(p["payout_id"], "bad ref!", "admin")[0] is False
    assert escrow.mark_payout_paid(999, "QGH7NOPE01", "admin")[0] is False
    assert escrow.mark_payout_paid(p["payout_id"], "QGH7ONCE01", "admin")[0]
    snap = books_ok()
    assert escrow.mark_payout_paid(p["payout_id"], "QGH7ONCE01", "admin") == (True, "Already marked as paid.")
    assert escrow.mark_payout_paid(p["payout_id"], "QGH7OTHER1", "admin")[0] is True and books_ok() == snap
    assert escrow.mark_payout_failed(p["payout_id"], "oops")[0] is False                              # already paid
    c2, p2, j2 = make_job(isolated_database); fund(c2, j2, "CO-2", receipt="QGH7SECND1"); complete(j2, c2, p2); escrow.reconcile()
    [q] = escrow.get_for_job(j2)["payouts"]
    assert "already used" in escrow.mark_payout_paid(q["payout_id"], "QGH7ONCE01", "admin")[1]


def test_failed_payout_can_be_retried(isolated_database):
    cid, pid, jid = make_job(isolated_database); fund(cid, jid); complete(jid, cid, pid); escrow.reconcile()
    [p] = escrow.get_for_job(jid)["payouts"]
    assert escrow.mark_payout_failed(p["payout_id"], "Wrong number on file")[0]
    assert "Set a failed payout back" in escrow.mark_payout_paid(p["payout_id"], "QGH7RETRY1", "admin")[1]
    books_ok()                                                                                       # money still owed, books still right
    assert escrow.retry_payout(p["payout_id"])[0] and escrow.mark_payout_paid(p["payout_id"], "QGH7RETRY1", "admin")[0]
    assert books_ok()[escrow.PAYABLE] == 0


# ------------------------------------------------------------------ safety properties
def test_two_threads_cannot_release_the_same_money_twice(isolated_database):
    cid, pid, jid = make_job(isolated_database); fund(cid, jid); complete(jid, cid, pid)
    results = []
    def go():
        results.append(escrow.reconcile(jid))
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sum(r["released"] for r in results) == 1 and len(escrow.get_for_job(jid)["payouts"]) == 1
    assert books_ok()[escrow.PAYABLE] == 100_000


def test_two_threads_confirming_one_payment_credit_it_once(isolated_database):
    cid, pid, jid = make_job(isolated_database)
    ok, a = escrow.start_payment(cid, jid, "0712345678", "simulated"); escrow.attach_checkout(a["attempt_id"], "CO-T")
    def go():
        escrow.record_result("CO-T", True, receipt="QGH7THREAD", amount_minor=100_000, result_code="0")
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    conn = dbmod.get_conn(); assert conn.execute("SELECT COUNT(*) FROM ledger_entries").fetchone()[0] == 2; conn.close()
    assert books_ok()[escrow.HELD] == 100_000


def test_the_database_refuses_to_edit_the_ledger(isolated_database):
    cid, pid, jid = make_job(isolated_database); fund(cid, jid)
    conn = dbmod.get_conn()
    for sql in ("UPDATE ledger_entries SET amount_minor=1", "DELETE FROM ledger_entries"):
        try:
            conn.execute(sql); assert False, sql
        except Exception as exc:
            assert "cannot be" in str(exc)
    conn.close()


def test_integrity_check_catches_tampering(isolated_database):
    cid, pid, jid = make_job(isolated_database); fund(cid, jid); books_ok()
    conn = dbmod.get_conn()
    conn.execute("INSERT INTO ledger_entries(txn_id, escrow_id, account, amount_minor, created_at) VALUES('x', 1, 'platform:fees', 500, '2026-01-01')"); conn.commit()
    rep = escrow.integrity_report(); assert not rep["ok"] and any("balance" in p for p in rep["problems"])
    conn.execute("INSERT INTO ledger_entries(txn_id, escrow_id, account, amount_minor, created_at) VALUES('x', 1, 'external:mpesa', -500, '2026-01-01')"); conn.commit()
    conn.execute("UPDATE escrows SET status='held'"); conn.execute("DELETE FROM payment_attempts"); conn.commit()      # held money with no payment on record
    rep = escrow.integrity_report(); assert not rep["ok"] and any("without a confirmed payment" in p for p in rep["problems"])
    conn.close()


def test_fee_is_fixed_when_payment_starts(isolated_database):
    aid = admin_id(); escrow.set_fee_bps(aid, 200, "Two percent while we test the system")
    cid, pid, jid = make_job(isolated_database); fund(cid, jid)
    escrow.set_fee_bps(aid, 900, "Raised the commission after launch")
    complete(jid, cid, pid); escrow.reconcile()
    assert escrow.get_for_job(jid)["fee_minor"] == 2_000                                              # the 2% in force when they paid
    c2, p2, j2 = make_job(isolated_database); fund(c2, j2, "CO-2", receipt="QGH7SECND1")
    assert escrow.get_for_job(j2)["fee_bps"] == 900


def test_fee_setting_validation_and_audit(isolated_database):
    aid = admin_id()
    for bad in ("abc", -1, 3001, None):
        assert escrow.set_fee_bps(aid, bad, "A perfectly good reason")[0] is False
    assert escrow.set_fee_bps(aid, 100, "short")[0] is False
    assert escrow.set_fee_bps(aid, "150", "Setting one and a half percent") [0] and escrow.fee_bps() == 150
    conn = dbmod.get_conn(); row = conn.execute("SELECT before_state, after_state FROM admin_actions WHERE action_type='set_platform_fee'").fetchone(); conn.close()
    assert row["before_state"] == "0 bps" and row["after_state"] == "150 bps"


def test_expiry_and_polling_helpers(isolated_database):
    cid, pid, jid = make_job(isolated_database)
    ok, a = escrow.start_payment(cid, jid, "0712345678", "simulated")
    assert escrow.attempts_to_poll(0) == []                                                          # not yet attached to a checkout
    escrow.attach_checkout(a["attempt_id"], "CO-P")
    assert escrow.attempts_to_poll(8) == []                                                          # too fresh to poll yet
    conn = dbmod.get_conn()
    conn.execute("UPDATE payment_attempts SET created_at='2000-01-01T00:00:00+00:00'"); conn.commit()
    assert [x["checkout_id"] for x in escrow.attempts_to_poll(8)] == ["CO-P"]
    escrow.mark_polled(a["attempt_id"])
    assert escrow.attempts_to_poll(8) == []                                                          # just polled: leave it alone
    conn.execute("UPDATE payment_attempts SET last_polled_at='2000-01-01T00:00:00+00:00'"); conn.commit()
    assert len(escrow.attempts_to_poll(8)) == 1
    assert escrow.expire_stale_attempts() == 1                                                       # created long ago -> timed out
    assert escrow.attempts_to_poll(8) == []
    conn.close()
