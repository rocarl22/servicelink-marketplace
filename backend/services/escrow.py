"""Escrow: the client pays the agreed price into escrow, the money is held while the work happens, and is
released to the provider (or refunded to the client) depending on how the job ends.

Safety rules this module enforces:
- Money is whole shillings, as integers (cents), never floats. Fees round DOWN to a whole shilling.
- Every movement is a balanced double-entry posting (the lines of a posting sum to zero) in an
  append-only ledger (the database itself refuses UPDATE/DELETE on it). `integrity_report()` re-checks
  the books at any time.
- Every state change is inside one `BEGIN IMMEDIATE` transaction and is idempotent: a payment confirmation
  that arrives twice, or a payout marked paid twice, changes nothing the second time.
- A payment is only credited if its amount matches what was asked for; extra/duplicate/late payments are
  never lost - they are booked as a refund owed to the payer.
- The release/refund decision follows the job's state (`reconcile`): completed -> release, cancelled or
  abandoned -> refund, disputed -> frozen until an administrator settles it.

Money accounts used in the ledger (signed amounts):
  external:mpesa     money outside the system (M-Pesa). Negative = money received, positive = money sent out
  escrow:held        client money being held for jobs
  provider:payable   owed to providers, not yet paid out
  client:refundable  owed back to clients, not yet paid out
  platform:fees      commission kept by the platform
"""
import re
import secrets
from datetime import datetime, timedelta, timezone

from .. import database as db
from . import settings
from .validation import normalize_ke_phone, now_iso, parse_iso

CURRENCY = "KES"
MIN_MINOR = 10 * 100                 # KSh 10
MAX_MINOR = 150_000 * 100            # KSh 150,000 (below the M-Pesa single-transaction limit)
MAX_FEE_BPS = 3000                   # 30%
ATTEMPT_TTL_SECONDS = 10 * 60
PAYABLE_STATES = ("accepted", "dispatched", "arrived", "started", "client_confirmed", "done")
DONE_STATES = ("completed", "completed_by_timeout")
CANCELLED_STATES = ("cancelled", "abandoned")

EXTERNAL, HELD, PAYABLE, REFUNDABLE, FEES = ("external:mpesa", "escrow:held", "provider:payable",
                                             "client:refundable", "platform:fees")
RECEIPT_RE = re.compile(r"^[A-Za-z0-9\-]{4,30}$")

_now = lambda: datetime.now(timezone.utc)      # noqa: E731  (injectable for tests)


# ------------------------------------------------------------------ settings / fees
def fee_bps() -> int:
    try:
        return max(0, min(MAX_FEE_BPS, int(settings.get("platform_fee_bps", "0"))))
    except ValueError:
        return 0


def set_fee_bps(admin_id: str, bps, reason: str):
    """Set the platform commission in basis points (100 = 1%). Applies only to NEW escrows."""
    from . import admin as admin_svc
    try:
        bps = int(bps)
    except (TypeError, ValueError):
        return False, "Enter the commission as a whole number of basis points (100 = 1%)."
    if not 0 <= bps <= MAX_FEE_BPS:
        return False, f"Commission must be between 0 and {MAX_FEE_BPS // 100}%."
    if len((reason or "").strip()) < 10:
        return False, "Please write a reason (at least 10 characters)."
    before = fee_bps()
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO app_settings(key, value) VALUES('platform_fee_bps', ?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(bps),))
        admin_svc._log_admin_action(conn, admin_id, "set_platform_fee", "setting", "platform_fee_bps",
                                    f"{before} bps", f"{bps} bps", reason.strip())
        conn.commit()
        return True, "Commission updated. It applies to new payments only."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def compute_fee(amount_minor: int, bps: int) -> int:
    """Commission in cents, rounded DOWN to a whole shilling so every payout stays in whole shillings."""
    return (amount_minor * bps // 10000) // 100 * 100


# ------------------------------------------------------------------ ledger
def _post(conn, escrow_id, memo, lines):
    """Insert one balanced posting. `lines` = [(account, signed_amount_minor)] and must sum to zero."""
    if not lines or sum(a for _, a in lines) != 0 or any(not isinstance(a, int) or a == 0 for _, a in lines):
        raise ValueError("unbalanced or invalid ledger posting")
    txn, stamp = secrets.token_hex(8), now_iso()
    for account, amount in lines:
        conn.execute("INSERT INTO ledger_entries(txn_id, escrow_id, account, amount_minor, memo, created_at) VALUES(?,?,?,?,?,?)",
                     (txn, escrow_id, account, amount, memo, stamp))


def balances(conn=None) -> dict:
    own = conn is None
    conn = conn or db.get_conn()
    try:
        out = {a: 0 for a in (EXTERNAL, HELD, PAYABLE, REFUNDABLE, FEES)}
        for r in conn.execute("SELECT account, SUM(amount_minor) s FROM ledger_entries GROUP BY account"):
            out[r["account"]] = r["s"]
        return out
    finally:
        if own:
            conn.close()


def integrity_report() -> dict:
    """Re-check the books. `ok` is False if anything is inconsistent."""
    conn = db.get_conn()
    try:
        problems = []
        b = balances(conn)
        total = conn.execute("SELECT COALESCE(SUM(amount_minor),0) FROM ledger_entries").fetchone()[0]
        if total != 0:
            problems.append(f"Ledger does not balance (off by {total} cents).")
        bad = conn.execute("SELECT txn_id FROM ledger_entries GROUP BY txn_id HAVING SUM(amount_minor) <> 0").fetchall()
        if bad:
            problems.append(f"{len(bad)} posting(s) are unbalanced.")
        for acct in (HELD, PAYABLE, REFUNDABLE, FEES):
            if b[acct] < 0:
                problems.append(f"Account {acct} is negative.")
        held = conn.execute("SELECT COALESCE(SUM(amount_minor),0) FROM escrows WHERE status='held'").fetchone()[0]
        if b[HELD] != held:
            problems.append(f"Held funds ({b[HELD]}) do not match escrows marked held ({held}).")
        owed_p = conn.execute("SELECT COALESCE(SUM(amount_minor),0) FROM payouts WHERE kind='release' AND status<>'paid'").fetchone()[0]
        if b[PAYABLE] != owed_p:
            problems.append(f"Provider payable ({b[PAYABLE]}) does not match unpaid release payouts ({owed_p}).")
        owed_c = conn.execute("SELECT COALESCE(SUM(amount_minor),0) FROM payouts WHERE kind='refund' AND status<>'paid'").fetchone()[0]
        if b[REFUNDABLE] != owed_c:
            problems.append(f"Client refundable ({b[REFUNDABLE]}) does not match unpaid refund payouts ({owed_c}).")
        unfunded = conn.execute("""SELECT COUNT(*) FROM escrows e WHERE e.status IN ('held','released','refunded','settled')
                                   AND NOT EXISTS (SELECT 1 FROM payment_attempts a WHERE a.escrow_id=e.escrow_id AND a.status='succeeded')""").fetchone()[0]
        if unfunded:
            problems.append(f"{unfunded} escrow(s) hold money without a confirmed payment.")
        return {"ok": not problems, "problems": problems, "balances": b}
    finally:
        conn.close()


# ------------------------------------------------------------------ paying in
def _job(conn, job_id):
    return conn.execute("SELECT job_id, client_account_id, provider_account_id, current_state, agreed_price_minor "
                        "FROM jobs WHERE job_id=?", (job_id,)).fetchone()


def start_payment(client_id: str, job_id: int, phone: str, gateway: str):
    """Create (or reuse) the escrow and a pending payment attempt. The caller then asks the gateway to prompt the
    phone and calls attach_checkout(). Returns (True, info_dict) or (False, message)."""
    ok, phone07 = normalize_ke_phone(phone)
    if not ok:
        return False, "Enter a valid Kenyan M-Pesa number, like 0712 345 678."
    now = _now()
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        job = _job(conn, job_id)
        if not job or job["client_account_id"] != client_id:
            conn.rollback(); return False, "Job not found."
        if job["current_state"] not in PAYABLE_STATES:
            conn.rollback(); return False, "This job can no longer be paid for."
        amount = job["agreed_price_minor"]
        if not amount:
            conn.rollback(); return False, "The provider hasn't set a clear price yet. Ask them to set one on the job page."
        if amount % 100:
            conn.rollback(); return False, "Escrow works in whole shillings. Ask the provider to set a whole-shilling price."
        if not MIN_MINOR <= amount <= MAX_MINOR:
            conn.rollback(); return False, f"Escrow payments must be between KSh {MIN_MINOR // 100:,} and KSh {MAX_MINOR // 100:,}."
        esc = conn.execute("SELECT * FROM escrows WHERE job_id=?", (job_id,)).fetchone()
        bps = fee_bps()
        if esc and esc["status"] != "awaiting_payment":
            conn.rollback(); return False, "This job has already been paid for."
        stamp = now.isoformat(timespec="seconds")
        if esc is None:
            cur = conn.execute(
                """INSERT INTO escrows(job_id, client_account_id, provider_account_id, amount_minor, fee_bps, fee_minor,
                   currency, status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,'awaiting_payment',?,?)""",
                (job_id, client_id, job["provider_account_id"], amount, bps, compute_fee(amount, bps), CURRENCY, stamp, stamp))
            escrow_id = cur.lastrowid
        else:
            escrow_id = esc["escrow_id"]
            conn.execute("UPDATE escrows SET amount_minor=?, fee_bps=?, fee_minor=?, updated_at=? WHERE escrow_id=?",
                         (amount, bps, compute_fee(amount, bps), stamp, escrow_id))      # price may change before payment
        live = conn.execute("SELECT created_at FROM payment_attempts WHERE escrow_id=? AND status='pending'", (escrow_id,)).fetchall()
        for r in live:
            t = parse_iso(r["created_at"])
            if t and (now - t).total_seconds() < ATTEMPT_TTL_SECONDS:
                conn.rollback()
                return False, "A payment request is already waiting. Check your phone and enter your M-Pesa PIN, or try again in a few minutes."
        conn.execute("UPDATE payment_attempts SET status='timeout', completed_at=? WHERE escrow_id=? AND status='pending'", (stamp, escrow_id))
        cur = conn.execute(
            """INSERT INTO payment_attempts(escrow_id, gateway, checkout_id, phone, amount_minor, status, created_at)
               VALUES(?,?,?,?,?,'pending',?)""", (escrow_id, gateway, "PENDING-" + secrets.token_hex(8), phone07, amount, stamp))
        conn.commit()
        return True, {"attempt_id": cur.lastrowid, "escrow_id": escrow_id, "amount_minor": amount, "phone": phone07, "job_id": job_id}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def attempt_status(checkout_id: str):
    """Status of the payment attempt with this provider reference, or None if we never started it."""
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT status FROM payment_attempts WHERE checkout_id=?", (checkout_id,)).fetchone()
        return row["status"] if row else None
    finally:
        conn.close()


def attach_checkout(attempt_id: int, checkout_id: str):
    conn = db.get_conn()
    try:
        conn.execute("UPDATE payment_attempts SET checkout_id=? WHERE attempt_id=? AND status='pending'", (checkout_id, attempt_id))
        conn.commit()
    finally:
        conn.close()


def fail_attempt(attempt_id: int, description: str):
    conn = db.get_conn()
    try:
        conn.execute("UPDATE payment_attempts SET status='failed', result_desc=?, completed_at=? WHERE attempt_id=? AND status='pending'",
                     ((description or "")[:200], now_iso(), attempt_id))
        conn.commit()
    finally:
        conn.close()


def record_result(checkout_id: str, success: bool, *, receipt: str = "", amount_minor=None,
                  result_code: str = "", result_desc: str = ""):
    """Apply a payment outcome that the payment provider has CONFIRMED. Safe to call repeatedly.
    Returns (ok, message). ok=False only for genuine problems (unknown payment, amount mismatch)."""
    receipt = (receipt or "").strip()[:30]
    if receipt and not RECEIPT_RE.match(receipt):
        receipt = ""
    stamp = now_iso()
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        att = conn.execute("SELECT * FROM payment_attempts WHERE checkout_id=?", (checkout_id,)).fetchone()
        if not att:
            conn.rollback(); return False, "Unknown payment."
        if att["status"] == "succeeded":
            if receipt and not att["receipt"]:                                    # late callback adds the receipt number
                try:
                    conn.execute("UPDATE payment_attempts SET receipt=? WHERE attempt_id=?", (receipt, att["attempt_id"]))
                    conn.commit(); return True, "Receipt recorded."
                except Exception:
                    conn.rollback(); return True, "Already recorded."
            conn.rollback(); return True, "Already recorded."
        if att["status"] not in ("pending", "timeout"):                          # failed/cancelled/mismatch are final
            conn.rollback(); return True, "Already recorded."
        if not success:
            status = "cancelled" if result_code == "1032" else ("timeout" if result_code == "1037" else "failed")
            conn.execute("UPDATE payment_attempts SET status=?, result_code=?, result_desc=?, completed_at=? WHERE attempt_id=? AND status='pending'",
                         (status, result_code[:10], (result_desc or "")[:200], stamp, att["attempt_id"]))
            conn.commit(); return True, "Payment was not completed."
        esc = conn.execute("SELECT * FROM escrows WHERE escrow_id=?", (att["escrow_id"],)).fetchone()
        if amount_minor is not None and int(amount_minor) != att["amount_minor"]:
            conn.execute("UPDATE payment_attempts SET status='mismatch', result_code=?, result_desc=?, completed_at=? WHERE attempt_id=?",
                         (result_code[:10], f"amount {amount_minor} <> expected {att['amount_minor']}", stamp, att["attempt_id"]))
            conn.commit(); return False, "Amount did not match; an administrator must review this payment."
        if receipt and conn.execute("SELECT 1 FROM payment_attempts WHERE receipt=? AND attempt_id<>?", (receipt, att["attempt_id"])).fetchone():
            conn.rollback(); return False, "That M-Pesa receipt was already used."
        conn.execute("UPDATE payment_attempts SET status='succeeded', receipt=?, result_code=?, result_desc=?, completed_at=? WHERE attempt_id=?",
                     (receipt, result_code[:10], (result_desc or "")[:200], stamp, att["attempt_id"]))
        if esc["status"] == "awaiting_payment":
            conn.execute("UPDATE escrows SET status='held', funded_at=?, updated_at=? WHERE escrow_id=?", (stamp, stamp, esc["escrow_id"]))
            _post(conn, esc["escrow_id"], f"payment received (attempt {att['attempt_id']})",
                  [(EXTERNAL, -att["amount_minor"]), (HELD, att["amount_minor"])])
            msg = "Payment held in escrow."
        else:
            # Money arrived for an escrow that is already funded or closed (duplicate or late payment): never keep it.
            _post(conn, esc["escrow_id"], f"extra payment received (attempt {att['attempt_id']}) - refund owed",
                  [(EXTERNAL, -att["amount_minor"]), (REFUNDABLE, att["amount_minor"])])
            conn.execute("""INSERT INTO payouts(escrow_id, kind, to_account_id, phone, amount_minor, status, note, created_at)
                            VALUES(?,?,?,?,?,'pending','duplicate or late payment',?)""",
                         (esc["escrow_id"], "refund", esc["client_account_id"], att["phone"], att["amount_minor"], stamp))
            msg = "Extra payment will be refunded."
        conn.commit()
        return True, msg
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------ deciding where the money goes
def _provider_phone(conn, account_id):
    row = conn.execute("SELECT phone FROM accounts WHERE account_id=?", (account_id,)).fetchone()
    return row["phone"] if row else ""


def _payer_phone(conn, esc):
    row = conn.execute("SELECT phone FROM payment_attempts WHERE escrow_id=? AND status='succeeded' ORDER BY attempt_id LIMIT 1",
                       (esc["escrow_id"],)).fetchone()
    return row["phone"] if row else _provider_phone(conn, esc["client_account_id"])


def _split(conn, esc, release_minor, status, memo):
    """Move held funds: `release_minor` to the provider (minus the commission), the rest back to the client."""
    amount, stamp = esc["amount_minor"], now_iso()
    refund = amount - release_minor
    fee = compute_fee(release_minor, esc["fee_bps"]) if release_minor else 0
    net = release_minor - fee
    lines = [(HELD, -amount)]
    if net:
        lines.append((PAYABLE, net))
    if fee:
        lines.append((FEES, fee))
    if refund:
        lines.append((REFUNDABLE, refund))
    _post(conn, esc["escrow_id"], memo, lines)
    if net:
        conn.execute("INSERT INTO payouts(escrow_id, kind, to_account_id, phone, amount_minor, status, created_at) VALUES(?,?,?,?,?,'pending',?)",
                     (esc["escrow_id"], "release", esc["provider_account_id"], _provider_phone(conn, esc["provider_account_id"]), net, stamp))
    if refund:
        conn.execute("INSERT INTO payouts(escrow_id, kind, to_account_id, phone, amount_minor, status, created_at) VALUES(?,?,?,?,?,'pending',?)",
                     (esc["escrow_id"], "refund", esc["client_account_id"], _payer_phone(conn, esc), refund, stamp))
    conn.execute("UPDATE escrows SET status=?, fee_minor=?, updated_at=?, closed_at=? WHERE escrow_id=?", (status, fee, stamp, stamp, esc["escrow_id"]))


def reconcile(job_id=None) -> dict:
    """Decide the fate of money based on how each job ended. Idempotent; call after job changes and from the sweeper."""
    done = {"released": 0, "refunded": 0, "voided": 0}
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        q = ("SELECT e.*, j.current_state FROM escrows e JOIN jobs j ON j.job_id=e.job_id "
             "WHERE e.status IN ('held','awaiting_payment')")
        rows = conn.execute(q + (" AND e.job_id=?" if job_id else ""), ((job_id,) if job_id else ())).fetchall()
        for esc in rows:
            state = esc["current_state"]
            if esc["status"] == "held":
                if state in DONE_STATES:
                    _split(conn, esc, esc["amount_minor"], "released", "job completed - released to provider"); done["released"] += 1
                elif state in CANCELLED_STATES:
                    _split(conn, esc, 0, "refunded", "job cancelled - refunded to client"); done["refunded"] += 1
            elif state in DONE_STATES + CANCELLED_STATES:
                conn.execute("UPDATE escrows SET status='void', updated_at=?, closed_at=? WHERE escrow_id=?", (now_iso(), now_iso(), esc["escrow_id"]))
                done["voided"] += 1
        conn.commit()
        return done
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def admin_settle(admin_id: str, escrow_id: int, release_minor, reason: str):
    """Administrator decides a disputed/finished job: `release_minor` goes to the provider, the rest is refunded."""
    from . import admin as admin_svc
    reason = (reason or "").strip()
    if len(reason) < 10:
        return False, "Please write a reason (at least 10 characters)."
    try:
        release_minor = int(release_minor)
    except (TypeError, ValueError):
        return False, "Enter the amount to release to the provider."
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        esc = conn.execute("SELECT e.*, j.current_state FROM escrows e JOIN jobs j ON j.job_id=e.job_id WHERE e.escrow_id=?", (escrow_id,)).fetchone()
        if not esc or esc["status"] != "held":
            conn.rollback(); return False, "Only money currently held in escrow can be settled."
        if esc["current_state"] != "disputed" and esc["current_state"] not in DONE_STATES + CANCELLED_STATES:
            conn.rollback(); return False, "Settle a job only when it is disputed or finished."
        if not 0 <= release_minor <= esc["amount_minor"] or release_minor % 100:
            conn.rollback(); return False, "The release amount must be a whole-shilling amount between 0 and the held total."
        _split(conn, esc, release_minor, "settled", "settled by administrator")
        admin_svc._log_admin_action(conn, admin_id, "settle_escrow", "escrow", str(escrow_id), "held",
                                    f"release {release_minor // 100} / refund {(esc['amount_minor'] - release_minor) // 100} KES", reason)
        conn.commit()
        return True, "Escrow settled. Pending payouts were created."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ------------------------------------------------------------------ paying out
def mark_payout_paid(payout_id: int, receipt: str, confirmed_by: str):
    receipt = (receipt or "").strip()
    if not RECEIPT_RE.match(receipt):
        return False, "Enter the M-Pesa (or bank) reference for this payment."
    stamp = now_iso()
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        p = conn.execute("SELECT * FROM payouts WHERE payout_id=?", (payout_id,)).fetchone()
        if not p:
            conn.rollback(); return False, "Payout not found."
        if p["status"] == "paid":
            conn.rollback(); return True, "Already marked as paid."
        if p["status"] != "pending":
            conn.rollback(); return False, "Set a failed payout back to pending before marking it paid."
        if conn.execute("SELECT 1 FROM payouts WHERE receipt=?", (receipt,)).fetchone():
            conn.rollback(); return False, "That reference was already used for another payout."
        owed = PAYABLE if p["kind"] == "release" else REFUNDABLE
        _post(conn, p["escrow_id"], f"{p['kind']} paid out (payout {payout_id})", [(owed, -p["amount_minor"]), (EXTERNAL, p["amount_minor"])])
        conn.execute("UPDATE payouts SET status='paid', receipt=?, paid_at=?, confirmed_by=? WHERE payout_id=?", (receipt, stamp, confirmed_by, payout_id))
        conn.commit()
        return True, "Payout recorded."
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_payout_failed(payout_id: int, note: str):
    conn = db.get_conn()
    try:
        cur = conn.execute("UPDATE payouts SET status='failed', note=? WHERE payout_id=? AND status='pending'", ((note or "")[:200], payout_id))
        conn.commit()
        return (True, "Marked as failed. The money is still owed.") if cur.rowcount else (False, "Only pending payouts can be marked failed.")
    finally:
        conn.close()


def retry_payout(payout_id: int):
    conn = db.get_conn()
    try:
        cur = conn.execute("UPDATE payouts SET status='pending' WHERE payout_id=? AND status='failed'", (payout_id,))
        conn.commit()
        return (True, "Payout is pending again.") if cur.rowcount else (False, "Only failed payouts can be retried.")
    finally:
        conn.close()


def audit(admin_id: str, action: str, target_type: str, target_id, before: str, after: str, reason: str):
    """Record an administrator's money action in the audit log."""
    from . import admin as admin_svc
    conn = db.get_conn()
    try:
        admin_svc._log_admin_action(conn, admin_id, action, target_type, str(target_id), before, after, (reason or "")[:500])
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------ housekeeping and reading
def expire_stale_attempts() -> int:
    cutoff = (_now() - timedelta(seconds=ATTEMPT_TTL_SECONDS)).isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        cur = conn.execute("UPDATE payment_attempts SET status='timeout', completed_at=? WHERE status='pending' AND created_at < ?", (now_iso(), cutoff))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def attempts_to_poll(min_age_seconds: int = 8, limit: int = 20):
    cutoff = (_now() - timedelta(seconds=min_age_seconds)).isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        rows = conn.execute("""SELECT attempt_id, checkout_id, gateway FROM payment_attempts
                               WHERE status='pending' AND checkout_id NOT LIKE 'PENDING-%'
                                 AND (last_polled_at='' OR last_polled_at < ?) AND created_at < ? ORDER BY attempt_id LIMIT ?""",
                            (cutoff, cutoff, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def mark_polled(attempt_id: int):
    conn = db.get_conn()
    try:
        conn.execute("UPDATE payment_attempts SET last_polled_at=? WHERE attempt_id=?", (now_iso(), attempt_id))
        conn.commit()
    finally:
        conn.close()


def get_for_job(job_id: int):
    conn = db.get_conn()
    try:
        esc = conn.execute("SELECT * FROM escrows WHERE job_id=?", (job_id,)).fetchone()
        if not esc:
            return None
        d = dict(esc)
        d["net_minor"] = esc["amount_minor"] - esc["fee_minor"]
        d["attempts"] = [dict(r) for r in conn.execute("SELECT * FROM payment_attempts WHERE escrow_id=? ORDER BY attempt_id DESC", (esc["escrow_id"],))]
        d["payouts"] = [dict(r) for r in conn.execute("SELECT * FROM payouts WHERE escrow_id=? ORDER BY payout_id", (esc["escrow_id"],))]
        return d
    finally:
        conn.close()


def list_escrows(status: str = "", limit: int = 100):
    conn = db.get_conn()
    try:
        q = """SELECT e.*, j.category, j.current_state, c.full_name AS client_name, p.full_name AS provider_name
               FROM escrows e JOIN jobs j ON j.job_id=e.job_id
               JOIN accounts c ON c.account_id=e.client_account_id JOIN accounts p ON p.account_id=e.provider_account_id"""
        args = []
        if status:
            q += " WHERE e.status=?"; args.append(status)
        return [dict(r) for r in conn.execute(q + " ORDER BY e.escrow_id DESC LIMIT ?", args + [limit])]
    finally:
        conn.close()


def list_payouts(status: str = "pending", limit: int = 200):
    conn = db.get_conn()
    try:
        q = """SELECT x.*, a.full_name AS to_name FROM payouts x JOIN accounts a ON a.account_id=x.to_account_id"""
        args = []
        if status:
            q += " WHERE x.status IN (%s)" % ",".join("?" * len(status.split(",")))
            args = status.split(",")
        return [dict(r) for r in conn.execute(q + " ORDER BY x.payout_id LIMIT ?", args + [limit])]
    finally:
        conn.close()
