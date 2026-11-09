"""One-time codes (SMS) for phone verification and password reset. Stdlib only.

Rules, chosen to make guessing and SMS abuse unprofitable:
- 6 digits from a CSPRNG, valid 10 minutes, single use
- at most 5 wrong guesses per code (the attempt is counted BEFORE comparing, so
  parallel requests cannot squeeze in extra guesses)
- asking for a new code invalidates the old one; 60 s between codes; 5 codes per hour
- only a salted hash of the code is stored (plus an optional server-side pepper)
- verification failures all return the same message (no hint about which part was wrong)
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from .. import database as db
from .validation import now_iso, parse_iso

PURPOSES = ("verify_phone", "reset_password")
CODE_TTL_SECONDS = 10 * 60
MAX_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 60
MAX_CODES_PER_HOUR = 5
GENERIC_FAIL = "That code isn't right or has expired. Check the latest message and try again."

_now = lambda: datetime.now(timezone.utc)      # noqa: E731  (injectable for tests)


def _hash(code: str, salt: str, pepper: str) -> str:
    return hashlib.sha256(f"{pepper}|{salt}|{code}".encode("utf-8")).hexdigest()


def issue(account_id: str, purpose: str, phone: str, pepper: str = ""):
    """Create a code. Returns (True, code) or (False, user_message)."""
    if purpose not in PURPOSES:
        raise ValueError("unknown purpose")
    now = _now()
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT created_at FROM otp_codes WHERE account_id=? AND purpose=? ORDER BY created_at DESC",
            (account_id, purpose)).fetchall()
        times = [parse_iso(r["created_at"]) for r in rows]
        if times and times[0] and (now - times[0]).total_seconds() < RESEND_COOLDOWN_SECONDS:
            conn.rollback()
            return False, "Please wait a minute before asking for another code."
        if sum(1 for t in times if t and (now - t).total_seconds() < 3600) >= MAX_CODES_PER_HOUR:
            conn.rollback()
            return False, "Too many codes requested. Please try again in an hour."
        conn.execute("UPDATE otp_codes SET consumed_at=? WHERE account_id=? AND purpose=? AND consumed_at=''",
                     (now.isoformat(timespec="seconds"), account_id, purpose))
        code = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_hex(8)
        conn.execute(
            """INSERT INTO otp_codes(account_id, purpose, phone, code_hash, salt, created_at, expires_at)
               VALUES(?,?,?,?,?,?,?)""",
            (account_id, purpose, phone, _hash(code, salt, pepper), salt, now.isoformat(timespec="seconds"),
             (now + timedelta(seconds=CODE_TTL_SECONDS)).isoformat(timespec="seconds")))
        conn.commit()
        return True, code
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def verify(account_id: str, purpose: str, code: str, pepper: str = ""):
    """Check a code. Returns (True, '') or (False, message). A correct code is consumed."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    now = _now()
    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT * FROM otp_codes WHERE account_id=? AND purpose=? AND consumed_at=''
               ORDER BY created_at DESC, otp_id DESC LIMIT 1""", (account_id, purpose)).fetchone()
        expires = parse_iso(row["expires_at"]) if row else None
        if not row or not expires or now >= expires or row["attempts"] >= MAX_ATTEMPTS:
            conn.rollback()
            return False, GENERIC_FAIL
        conn.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE otp_id=?", (row["otp_id"],))
        if len(code) == 6 and hmac.compare_digest(_hash(code, row["salt"], pepper), row["code_hash"]):
            conn.execute("UPDATE otp_codes SET consumed_at=? WHERE otp_id=?", (now.isoformat(timespec="seconds"), row["otp_id"]))
            conn.commit()
            return True, ""
        conn.commit()
        return False, GENERIC_FAIL
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def purge(days: int = 2):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        conn.execute("DELETE FROM otp_codes WHERE created_at < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()
