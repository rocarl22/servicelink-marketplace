"""Accounts: create, sign in, profile, password, holds, photo."""
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from .. import database as db
from . import passwords
from .validation import (
    required, normalize_ke_phone, now_iso, parse_iso,
)


log = logging.getLogger("servicelink.accounts")


DEFAULT_HOLD_HOURS = 24
MAX_DISPLAY_NAME_LEN = 60
MAX_AREA_LEN = 100
MAX_BIO_LEN = 500
MAX_PHOTO_PATH_LEN = 500

# PBKDF2 parameters. 200k iterations is OWASP's 2024 recommendation
# for PBKDF2-HMAC-SHA256.
_PBKDF2_ITERATIONS = 200_000
_PBKDF2_DKLEN = 32


# ------------------------------------------------------------------
# Password hashing
# ------------------------------------------------------------------

# Hash schemes, best first. New hashes use the best scheme available on this
# machine; older hashes keep verifying and are upgraded after a successful
# sign-in (never downgraded).
_RANK = {"argon2id": 4, "bcrypt": 3, "scrypt": 2, "pbkdf2": 1, "plaintext": 0}
_ARGON2_PARAMS = {"time_cost": 2, "memory_cost": 19456, "parallelism": 1}   # OWASP minimum for Argon2id
_BCRYPT_MIN_COST = 12
_BCRYPT_MAX_BYTES = 72


def _argon2_hasher():
    try:
        from argon2 import PasswordHasher
    except ImportError:
        return None
    return PasswordHasher(**_ARGON2_PARAMS)        # argon2-cffi default type is Argon2id


def _bcrypt_module():
    try:
        import bcrypt
        return bcrypt
    except ImportError:
        return None


def current_scheme() -> str:
    """Best password-hash scheme available on this machine."""
    if _argon2_hasher() is not None:
        return "argon2id"
    if _bcrypt_module() is not None:
        return "bcrypt"
    return "pbkdf2"


def scheme_of(stored: str) -> str:
    value = stored or ""
    if value.startswith("$argon2"):
        return "argon2id"
    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if value.startswith("scrypt$"):
        return "scrypt"
    if value.startswith("pbkdf2_sha256$"):
        return "pbkdf2"
    return "plaintext"


def needs_rehash(stored: str) -> bool:
    """True if `stored` should be replaced by a fresh hash after a successful login."""
    scheme, best = scheme_of(stored), current_scheme()
    if _RANK[scheme] < _RANK[best]:
        return True
    if scheme == "argon2id":
        ph = _argon2_hasher()
        try:
            return bool(ph and ph.check_needs_rehash(stored))
        except Exception:
            return False
    if scheme == "bcrypt":
        try:
            return int(stored.split("$")[2]) < _BCRYPT_MIN_COST
        except (IndexError, ValueError):
            return True
    if scheme == "pbkdf2":
        try:
            return int(stored.split("$")[1]) < _PBKDF2_ITERATIONS
        except (IndexError, ValueError):
            return True
    return False


def _legacy_plaintext_allowed() -> bool:
    """Plaintext credentials are refused unless an operator explicitly opts in
    for a one-off migration (SERVICELINK_ALLOW_LEGACY_PLAINTEXT=1)."""
    return os.environ.get("SERVICELINK_ALLOW_LEGACY_PLAINTEXT", "0") == "1"


def _hash_password(password: str) -> str:
    """Hash a password with the best available scheme: Argon2id, else bcrypt,
    else PBKDF2-HMAC-SHA256 (pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>)."""
    if not password:
        raise ValueError("password is required")

    ph = _argon2_hasher()
    if ph is not None:
        return ph.hash(password)

    bcrypt = _bcrypt_module()
    if bcrypt is not None:
        raw = password.encode("utf-8")
        if len(raw) > _BCRYPT_MAX_BYTES:       # bcrypt would silently ignore the rest
            raise ValueError("password is too long")
        return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=_BCRYPT_MIN_COST)).decode("ascii")

    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             _PBKDF2_ITERATIONS, dklen=_PBKDF2_DKLEN)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def _check_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash. Constant-time compare."""
    if not password or not stored:
        return False

    if stored.startswith("$argon2"):
        ph = _argon2_hasher()
        if ph is None:
            log.warning("argon2 hash in DB but argon2-cffi not installed")
            return False
        try:
            return bool(ph.verify(stored, password))
        except Exception:                       # mismatch / invalid hash / verification error
            return False

    if stored.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode("utf-8"), stored.encode("ascii"))
        except ImportError:
            log.warning("bcrypt hash in DB but bcrypt not installed")
            return False
        except ValueError:
            return False

    # scrypt hashes from earlier project versions must remain usable.
    if stored.startswith("scrypt$"):
        from .security import verify_password
        return verify_password(password, stored)

    # PBKDF2. Bound stored parameters before invoking the KDF.
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters_s, salt_b64, hash_b64 = stored.split("$", 3)
            iters = int(iters_s)
            salt = base64.b64decode(salt_b64, validate=True)
            expected = base64.b64decode(hash_b64, validate=True)
        except (ValueError, base64.binascii.Error):
            return False
        if not (100_000 <= iters <= 2_000_000 and 16 <= len(salt) <= 64
                and len(expected) == _PBKDF2_DKLEN):
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                     salt, iters, dklen=len(expected))
        return hmac.compare_digest(actual, expected)

    # Legacy plaintext: refused by default. Operators with old data can opt in
    # temporarily; the credential is upgraded to a real hash on first success.
    if _legacy_plaintext_allowed():
        return hmac.compare_digest(password, stored)
    return False


def _is_supported_password_hash(stored: str) -> bool:
    value = stored or ""
    return value.startswith(("$argon2", "$2a$", "$2b$", "$2y$", "pbkdf2_sha256$", "scrypt$"))


_DUMMY_STORED = None


def _dummy_verify(password: str) -> None:
    """Burn the same CPU as a real verification so unknown phone numbers /
    usernames cannot be told apart from wrong passwords by response time.
    (The old scrypt dummy was much cheaper than a real bcrypt check.)"""
    global _DUMMY_STORED
    if _DUMMY_STORED is None:
        _DUMMY_STORED = _hash_password(secrets.token_urlsafe(18))
    _check_password(password or "x", _DUMMY_STORED)


def _identity_context(account_id: str):
    """The user's own identifiers, which must not appear inside their password."""
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT full_name, phone, email FROM accounts WHERE account_id=?",
                           (account_id,)).fetchone()
        return tuple(row) if row else ()
    except Exception:
        return ()
    finally:
        conn.close()


def _new_account_id(role: str) -> str:
    prefix = "C-" if role == "client" else "P-"
    return prefix + uuid.uuid4().hex[:10].upper()


def get_account(account_id: str) -> dict:
    """Return the account's public fields, or {}."""
    if not account_id:
        return {}
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT account_id, role, role_locked, full_name, phone, email,
                      display_name, area, bio, work_photo_path, service_family,
                      capacity, account_status, password_upgrade_required,
                      password_warning_seen, setup_complete, phone_verified_at,
                      created_at, updated_at
               FROM accounts WHERE account_id=?""",
            (account_id,),
        ).fetchone()
        if not row:
            return {}
        d = dict(row)
        d["phone_display"] = _format_phone(d.get("phone") or "")
        return d
    finally:
        conn.close()


def _format_phone(digits: str) -> str:
    s = re.sub(r"\D", "", digits or "")
    if len(s) == 10 and s.startswith("07"):
        return f"{s[:4]} {s[4:7]} {s[7:]}"
    return digits or ""


# ------------------------------------------------------------------
# Signup / sign-in
# ------------------------------------------------------------------

def create_account(role: str, full_name: str, phone: str, email: str,
                   password: str, password_confirm: str,
                   terms_accepted: bool, role_locked: bool,
                   service_family: str, device_key: str):
    role = (role or "").strip().lower()
    full_name = " ".join((full_name or "").split())
    email = (email or "").strip()
    service_family = (service_family or "").strip()

    if role not in ("client", "provider"):
        return False, "Choose whether you are a client or a provider."
    if not terms_accepted:
        return False, "Please accept the terms to continue."

    ok, msg = required({
        "Full name": full_name,
        "Phone": phone,
        "Password": password,
        "Confirm password": password_confirm,
    })
    if not ok:
        return False, msg

    if len(full_name) > MAX_DISPLAY_NAME_LEN:
        return False, f"Name must be {MAX_DISPLAY_NAME_LEN} characters or fewer."

    if password != password_confirm:
        return False, "Passwords do not match."

    # Full password policy - length, common/guessable patterns, own phone/name/email
    ok, msg = passwords.validate_password(password, context=(full_name, phone, email))
    if not ok:
        return False, msg

    ok, pnorm = normalize_ke_phone(phone)
    if not ok:
        return False, pnorm

    if role == "provider" and not service_family:
        return False, "Choose the service family you provide."

    from . import machine_id as _mi
    os_user = device_key or ""

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT 1 FROM accounts WHERE phone=?", (pnorm,)
        ).fetchone()
        if row:
            conn.rollback()
            return False, "This phone number already has an account."

        if email:
            row = conn.execute(
                "SELECT 1 FROM accounts WHERE lower(email)=lower(?) AND email <> ''",
                (email,),
            ).fetchone()
            if row:
                conn.rollback()
                return False, "This email is already registered."

        now = now_iso()
        account_id = _new_account_id(role)
        conn.execute(
            """INSERT INTO accounts(
                account_id, role, role_locked, full_name, phone, email,
                password_hash, display_name, area, bio, work_photo_path,
                service_family, capacity, account_status,
                password_upgrade_required, password_warning_seen,
                setup_complete, created_by_os_user, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (account_id, role, 1 if role_locked else 0, full_name, pnorm,
             email, _hash_password(password),
             full_name, "", "", "",
             service_family, 1, "active",
             0, 0,
             0, os_user, now, now),
        )
        conn.commit()
        return True, account_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def sign_in(phone: str, password: str, device_key: str):
    ok, pnorm = normalize_ke_phone(phone)
    if not ok:
        return False, "Enter a valid Kenyan phone number."

    # Rate-limit attempts by a one-way phone identifier so raw phone numbers
    # are never written into the rate-limit table.
    from . import ratelimit, security
    phone_key = hashlib.sha256(pnorm.encode("utf-8")).hexdigest()
    try:
        allowed, _remaining = ratelimit.consume(
            f"login:phone:{phone_key}", max_count=30, window_seconds=900
        )
    except Exception:
        log.exception("Login rate-limit check failed")
        return False, "Sign-in is temporarily unavailable. Please try again."
    if not allowed:
        # Keep the response generic to avoid revealing whether the account exists.
        return False, "The phone number or password is incorrect. Try again later."

    conn = db.get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM accounts WHERE phone=?", (pnorm,)
        ).fetchone()
        if not row:
            # Match the cost of a real hash verification for unknown accounts.
            _dummy_verify(password)
            conn.rollback()
            return False, "The phone number or password is incorrect."

        locked_until = parse_iso(row["locked_until"] or "")
        if locked_until and datetime.now(timezone.utc) < locked_until:
            conn.rollback()
            return False, "Account temporarily locked. Try again later."

        if not _check_password(password, row["password_hash"]):
            # BEGIN IMMEDIATE above serializes attempts so simultaneous failures
            # cannot lose increments. Use progressive temporary lockouts.
            failed = int(row["failed_login_count"] or 0) + 1
            lock_minutes = 0
            if failed >= 15:
                lock_minutes = 60
            elif failed >= 10:
                lock_minutes = 15
            elif failed >= 5:
                lock_minutes = 5
            new_lock = ""
            if lock_minutes:
                new_lock = (datetime.now(timezone.utc)
                            + timedelta(minutes=lock_minutes)).isoformat(timespec="seconds")
            conn.execute(
                """UPDATE accounts
                   SET failed_login_count=?, locked_until=?, updated_at=?
                   WHERE account_id=?""",
                (failed, new_lock, now_iso(), row["account_id"]),
            )
            conn.commit()
            if new_lock:
                return False, "Too many failed attempts. Account temporarily locked; try again later."
            return False, "The phone number or password is incorrect."

        status = row["account_status"] or "active"
        if status == "closed":
            conn.rollback()
            return False, "This account is closed."
        if status == "suspended":
            conn.rollback()
            return False, "This account is suspended."
        if status == "restricted":
            conn.rollback()
            return False, "This account is currently restricted."

        # Upgrade any legacy/weaker hash only after a successful comparison;
        # never store a plaintext password, never downgrade a stronger hash.
        stored_hash = row["password_hash"] or ""
        if needs_rehash(stored_hash):
            conn.execute(
                """UPDATE accounts SET password_hash=?, failed_login_count=0,
                   locked_until='', updated_at=? WHERE account_id=?""",
                (_hash_password(password), now_iso(), row["account_id"]),
            )
        else:
            conn.execute(
                """UPDATE accounts
                   SET failed_login_count = 0, locked_until = '', updated_at=?
                   WHERE account_id=?""",
                (now_iso(), row["account_id"]),
            )
        conn.commit()
        return True, row["account_id"]
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def expire_stale_holds():
    """Clear on_hold status when the window passes."""
    now = now_iso()
    conn = db.get_conn()
    try:
        conn.execute(
            """UPDATE accounts
               SET account_status = COALESCE(NULLIF(on_hold_prev_status, ''), 'active'),
                   on_hold_until = '', on_hold_reason = '',
                   on_hold_prev_status = '', updated_at = ?
               WHERE account_status='on_hold'
                 AND on_hold_until <> ''
                 AND on_hold_until <= ?""",
            (now, now),
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------
# Profile
# ------------------------------------------------------------------

def save_profile_draft(account_id: str, display_name: str, area: str,
                       bio: str, role: str, service_family: str):
    display_name = " ".join((display_name or "").split())
    area = " ".join((area or "").split())
    bio = (bio or "").strip()
    role = (role or "").strip().lower()
    service_family = (service_family or "").strip()

    if len(display_name) > MAX_DISPLAY_NAME_LEN:
        return False, f"Display name must be {MAX_DISPLAY_NAME_LEN} characters or fewer."
    if len(area) > MAX_AREA_LEN:
        return False, f"Area must be {MAX_AREA_LEN} characters or fewer."
    if len(bio) > MAX_BIO_LEN:
        return False, f"Bio must be {MAX_BIO_LEN} characters or fewer."

    if not display_name:
        return False, "Display name is required."
    if not area:
        return False, "Area is required."

    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if not row:
            return False, "Account not found."

        conn.execute(
            """UPDATE accounts
               SET display_name=?, area=?, bio=?, service_family=?, updated_at=?
               WHERE account_id=?""",
            (display_name, area, bio,
             service_family if row["role"] == "provider" else "",
             now_iso(), account_id),
        )
        conn.commit()
        return True, "Draft saved."
    finally:
        conn.close()


def complete_profile(account_id: str, display_name: str, area: str, bio: str,
                     work_photo_path: str, role: str, service_family: str):
    display_name = " ".join((display_name or "").split())
    area = " ".join((area or "").split())
    bio = (bio or "").strip()
    work_photo_path = (work_photo_path or "").strip()
    service_family = (service_family or "").strip()

    if not display_name:
        return False, "Display name is required."
    if not area:
        return False, "Area is required."
    if len(display_name) > MAX_DISPLAY_NAME_LEN:
        return False, f"Display name must be {MAX_DISPLAY_NAME_LEN} characters or fewer."
    if len(area) > MAX_AREA_LEN:
        return False, f"Area must be {MAX_AREA_LEN} characters or fewer."
    if len(bio) > MAX_BIO_LEN:
        return False, f"Bio must be {MAX_BIO_LEN} characters or fewer."
    if len(work_photo_path) > MAX_PHOTO_PATH_LEN:
        return False, "Photo path is too long."

    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT role FROM accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if not row:
            return False, "Account not found."
        actual_role = row["role"]

        if actual_role == "provider" and not service_family:
            return False, "Choose the service family you provide."

        conn.execute(
            """UPDATE accounts
               SET display_name=?, area=?, bio=?, work_photo_path=?,
                   service_family=?, setup_complete=1, updated_at=?
               WHERE account_id=?""",
            (display_name, area, bio, work_photo_path,
             service_family if actual_role == "provider" else "",
             now_iso(), account_id),
        )
        conn.commit()
        return True, "Profile saved."
    finally:
        conn.close()


def update_profile(account_id: str, display_name: str, area: str,
                   bio: str, work_photo_path: str):
    """Edit an existing profile without touching service_family or setup state."""
    display_name = " ".join((display_name or "").split())
    area = " ".join((area or "").split())
    bio = (bio or "").strip()
    work_photo_path = (work_photo_path or "").strip()

    if not display_name:
        return False, "Display name is required."
    if not area:
        return False, "Area is required."
    if len(display_name) > MAX_DISPLAY_NAME_LEN:
        return False, f"Display name must be {MAX_DISPLAY_NAME_LEN} characters or fewer."
    if len(area) > MAX_AREA_LEN:
        return False, f"Area must be {MAX_AREA_LEN} characters or fewer."
    if len(bio) > MAX_BIO_LEN:
        return False, f"Bio must be {MAX_BIO_LEN} characters or fewer."
    if len(work_photo_path) > MAX_PHOTO_PATH_LEN:
        return False, "Photo path is too long."

    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT account_id FROM accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if not row:
            return False, "Account not found."

        conn.execute(
            """UPDATE accounts
               SET display_name=?, area=?, bio=?, work_photo_path=?, updated_at=?
               WHERE account_id=?""",
            (display_name, area, bio, work_photo_path, now_iso(), account_id),
        )
        conn.commit()
        return True, "Profile updated."
    finally:
        conn.close()


def get_account_summary(account_id: str) -> dict:
    """Return aggregated profile + activity stats for the Profile screen."""
    if not account_id:
        return {}
    conn = db.get_conn()
    try:
        row = conn.execute(
            """SELECT account_id, role, full_name, phone, email, display_name,
                      area, bio, work_photo_path, service_family, account_status,
                      created_at, setup_complete
               FROM accounts WHERE account_id=?""",
            (account_id,),
        ).fetchone()
        if not row:
            return {}
        d = dict(row)
        d["phone_display"] = _format_phone(d.get("phone") or "")

        d["completed_jobs"] = conn.execute(
            """SELECT COUNT(*) AS n FROM jobs
               WHERE (client_account_id=? OR provider_account_id=?)
                 AND current_state IN ('completed','completed_by_timeout')""",
            (account_id, account_id),
        ).fetchone()["n"]

        d["cancelled_jobs"] = conn.execute(
            """SELECT COUNT(*) AS n FROM jobs
               WHERE (client_account_id=? OR provider_account_id=?)
                 AND current_state IN ('cancelled','abandoned')""",
            (account_id, account_id),
        ).fetchone()["n"]

        d["active_jobs"] = conn.execute(
            """SELECT COUNT(*) AS n FROM jobs
               WHERE (client_account_id=? OR provider_account_id=?)
                 AND closed_at=''
                 AND current_state NOT IN ('cancelled','abandoned','disputed')""",
            (account_id, account_id),
        ).fetchone()["n"]

        rrow = conn.execute(
            """SELECT AVG(CAST(stars AS REAL)) AS avg_stars, COUNT(*) AS n
               FROM reviews WHERE reviewee_account_id=?""",
            (account_id,),
        ).fetchone()
        d["review_count"] = rrow["n"] if rrow else 0
        d["avg_stars"] = float(rrow["avg_stars"]) if rrow and rrow["avg_stars"] is not None else 0.0

        return d
    finally:
        conn.close()


# ------------------------------------------------------------------
# Password
# ------------------------------------------------------------------

def change_password(account_id: str, current_password: str,
                    new_password: str, confirmation: str):
    if not current_password:
        return False, "Enter your current password."
    if not new_password:
        return False, "Enter a new password."
    if new_password != confirmation:
        return False, "New passwords do not match."

    ok, msg = passwords.validate_password(new_password, context=_identity_context(account_id))
    if not ok:
        return False, msg

    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT password_hash FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            return False, "Account not found."
        if not _check_password(current_password, row["password_hash"]):
            return False, "Current password is incorrect."

        conn.execute(
            """UPDATE accounts
               SET password_hash=?, password_upgrade_required=0, updated_at=?
               WHERE account_id=?""",
            (_hash_password(new_password), now_iso(), account_id),
        )
        conn.commit()
        return True, "Password updated."
    finally:
        conn.close()


def get_account_by_phone(phone: str) -> dict:
    """Account for a Kenyan phone number in any accepted format, or {}."""
    from .validation import normalize_ke_phone
    ok, normalized = normalize_ke_phone(phone)
    if not ok:
        return {}
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT account_id FROM accounts WHERE phone=?", (normalized,)).fetchone()
    finally:
        conn.close()
    return get_account(row["account_id"]) if row else {}


def mark_phone_verified(account_id: str) -> bool:
    conn = db.get_conn()
    try:
        cur = conn.execute("UPDATE accounts SET phone_verified_at=?, updated_at=? WHERE account_id=?",
                           (now_iso(), now_iso(), account_id))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def verified_ids(account_ids) -> set:
    """Which of these accounts have a verified phone number."""
    ids = [i for i in account_ids if i]
    if not ids:
        return set()
    conn = db.get_conn()
    try:
        marks = ",".join("?" * len(ids))
        rows = conn.execute(f"SELECT account_id FROM accounts WHERE phone_verified_at<>'' AND account_id IN ({marks})", ids).fetchall()
        return {r["account_id"] for r in rows}
    finally:
        conn.close()


def reset_password(account_id: str, new_password: str, confirmation: str):
    """Set a new password after the caller has proven control of the phone (one-time code).

    Applies the normal password policy, clears sign-in lockouts and the forced-change flag.
    Suspended/closed accounts cannot use this path.
    """
    if new_password != confirmation:
        return False, "The two passwords do not match."
    ok, msg = passwords.validate_password(new_password, context=_identity_context(account_id))
    if not ok:
        return False, msg
    conn = db.get_conn()
    try:
        row = conn.execute("SELECT account_status FROM accounts WHERE account_id=?", (account_id,)).fetchone()
        if not row or row["account_status"] in ("suspended", "closed"):
            return False, "This account can't be reset here. Please contact an administrator."
        conn.execute(
            """UPDATE accounts SET password_hash=?, password_upgrade_required=0,
               failed_login_count=0, locked_until='', updated_at=? WHERE account_id=?""",
            (_hash_password(new_password), now_iso(), account_id))
        conn.commit()
        return True, "Password updated."
    finally:
        conn.close()


def mark_password_warning_seen(account_id: str) -> bool:
    conn = db.get_conn()
    try:
        conn.execute(
            """UPDATE accounts SET password_warning_seen=1, updated_at=?
               WHERE account_id=?""",
            (now_iso(), account_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


# ------------------------------------------------------------------
# Profile photo
# ------------------------------------------------------------------

def _delete_photo_file(path: str):
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        log.exception("Could not remove profile photo file")


def set_work_photo(account_id: str, src_path: str):
    """Copy a source image into the profile_photos dir, strip EXIF,
    re-encode, and store the new path on the account.

    Replaces any previously stored photo (the old file is deleted).
    Returns (ok, new_path_or_error).
    """
    src_path = (src_path or "").strip()
    if src_path.startswith("file:///"):
        src_path = src_path[8:]
    elif src_path.startswith("file://"):
        src_path = src_path[7:]
    if not src_path or not os.path.exists(src_path):
        return False, "Pick a photo to upload."

    conn = db.get_conn()
    old_path = ""
    try:
        row = conn.execute(
            "SELECT work_photo_path FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            return False, "Account not found."
        old_path = row["work_photo_path"] or ""
    finally:
        conn.close()

    photo_dir = os.path.join(db.DATA_DIR, "profile_photos")
    os.makedirs(photo_dir, exist_ok=True)
    fname = f"{account_id}_{uuid.uuid4().hex[:8]}.jpg"
    dst = os.path.join(photo_dir, fname)

    from ..face_screen import prepare_profile_image
    ok, msg = prepare_profile_image(src_path, dst)
    if not ok:
        return False, msg

    conn = db.get_conn()
    try:
        conn.execute(
            """UPDATE accounts SET work_photo_path=?, updated_at=?
               WHERE account_id=?""",
            (dst, now_iso(), account_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        try:
            if os.path.exists(dst):
                os.remove(dst)
        except Exception:
            pass
        raise
    finally:
        conn.close()

    if old_path and old_path != dst:
        _delete_photo_file(old_path)

    return True, dst


def remove_work_photo(account_id: str):
    """Clear the account's profile photo and delete the file."""
    conn = db.get_conn()
    old_path = ""
    try:
        row = conn.execute(
            "SELECT work_photo_path FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            return False, "Account not found."
        old_path = row["work_photo_path"] or ""

        if not old_path:
            return False, "No photo to remove."

        conn.execute(
            """UPDATE accounts SET work_photo_path='', updated_at=?
               WHERE account_id=?""",
            (now_iso(), account_id),
        )
        conn.commit()
    finally:
        conn.close()

    _delete_photo_file(old_path)
    return True, "Profile photo removed."