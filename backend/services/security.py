"""Password hashing and verification. Stdlib only, no Qt."""
import base64
import hashlib
import hmac
import secrets


SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    """Return scrypt$N$r$p$salt$digest. Storage format only."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        dklen=32, maxmem=SCRYPT_MAXMEM,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a scrypt hash with bounded parameters and constant-time compare.

    Stored parameters are untrusted input: cap them before invoking the KDF so
    a damaged or tampered database cannot request unbounded CPU/memory.
    """
    try:
        algorithm, n_text, r_text, p_text, salt_text, digest_text = stored.split("$")
        if algorithm != "scrypt":
            return False
        n, r, p = int(n_text), int(r_text), int(p_text)
        salt = _b64d(salt_text)
        expected = _b64d(digest_text)
        if not (2**14 <= n <= 2**18 and n & (n - 1) == 0):
            return False
        if not (1 <= r <= 16 and 1 <= p <= 4):
            return False
        if not (16 <= len(salt) <= 64 and len(expected) == 32):
            return False
        if not isinstance(password, str) or len(password) > 1024:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=n, r=r, p=p, dklen=len(expected), maxmem=SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, MemoryError, OverflowError, base64.binascii.Error):
        return False


def looks_hashed(value: str) -> bool:
    """Sanity-check a stored value to detect legacy plaintext."""
    if not isinstance(value, str):
        return False
    try:
        algorithm, n, r, p, salt_text, digest_text = value.split("$")
        salt = _b64d(salt_text)
        digest = _b64d(digest_text)
        return (
            algorithm == "scrypt"
            and int(n) >= 2**14 and int(r) >= 1 and int(p) >= 1
            and len(salt) >= 16 and len(digest) == 32
        )
    except (ValueError, TypeError):
        return False


# A pre-computed dummy hash used for sign-in timing defence when the phone
# number is unknown. Computed once at import time.
DUMMY_HASH = hash_password("NotARealAccountPassword42")