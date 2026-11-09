"""Password policy, strength scoring, and suggestion generator.

Policy (NIST SP 800-63B / OWASP ASVS 2.1 style - length over complexity):
    - 12 to 72 characters (72 BYTES max: bcrypt silently ignores anything past
      72 bytes, so a longer password would be weaker than the user believes)
    - NO forced uppercase/digit/symbol rules (they push people to "Password1!")
    - Rejected: common passwords (including leetspeak variants like P@ssw0rd),
      trivial patterns (repeats, 123456/abcdef runs, keyboard walks), and
      passwords containing the user's own phone, name or email
    - Optional k-anonymity breach check (Have I Been Pwned range API), off by
      default, enabled with SERVICELINK_HIBP=1. It fails OPEN: if the network
      is unavailable the password is simply not blocked on that basis.

The policy applies to NEW or CHANGED passwords only; existing passwords keep
working and are never re-validated at sign-in.
"""
import hashlib
import os
import re
import secrets
import string
import unicodedata
import urllib.request

MIN_LENGTH = 12
MAX_LENGTH = 72
MAX_BYTES = 72
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>?/"

_COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwerty", "qwerty123", "abc123", "letmein",
    "welcome", "welcome1", "admin", "admin123", "administrator",
    "iloveyou", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "superman", "batman", "trustno1",
    "passw0rd", "p@ssw0rd", "password!", "qwertyuiop", "1q2w3e4r",
    "1qaz2wsx", "zxcvbnm", "asdfghjkl", "poiuytrewq", "987654321",
    "qwerty1", "qwerty12", "abcdefgh", "abcd1234", "welcome123",
    "adminadmin", "root", "toor", "test1234", "pass1234", "mypassword",
    "mypass", "letmein123", "changeme",
}

# Letters-only stems; a password dominated by one of these is guessable
# whatever digits/symbols are bolted on ("Nairobi#2024", "P@ssw0rd!!").
_COMMON_STEMS = {
    "password", "passw", "welcome", "admin", "administrator", "qwerty", "letmein",
    "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "superman",
    "batman", "trustno", "changeme", "secret", "login", "master", "hello", "freedom",
    "kenya", "nairobi", "mombasa", "kisumu", "nakuru", "harambee", "mpesa", "safaricom",
    "servicelink", "provider", "client", "handyman", "jesus", "blessed", "god", "mypassword",
}

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qazwsxedcrfv", "1q2w3e4r5t")
_LEET = str.maketrans({"@": "a", "0": "o", "1": "i", "3": "e", "$": "s", "5": "s", "4": "a", "7": "t", "!": "i"})


def _has_upper(s): return any(c.isupper() for c in s)
def _has_lower(s): return any(c.islower() for c in s)
def _has_digit(s): return any(c.isdigit() for c in s)
def _has_special(s): return any(not c.isalnum() for c in s)


def _classes_present(password: str) -> int:
    return sum([_has_upper(password), _has_lower(password), _has_digit(password), _has_special(password)])


def _letters_only(s: str) -> str:
    return "".join(c for c in s.casefold() if c.isalpha())


def _longest_run(s: str) -> int:
    """Longest ascending/descending run of consecutive characters (abcdef, 98765)."""
    best = cur_up = cur_down = 1
    for a, b in zip(s, s[1:]):
        cur_up = cur_up + 1 if ord(b) - ord(a) == 1 else 1
        cur_down = cur_down + 1 if ord(a) - ord(b) == 1 else 1
        best = max(best, cur_up, cur_down)
    return best


def _keyboard_walk(s: str) -> bool:
    low = s.casefold()
    for row in _KEYBOARD_ROWS:
        for chunk in (row, row[::-1]):
            for i in range(len(chunk) - 5):               # any 6-char slice of a row
                if chunk[i:i + 6] in low:
                    return True
    return False


def _is_trivial(password: str) -> str:
    """Return a reason string if the password is guessable, else ''."""
    low = password.casefold()
    if low in _COMMON_PASSWORDS or low.translate(_LEET) in _COMMON_PASSWORDS:
        return "That password is too common. Choose another."
    if len(set(low)) <= 3:
        return "That password repeats the same few characters. Choose another."
    if _longest_run(low) >= max(6, int(len(low) * 0.6)):
        return "That password is a simple sequence. Choose another."
    if _keyboard_walk(low):
        return "That password follows a keyboard pattern. Choose another."
    stem = _letters_only(low.translate(_LEET))
    if stem in _COMMON_STEMS:
        return "That password is too common. Choose another."
    for common in _COMMON_STEMS:
        if len(common) >= 5 and common in stem and len(common) >= 0.6 * len(stem):
            return "That password is too easy to guess. Choose another."
    # Built entirely from common words ("kenyakenya", "welcomekenya", "passwordadmin").
    leftover = stem
    for common in sorted(_COMMON_STEMS, key=len, reverse=True):
        if len(common) >= 4:
            leftover = leftover.replace(common, "")
    if len(stem) >= 4 and len(leftover) <= 2:
        return "That password is made of common words. Choose another."
    return ""


def _context_tokens(context):
    tokens = []
    for item in context or ():
        text = unicodedata.normalize("NFKC", str(item or "")).casefold().strip()
        if "@" in text:
            text = text.split("@", 1)[0]
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 7:
            tokens.append(("digits", digits[-9:]))
        for part in re.split(r"[^\w]+", text):
            if len(part) >= 4 and not part.isdigit():
                tokens.append(("text", part))
    return tokens


def _breach_check_enabled() -> bool:
    return os.environ.get("SERVICELINK_HIBP", "0") == "1"


def _default_fetch(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"Add-Padding": "true", "User-Agent": "ServiceLink-password-check"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed https host
        return resp.read().decode("utf-8", "replace")


def breach_count(password: str, fetch=None, timeout: float = 3.0):
    """Times this password appears in known breaches, or None if unknown.

    k-anonymity: only the first 5 hex chars of the SHA-1 leave this machine.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()   # nosec - protocol requirement
    prefix, suffix = digest[:5], digest[5:]
    try:
        body = (fetch or _default_fetch)(f"https://api.pwnedpasswords.com/range/{prefix}", timeout)
    except Exception:
        return None
    for line in body.splitlines():
        tail, _, count = line.strip().partition(":")
        if tail.upper() == suffix:
            try:
                return int(count)
            except ValueError:
                return 1
    return 0


def validate_password(password: str, context=(), fetch=None):
    """Return (ok, message). Message is empty on success.

    `context` is an iterable of the user's own identifiers (phone, full name,
    email) that must not appear inside the password.
    """
    if not password:
        return False, "Password is required."
    if len(password) < MIN_LENGTH:
        return False, f"Use at least {MIN_LENGTH} characters. A short phrase of unrelated words works well."
    if len(password) > MAX_LENGTH or len(password.encode("utf-8")) > MAX_BYTES:
        return False, f"Password must be {MAX_LENGTH} characters or fewer."
    reason = _is_trivial(password)
    if reason:
        return False, reason
    low = password.casefold()
    pw_digits = re.sub(r"\D", "", password)
    for kind, token in _context_tokens(context):
        if (kind == "digits" and token in pw_digits) or (kind == "text" and token in low):
            return False, "Don't use your name, phone number or email inside your password."
    if _breach_check_enabled():
        count = breach_count(password, fetch=fetch)
        if count:
            return False, "That password appeared in a known data breach. Choose another."
    return True, ""


def strength(password: str) -> str:
    """Return 'weak' | 'fair' | 'strong' (length-led, matching the policy).

    weak   - fails the policy basics (too short or guessable)
    fair   - passes the policy
    strong - 16+ characters, or 12+ with three or more character types
    """
    if not password or len(password) < MIN_LENGTH or len(password.encode("utf-8")) > MAX_BYTES:
        return "weak"
    if _is_trivial(password):
        return "weak"
    if len(password) >= 16 or _classes_present(password) >= 3:
        return "strong"
    return "fair"


def suggest(length: int = 16) -> str:
    """Return a strong random password that satisfies the policy."""
    length = max(MIN_LENGTH, min(length, MAX_LENGTH))
    lower, upper, digits, specials = string.ascii_lowercase, string.ascii_uppercase, string.digits, SPECIAL_CHARS
    alphabet = lower + upper + digits + specials
    while True:
        chars = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits), secrets.choice(specials)]
        while len(chars) < length:
            chars.append(secrets.choice(alphabet))
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]
        candidate = "".join(chars)
        if not _is_trivial(candidate):
            return candidate
