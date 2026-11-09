"""Pure input validation. No DB, no Qt."""
import re
from datetime import datetime, timezone


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_DIGITS_RE = re.compile(r"^(?:\+254|254|0)(7\d{8})$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def required(fields: dict):
    """Return (ok, message). fields maps label -> value."""
    missing = [k for k, v in fields.items() if not str(v or "").strip()]
    if missing:
        return False, "Please fill: " + ", ".join(missing)
    return True, ""


def normalize_ke_phone(raw: str):
    """Accept 07XXXXXXXX, +2547XXXXXXXX, 2547XXXXXXXX.
    Return (ok, normalized_07XXXXXXXX_or_error)."""
    if not raw:
        return False, "Phone number is required."
    s = re.sub(r"[\s\-()]", "", str(raw).strip())
    m = PHONE_DIGITS_RE.fullmatch(s)
    if not m:
        return False, "Enter a valid Kenyan mobile number (07XXXXXXXX or +2547XXXXXXXX)."
    return True, "0" + m.group(1)


def format_ke_phone(digits: str) -> str:
    s = re.sub(r"\D", "", digits or "")
    if len(s) == 10 and s.startswith("07"):
        return f"{s[:4]} {s[4:7]} {s[7:]}"
    return digits or ""


def validate_email(email: str):
    """Empty is allowed. Non-empty must be a valid address."""
    value = (email or "").strip()
    if not value:
        return True, ""
    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        return False, "Enter a valid email address."
    return True, value.lower()


def parse_iso(value):
    """Parse an ISO 8601 string; return None if invalid."""
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


_INVISIBLE = None


def clean_text(value) -> str:
    """Normalise user-supplied free text before storing or screening it.

    NFC-normalises, then removes control characters, zero-width characters and
    bidirectional overrides (used to hide contact details from filters and to
    visually spoof text). Newlines and tabs are kept.
    """
    global _INVISIBLE
    import re
    import unicodedata
    if _INVISIBLE is None:
        _INVISIBLE = re.compile(
            "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
    return _INVISIBLE.sub("", unicodedata.normalize("NFC", str(value or "")))
