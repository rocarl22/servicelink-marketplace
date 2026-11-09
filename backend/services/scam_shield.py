"""Chat scam shield: hide contact details and flag off-platform payment talk.

Pure functions, no Qt/DB, so the future web API reuses them unchanged.
Masking keeps both parties on-platform (where escrow, reviews and dispute
evidence protect them). Set SERVICELINK_MASK_CONTACTS=0 to disable masking.
"""
import os
import re
import unicodedata
from dataclasses import dataclass

MASK = "[contact hidden]"

_EMAIL = re.compile(
    r"[A-Za-z0-9._%+\-]+\s*(?:@|\[at\]|\(at\))\s*[A-Za-z0-9\-]+"
    r"(?:\s*(?:\.|\[dot\]|\(dot\))\s*[A-Za-z0-9\-]+)*\s*(?:\.|\[dot\]|\(dot\))\s*[A-Za-z]{2,}",
    re.IGNORECASE)
_URL = re.compile(
    r"(?:https?://|www\.)\S+|\b(?:wa\.me|t\.me|bit\.ly|tinyurl\.com)/\S*"
    r"|\b[a-z0-9\-]{2,}\.(?:com|net|org|co\.ke|ke|io|me|app|link|info)\b(?:/\S*)?",
    re.IGNORECASE)
_PHONE_KE = re.compile(r"(?<!\d)(?:\+?254|0)[\s.\-]?[17]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}(?!\d)")
_PHONE_INTL = re.compile(r"(?<![\w])\+\d[\d\s.\-()]{7,}\d(?!\d)")
_DIGIT_WORDS = re.compile(
    r"\b(?:(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)[\s,.\-]*){7,}",
    re.IGNORECASE)

_PAYMENT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"\bpay\s+(?:me\s+)?(?:directly|outside|cash|in\s+cash)\b",
    r"\b(?:send|pay|deposit|transfer)\s+(?:it\s+)?(?:to\s+)?(?:my\s+)?(?:m-?pesa|mpesa|till|paybill|bank|account)\b",
    r"\b(?:till|paybill|pay\s*bill)\s*(?:number|no\.?)?\s*[:#]?\s*\d{4,}",
    r"\boutside\s+(?:of\s+)?(?:the\s+)?(?:app|platform|servicelink)\b",
    r"\b(?:advance|upfront|deposit)\s+(?:payment|fee|first)\b",
    r"\bcash\s+only\b",
    r"\b(?:don'?t|do\s+not|no\s+need\s+to)\s+use\s+(?:the\s+)?(?:app|platform)\b",
)]
_CONTACT_NUDGE = re.compile(r"\b(?:whats\s?app|telegram|signal|call\s+me|text\s+me|dm\s+me)\b",
                            re.IGNORECASE)


@dataclass
class ShieldResult:
    text: str
    masked_count: int = 0
    off_platform_payment: bool = False
    off_platform_contact: bool = False


def enabled() -> bool:
    return os.environ.get("SERVICELINK_MASK_CONTACTS", "1") != "0"


def screen(text: str) -> ShieldResult:
    """Return the text with contact details hidden plus warning flags."""
    original = text or ""
    work = unicodedata.normalize("NFKC", original)     # folds full-width digits etc.
    flags_payment = any(p.search(work) for p in _PAYMENT_PATTERNS)
    flags_contact = bool(_CONTACT_NUDGE.search(work))
    if not enabled():
        return ShieldResult(original, 0, flags_payment, flags_contact)
    count = 0
    for pattern in (_EMAIL, _URL, _PHONE_KE, _PHONE_INTL, _DIGIT_WORDS):
        work, n = pattern.subn(MASK, work)
        count += n
    if count:
        flags_contact = True
    return ShieldResult(work if count else original, count, flags_payment, flags_contact)


PAYMENT_WARNING = ("Safety reminder: keep payments and contact details on ServiceLink. "
                   "Requests to pay outside the app are a common scam sign - you can report this chat.")
