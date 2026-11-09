"""Money parsing/formatting. Stdlib only, no Qt.

Phase 1 foundation for payments/escrow: prices were free text
("KSh 2,500"); settlement needs exact integer minor units (cents), never
floats. Free text that is ambiguous (ranges, several numbers) returns None
rather than guessing.
"""
import re
from decimal import Decimal, InvalidOperation

CURRENCY = "KES"
MAX_MINOR = 100_000_000 * 100          # KSh 100 million sanity ceiling

_NUMBER = re.compile(r"(\d[\d,]*(?:\.\d+)?)\s*([kK])?(?![\d.])")


def parse_kes_minor(text):
    """Parse 'KSh 2,500', '2500', 'KES 2,500.50', '2.5k' -> integer cents.

    Returns None when no single unambiguous amount can be read.
    """
    if not isinstance(text, str):
        return None
    cleaned = re.sub(r"(?i)\b(?:kes|kshs?|shs?|shillings?)\b\.?", " ", text)
    cleaned = cleaned.replace("/=", " ").strip()
    matches = list(_NUMBER.finditer(cleaned))
    if len(matches) != 1:
        return None
    number, suffix = matches[0].group(1), matches[0].group(2)
    if re.search(r",(?!\d{3}(?:\D|$))", number):       # '1,2' or '12,34' style typos
        return None
    try:
        value = Decimal(number.replace(",", ""))
    except InvalidOperation:
        return None
    if suffix:
        value *= 1000
    minor = int((value * 100).to_integral_value())
    if minor <= 0 or minor > MAX_MINOR:
        return None
    return minor


def format_kes(minor):
    if minor is None:
        return ""
    shillings, cents = divmod(int(minor), 100)
    return f"KSh {shillings:,}" + (f".{cents:02d}" if cents else "")
