"""TOTP (RFC 6238) - the 6-digit codes from authenticator apps. Standard library only."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _code_for_step(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def verify(secret: str, code: str, last_step: int = 0, now=None, window: int = 1):
    """Return the matched time step, or None. A step <= last_step is refused, so a
    code that was already used (or an older one) can never be replayed."""
    code = re.sub(r"\s", "", code or "")
    if not secret or len(code) != 6 or not code.isdigit():
        return None
    current = int((now if now is not None else time.time()) // STEP_SECONDS)
    for step in range(current - window, current + window + 1):
        if step > int(last_step or 0) and hmac.compare_digest(_code_for_step(secret, step), code):
            return step
    return None


def group(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def otpauth_uri(secret: str, username: str, issuer: str = "ServiceLink Admin") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
