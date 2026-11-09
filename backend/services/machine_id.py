"""Stable, platform-agnostic device identifier.

Used as the key prefix for rate limits on desktop. On a future web
deployment, this function is not called — the web layer passes the
client IP to ratelimit.consume() instead.

No third-party dependencies. Windows-only at the moment; a Linux or
macOS implementation would read /etc/machine-id or IOPlatformUUID
respectively.
"""
import hashlib
import os
import platform


def _hash(value: str) -> str:
    """Return a stable 16-hex-char prefix of the SHA-256 of the input."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:16]


def _windows_machine_guid() -> str:
    """Read the Windows MachineGuid from the registry. Returns '' on failure."""
    try:
        import winreg  # stdlib on Windows only
    except ImportError:
        return ""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value)
    except OSError:
        return ""


def _fallback_id() -> str:
    """Fallback based on environment. Only used if the registry lookup fails."""
    username = os.environ.get("USERNAME", "")
    computername = os.environ.get("COMPUTERNAME", "")
    return f"{platform.system()}|{username}|{computername}"


def get_machine_id() -> str:
    """Return a stable, hashed identifier for this device.

    Result is deterministic across runs on the same machine and does not
    reveal the underlying GUID.
    """
    guid = _windows_machine_guid()
    if guid:
        return _hash("win:" + guid)
    return _hash("fallback:" + _fallback_id())