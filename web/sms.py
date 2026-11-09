"""Sending text messages. Backends:

  none          features that need SMS are switched off (safe production default)
  console       prints messages to the server log (development only - shows the codes!)
  memory        keeps messages in `outbox` (tests)
  africastalking  real SMS through Africa's Talking (set AT_USERNAME / AT_API_KEY)

Messages are only ever sent to phone numbers that belong to an existing account, and
the callers rate-limit, so this cannot be used as a free SMS blaster. API keys are
never logged.
"""
import json
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("servicelink.sms")
outbox = []            # (phone, message) pairs for the "memory" backend
AT_LIVE = "https://api.africastalking.com/version1/messaging"
AT_SANDBOX = "https://api.sandbox.africastalking.com/version1/messaging"


def enabled(settings) -> bool:
    return settings.get("SMS_BACKEND", "none") != "none"


def mask(phone07: str) -> str:
    return f"{phone07[:4]} \u2022\u2022\u2022 {phone07[-3:]}" if len(phone07) >= 8 else "your phone"


def to_e164(phone07: str) -> str:
    return "+254" + phone07[1:]


def _http_post(url, headers, data, timeout=8):
    """Tiny wrapper so tests can replace the network call."""
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # fixed https hosts only
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _send_africastalking(phone07, message, settings) -> bool:
    user, key = settings.get("AT_USERNAME", ""), settings.get("AT_API_KEY", "")
    if not user or not key:
        log.error("Africa's Talking is selected but AT_USERNAME / AT_API_KEY are not set.")
        return False
    data = {"username": user, "to": to_e164(phone07), "message": message}
    if settings.get("AT_SENDER_ID"):
        data["from"] = settings["AT_SENDER_ID"]
    headers = {"apiKey": key, "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    url = AT_SANDBOX if settings.get("AT_SANDBOX") else AT_LIVE
    try:
        status, body = _http_post(url, headers, data)
        recipients = json.loads(body)["SMSMessageData"]["Recipients"]
        ok = status in (200, 201) and any(int(r.get("statusCode", 0)) in (100, 101, 102) for r in recipients)
    except Exception as exc:                              # network, JSON shape, anything
        log.error("SMS send failed (%s)", type(exc).__name__)
        return False
    if not ok:
        log.error("SMS provider rejected the message to %s", mask(phone07))
    return ok


def send(phone07: str, message: str, settings) -> bool:
    backend = settings.get("SMS_BACKEND", "none")
    if backend == "memory":
        outbox.append((phone07, message))
        return True
    if backend == "console":
        log.warning("SMS (console backend, development only) to %s: %s", phone07, message)
        return True
    if backend == "africastalking":
        return _send_africastalking(phone07, message, settings)
    return False


def send_async(phone07: str, message: str, settings):
    """Send without making the web request wait, so a known and an unknown phone number
    take the same time to answer. Tests set SMS_ASYNC=False to send inline."""
    if not settings.get("SMS_ASYNC", True):
        return send(phone07, message, settings)
    threading.Thread(target=send, args=(phone07, message, dict(settings)), daemon=True).start()
    return True
