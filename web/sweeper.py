"""Runs the passive timer sweep (backend/services/timers.py) in the background.

The sweep is what makes jobs finish on their own: it auto-confirms a job whose client never
confirmed the start, auto-completes finished work nobody disputed, expires open requests after
7 days and auto-dismisses disputes left open for 30 days. The desktop app runs it at start-up
and periodically; the website must too, or those jobs would sit forever.
It is idempotent and takes a database write lock, so running it from several processes is safe.
"""
import logging
import threading
import time

from backend.services import timers

log = logging.getLogger("servicelink.sweeper")
_started = False
_lock = threading.Lock()


def run_once() -> bool:
    try:
        timers.sweep()
        return True
    except Exception:
        log.exception("timer sweep failed")
        return False


def start(interval_seconds: int = 300) -> bool:
    """Start the background loop once per process. Returns False if it was already running."""
    global _started
    with _lock:
        if _started:
            return False
        _started = True

    def loop():
        while True:
            time.sleep(interval_seconds)
            run_once()

    threading.Thread(target=loop, name="servicelink-sweeper", daemon=True).start()
    return True
