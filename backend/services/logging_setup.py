"""Application logging with daily rotation. Safe to call multiple times.

Logs to data/app.log. Rotates daily, keeps 30 days.

Rotation is best-effort: on Windows, antivirus, cloud-sync tools, or a
second running instance can hold the log file open at midnight. When
that happens, TimedRotatingFileHandler raises inside emit() and the
whole logging call fails. To keep user actions safe, we swallow
rotation errors and keep logging to the same file.
"""
import logging
import os
from logging.handlers import TimedRotatingFileHandler

from .. import database as db


_CONFIGURED = False


class _SafeTimedRotatingFileHandler(TimedRotatingFileHandler):
    """TimedRotatingFileHandler that never raises on rotation failure.

    If the underlying file cannot be renamed (Windows file lock,
    antivirus, etc.), we silently keep appending to the same file
    rather than propagate the exception into the caller.
    """

    def doRollover(self):
        try:
            super().doRollover()
        except (OSError, PermissionError):
            # Could not rotate. Keep the stream open and carry on.
            if self.stream is None:
                try:
                    self.stream = self._open()
                except Exception:
                    pass


def configure():
    global _CONFIGURED
    if _CONFIGURED:
        return
    os.makedirs(db.DATA_DIR, exist_ok=True)
    log_path = os.path.join(db.DATA_DIR, "app.log")

    level_name = os.environ.get("SL_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = _SafeTimedRotatingFileHandler(
        log_path,
        when="midnight",
        backupCount=30,
        encoding="utf-8",
        utc=True,
        delay=False,
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))

    root = logging.getLogger()
    root.setLevel(level)
    if not any(isinstance(h, TimedRotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)

    # Mirror WARNING+ to stderr so the terminal shows errors.
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    if not any(isinstance(h, logging.StreamHandler)
               and not isinstance(h, TimedRotatingFileHandler)
               for h in root.handlers):
        root.addHandler(console)

    _CONFIGURED = True