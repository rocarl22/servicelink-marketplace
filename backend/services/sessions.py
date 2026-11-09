"""In-process session guard for the desktop bridge (idle AND absolute expiry).

A session ends when EITHER the user has been idle too long OR the session has
simply lived too long, no matter how active it is. The absolute limit bounds
the damage of a stolen/left-open session. Uses a monotonic clock so system
clock changes cannot extend or prematurely expire sessions.

This is a local-app safeguard; the web deployment needs server-side sessions
(rotating refresh tokens, revocation) - see SECURITY_HARDENING.md.
"""
from __future__ import annotations

import time
from typing import Callable, Optional


DEFAULT_IDLE_TIMEOUT_SECONDS = 20 * 60
DEFAULT_ABSOLUTE_TIMEOUT_SECONDS = 8 * 60 * 60


class IdleSession:
    def __init__(self, timeout_seconds: int = DEFAULT_IDLE_TIMEOUT_SECONDS,
                 clock: Callable[[], float] = time.monotonic,
                 absolute_timeout_seconds: int = DEFAULT_ABSOLUTE_TIMEOUT_SECONDS):
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if absolute_timeout_seconds <= 0:
            raise ValueError("absolute_timeout_seconds must be positive")
        self.timeout_seconds = int(timeout_seconds)
        self.absolute_timeout_seconds = int(absolute_timeout_seconds)
        self._clock = clock
        self.identifier: Optional[str] = None
        self._last_activity = 0.0
        self._started_at = 0.0

    def start(self, identifier: str) -> None:
        if not identifier:
            self.clear()
            return
        self.identifier = str(identifier)
        self._started_at = self._last_activity = self._clock()

    def clear(self) -> None:
        self.identifier = None
        self._last_activity = 0.0
        self._started_at = 0.0

    def is_active(self, touch: bool = True) -> bool:
        if not self.identifier:
            return False
        now = self._clock()
        if (now - self._last_activity >= self.timeout_seconds
                or now - self._started_at >= self.absolute_timeout_seconds):
            self.clear()
            return False
        if touch:
            self._last_activity = now
        return True

    def owns(self, identifier: str) -> bool:
        return bool(identifier) and identifier == self.identifier and self.is_active()

    def touch(self) -> bool:
        return self.is_active(touch=True)
