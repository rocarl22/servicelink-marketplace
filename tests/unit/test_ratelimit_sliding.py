"""The limiter must be a true sliding window, not fixed buckets."""
from backend.services import ratelimit

BASE = 1_000_000_020          # divisible by 60 => start of a 60s bucket


def _at(monkeypatch, t):
    monkeypatch.setattr(ratelimit, "_now", lambda: float(t))


def test_allows_up_to_the_limit_then_blocks(isolated_database, monkeypatch):
    _at(monkeypatch, BASE + 10)
    results = [ratelimit.consume("k1", 5, 60)[0] for _ in range(6)]
    assert results == [True] * 5 + [False]


def test_boundary_burst_is_blocked(isolated_database, monkeypatch):
    """A fixed window would allow 5 at t=59s AND 5 more at t=61s (10 in 2 seconds)."""
    _at(monkeypatch, BASE + 59)
    assert all(ratelimit.consume("k2", 5, 60)[0] for _ in range(5))
    _at(monkeypatch, BASE + 61)
    allowed, remaining = ratelimit.consume("k2", 5, 60)
    assert allowed is False and remaining == 0


def test_capacity_returns_gradually_then_fully(isolated_database, monkeypatch):
    _at(monkeypatch, BASE + 59)
    for _ in range(5):
        ratelimit.consume("k3", 5, 60)
    _at(monkeypatch, BASE + 60 + 45)          # three quarters of the previous bucket has aged out
    assert ratelimit.consume("k3", 5, 60)[0] is True
    _at(monkeypatch, BASE + 60 * 4)           # long after: fully recovered
    assert ratelimit.consume("k3", 5, 60) == (True, 4)


def test_keys_are_independent_and_peek_does_not_consume(isolated_database, monkeypatch):
    _at(monkeypatch, BASE + 5)
    for _ in range(5):
        ratelimit.consume("a", 5, 60)
    assert ratelimit.consume("b", 5, 60)[0] is True
    assert ratelimit.peek("a", 60) == 5 and ratelimit.peek("a", 60) == 5
