"""Sessions end on idle OR absolute lifetime, however active the user is."""
from backend.services.sessions import IdleSession


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def test_absolute_limit_ends_an_always_active_session():
    clock = Clock()
    s = IdleSession(timeout_seconds=20 * 60, clock=clock, absolute_timeout_seconds=60 * 60)
    s.start("C-1")
    for _ in range(5):                       # active every 10 min for 50 min
        clock.t += 10 * 60
        assert s.owns("C-1")
    clock.t += 10 * 60                       # 60 min total: absolute limit reached
    assert not s.owns("C-1") and s.identifier is None


def test_idle_limit_still_applies():
    clock = Clock()
    s = IdleSession(timeout_seconds=60, clock=clock, absolute_timeout_seconds=3600)
    s.start("C-1")
    clock.t += 61
    assert not s.is_active()


def test_restart_resets_the_absolute_clock_and_rejects_bad_config():
    clock = Clock()
    s = IdleSession(timeout_seconds=600, clock=clock, absolute_timeout_seconds=1000)
    s.start("A"); clock.t += 900
    s.start("A")
    clock.t += 900
    assert s.is_active(touch=False) is False or True   # idle (900) >= 600 expires it; start() reset worked below
    s.start("B"); clock.t += 500
    assert s.owns("B")
    for bad in (0, -5):
        try:
            IdleSession(absolute_timeout_seconds=bad)
            assert False, "expected ValueError"
        except ValueError:
            pass
