from backend.services.sessions import IdleSession


def test_idle_session_refreshes_and_expires_using_monotonic_clock():
    clock = [100.0]
    session = IdleSession(timeout_seconds=20, clock=lambda: clock[0])
    session.start("account-123")
    assert session.owns("account-123")

    clock[0] += 15
    assert session.owns("account-123")  # Activity refreshes the idle window.

    clock[0] += 19
    assert session.is_active(touch=False)
    clock[0] += 1
    assert not session.owns("account-123")
    assert session.identifier is None


def test_wrong_identifier_does_not_keep_session_alive():
    clock = [0.0]
    session = IdleSession(timeout_seconds=10, clock=lambda: clock[0])
    session.start("account-123")
    clock[0] = 9
    assert not session.owns("another-account")
    clock[0] = 10
    assert not session.is_active(touch=False)


def test_sign_out_clears_session_immediately():
    session = IdleSession(timeout_seconds=30, clock=lambda: 1.0)
    session.start("account-123")
    session.clear()
    assert not session.is_active()
    assert session.identifier is None
