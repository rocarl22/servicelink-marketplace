from backend.services import admin


TEST_PASSWORD = "N3w!ServiceLinkAdmin#2026"


def test_fresh_install_requires_setup_and_never_bootstraps_default(isolated_database):
    assert admin.ensure_admin_exists() is True
    # The compatibility entry point must not create a predictable credential.
    assert admin.ensure_admin_exists() is True
    conn = isolated_database.get_conn()
    try:
        assert conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0] == 0
    finally:
        conn.close()


def test_initial_admin_setup_and_duplicate_setup_prevention(isolated_database):
    ok, message = admin.create_initial_admin("firstadmin", TEST_PASSWORD, TEST_PASSWORD)
    assert ok, message
    assert admin.ensure_admin_exists() is False

    ok, message = admin.create_initial_admin("secondadmin", TEST_PASSWORD, TEST_PASSWORD)
    assert not ok
    assert "already" in message.lower()

    conn = isolated_database.get_conn()
    try:
        assert conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM admin_actions WHERE action_type='admin_initial_setup'").fetchone()[0] == 1
    finally:
        conn.close()


def test_admin_lockout_after_five_failed_attempts(isolated_database):
    ok, message = admin.create_initial_admin("secureadmin", TEST_PASSWORD, TEST_PASSWORD)
    assert ok, message

    for _ in range(admin.ADMIN_MAX_FAILED_ATTEMPTS):
        ok, _ = admin.admin_login("secureadmin", "Wrong!Password123")
        assert not ok

    ok, message = admin.admin_login("secureadmin", TEST_PASSWORD)
    assert not ok
    assert "locked" in message.lower()


def test_successful_admin_login_resets_failure_counter(isolated_database):
    ok, message = admin.create_initial_admin("secureadmin", TEST_PASSWORD, TEST_PASSWORD)
    assert ok, message
    ok, _ = admin.admin_login("secureadmin", "Wrong!Password123")
    assert not ok
    ok, admin_id = admin.admin_login("secureadmin", TEST_PASSWORD)
    assert ok

    conn = isolated_database.get_conn()
    try:
        row = conn.execute("SELECT failed_login_count, locked_until FROM admin_users WHERE admin_id=?", (admin_id,)).fetchone()
        assert row["failed_login_count"] == 0
        assert row["locked_until"] == ""
    finally:
        conn.close()


def test_client_provider_login_lockout(isolated_database):
    from backend.services import accounts

    password = "Copper-Meadow-Violin-2026"
    ok, account_id = accounts.create_account(
        role="client",
        full_name="Synthetic Test User",
        phone="0712345678",
        email="synthetic@example.invalid",
        password=password,
        password_confirm=password,
        terms_accepted=True,
        role_locked=True,
        service_family="",
        device_key="pytest-device",
    )
    assert ok, account_id

    for _ in range(5):
        ok, _ = accounts.sign_in("0712345678", "Wrong!Password123", "pytest-device")
        assert not ok

    ok, message = accounts.sign_in("0712345678", password, "pytest-device")
    assert not ok
    assert "locked" in message.lower()


def test_legacy_plaintext_admin_password_is_upgraded_after_successful_login(isolated_database, monkeypatch):
    monkeypatch.setenv("SERVICELINK_ALLOW_LEGACY_PLAINTEXT", "1")   # plaintext is refused unless opted in
    password = "Legacy!AdminPassword#2026"
    ok, message = admin.create_initial_admin("legacyadmin", password, password)
    assert ok, message

    conn = isolated_database.get_conn()
    try:
        conn.execute("UPDATE admin_users SET password_hash=? WHERE username=?",
                     (password, "legacyadmin"))
        conn.commit()
    finally:
        conn.close()

    ok, admin_id = admin.admin_login("legacyadmin", password)
    assert ok, admin_id
    conn = isolated_database.get_conn()
    try:
        stored = conn.execute("SELECT password_hash FROM admin_users WHERE admin_id=?",
                              (admin_id,)).fetchone()[0]
    finally:
        conn.close()
    assert stored != password
    assert admin._check_password(password, stored)


def test_inactive_historical_admin_tombstone_does_not_block_initial_setup(isolated_database):
    conn = isolated_database.get_conn()
    try:
        conn.execute(
            """INSERT INTO admin_users(
                admin_id, username, password_hash, role, active, created_at,
                last_login_at, failed_login_count, locked_until
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            ("A-RETIRED0001", "retired_oldadmin", admin._hash_password("Unused!Secret#2026"),
             "admin", 0, "2026-01-01T00:00:00+00:00", "", 0, ""),
        )
        conn.commit()
    finally:
        conn.close()

    assert admin.ensure_admin_exists() is True
    ok, message = admin.create_initial_admin("newadmin", TEST_PASSWORD, TEST_PASSWORD)
    assert ok, message
    assert admin.ensure_admin_exists() is False
