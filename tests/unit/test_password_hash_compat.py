"""Compatibility tests for password formats already present in older DBs."""
from backend.services import accounts, security


def test_scrypt_hashes_from_older_releases_still_authenticate(isolated_database):
    password = "Quiet-Harbor-Lantern-2026"
    ok, account_id = accounts.create_account(
        role="client", full_name="Legacy Hash User", phone="0712345681",
        email="legacy-hash@example.invalid", password=password,
        password_confirm=password, terms_accepted=True, role_locked=True,
        service_family="", device_key="pytest-device")
    assert ok, account_id

    conn = isolated_database.get_conn()
    try:
        conn.execute(
            "UPDATE accounts SET password_hash=? WHERE account_id=?",
            (security.hash_password(password), account_id),
        )
        conn.commit()
    finally:
        conn.close()

    assert accounts._check_password(password, security.hash_password(password))
    ok, result = accounts.sign_in("0712345681", password, "pytest-device")
    assert ok, result
    assert result == account_id


def test_scrypt_verifier_rejects_unsafe_parameters_without_running_kdf():
    malformed = "scrypt$999999999$8$1$AAAAAAAAAAAAAAAAAAAAAA$" + ("A" * 43)
    assert not security.verify_password("anything", malformed)


def test_scrypt_verifier_rejects_wrong_password():
    stored = security.hash_password("Correct!Password#2026")
    assert not security.verify_password("Wrong!Password#2026", stored)


def test_legacy_plaintext_account_password_is_upgraded_after_successful_login(isolated_database, monkeypatch):
    # Plaintext is refused by default; an operator must opt in for a one-off migration.
    monkeypatch.setenv("SERVICELINK_ALLOW_LEGACY_PLAINTEXT", "1")
    password = "Amber-Falcon-River-2026"
    ok, account_id = accounts.create_account(
        role="client", full_name="Plaintext Migration User", phone="0712345683",
        email="plaintext-migration@example.invalid", password=password,
        password_confirm=password, terms_accepted=True, role_locked=True,
        service_family="", device_key="pytest-device")
    assert ok, account_id
    conn = isolated_database.get_conn()
    try:
        conn.execute("UPDATE accounts SET password_hash=? WHERE account_id=?",
                     (password, account_id))
        conn.commit()
    finally:
        conn.close()

    ok, result = accounts.sign_in("0712345683", password, "pytest-device")
    assert ok, result
    conn = isolated_database.get_conn()
    try:
        stored = conn.execute("SELECT password_hash FROM accounts WHERE account_id=?",
                              (account_id,)).fetchone()[0]
    finally:
        conn.close()
    assert stored != password
    assert accounts._check_password(password, stored)
