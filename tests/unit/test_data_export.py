import json

from backend.services import accounts, data_export


def test_export_includes_account_data_but_never_password_hash_or_local_media_paths(isolated_database):
    password = "Quiet-Harbor-Lantern-2026"
    ok, account_id = accounts.create_account(
        role="client", full_name="Export Test User", phone="0712345682",
        email="export@example.invalid", password=password,
        password_confirm=password, terms_accepted=True, role_locked=True,
        service_family="", device_key="pytest-device")
    assert ok, account_id

    conn = isolated_database.get_conn()
    try:
        conn.execute(
            "UPDATE accounts SET work_photo_path=? WHERE account_id=?",
            ("C:/private/profile_photos/private-photo.jpg", account_id),
        )
        conn.commit()
    finally:
        conn.close()

    payload = data_export.export_account_data(account_id)
    assert payload["account"]["account_id"] == account_id
    assert payload["account"]["has_profile_photo"] == 1
    assert "password_hash" not in payload["account"]
    assert "created_by_os_user" not in payload["account"]
    encoded = json.dumps(payload)
    assert "private-photo.jpg" not in encoded
    assert password not in encoded
    assert payload["format_version"] == 1


def test_export_refuses_unknown_account(isolated_database):
    try:
        data_export.export_account_data("not-an-account")
    except ValueError as exc:
        assert "not found" in str(exc).lower()
    else:
        raise AssertionError("Export should refuse an unknown account")
