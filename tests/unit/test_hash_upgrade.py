import base64
from backend.services import accounts

BCRYPT12 = "$2b$12$" + "A" * 53
BCRYPT10 = "$2b$10$" + "A" * 53


def _scheme(monkeypatch, name):
    monkeypatch.setattr(accounts, "current_scheme", lambda: name)


def test_weaker_hashes_are_upgraded_and_never_downgraded(monkeypatch):
    _scheme(monkeypatch, "argon2id")
    assert accounts.needs_rehash(BCRYPT12) and accounts.needs_rehash("scrypt$x") \
        and accounts.needs_rehash("plain text pw")
    _scheme(monkeypatch, "bcrypt")
    assert not accounts.needs_rehash(BCRYPT12)
    assert accounts.needs_rehash(BCRYPT10)                       # cost below minimum
    assert accounts.needs_rehash("pbkdf2_sha256$200000$a$b")
    _scheme(monkeypatch, "pbkdf2")
    assert not accounts.needs_rehash(BCRYPT12)                   # must not downgrade bcrypt


def test_scheme_detection():
    assert accounts.scheme_of("$argon2id$v=19$m=19456,t=2,p=1$x$y") == "argon2id"
    assert accounts.scheme_of(BCRYPT12) == "bcrypt"
    assert accounts.scheme_of("scrypt$1") == "scrypt"
    assert accounts.scheme_of("pbkdf2_sha256$1$2$3") == "pbkdf2"
    assert accounts.scheme_of("hunter2") == "plaintext"


def test_plaintext_credentials_are_refused_by_default(monkeypatch):
    monkeypatch.delenv("SERVICELINK_ALLOW_LEGACY_PLAINTEXT", raising=False)
    assert accounts._check_password("hunter2hunter2", "hunter2hunter2") is False
    monkeypatch.setenv("SERVICELINK_ALLOW_LEGACY_PLAINTEXT", "1")
    assert accounts._check_password("hunter2hunter2", "hunter2hunter2") is True


def test_new_hash_round_trips_and_dummy_verify_runs():
    stored = accounts._hash_password("amber-falcon-river-lamp")
    assert accounts._check_password("amber-falcon-river-lamp", stored)
    assert not accounts._check_password("wrong-password-here!", stored)
    accounts._dummy_verify("whatever")           # same cost path as a real check; must not raise
    assert accounts._DUMMY_STORED
