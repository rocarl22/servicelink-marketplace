# ServiceLink hardening changes

> **Phase 1 (v3.1)** fixes are listed in `CHANGELOG_PHASE1.md`. Where this older document disagrees with it, the Phase 1 notes are current.

This release hardens the existing desktop application while preserving the existing schema/data and QML navigation patterns.

## Changes included

- Client/provider sign-in applies progressive temporary lockouts after repeated failed passwords (5 attempts: 5 minutes; 10: 15 minutes; 15+: 60 minutes). A successful login clears the counters.
- Client/provider and admin sign-in also use sliding-window rate limits (see Phase 1 notes: earlier releases used fixed buckets despite the name) keyed by SHA-256 identifiers, not raw phone numbers or usernames. Unknown account names perform a dummy verification using the same hash scheme and cost as real accounts to reduce account-enumeration timing differences (earlier releases used a cheaper scrypt dummy, which was distinguishable from a bcrypt check). Stale rate-limit buckets are pruned at startup.
- Idle client/provider and admin sessions expire after 20 minutes, with a warning shown at 18 minutes. This is a local desktop safeguard; it is not a server-side session system.
- Password verification supports existing bcrypt, PBKDF2, and scrypt formats. Scrypt/PBKDF2 parameters are bounded before running the KDF. A legacy plaintext credential is upgraded to a password hash only after successful authentication.
- Admin sign-in now uses equivalent lockout tracking. Existing administrator accounts are migrated in place with `failed_login_count` and `locked_until` columns.
- The startup bootstrap no longer creates the predictable `admin` / `admin123` account. On a genuinely empty admin table, the Staff access screen presents a first-admin setup form. Setup is transaction-protected and only the first administrator can be created.
- The old default password remains detectable only so an existing installation can continue to display its existing security warning. Existing credentials are not automatically changed or deleted; administrators still using the old credential should change it immediately from My account.
- Database initialization adds a `schema_migrations` baseline ledger and idempotently adds administrator lockout columns. Existing records are not deleted by this change.
- Daily SQLite backups are written to a temporary file, integrity-checked, and atomically moved into place. Existing foreign-key violations are logged for investigation rather than preventing a backup of legacy data.
- Pillow is now declared in `requirements.txt`. Image uploads have file-size and pixel-count limits; portfolio uploads fail closed if face screening is unavailable. User-facing image errors no longer expose local exception details.
- Added privacy-safe JSON export for a signed-in account. It excludes authentication hashes, device identifiers, and local media paths.
- Provider profiles can open an OpenStreetMap search for their self-reported service area. This is a search link, not GPS verification or a claim that a provider has been verified.
- Added automated tests for administrator setup/lockout, client login lockout, password hash compatibility, idle-session expiry, privacy-safe export, database initialization, backup snapshots, and image screening/processing.

## Historical audit reference repair

The supplied database originally had one `PRAGMA foreign_key_check` violation: an `admin_actions` record referenced an administrator missing from the current database. The 1 October backup contained that historical administrator record. The release therefore preserves the original audit event and creates an inactive tombstone with the same historical ID and a fresh random credential hash; it does not restore the old credential or active access. The included database now passes both `PRAGMA integrity_check` and `PRAGMA foreign_key_check`. First-admin setup checks for an active administrator, so inactive tombstones cannot lock an installation out of setup.

## Install and test

From the project root in a supported Python environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q backend main.py
python main.py
```

Tests use isolated temporary databases. Do not point tests at the live `data/service_link.db`.

## Upgrade safety

1. Close ServiceLink before upgrading.
2. Keep a copy of the original project and database.
3. Start the upgraded app against a copied database first and validate key workflows.
4. Verify backups and preserve the original database until acceptance testing is complete.
5. On an existing install, review the default-password warning and change any legacy default credential immediately.

## Scope note

These changes improve desktop-local authentication and data handling. They do not by themselves make the app safe for public internet deployment. A networked deployment still needs a central API, server-side authorization/session design, operational monitoring, secure secret management, and deployment-specific security review.


## Final validation

- `python -m pytest -q`: 23 passed.
- `python -m compileall -q backend main.py`: passed.
- The included database was checked after the audit-reference repair: SQLite integrity check `ok`; foreign-key violations `0`; existing account, request, job, message, review, and audit-event counts preserved.
- The QML interface was structurally checked for balanced delimiters, but a live Qt GUI launch was not available in the build environment. Verify the desktop interface on Windows after extracting the release.
