"""SQLite connection, schema initialization, migrations, and light housekeeping.

Free of Qt imports. Runs unchanged on a future web backend.
"""
import os
import sqlite3
from datetime import datetime, timezone

from . import paths


DATA_DIR = paths.data_root()
DB_PATH = paths.db_path()
BACKUP_DIR = paths.backup_dir()
PHOTO_DIR = paths.photo_dir()


# ------------------------------------------------------------------
# Constants used across services
# ------------------------------------------------------------------

INCIDENT_TYPES_CLIENT = [
    "Provider didn't arrive",
    "Provider cancelled",
    "Price changed unexpectedly",
    "Service materially different from description",
    "Provider unreachable",
    "Suspected fraud",
    "Other",
]

INCIDENT_TYPES_PROVIDER = [
    "Client unavailable",
    "Wrong location",
    "Client cancelled after dispatch",
    "Client changed agreed service",
    "Price disagreement",
    "Unsafe working environment",
    "Client unreachable",
    "Suspected fraud",
    "Other",
]


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level="DEFERRED")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS schema_migrations(
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS app_settings(
        key    TEXT PRIMARY KEY,
        value  TEXT NOT NULL
    )
    """,

    """
    CREATE TABLE IF NOT EXISTS accounts(
        account_id       TEXT PRIMARY KEY,
        role             TEXT NOT NULL CHECK(role IN ('client','provider')),
        role_locked      INTEGER NOT NULL DEFAULT 1 CHECK(role_locked IN (0,1)),
        full_name        TEXT NOT NULL,
        phone            TEXT NOT NULL,
        email            TEXT DEFAULT '',
        password_hash    TEXT NOT NULL,
        display_name     TEXT DEFAULT '',
        area             TEXT DEFAULT '',
        bio              TEXT DEFAULT '',
        work_photo_path  TEXT DEFAULT '',
        service_family   TEXT DEFAULT '',
        capacity         INTEGER NOT NULL DEFAULT 1,
        account_status   TEXT NOT NULL DEFAULT 'active'
                         CHECK(account_status IN (
                             'active','under_review','restricted',
                             'suspended','on_hold','closed'
                         )),
        on_hold_until       TEXT DEFAULT '',
        on_hold_reason      TEXT DEFAULT '',
        on_hold_prev_status TEXT DEFAULT '',
        password_upgrade_required INTEGER NOT NULL DEFAULT 0,
        password_warning_seen     INTEGER NOT NULL DEFAULT 0,
        failed_login_count        INTEGER NOT NULL DEFAULT 0,
        locked_until              TEXT DEFAULT '',
        terms_version     TEXT DEFAULT '',
        terms_accepted_at TEXT DEFAULT '',
        created_by_os_user TEXT DEFAULT '',
        setup_complete     INTEGER NOT NULL DEFAULT 0,
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_accounts_phone ON accounts(phone)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_accounts_email ON accounts(lower(email)) WHERE email <> ''",
    "CREATE INDEX IF NOT EXISTS ix_accounts_role_status ON accounts(role, account_status, setup_complete)",
    "CREATE INDEX IF NOT EXISTS ix_accounts_os_user ON accounts(created_by_os_user)",
    "CREATE INDEX IF NOT EXISTS ix_accounts_on_hold ON accounts(account_status, on_hold_until) WHERE account_status='on_hold'",

    """
    CREATE TABLE IF NOT EXISTS admin_users(
        admin_id        TEXT PRIMARY KEY,
        username        TEXT NOT NULL UNIQUE,
        password_hash   TEXT NOT NULL,
        role            TEXT NOT NULL DEFAULT 'admin'
                        CHECK(role IN ('admin','support')),
        active          INTEGER NOT NULL DEFAULT 1,
        created_at      TEXT NOT NULL,
        last_login_at   TEXT DEFAULT '',
        failed_login_count INTEGER NOT NULL DEFAULT 0,
        locked_until      TEXT DEFAULT ''
    )
    """,

    """
    CREATE TABLE IF NOT EXISTS admin_actions(
        action_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id           TEXT NOT NULL REFERENCES admin_users(admin_id) ON DELETE RESTRICT,
        action_type        TEXT NOT NULL,
        target_type        TEXT NOT NULL,
        target_id          TEXT NOT NULL,
        before_state       TEXT DEFAULT '',
        after_state        TEXT DEFAULT '',
        reason             TEXT DEFAULT '',
        created_at         TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_admin_actions_admin ON admin_actions(admin_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_admin_actions_target ON admin_actions(target_type, target_id, created_at)",

    """
    CREATE TABLE IF NOT EXISTS admin_password_resets(
        reset_id            INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id            TEXT NOT NULL REFERENCES admin_users(admin_id) ON DELETE RESTRICT,
        target_account_id   TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        expires_at          TEXT NOT NULL,
        consumed_at         TEXT DEFAULT '',
        created_at          TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_password_resets_target ON admin_password_resets(target_account_id, expires_at)",

    """
    CREATE TABLE IF NOT EXISTS provider_services(
        service_id           INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        title                TEXT NOT NULL,
        category             TEXT NOT NULL,
        family               TEXT NOT NULL,
        description          TEXT NOT NULL DEFAULT '',
        rate_text            TEXT NOT NULL DEFAULT '',
        active               INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        created_at           TEXT NOT NULL,
        updated_at           TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_services_provider ON provider_services(provider_account_id, active)",
    "CREATE INDEX IF NOT EXISTS ix_services_category ON provider_services(category, active)",

    """
    CREATE TABLE IF NOT EXISTS provider_availability(
        provider_account_id  TEXT PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
        mode                 TEXT NOT NULL DEFAULT 'available_now'
                             CHECK(mode IN ('available_now','available_at','busy_until','unavailable')),
        available_at         TEXT DEFAULT '',
        note                 TEXT DEFAULT '',
        updated_at           TEXT NOT NULL
    )
    """,

    """
    CREATE TABLE IF NOT EXISTS service_requests(
        request_id             INTEGER PRIMARY KEY AUTOINCREMENT,
        client_account_id      TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        provider_account_id    TEXT REFERENCES accounts(account_id) ON DELETE SET NULL,
        mode                   TEXT NOT NULL DEFAULT 'open'
                               CHECK(mode IN ('direct','open')),
        category               TEXT NOT NULL,
        family                 TEXT NOT NULL,
        description            TEXT NOT NULL,
        area                   TEXT NOT NULL,
        preferred_time         TEXT DEFAULT '',
        budget_text            TEXT DEFAULT '',
        status                 TEXT NOT NULL DEFAULT 'open'
                               CHECK(status IN ('open','accepted','declined','expired','converted','cancelled')),
        created_at             TEXT NOT NULL,
        updated_at             TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_requests_client ON service_requests(client_account_id, status, updated_at)",
    "CREATE INDEX IF NOT EXISTS ix_requests_provider ON service_requests(provider_account_id, status, updated_at)",
    "CREATE INDEX IF NOT EXISTS ix_requests_open ON service_requests(status, area) WHERE status='open'",

    """
    CREATE TABLE IF NOT EXISTS jobs(
        job_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id             INTEGER REFERENCES service_requests(request_id) ON DELETE SET NULL,
        client_account_id      TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        provider_account_id    TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        category               TEXT NOT NULL,
        family                 TEXT NOT NULL,
        description            TEXT NOT NULL,
        area                   TEXT NOT NULL,
        agreed_price_text      TEXT DEFAULT '',
        current_state          TEXT NOT NULL DEFAULT 'accepted'
                               CHECK(current_state IN (
                                   'accepted','dispatched','arrived','started',
                                   'client_confirmed','done','completed',
                                   'completed_by_timeout',
                                   'disputed','abandoned','cancelled'
                               )),
        mutual_completion_deadline  TEXT DEFAULT '',
        hard_timeout_deadline       TEXT DEFAULT '',
        accepted_at            TEXT NOT NULL,
        dispatched_at          TEXT DEFAULT '',
        arrived_at             TEXT DEFAULT '',
        started_at             TEXT DEFAULT '',
        client_confirmed_at    TEXT DEFAULT '',
        done_at                TEXT DEFAULT '',
        closed_at              TEXT DEFAULT '',
        completed_by_timeout   INTEGER NOT NULL DEFAULT 0,
        cancellation_reason    TEXT DEFAULT '',
        cancellation_by        TEXT DEFAULT '',
        created_at             TEXT NOT NULL,
        updated_at             TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_jobs_client ON jobs(client_account_id, current_state, updated_at)",
    "CREATE INDEX IF NOT EXISTS ix_jobs_provider ON jobs(provider_account_id, current_state, updated_at)",
    "CREATE INDEX IF NOT EXISTS ix_jobs_active ON jobs(provider_account_id) WHERE current_state IN ('dispatched','arrived','started')",

    """
    CREATE TABLE IF NOT EXISTS job_events(
        event_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id            INTEGER NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
        actor_account_id  TEXT REFERENCES accounts(account_id) ON DELETE SET NULL,
        actor_role        TEXT NOT NULL
                          CHECK(actor_role IN ('client','provider','system','admin')),
        event_type        TEXT NOT NULL
                          CHECK(event_type IN (
                              'accepted','dispatched','arrived','started',
                              'client_confirmed','done','closed',
                              'undo','correction_requested','correction_approved','correction_rejected',
                              'disputed','dispute_resolved',
                              'abandoned','cancelled',
                              'auto_completed','auto_confirmed'
                          )),
        from_state        TEXT DEFAULT '',
        to_state          TEXT DEFAULT '',
        note              TEXT DEFAULT '',
        evidence_path     TEXT DEFAULT '',
        client_event_id   TEXT DEFAULT '',
        created_at        TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_events_job ON job_events(job_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_events_actor ON job_events(actor_account_id, created_at)",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_events_client_id ON job_events(client_event_id) WHERE client_event_id <> ''",

    """
    CREATE TABLE IF NOT EXISTS reviews(
        review_id             INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id                INTEGER NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
        reviewer_account_id   TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        reviewee_account_id   TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        reviewer_role         TEXT NOT NULL CHECK(reviewer_role IN ('client','provider')),
        stars                 INTEGER NOT NULL CHECK(stars BETWEEN 1 AND 5),
        comment               TEXT DEFAULT '',
        editable_until        TEXT DEFAULT '',
        created_at            TEXT NOT NULL,
        updated_at            TEXT NOT NULL,
        UNIQUE(job_id, reviewer_account_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_reviews_reviewee ON reviews(reviewee_account_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_reviews_reviewer ON reviews(reviewer_account_id, created_at)",

    """
    CREATE TABLE IF NOT EXISTS portfolio(
        item_id              INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        job_id               INTEGER REFERENCES jobs(job_id) ON DELETE SET NULL,
        title                TEXT NOT NULL,
        description          TEXT DEFAULT '',
        photo_path           TEXT NOT NULL,
        visible              INTEGER NOT NULL DEFAULT 1,
        created_at           TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_portfolio_provider ON portfolio(provider_account_id, visible, created_at)",

    """
    CREATE TABLE IF NOT EXISTS conversations(
        conversation_id      INTEGER PRIMARY KEY AUTOINCREMENT,
        client_account_id    TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        provider_account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        last_message_at      TEXT DEFAULT '',
        last_message_preview TEXT DEFAULT '',
        created_at           TEXT NOT NULL,
        updated_at           TEXT NOT NULL,
        UNIQUE(client_account_id, provider_account_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_conversations_client ON conversations(client_account_id, last_message_at DESC)",
    "CREATE INDEX IF NOT EXISTS ix_conversations_provider ON conversations(provider_account_id, last_message_at DESC)",

    """
    CREATE TABLE IF NOT EXISTS messages(
        message_id           INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id      INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
        sender_account_id    TEXT REFERENCES accounts(account_id) ON DELETE SET NULL,
        sender_role          TEXT NOT NULL CHECK(sender_role IN ('client','provider','system')),
        body                 TEXT NOT NULL,
        request_id           INTEGER REFERENCES service_requests(request_id) ON DELETE SET NULL,
        job_id               INTEGER REFERENCES jobs(job_id) ON DELETE SET NULL,
        target_account_id    TEXT DEFAULT '',
        is_admin_message     INTEGER NOT NULL DEFAULT 0,
        read_at              TEXT DEFAULT '',
        created_at           TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS web_sessions(
        session_hash   TEXT PRIMARY KEY,
        account_id     TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        created_at     TEXT NOT NULL,
        last_seen_at   TEXT NOT NULL,
        expires_at     TEXT NOT NULL,
        ip             TEXT DEFAULT '',
        user_agent     TEXT DEFAULT '',
        revoked_at     TEXT DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_web_sessions_account ON web_sessions(account_id)",
    """
    CREATE TABLE IF NOT EXISTS escrows(
        escrow_id         INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id            INTEGER NOT NULL UNIQUE REFERENCES jobs(job_id),
        client_account_id   TEXT NOT NULL,
        provider_account_id TEXT NOT NULL,
        amount_minor      INTEGER NOT NULL CHECK(amount_minor > 0),
        fee_bps           INTEGER NOT NULL DEFAULT 0 CHECK(fee_bps BETWEEN 0 AND 3000),
        fee_minor         INTEGER NOT NULL DEFAULT 0 CHECK(fee_minor >= 0),
        currency          TEXT NOT NULL DEFAULT 'KES',
        status            TEXT NOT NULL CHECK(status IN
                          ('awaiting_payment','held','released','refunded','settled','void')),
        created_at        TEXT NOT NULL,
        updated_at        TEXT NOT NULL,
        funded_at         TEXT NOT NULL DEFAULT '',
        closed_at         TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS payment_attempts(
        attempt_id     INTEGER PRIMARY KEY AUTOINCREMENT,
        escrow_id      INTEGER NOT NULL REFERENCES escrows(escrow_id),
        gateway        TEXT NOT NULL,
        checkout_id    TEXT NOT NULL UNIQUE,
        phone          TEXT NOT NULL,
        amount_minor   INTEGER NOT NULL CHECK(amount_minor > 0),
        status         TEXT NOT NULL CHECK(status IN
                       ('pending','succeeded','failed','cancelled','timeout','mismatch')),
        receipt        TEXT NOT NULL DEFAULT '',
        result_code    TEXT NOT NULL DEFAULT '',
        result_desc    TEXT NOT NULL DEFAULT '',
        created_at     TEXT NOT NULL,
        completed_at   TEXT NOT NULL DEFAULT '',
        last_polled_at TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_attempt_receipt ON payment_attempts(receipt) WHERE receipt <> ''",
    """
    CREATE TABLE IF NOT EXISTS payouts(
        payout_id     INTEGER PRIMARY KEY AUTOINCREMENT,
        escrow_id     INTEGER NOT NULL REFERENCES escrows(escrow_id),
        kind          TEXT NOT NULL CHECK(kind IN ('release','refund')),
        to_account_id TEXT NOT NULL,
        phone         TEXT NOT NULL,
        amount_minor  INTEGER NOT NULL CHECK(amount_minor > 0),
        status        TEXT NOT NULL CHECK(status IN ('pending','paid','failed')),
        receipt       TEXT NOT NULL DEFAULT '',
        note          TEXT NOT NULL DEFAULT '',
        created_at    TEXT NOT NULL,
        paid_at       TEXT NOT NULL DEFAULT '',
        confirmed_by  TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_payout_receipt ON payouts(receipt) WHERE receipt <> ''",
    """
    CREATE TABLE IF NOT EXISTS ledger_entries(
        entry_id      INTEGER PRIMARY KEY AUTOINCREMENT,
        txn_id        TEXT NOT NULL,
        escrow_id     INTEGER,
        account       TEXT NOT NULL,
        amount_minor  INTEGER NOT NULL,
        memo          TEXT NOT NULL DEFAULT '',
        created_at    TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_ledger_txn ON ledger_entries(txn_id)",
    "CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger_entries BEGIN SELECT RAISE(ABORT, 'ledger entries cannot be changed'); END",
    "CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger_entries BEGIN SELECT RAISE(ABORT, 'ledger entries cannot be deleted'); END",
    """
    CREATE TABLE IF NOT EXISTS otp_codes(
        otp_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id   TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        purpose      TEXT NOT NULL CHECK(purpose IN ('verify_phone','reset_password')),
        phone        TEXT NOT NULL,
        code_hash    TEXT NOT NULL,
        salt         TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        expires_at   TEXT NOT NULL,
        attempts     INTEGER NOT NULL DEFAULT 0,
        consumed_at  TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_otp_account ON otp_codes(account_id, purpose, created_at)",
    """
    CREATE TABLE IF NOT EXISTS web_admin_sessions(
        session_hash   TEXT PRIMARY KEY,
        admin_id       TEXT NOT NULL REFERENCES admin_users(admin_id) ON DELETE CASCADE,
        stage          TEXT NOT NULL CHECK(stage IN ('pending_mfa','pending_enroll','full')),
        created_at     TEXT NOT NULL,
        last_seen_at   TEXT NOT NULL,
        expires_at     TEXT NOT NULL,
        ip             TEXT DEFAULT '',
        user_agent     TEXT DEFAULT '',
        revoked_at     TEXT DEFAULT '',
        mfa_failures   INTEGER NOT NULL DEFAULT 0,
        pending_totp   TEXT DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_messages_conversation ON messages(conversation_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS ix_messages_unread ON messages(conversation_id, read_at) WHERE read_at = ''",

    """
    CREATE TABLE IF NOT EXISTS disputes(
        dispute_id           INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id               INTEGER NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
        opened_by_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        title                TEXT NOT NULL,
        description          TEXT NOT NULL,
        status               TEXT NOT NULL DEFAULT 'open'
                             CHECK(status IN ('open','under_review','resolved','dismissed')),
        resolution_note      TEXT DEFAULT '',
        resolved_by_admin_id TEXT REFERENCES admin_users(admin_id) ON DELETE SET NULL,
        previous_state       TEXT DEFAULT '',
        created_at           TEXT NOT NULL,
        updated_at           TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_disputes_job ON disputes(job_id, status)",
    "CREATE INDEX IF NOT EXISTS ix_disputes_status ON disputes(status, created_at)",

    """
    CREATE TABLE IF NOT EXISTS admin_party_messages(
        message_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        dispute_id          INTEGER NOT NULL REFERENCES disputes(dispute_id) ON DELETE CASCADE,
        party_account_id    TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        sender_role         TEXT NOT NULL CHECK(sender_role IN ('admin','party')),
        sender_admin_id     TEXT REFERENCES admin_users(admin_id) ON DELETE SET NULL,
        body                TEXT NOT NULL,
        read_by_party       INTEGER NOT NULL DEFAULT 0,
        read_by_admin       INTEGER NOT NULL DEFAULT 0,
        created_at          TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_admin_party_dispute ON admin_party_messages(dispute_id, party_account_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_admin_party_unread_party ON admin_party_messages(party_account_id, read_by_party) WHERE read_by_party = 0",
    "CREATE INDEX IF NOT EXISTS ix_admin_party_unread_admin ON admin_party_messages(read_by_admin) WHERE read_by_admin = 0",
   
    """
    CREATE TABLE IF NOT EXISTS dispute_evidence(
        evidence_id      INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id       INTEGER NOT NULL REFERENCES admin_party_messages(message_id) ON DELETE CASCADE,
        file_path        TEXT NOT NULL,
        mime_type        TEXT NOT NULL DEFAULT 'image/jpeg',
        original_name    TEXT DEFAULT '',
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_evidence_message ON dispute_evidence(message_id)",

    """
    CREATE TABLE IF NOT EXISTS search_synonyms(
        term      TEXT NOT NULL,
        category  TEXT NOT NULL,
        PRIMARY KEY(term, category)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_synonyms_term ON search_synonyms(term)",

    """
    CREATE TABLE IF NOT EXISTS saved_providers(
        client_account_id    TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        provider_account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        created_at           TEXT NOT NULL,
        PRIMARY KEY(client_account_id, provider_account_id)
    )
    """,

    """
    CREATE TABLE IF NOT EXISTS blocks(
        blocker_account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        blocked_account_id  TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        reason              TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        PRIMARY KEY(blocker_account_id, blocked_account_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_blocks_blocked ON blocks(blocked_account_id)",

    """
    CREATE TABLE IF NOT EXISTS user_reports(
        report_id           INTEGER PRIMARY KEY AUTOINCREMENT,
        kind                TEXT NOT NULL CHECK(kind IN ('block','dispute','review')),
        reporter_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        reported_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        reason              TEXT NOT NULL,
        notes               TEXT DEFAULT '',
        context_job_id      INTEGER REFERENCES jobs(job_id) ON DELETE SET NULL,
        status              TEXT NOT NULL DEFAULT 'open'
                            CHECK(status IN ('open','reviewed','dismissed')),
        created_at          TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_user_reports_reporter ON user_reports(reporter_account_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_user_reports_status ON user_reports(status, created_at)",

    """
    CREATE TABLE IF NOT EXISTS rate_limits(
        key            TEXT NOT NULL,
        window_start   TEXT NOT NULL,
        count          INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(key, window_start)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_rate_limits_window ON rate_limits(window_start)",

    """
    CREATE TABLE IF NOT EXISTS notification_reads(
        account_id        TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
        notification_key  TEXT NOT NULL,
        read_at           TEXT NOT NULL,
        PRIMARY KEY(account_id, notification_key)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_notification_reads_account ON notification_reads(account_id, read_at)",
]


# ------------------------------------------------------------------
# Migrations
# ------------------------------------------------------------------

_MIGRATIONS = [
    ("admin_users", "failed_login_count", "INTEGER NOT NULL DEFAULT 0"),
    ("admin_users", "locked_until", "TEXT DEFAULT ''"),
    ("accounts", "capacity", "INTEGER NOT NULL DEFAULT 1"),
    ("service_requests", "mode", "TEXT NOT NULL DEFAULT 'open'"),
    ("messages", "job_id", "INTEGER"),
    ("messages", "target_account_id", "TEXT DEFAULT ''"),
    ("messages", "is_admin_message", "INTEGER NOT NULL DEFAULT 0"),
    ("disputes", "previous_state", "TEXT DEFAULT ''"),
    ("disputes", "is_anonymous", "INTEGER NOT NULL DEFAULT 0"),
    ("reviews", "editable_until", "TEXT DEFAULT ''"),
    # Phase 1: exact integer money (minor units) alongside the legacy free-text price.
    ("jobs", "agreed_price_minor", "INTEGER"),
    ("jobs", "agreed_price_currency", "TEXT DEFAULT 'KES'"),
    # Web admin console: authenticator-app (TOTP) second factor, with replay protection.
    ("admin_users", "totp_secret", "TEXT DEFAULT ''"),
    ("admin_users", "totp_last_step", "INTEGER DEFAULT 0"),
    # Phone verification by one-time code.
    ("accounts", "phone_verified_at", "TEXT DEFAULT ''"),
]


_POST_MIGRATION_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_requests_mode ON service_requests(mode, status)",
    "CREATE INDEX IF NOT EXISTS ix_messages_job ON messages(job_id) WHERE job_id IS NOT NULL",
]


def _table_columns(conn, table: str):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column_if_missing(conn, table: str, column: str, declaration: str):
    cols = _table_columns(conn, table)
    if column in cols:
        return
    for bad in (";", "--", "/*"):
        if bad in column or bad in declaration:
            raise ValueError(f"Refusing unsafe migration for {table}.{column}")
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _migrate_request_status_check(conn):
    """Rebuild service_requests if its CHECK doesn't allow 'cancelled'."""
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='service_requests'"
    ).fetchone()
    if not sql:
        return
    table_sql = sql[0] or ""
    if "'cancelled'" in table_sql:
        return

    conn.execute("""
        CREATE TABLE service_requests_new(
            request_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            client_account_id      TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
            provider_account_id    TEXT REFERENCES accounts(account_id) ON DELETE SET NULL,
            mode                   TEXT NOT NULL DEFAULT 'open'
                                   CHECK(mode IN ('direct','open')),
            category               TEXT NOT NULL,
            family                 TEXT NOT NULL,
            description            TEXT NOT NULL,
            area                   TEXT NOT NULL,
            preferred_time         TEXT DEFAULT '',
            budget_text            TEXT DEFAULT '',
            status                 TEXT NOT NULL DEFAULT 'open'
                                   CHECK(status IN ('open','accepted','declined','expired','converted','cancelled')),
            created_at             TEXT NOT NULL,
            updated_at             TEXT NOT NULL
        )
    """)
    conn.execute("""
        INSERT INTO service_requests_new(
            request_id, client_account_id, provider_account_id, mode,
            category, family, description, area, preferred_time, budget_text,
            status, created_at, updated_at
        )
        SELECT request_id, client_account_id, provider_account_id,
               COALESCE(mode, 'open'),
               category, family, description, area, preferred_time, budget_text,
               status, created_at, updated_at
        FROM service_requests
    """)
    conn.execute("DROP TABLE service_requests")
    conn.execute("ALTER TABLE service_requests_new RENAME TO service_requests")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_requests_client ON service_requests(client_account_id, status, updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_requests_provider ON service_requests(provider_account_id, status, updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_requests_open ON service_requests(status, area) WHERE status='open'")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_requests_mode ON service_requests(mode, status)")


def _migrate_jobs_state_check(conn):
    """Rebuild jobs if its CHECK doesn't allow 'completed'."""
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='jobs'"
    ).fetchone()
    if not sql:
        return
    table_sql = sql[0] or ""
    if "'completed'" in table_sql:
        return

    events_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='job_events'"
    ).fetchone()
    events_needs_rebuild = events_sql and "'closed'" not in (events_sql[0] or "")

    conn.execute("""
        CREATE TABLE jobs_new(
            job_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id             INTEGER REFERENCES service_requests(request_id) ON DELETE SET NULL,
            client_account_id      TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
            provider_account_id    TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
            category               TEXT NOT NULL,
            family                 TEXT NOT NULL,
            description            TEXT NOT NULL,
            area                   TEXT NOT NULL,
            agreed_price_text      TEXT DEFAULT '',
            current_state          TEXT NOT NULL DEFAULT 'accepted'
                                   CHECK(current_state IN (
                                       'accepted','dispatched','arrived','started',
                                       'client_confirmed','done','completed',
                                       'completed_by_timeout',
                                       'disputed','abandoned','cancelled'
                                   )),
            mutual_completion_deadline  TEXT DEFAULT '',
            hard_timeout_deadline       TEXT DEFAULT '',
            accepted_at            TEXT NOT NULL,
            dispatched_at          TEXT DEFAULT '',
            arrived_at             TEXT DEFAULT '',
            started_at             TEXT DEFAULT '',
            client_confirmed_at    TEXT DEFAULT '',
            done_at                TEXT DEFAULT '',
            closed_at              TEXT DEFAULT '',
            completed_by_timeout   INTEGER NOT NULL DEFAULT 0,
            cancellation_reason    TEXT DEFAULT '',
            cancellation_by        TEXT DEFAULT '',
            created_at             TEXT NOT NULL,
            updated_at             TEXT NOT NULL
        )
    """)
    conn.execute("""
        INSERT INTO jobs_new(
            job_id, request_id, client_account_id, provider_account_id,
            category, family, description, area, agreed_price_text,
            current_state, mutual_completion_deadline, hard_timeout_deadline,
            accepted_at, dispatched_at, arrived_at, started_at,
            client_confirmed_at, done_at, closed_at, completed_by_timeout,
            cancellation_reason, cancellation_by, created_at, updated_at
        )
        SELECT job_id, request_id, client_account_id, provider_account_id,
               category, family, description, area, agreed_price_text,
               current_state, mutual_completion_deadline, hard_timeout_deadline,
               accepted_at, dispatched_at, arrived_at, started_at,
               client_confirmed_at, done_at, closed_at, completed_by_timeout,
               cancellation_reason, cancellation_by, created_at, updated_at
        FROM jobs
    """)
    conn.execute("DROP TABLE jobs")
    conn.execute("ALTER TABLE jobs_new RENAME TO jobs")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_jobs_client ON jobs(client_account_id, current_state, updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_jobs_provider ON jobs(provider_account_id, current_state, updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_jobs_active ON jobs(provider_account_id) WHERE current_state IN ('dispatched','arrived','started')")

    if events_needs_rebuild:
        _rebuild_job_events(conn)


def _rebuild_job_events(conn):
    """Rebuild job_events with 'closed' added to the event_type CHECK."""
    conn.execute("""
        CREATE TABLE job_events_new(
            event_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id            INTEGER NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
            actor_account_id  TEXT REFERENCES accounts(account_id) ON DELETE SET NULL,
            actor_role        TEXT NOT NULL
                              CHECK(actor_role IN ('client','provider','system','admin')),
            event_type        TEXT NOT NULL
                              CHECK(event_type IN (
                                  'accepted','dispatched','arrived','started',
                                  'client_confirmed','done','closed',
                                  'undo','correction_requested','correction_approved','correction_rejected',
                                  'disputed','dispute_resolved',
                                  'abandoned','cancelled',
                                  'auto_completed','auto_confirmed'
                              )),
            from_state        TEXT DEFAULT '',
            to_state          TEXT DEFAULT '',
            note              TEXT DEFAULT '',
            evidence_path     TEXT DEFAULT '',
            client_event_id   TEXT DEFAULT '',
            created_at        TEXT NOT NULL
        )
    """)
    conn.execute("""
        INSERT INTO job_events_new(
            event_id, job_id, actor_account_id, actor_role, event_type,
            from_state, to_state, note, evidence_path, client_event_id, created_at
        )
        SELECT event_id, job_id, actor_account_id, actor_role, event_type,
               from_state, to_state, note, evidence_path, client_event_id, created_at
        FROM job_events
    """)
    conn.execute("DROP TABLE job_events")
    conn.execute("ALTER TABLE job_events_new RENAME TO job_events")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_events_job ON job_events(job_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_events_actor ON job_events(actor_account_id, created_at)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_events_client_id ON job_events(client_event_id) WHERE client_event_id <> ''")


def _migrate_user_reports_kind_check(conn):
    """Rebuild user_reports if its CHECK doesn't allow 'review'."""
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='user_reports'"
    ).fetchone()
    if not sql:
        return
    table_sql = sql[0] or ""
    if "'review'" in table_sql:
        return

    conn.execute("""
        CREATE TABLE user_reports_new(
            report_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            kind                TEXT NOT NULL CHECK(kind IN ('block','dispute','review')),
            reporter_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
            reported_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
            reason              TEXT NOT NULL,
            notes               TEXT DEFAULT '',
            context_job_id      INTEGER REFERENCES jobs(job_id) ON DELETE SET NULL,
            status              TEXT NOT NULL DEFAULT 'open'
                                CHECK(status IN ('open','reviewed','dismissed')),
            created_at          TEXT NOT NULL
        )
    """)
    conn.execute("""
        INSERT INTO user_reports_new(
            report_id, kind, reporter_account_id, reported_account_id,
            reason, notes, context_job_id, status, created_at
        )
        SELECT report_id, kind, reporter_account_id, reported_account_id,
               reason, notes, context_job_id, status, created_at
        FROM user_reports
    """)
    conn.execute("DROP TABLE user_reports")
    conn.execute("ALTER TABLE user_reports_new RENAME TO user_reports")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_user_reports_reporter ON user_reports(reporter_account_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_user_reports_status ON user_reports(status, created_at)")


def _backfill_completed_state(conn):
    """One-shot: any job in state 'done' with closed_at set becomes 'completed'."""
    cur = conn.execute(
        """UPDATE jobs SET current_state='completed'
           WHERE current_state='done' AND closed_at <> ''"""
    )
    if cur.rowcount:
        import logging
        logging.getLogger("servicelink.db").info(
            "Backfilled %d jobs from 'done' to 'completed'", cur.rowcount
        )


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(PHOTO_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    conn = get_conn()
    try:
        conn.execute("PRAGMA foreign_keys = OFF")

        for ddl in _SCHEMA:
            conn.execute(ddl)

        _migrate_request_status_check(conn)
        _migrate_jobs_state_check(conn)
        _migrate_user_reports_kind_check(conn)

        for table, column, declaration in _MIGRATIONS:
            _add_column_if_missing(conn, table, column, declaration)

        for ddl in _POST_MIGRATION_INDEXES:
            conn.execute(ddl)

        _backfill_completed_state(conn)
        _backfill_agreed_price_minor(conn)

        # Versioned baseline marker supports future ordered migrations while keeping
        # existing databases upgradeable through the idempotent legacy migrations.
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES(?,?,?)",
            (1, "legacy_schema_baseline", utcnow_iso()),
        )
        conn.commit()
        conn.execute("PRAGMA foreign_keys = ON")

        _seed_defaults(conn)
        _purge_expired_rate_limits(conn)
    finally:
        conn.close()
    harden_permissions()


def _backfill_agreed_price_minor(conn):
    """Idempotent: parse legacy free-text prices into integer minor units.

    Ambiguous text ("2000 or 2500", ranges) stays NULL rather than guessing.
    """
    from .services import money
    rows = conn.execute(
        """SELECT job_id, agreed_price_text FROM jobs
           WHERE agreed_price_minor IS NULL AND agreed_price_text <> ''"""
    ).fetchall()
    for row in rows:
        minor = money.parse_kes_minor(row["agreed_price_text"])
        if minor is not None:
            conn.execute("UPDATE jobs SET agreed_price_minor=?, agreed_price_currency='KES' WHERE job_id=?",
                         (minor, row["job_id"]))


def harden_permissions():
    """Owner-only access to the database, backups and uploads (POSIX).

    The data folder holds phone numbers, names, photos and dispute evidence.
    On Windows file ACLs apply instead and chmod is a no-op, so it is skipped.
    """
    if os.name == "nt":
        return
    targets = [(DATA_DIR, 0o700), (BACKUP_DIR, 0o700), (PHOTO_DIR, 0o700)]
    for suffix in ("", "-wal", "-shm"):
        targets.append((DB_PATH + suffix, 0o600))
    for path, mode in targets:
        try:
            if os.path.exists(path):
                os.chmod(path, mode)
        except OSError:
            pass


def _seed_defaults(conn):
    defaults = {
        "theme_mode": "auto",
    }
    for key, value in defaults.items():
        conn.execute(
            "INSERT OR IGNORE INTO app_settings(key, value) VALUES(?, ?)",
            (key, value),
        )
    conn.commit()


def _purge_expired_rate_limits(conn):
    cutoff = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "DELETE FROM rate_limits WHERE window_start < datetime(?, '-1 day')",
        (cutoff,),
    )
    conn.commit()