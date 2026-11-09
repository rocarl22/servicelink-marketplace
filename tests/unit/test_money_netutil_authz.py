from backend.services import authz, money, netutil


def test_money_parsing():
    assert money.parse_kes_minor("KSh 2,500") == 250000
    assert money.parse_kes_minor("2500") == 250000
    assert money.parse_kes_minor("KES 2,500.50") == 250050
    assert money.parse_kes_minor("2.5k") == 250000
    assert money.parse_kes_minor("KSh 1,000,000/=") == 100000000
    for ambiguous in ("2000 or 2500", "2000-3000", "1,2", "abc", "0", "", None):
        assert money.parse_kes_minor(ambiguous) is None, ambiguous
    assert money.format_kes(250050) == "KSh 2,500.50" and money.format_kes(250000) == "KSh 2,500"


def test_price_backfill_is_idempotent_and_skips_ambiguous(isolated_database):
    from backend import database as db
    conn = isolated_database.get_conn()
    try:
        conn.execute("PRAGMA foreign_keys=OFF")
        for i, text in enumerate(("KSh 3,000", "2000 or 2500", "")):
            conn.execute(
                """INSERT INTO jobs(request_id, client_account_id, provider_account_id, category, family,
                   description, area, agreed_price_text, accepted_at, created_at, updated_at)
                   VALUES(NULL,?,?,?,?,?,?,?,?,?,?)""",
                (f"C-{i}", f"P-{i}", "Plumbing", "Home", "d", "Nairobi", text, "t", "t", "t"))
        conn.commit()
        for _ in range(2):
            db._backfill_agreed_price_minor(conn)
        conn.commit()
        got = [r[0] for r in conn.execute("SELECT agreed_price_minor FROM jobs ORDER BY job_id")]
    finally:
        conn.close()
    assert got == [300000, None, None]


def test_client_ip_ignores_spoofed_headers_from_untrusted_peers():
    proxies = ["10.0.0.0/8"]
    assert netutil.client_ip("8.8.8.8", "1.2.3.4", proxies) == "8.8.8.8"                 # spoof ignored
    assert netutil.client_ip("10.0.0.5", "1.2.3.4, 9.9.9.9, 10.0.0.7", proxies) == "9.9.9.9"
    assert netutil.client_ip("10.0.0.5", "garbage", proxies) == "10.0.0.5"
    assert netutil.client_ip("10.0.0.5", "1.2.3.4", []) == "10.0.0.5"                    # no trusted proxies
    assert netutil.client_ip("not-an-ip") is None


def test_ipv6_grouped_by_64_and_keys_are_hashed():
    assert netutil.rate_bucket_ip("2001:db8::1:2") == netutil.rate_bucket_ip("2001:db8::ffff") == "2001:db8::/64"
    k1, k2 = netutil.rate_key("login", "0712345678"), netutil.rate_key("login", "0712345678")
    assert k1 == k2 and "0712345678" not in k1 and k1.startswith("login:")


def test_authz_pair_resolution_uses_the_session_account_only():
    roles = {"C1": "client", "P1": "provider", "C2": "client"}.get
    assert authz.resolve_client_provider("C1", "P1", roles) == ("C1", "P1")
    assert authz.resolve_client_provider("P1", "C1", roles) == ("C1", "P1")
    assert authz.resolve_client_provider("C1", "C2", roles) is None           # same role
    assert authz.resolve_client_provider("C1", "C1", roles) is None           # self
    assert authz.resolve_client_provider("", "P1", roles) is None
    assert authz.resolve_client_provider("X", "P1", roles) is None            # unknown account
