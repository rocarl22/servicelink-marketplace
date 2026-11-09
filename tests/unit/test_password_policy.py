from backend.services import passwords as p

CTX = ("Jane Wanjiku", "0712345678", "jane.w@example.invalid")


def ok(pw, ctx=()):
    return p.validate_password(pw, context=ctx)[0]


def test_length_over_complexity():
    assert not ok("Sh0rt!")
    assert ok("correct horse battery staple")       # no digits/symbols/caps needed
    assert ok("blue-giraffe-sings-loud")


def test_common_and_leetspeak_passwords_rejected():
    for bad in ("Password123!", "P@ssw0rd2024!!", "Nairobi#2024!!", "kenyakenya2024",
                "welcomekenya99!", "qwertyuiop12", "abcdefghijkl", "aaaaaaaaaaaa"):
        assert not ok(bad), bad


def test_own_identity_not_allowed_inside_password():
    assert not ok("JaneWanjiku2024x", CTX)
    assert not ok("my-number-0712345678-ok", CTX)
    assert not ok("jane.w-loves-tea-daily", CTX)
    assert ok("amber-falcon-river-lamp", CTX)


def test_max_length_is_enforced_in_bytes():
    assert not ok("z" * 73)
    assert not ok("é" * 40)           # 80 bytes: bcrypt would silently truncate
    assert ok("amber-falcon-river-lamp-" + "x" * 10)


def test_strength_and_suggestion_follow_the_policy():
    assert p.strength("short") == "weak"
    assert p.strength("blue-giraffe-sings-loud") == "strong"
    for _ in range(25):
        s = p.suggest()
        assert len(s) == 16 and ok(s)


def test_breach_check_is_k_anonymous_and_fails_open(monkeypatch):
    seen = []

    def fake(url, timeout):
        seen.append(url)
        return "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n"       # sha1('password') suffix
    assert p.breach_count("password", fetch=fake) == 3861493
    assert seen[0].endswith("/5BAA6")                                  # only the 5-char prefix is sent
    assert p.breach_count("password", fetch=lambda u, t: (_ for _ in ()).throw(OSError())) is None
    monkeypatch.setenv("SERVICELINK_HIBP", "1")
    assert p.validate_password("amber-falcon-river-lamp", fetch=lambda u, t: "")[0]      # not breached
    assert not p.validate_password("amber-falcon-river-lamp",
                                   fetch=lambda u, t: _suffix_line("amber-falcon-river-lamp"))[0]


def _suffix_line(pw):
    import hashlib
    return hashlib.sha1(pw.encode()).hexdigest().upper()[5:] + ":42"
