from backend.services import accounts, chat, scam_shield as s
from backend.services.validation import clean_text


def test_contact_details_are_hidden():
    for raw in ("call 0712 345 678 now", "my number +254 712 345 678", "mail bob@gmail.com",
                "bob [at] gmail [dot] com", "see www.example.co.ke", "wa.me/254712345678",
                "zero seven one two three four five six seven eight", "call ０７１２３４５６７８ now"):
        r = s.screen(raw)
        assert r.masked_count >= 1 and s.MASK in r.text, raw
        assert not any(ch.isdigit() for ch in r.text.replace("０", "")) or "@" not in r.text


def test_normal_messages_and_prices_untouched():
    for raw in ("I can come at 3pm for 2500", "Price is KSh 12,500 for the whole job", "see you tomorrow"):
        r = s.screen(raw)
        assert r.text == raw and r.masked_count == 0 and not r.off_platform_payment


def test_off_platform_payment_is_flagged_not_masked():
    for raw in ("send to my mpesa please", "pay me directly in cash", "paybill number 400200",
                "pay outside the app", "advance payment first"):
        assert s.screen(raw).off_platform_payment, raw


def test_masking_can_be_disabled(monkeypatch):
    monkeypatch.setenv("SERVICELINK_MASK_CONTACTS", "0")
    assert s.screen("call 0712345678").text == "call 0712345678"


def test_clean_text_removes_invisible_and_bidi_characters():
    assert clean_text("07\u200b12\u202e345\x00678") == "0712345678"
    assert clean_text("line1\nline2\tok") == "line1\nline2\tok"
    assert s.screen(clean_text("call 07\u200b12 345 678")).masked_count == 1       # zero-width evasion fails


def _client(isolated_database, name, phone, role="client"):
    from backend.services import categories
    family = categories.SERVICE_FAMILIES[0][0] if role == "provider" else ""
    ok, account_id = accounts.create_account(
        role=role, full_name=name, phone=phone, email="", password="amber-falcon-river-lamp",
        password_confirm="amber-falcon-river-lamp", terms_accepted=True, role_locked=True,
        service_family=family, device_key="pytest-device")
    assert ok, account_id
    return account_id


def test_chat_stores_masked_text_and_posts_one_warning(isolated_database, monkeypatch):
    a = _client(isolated_database, "Ann Mwangi", "0712345601")
    b = _client(isolated_database, "Ben Otieno", "0712345602", role="provider")
    monkeypatch.setattr(chat, "_has_live_engagement", lambda *args, **kw: True)
    conv = chat.ensure_conversation(a, b)
    assert chat.send_message(conv, a, "call me on 0712 345 678 or bob@gmail.com")[0]
    assert chat.send_message(conv, a, "send to my mpesa please")[0]
    assert chat.send_message(conv, b, "pay me directly in cash")[0]
    conn = isolated_database.get_conn()
    try:
        bodies = [r["body"] for r in conn.execute(
            "SELECT body FROM messages WHERE conversation_id=? AND sender_role!='system' ORDER BY message_id", (conv,))]
        warnings = conn.execute("SELECT COUNT(*) c FROM messages WHERE conversation_id=? AND sender_role='system' AND body=?",
                                (conv, s.PAYMENT_WARNING)).fetchone()["c"]
    finally:
        conn.close()
    assert bodies[0] == f"call me on {s.MASK} or {s.MASK}"
    assert "0712" not in " ".join(bodies) and "gmail" not in " ".join(bodies)
    assert warnings == 1                                   # not repeated for every flagged message
