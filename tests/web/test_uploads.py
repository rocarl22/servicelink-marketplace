"""Photo uploads: profile photo, portfolio, dispute evidence - validation and access control."""
import io
import os
import re
import sys

from PIL import Image

sys.path.insert(0, os.path.dirname(__file__))
import webhelpers as H                                           # noqa: E402
import test_admin as A                                           # noqa: E402
from backend import database as dbmod, face_screen               # noqa: E402
from backend.services import accounts                            # noqa: E402


# ------------------------------------------------------------------ test images
def jpeg(size=(900, 600), gps=False):
    img = Image.effect_noise(size, 60).convert("RGB")             # no faces in noise
    exif = img.getexif()
    if gps:
        exif[0x010F] = "SecretCamBrand"
        gps_ifd = exif.get_ifd(0x8825)
        gps_ifd[1], gps_ifd[2], gps_ifd[3], gps_ifd[4] = "S", (1.0, 17.0, 0.0), "E", (36.0, 49.0, 0.0)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=85, exif=exif)
    return buf.getvalue()


def png(size=(400, 300)):
    buf = io.BytesIO(); Image.effect_noise(size, 50).convert("RGB").save(buf, "PNG"); return buf.getvalue()


def webp(size=(400, 300)):
    buf = io.BytesIO(); Image.effect_noise(size, 50).convert("RGB").save(buf, "WEBP"); return buf.getvalue()


PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"


def up(client, path, field, content, filename="photo.jpg", page="/settings", **fields):
    data = {"csrf_token": H.token_for(client, page), field: (io.BytesIO(content), filename)}
    data.update(fields)
    return client.post(path, data=data, content_type="multipart/form-data")


def tmp_files(isolated_database):
    d = os.path.join(isolated_database.DATA_DIR, "tmp_uploads")
    return os.listdir(d) if os.path.isdir(d) else []


def acct_id(phone):
    return accounts.get_account_by_phone(phone)["account_id"]


def world(isolated_database, **cfg):
    app = H.make_app(isolated_database, **cfg)
    client, provider = H.setup_marketplace(app)
    return app, client, provider


def jpeg_ok(body):
    img = Image.open(io.BytesIO(body)); img.load()
    return img


# ------------------------------------------------------------------ profile photo
def test_profile_photo_is_re_encoded_without_metadata_and_served_safely(isolated_database):
    app, client, provider = world(isolated_database)
    original = jpeg((3000, 2000), gps=True)
    assert b"SecretCamBrand" in original
    r = up(client, "/settings/photo", "photo", original, "../../evil.php.jpg")
    assert r.status_code == 302
    cid = acct_id("0712345601")
    resp = client.get(f"/media/avatar/{cid}")
    assert resp.status_code == 200 and resp.mimetype == "image/jpeg"
    assert "sandbox" in resp.headers["Content-Security-Policy"] and resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Content-Disposition"].startswith("inline") and "evil" not in resp.headers["Content-Disposition"]
    assert resp.headers["Cache-Control"].startswith("private")
    img = jpeg_ok(resp.data)
    assert max(img.size) <= 1280 and len(img.getexif()) == 0 and b"SecretCamBrand" not in resp.data     # shrunk, GPS/camera data gone
    stored = accounts.get_account(cid)["work_photo_path"]
    assert os.path.dirname(stored).endswith("profile_photos") and "evil" not in stored
    assert not any("evil" in f for _, _, fs in os.walk(isolated_database.DATA_DIR) for f in fs)
    assert tmp_files(isolated_database) == []


def test_who_may_see_a_profile_photo(isolated_database):
    app, client, provider = world(isolated_database)
    up(client, "/settings/photo", "photo", jpeg()); up(provider, "/settings/photo", "photo", png())
    cid, pid = acct_id("0712345601"), acct_id("0712345602")
    anon = app.test_client()
    assert anon.get(f"/media/avatar/{pid}").status_code == 200 and anon.get(f"/media/avatar/{pid}").headers["Cache-Control"].startswith("public")
    assert anon.get(f"/media/avatar/{cid}").status_code == 404                           # a client's photo is not public
    stranger = H.register(app, "client", "Mallory Kip", "0712345609")
    assert stranger.get(f"/media/avatar/{cid}").status_code == 404
    H.post(client, "/request/new", f"/request/new?provider={pid}", provider=pid, category="Plumbing", area="Westlands", description="Fix my kitchen tap please")
    assert provider.get(f"/media/avatar/{cid}").status_code == 200                       # they now deal with each other
    assert stranger.get(f"/media/avatar/{cid}").status_code == 404
    assert client.get(f"/media/avatar/{cid}").status_code == 200
    H.post(provider, "/settings/photo/remove", "/settings")
    assert anon.get(f"/media/avatar/{pid}").status_code == 404
    assert anon.get("/media/avatar/not-an-id").status_code == 404


def test_new_photo_changes_its_cache_busting_address(isolated_database):
    app, client, provider = world(isolated_database)
    up(client, "/settings/photo", "photo", jpeg()); v1 = re.search(r"/media/avatar/[^\"?]+\?v=(\w+)", client.get("/settings").get_data(as_text=True)).group(1)
    up(client, "/settings/photo", "photo", png()); v2 = re.search(r"/media/avatar/[^\"?]+\?v=(\w+)", client.get("/settings").get_data(as_text=True)).group(1)
    assert v1 != v2


def test_non_images_and_disguised_files_are_rejected(isolated_database):
    app, client, provider = world(isolated_database)
    bad = {
        "text renamed .jpg": (b"just some text pretending to be a photo " * 5, "photo.jpg"),
        "html": (b"<html><script>alert(1)</script></html>" * 3, "photo.jpg"),
        "svg with script": (b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>" * 2, "logo.svg"),
        "gif": (b"GIF89a" + b"\x00" * 60, "anim.gif"),
        "windows exe": (b"MZ" + b"\x90" * 80, "setup.jpg"),
        "pdf where photos expected": (PDF, "doc.pdf"),
        "jpeg header + garbage": (b"\xff\xd8\xff\xe0" + os.urandom(2000), "photo.jpg"),
        "empty": (b"", "empty.jpg"),
    }
    for name, (content, fname) in bad.items():
        r = up(client, "/settings/photo", "photo", content, fname)
        assert r.status_code == 302, name
    assert accounts.get_account(acct_id("0712345601"))["work_photo_path"] == ""
    assert tmp_files(isolated_database) == []                                            # temp files always cleaned up
    r = up(client, "/settings/photo", "photo", b"<html><script>alert(1)</script></html>" * 3, "photo.jpg")
    assert "isn&#39;t allowed" in client.get("/settings").get_data(as_text=True)               # the visitor is told why


def test_size_limits(isolated_database):
    app, client, provider = world(isolated_database)
    big_valid_header = b"\xff\xd8\xff\xe0" + b"\x00" * (12 * 1024 * 1024 + 4096)           # > 12 MB image, < 13 MB request
    r = up(client, "/settings/photo", "photo", big_valid_header)
    assert r.status_code == 302 and accounts.get_account(acct_id("0712345601"))["work_photo_path"] == ""
    assert tmp_files(isolated_database) == []
    assert "too large" in client.get("/settings").get_data(as_text=True)
    huge = b"\xff\xd8\xff\xe0" + b"\x00" * (14 * 1024 * 1024)
    assert up(client, "/settings/photo", "photo", huge).status_code == 413                  # whole request too big
    tok = H.token_for(client, "/settings")
    assert client.post("/settings/profile", data={"csrf_token": tok, "display_name": "A", "area": "Rongai", "bio": "x" * 400_000}).status_code == 413   # other routes stay tiny


def test_upload_needs_login_csrf_and_the_right_role(isolated_database):
    app, client, provider = world(isolated_database)
    anon = app.test_client()
    r = anon.post("/settings/photo", data={"photo": (io.BytesIO(jpeg()), "a.jpg")}, content_type="multipart/form-data")
    assert r.status_code == 403
    r = client.post("/settings/photo", data={"photo": (io.BytesIO(jpeg()), "a.jpg")}, content_type="multipart/form-data")   # logged in, no token
    assert r.status_code == 403 and accounts.get_account(acct_id("0712345601"))["work_photo_path"] == ""
    r = client.post("/settings/photo", data={"csrf_token": H.token_for(client, "/settings"), "photo": (io.BytesIO(jpeg()), "a.jpg")},
                    content_type="multipart/form-data", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert up(client, "/settings/portfolio/add", "photo", jpeg(), title="x").status_code == 403          # clients have no portfolio


def test_uploads_are_rate_limited(isolated_database):
    app, client, provider = world(isolated_database, RATE_LIMITS_ENABLED=True)
    codes = [up(client, "/settings/photo", "photo", b"junk-not-an-image" * 4).status_code for _ in range(24)]
    assert 429 in codes and codes[0] == 302


# ------------------------------------------------------------------ portfolio
def test_portfolio_flow_with_face_screening_and_visibility(isolated_database, monkeypatch):
    app, client, provider = world(isolated_database)
    pid = acct_id("0712345602")
    r = up(provider, "/settings/portfolio/add", "photo", jpeg(), title="Kitchen sink repair", description="Call me on 0712 345 678")
    assert r.status_code == 302
    conn = isolated_database.get_conn(); item = conn.execute("SELECT * FROM portfolio").fetchone(); conn.close()
    assert item["title"] == "Kitchen sink repair" and "0712 345 678" not in item["description"] and "[contact hidden]" in item["description"]
    anon = app.test_client()
    page = anon.get(f"/providers/{pid}").get_data(as_text=True)
    assert "Work samples" in page and f"/media/portfolio/{item['item_id']}" in page and "Kitchen sink repair" in page
    assert item["photo_path"] not in page and "portfolio/" in page and isolated_database.DATA_DIR not in page
    img = anon.get(f"/media/portfolio/{item['item_id']}")
    assert img.status_code == 200 and img.mimetype == "image/jpeg" and "sandbox" in img.headers["Content-Security-Policy"] and img.headers["Cache-Control"].startswith("public")
    # hide: public loses it, owner keeps it
    H.post(provider, f"/settings/portfolio/{item['item_id']}/toggle", "/settings")
    assert anon.get(f"/media/portfolio/{item['item_id']}").status_code == 404 and "Work samples" not in anon.get(f"/providers/{pid}").get_data(as_text=True)
    own = provider.get(f"/media/portfolio/{item['item_id']}")
    assert own.status_code == 200 and own.headers["Cache-Control"] == "private, no-store"
    H.post(provider, f"/settings/portfolio/{item['item_id']}/toggle", "/settings")
    assert anon.get(f"/media/portfolio/{item['item_id']}").status_code == 200
    # another provider cannot touch it
    rogue = H.register(app, "provider", "Rick Oduor", "0712345610", "home")
    H.post(rogue, f"/settings/portfolio/{item['item_id']}/edit", "/settings", title="HACKED", description="")
    H.post(rogue, f"/settings/portfolio/{item['item_id']}/toggle", "/settings")
    H.post(rogue, f"/settings/portfolio/{item['item_id']}/delete", "/settings")
    conn = isolated_database.get_conn(); row = conn.execute("SELECT title, visible FROM portfolio WHERE item_id=?", (item["item_id"],)).fetchone(); conn.close()
    assert row and row["title"] == "Kitchen sink repair" and row["visible"] == 1
    # edit + delete by the owner; the file leaves the disk
    H.post(provider, f"/settings/portfolio/{item['item_id']}/edit", "/settings", title="Sink repair", description="Neat finish")
    assert "Sink repair" in anon.get(f"/providers/{pid}").get_data(as_text=True)
    assert os.path.isfile(item["photo_path"])
    H.post(provider, f"/settings/portfolio/{item['item_id']}/delete", "/settings")
    assert not os.path.exists(item["photo_path"]) and anon.get(f"/media/portfolio/{item['item_id']}").status_code == 404
    assert tmp_files(isolated_database) == []


def test_portfolio_refuses_photos_of_people_and_fails_closed(isolated_database, monkeypatch):
    app, client, provider = world(isolated_database)
    monkeypatch.setattr(face_screen, "contains_face", lambda path: True)
    up(provider, "/settings/portfolio/add", "photo", jpeg(), title="Team photo")
    conn = isolated_database.get_conn(); assert conn.execute("SELECT COUNT(*) FROM portfolio").fetchone()[0] == 0; conn.close()
    assert "face" in provider.get("/settings").get_data(as_text=True).lower() or "people" in provider.get("/settings").get_data(as_text=True).lower()
    monkeypatch.setattr(face_screen, "CV2_OK", False)                                     # detector unavailable -> refuse, never skip the check
    up(provider, "/settings/portfolio/add", "photo", jpeg(), title="Another")
    conn = isolated_database.get_conn(); assert conn.execute("SELECT COUNT(*) FROM portfolio").fetchone()[0] == 0; conn.close()
    assert tmp_files(isolated_database) == []


def test_database_paths_are_never_trusted(isolated_database, tmp_path):
    app, client, provider = world(isolated_database)
    up(provider, "/settings/photo", "photo", jpeg())
    up(provider, "/settings/portfolio/add", "photo", jpeg(), title="Sink")
    pid = acct_id("0712345602")
    secret = tmp_path / "secret.txt"; secret.write_bytes(b"top secret")
    conn = isolated_database.get_conn()
    item = conn.execute("SELECT item_id FROM portfolio").fetchone()[0]
    anon = app.test_client()
    assert anon.get(f"/media/avatar/{pid}").status_code == 200
    # 1) a path pointing outside the data folder
    conn.execute("UPDATE accounts SET work_photo_path=? WHERE account_id=?", (str(secret), pid))
    conn.execute("UPDATE portfolio SET photo_path=?", (str(secret),)); conn.commit()
    assert anon.get(f"/media/avatar/{pid}").status_code == 404 and anon.get(f"/media/portfolio/{item}").status_code == 404
    # 2) a path with ../ that escapes
    escape = os.path.join(isolated_database.DATA_DIR, "portfolio", "..", "..", "secret.txt")
    conn.execute("UPDATE portfolio SET photo_path=?", (escape,)); conn.commit()
    assert anon.get(f"/media/portfolio/{item}").status_code == 404
    # 3) a symlink inside the folder that points outside
    link = os.path.join(isolated_database.DATA_DIR, "portfolio", "link.jpg")
    os.makedirs(os.path.dirname(link), exist_ok=True)
    try:
        os.symlink(str(secret), link)
        conn.execute("UPDATE portfolio SET photo_path=?", (link,)); conn.commit()
        assert anon.get(f"/media/portfolio/{item}").status_code == 404
    except OSError:
        pass                                                                                # symlinks unavailable on this system
    conn.close()


def test_server_file_paths_never_appear_in_pages(isolated_database):
    app, client, provider = world(isolated_database)
    up(provider, "/settings/photo", "photo", jpeg()); up(provider, "/settings/portfolio/add", "photo", jpeg(), title="Sink")
    root = isolated_database.DATA_DIR
    pid = acct_id("0712345602")
    for who in (client, provider, app.test_client()):
        for path in ("/", "/providers", f"/providers/{pid}", "/settings", "/dashboard"):
            r = who.get(path)
            if r.status_code == 200:
                html = r.get_data(as_text=True)
                assert root not in html and "profile_photos" not in html and "work_photo_path" not in html, path
                assert not re.search(r"\sstyle=|<script(?![^>]*\bsrc=)", html), path


# ------------------------------------------------------------------ dispute evidence
def dispute_with_world(isolated_database, **cfg):
    app = H.make_app(isolated_database, **cfg)
    A.mk_admin()
    client, provider, job = A.start_dispute(app, isolated_database)
    conn = isolated_database.get_conn(); did = conn.execute("SELECT dispute_id FROM disputes").fetchone()[0]; conn.close()
    return app, client, provider, did


def evidence_ids(isolated_database):
    conn = isolated_database.get_conn()
    try:
        return [r[0] for r in conn.execute("SELECT evidence_id FROM dispute_evidence ORDER BY evidence_id")]
    finally:
        conn.close()


def test_evidence_is_private_to_the_sender_and_visible_to_admins(isolated_database):
    app, client, provider, did = dispute_with_world(isolated_database)
    r = up(client, f"/disputes/{did}/reply", "evidence", jpeg(gps=True), "../../shell.php.jpg", page="/disputes", body="Photo of the unfinished pipe")
    assert r.status_code == 302
    [eid] = evidence_ids(isolated_database)
    conn = isolated_database.get_conn(); row = conn.execute("SELECT * FROM dispute_evidence").fetchone(); conn.close()
    assert "shell" not in row["original_name"] and "shell" not in row["file_path"]
    page = client.get("/disputes").get_data(as_text=True)
    assert f"/media/evidence/{eid}" in page and "unfinished pipe" in page and isolated_database.DATA_DIR not in page
    mine = client.get(f"/media/evidence/{eid}")
    assert mine.status_code == 200 and mine.mimetype == "image/jpeg" and mine.headers["Cache-Control"] == "private, no-store"
    assert "sandbox" in mine.headers["Content-Security-Policy"] and len(jpeg_ok(mine.data).getexif()) == 0 and b"SecretCamBrand" not in mine.data
    stranger = H.register(app, "client", "Mallory Kip", "0712345609")
    for who in (provider, stranger, app.test_client()):                                    # other party, stranger, signed-out
        assert who.get(f"/media/evidence/{eid}").status_code in (302, 404)
        assert "image/jpeg" not in (who.get(f"/media/evidence/{eid}").headers.get("Content-Type") or "")
    c, _ = A.enrolled_admin_client(app)
    assert f"/admin/media/evidence/{eid}" in c.get(f"/admin/disputes/{did}").get_data(as_text=True)
    adm = c.get(f"/admin/media/evidence/{eid}")
    assert adm.status_code == 200 and adm.mimetype == "image/jpeg" and "sandbox" in adm.headers["Content-Security-Policy"]
    assert client.get(f"/admin/media/evidence/{eid}").status_code == 302                  # users cannot use the admin route
    assert app.test_client().get(f"/admin/media/evidence/{eid}").status_code == 302
    assert tmp_files(isolated_database) == []


def test_evidence_rejects_bad_files_and_pdfs_are_off_by_default(isolated_database):
    app, client, provider, did = dispute_with_world(isolated_database)
    for content, name in ((b"<html>x</html>" * 5, "e.jpg"), (PDF, "evidence.pdf"), (b"MZ" + b"\x00" * 100, "e.jpg"), (b"\xff\xd8\xff" + os.urandom(500), "e.jpg")):
        up(client, f"/disputes/{did}/reply", "evidence", content, name, page="/disputes", body="see attached")
    assert evidence_ids(isolated_database) == []
    assert tmp_files(isolated_database) == []
    # an image without any text still works ("Evidence attached.")
    up(client, f"/disputes/{did}/reply", "evidence", png(), "p.png", page="/disputes", body="")
    assert len(evidence_ids(isolated_database)) == 1 and "Evidence attached." in client.get("/disputes").get_data(as_text=True)


def test_pdf_evidence_when_enabled_is_downloaded_not_displayed(isolated_database):
    app, client, provider, did = dispute_with_world(isolated_database, ALLOW_PDF_EVIDENCE=True)
    up(client, f"/disputes/{did}/reply", "evidence", PDF, "../../invoice.php", page="/disputes", body="Invoice attached")
    [eid] = evidence_ids(isolated_database)
    r = client.get(f"/media/evidence/{eid}")
    assert r.status_code == 200 and r.mimetype == "application/pdf" and r.headers["Content-Disposition"].startswith("attachment")
    assert "sandbox" in r.headers["Content-Security-Policy"] and "invoice" not in r.headers["Content-Disposition"]
    assert "Document (PDF)" in client.get("/disputes").get_data(as_text=True)


def test_only_the_three_upload_routes_accept_large_bodies(isolated_database):
    app, client, provider = world(isolated_database)
    tok = H.token_for(client, "/settings")
    for path in ("/settings/profile", "/settings/password", "/jobs/1/cancel", "/messages/1"):
        assert client.post(path, data={"csrf_token": tok, "x": "y" * 300_000}).status_code in (413,), path
