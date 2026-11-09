"""Job tracking, disputes from the job page, reviews, availability, services and the timer sweep."""
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
import webhelpers as H                                           # noqa: E402
import test_admin as A                                           # noqa: E402
from backend import database as dbmod                            # noqa: E402
from backend.services import admin, timers                       # noqa: E402
from web import sweeper                                          # noqa: E402
from web.app import create_app                                   # noqa: E402


def adv(who, job, action):
    r = H.post(who, f"/jobs/{job}/advance", f"/jobs/{job}", action=action)
    assert r.status_code == 302, action


def page(who, path):
    return who.get(path).get_data(as_text=True)


def step_classes(html):
    """[(label, classes)] for the tracker."""
    out = []
    for m in re.finditer(r'<li class="([^"]*)">\s*<span class="dot-mark"[^>]*>.*?</span>\s*<div><strong class="step-label">([^<]+)</strong>', html, re.S):
        out.append((m.group(2), " ".join(m.group(1).split())))
    return out


def world(isolated_database):
    app = H.make_app(isolated_database)
    client, provider = H.setup_marketplace(app)
    job = H.make_job(app, isolated_database, client, provider)
    return app, client, provider, job


# ------------------------------------------------------------------ tracker
def test_tracker_shows_every_stage_and_moves_with_the_job(isolated_database):
    app, client, provider, job = world(isolated_database)
    steps = step_classes(page(client, f"/jobs/{job}"))
    assert [s[0] for s in steps] == ["Job accepted", "Provider on the way", "Provider arrived", "Work started",
                                     "Client confirmed the start", "Work marked done", "Job closed"]
    assert steps[0][1] == "done" and "current" in steps[1][1] and all("done" not in s[1] for s in steps[2:])
    adv(provider, job, "dispatched")
    adv(provider, job, "arrived")
    steps = step_classes(page(client, f"/jobs/{job}"))
    assert [("done" in s[1]) for s in steps] == [True, True, True, False, False, False, False] and "current" in steps[3][1]


def test_waiting_guidance_follows_who_must_act(isolated_database):
    app, client, provider, job = world(isolated_database)
    assert "Waiting for the provider to set off" in page(client, f"/jobs/{job}")
    assert "Your next step" in page(provider, f"/jobs/{job}")
    adv(provider, job, "dispatched"); adv(provider, job, "arrived"); adv(provider, job, "started")
    assert "Your next step" in page(client, f"/jobs/{job}")                              # client must confirm the start
    html = page(provider, f"/jobs/{job}")
    assert "Waiting for the client to confirm the work has started" in html and "automatically after" in html
    adv(client, job, "client_confirmed"); adv(provider, job, "done")
    html = page(provider, f"/jobs/{job}")
    assert "Waiting for the client to confirm the job is complete" in html
    adv(client, job, "close")
    html = page(client, f"/jobs/{job}")
    assert "This job is complete" in html and step_classes(html)[-1] == ("Job closed", "done")


def test_cancelled_job_ends_in_a_red_marker_with_the_reason(isolated_database):
    app, client, provider, job = world(isolated_database)
    adv(provider, job, "dispatched")
    H.post(client, f"/jobs/{job}/cancel", f"/jobs/{job}", reason="Plans changed, sorry")
    html = page(provider, f"/jobs/{job}")
    steps = step_classes(html)
    assert steps[-1][0] == "Job cancelled" and "bad" in steps[-1][1] and "Plans changed" in html and "This job has been cancelled" in html
    assert 'data-live="0"' in html


def test_live_refresh_only_for_unfinished_jobs(isolated_database):
    app, client, provider, job = world(isolated_database)
    assert 'data-live="20"' in page(client, f"/jobs/{job}") and 'data-live="30"' in page(client, "/jobs")


def test_job_tabs_split_active_completed_cancelled(isolated_database):
    app, client, provider, job = world(isolated_database)
    html = page(client, "/jobs")
    assert "Active" in html and re.search(r"Active <span[^>]*>1</span>", html) and re.search(r"Completed <span[^>]*>0</span>", html)
    adv(provider, job, "dispatched"); adv(provider, job, "arrived"); adv(provider, job, "started")
    adv(client, job, "client_confirmed"); adv(provider, job, "done"); adv(client, job, "close")
    assert "Plumbing" in page(client, "/jobs?tab=completed") and "Nothing here yet" in page(client, "/jobs?tab=cancelled")
    assert "Nothing here yet" in page(client, "/jobs?tab=active")
    assert "Nothing here yet" in page(client, "/jobs?tab=bogus")                                # unknown tab falls back to Active
    assert re.search(r"Completed <span[^>]*>1</span>", page(client, "/jobs"))


# ------------------------------------------------------------------ disputes from the job page
def open_dispute(client, job):
    cat = dbmod.INCIDENT_TYPES_CLIENT[0]
    return H.post(client, f"/jobs/{job}/dispute", f"/jobs/{job}", category=cat, description="The provider never turned up at the agreed time at all.")


def test_dispute_can_be_withdrawn_by_opener_only(isolated_database):
    app, client, provider, job = world(isolated_database)
    adv(provider, job, "dispatched"); adv(provider, job, "arrived")
    open_dispute(client, job)
    c_html, p_html = page(client, f"/jobs/{job}"), page(provider, f"/jobs/{job}")
    assert "Withdraw dispute" in c_html and "Accept dispute" not in c_html and "Dispute opened" in c_html
    assert "Accept dispute" in p_html and "Withdraw dispute" not in p_html
    H.post(provider, f"/jobs/{job}/dispute/withdraw", f"/jobs/{job}")                      # not the opener: refused
    assert "A dispute is open" in page(client, f"/jobs/{job}")
    H.post(client, f"/jobs/{job}/dispute/withdraw", f"/jobs/{job}")
    html = page(client, f"/jobs/{job}")
    assert "A dispute is open" not in html and "Provider arrived" in html
    intruder = H.register(app, "client", "Mallory Kip", "0712345609")
    assert H.post(intruder, f"/jobs/{job}/dispute/withdraw", "/settings").status_code == 404
    assert H.post(intruder, f"/jobs/{job}/dispute/accept", "/settings").status_code == 404


def test_other_party_can_accept_a_dispute_which_cancels_the_job(isolated_database):
    app, client, provider, job = world(isolated_database)
    adv(provider, job, "dispatched"); adv(provider, job, "arrived")
    open_dispute(client, job)
    H.post(client, f"/jobs/{job}/dispute/accept", f"/jobs/{job}")                          # can't accept your own
    assert "A dispute is open" in page(client, f"/jobs/{job}")
    H.post(provider, f"/jobs/{job}/dispute/accept", f"/jobs/{job}", note="Fair enough")
    assert "This job has been cancelled" in page(client, f"/jobs/{job}")


# ------------------------------------------------------------------ reviews
def finish(client, provider, job):
    adv(provider, job, "dispatched"); adv(provider, job, "arrived"); adv(provider, job, "started")
    adv(client, job, "client_confirmed"); adv(provider, job, "done"); adv(client, job, "close")


def test_review_can_be_edited_within_a_week_and_is_listed(isolated_database):
    app, client, provider, job = world(isolated_database)
    finish(client, provider, job)
    H.post(client, f"/jobs/{job}/review", f"/jobs/{job}", stars="5", comment="Great work")
    html = page(client, f"/jobs/{job}")
    assert "Your review of" in html and "Edit my review" in html and "Leave a review" not in html
    H.post(client, f"/jobs/{job}/review/edit", f"/jobs/{job}", stars="4", comment="Good work, call 0712 345 678")
    html = page(client, f"/jobs/{job}")
    assert "Good work" in html and "0712 345 678" not in html and "[contact hidden]" in html
    rec = page(provider, "/reviews")
    assert "Good work" in rec and "4.0" in rec and "Plumbing" in rec
    given = page(client, "/reviews?tab=given")
    assert "Good work" in given
    assert "Review from" in page(provider, f"/jobs/{job}")
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat(timespec="seconds")
    conn = dbmod.get_conn(); conn.execute("UPDATE reviews SET editable_until=?", (old,)); conn.commit(); conn.close()
    html = page(client, f"/jobs/{job}")
    assert "Edit my review" not in html and "edited for 7 days" in html
    H.post(client, f"/jobs/{job}/review/edit", f"/jobs/{job}", stars="1", comment="Changed my mind")
    assert "Changed my mind" not in page(client, f"/jobs/{job}")


def test_nobody_can_edit_someone_elses_review(isolated_database):
    app, client, provider, job = world(isolated_database)
    finish(client, provider, job)
    H.post(client, f"/jobs/{job}/review", f"/jobs/{job}", stars="5", comment="Great work")
    intruder = H.register(app, "client", "Mallory Kip", "0712345609")
    assert H.post(intruder, f"/jobs/{job}/review/edit", "/settings", stars="1", comment="vandal").status_code == 404
    assert H.post(provider, f"/jobs/{job}/review/edit", f"/jobs/{job}", stars="1", comment="vandal").status_code == 404   # provider has no review yet
    assert "vandal" not in page(client, f"/jobs/{job}")


# ------------------------------------------------------------------ availability
def test_provider_availability_shows_on_cards_and_is_validated(isolated_database):
    app, client, provider, job = world(isolated_database)
    assert "Available now" in page(client, "/providers") or "On a job" in page(client, "/providers")
    adv(provider, job, "dispatched"); adv(provider, job, "arrived"); adv(provider, job, "started")
    adv(client, job, "client_confirmed"); adv(provider, job, "done"); adv(client, job, "close")
    H.post(provider, "/availability", "/dashboard", mode="busy_until", when="tomorrow 9am", note="Back after the weekend")
    assert "Busy until tomorrow 9am" in page(client, "/providers")
    assert 'value="tomorrow 9am"' in page(provider, "/dashboard")
    H.post(provider, "/availability", "/dashboard", mode="available_at", when="3pm today", note="")
    assert "Available from 3pm today" in page(client, "/providers")
    H.post(provider, "/availability", "/dashboard", mode="unavailable", when="", note="")
    assert "Unavailable" in page(client, "/providers")
    H.post(provider, "/availability", "/dashboard", mode="hacked", when="", note="")
    assert "Unavailable" in page(client, "/providers")                                         # invalid mode ignored
    assert H.post(client, "/availability", "/dashboard", mode="available_now", when="", note="").status_code == 403


def test_on_a_job_is_automatic(isolated_database):
    app, client, provider, job = world(isolated_database)
    assert "On a job" in page(client, "/providers")
    assert "On a job" in page(provider, "/dashboard") and "automatically" in page(provider, "/dashboard")


# ------------------------------------------------------------------ services and custom categories
def test_provider_can_edit_own_service_only(isolated_database):
    app, client, provider, job = world(isolated_database)
    other = H.register(app, "provider", "Rick Oduor", "0712345610", "home")
    conn = dbmod.get_conn(); sid = conn.execute("SELECT service_id FROM provider_services").fetchone()[0]; conn.close()
    assert "Edit" in page(provider, "/settings")
    H.post(provider, f"/settings/services/{sid}/edit", "/settings", title="Emergency leak repair", rate_text="From KSh 2,000", description="24/7")
    assert "Emergency leak repair" in page(provider, "/settings")
    H.post(other, f"/settings/services/{sid}/edit", "/settings", title="HACKED", rate_text="", description="")
    assert "HACKED" not in page(provider, "/settings") and "Emergency leak repair" in page(provider, "/settings")


def test_custom_service_requests(isolated_database):
    app = H.make_app(isolated_database)
    client, provider = H.setup_marketplace(app)
    base = dict(area="Westlands", description="The old sofa needs a deep clean, three seats please")
    r = H.post(client, "/request/new", "/request/new", category="__custom__", custom_category="x", **base)
    assert r.status_code == 200 and "3-60 letters" in r.get_data(as_text=True)
    r = H.post(client, "/request/new", "/request/new", category="__custom__", custom_category="<script>alert(1)</script>", **base)
    assert r.status_code == 200 and "3-60 letters" in r.get_data(as_text=True)
    r = H.post(client, "/request/new", "/request/new", category="__custom__", custom_category="Sofa cleaning", **base)
    assert r.status_code == 302
    assert "Sofa cleaning" in page(client, "/requests") and "Sofa cleaning" in page(client, "/request/new")   # offered next time
    assert "Other (type your own)" in page(client, "/request/new")


# ------------------------------------------------------------------ chat panels
def test_thread_shows_open_request_and_dispute_banner(isolated_database):
    app = H.make_app(isolated_database)
    client, provider = H.setup_marketplace(app)
    pid = H.provider_id(isolated_database)
    H.post(client, "/request/new", f"/request/new?provider={pid}", provider=pid, category="Plumbing", area="Westlands", description="Fix my kitchen tap please")
    conn = dbmod.get_conn(); cid = conn.execute("SELECT conversation_id FROM conversations").fetchone()[0]; conn.close()
    assert "Accept job" in page(provider, f"/messages/{cid}") and "Request for you" in page(provider, f"/messages/{cid}")
    assert "Waiting for a reply" in page(client, f"/messages/{cid}") and "Accept job" not in page(client, f"/messages/{cid}")
    conn = dbmod.get_conn(); rid = conn.execute("SELECT request_id FROM service_requests").fetchone()[0]; conn.close()
    r = H.post(provider, f"/requests/{rid}/accept", f"/messages/{cid}")
    job = int(r.headers["Location"].rsplit("/", 1)[1])
    adv(provider, job, "dispatched"); adv(provider, job, "arrived")
    open_dispute(client, job)
    assert "A dispute is open on this job" in page(provider, f"/messages/{cid}") and "Accept job" not in page(provider, f"/messages/{cid}")


# ------------------------------------------------------------------ timers
def test_timer_sweep_finishes_stalled_jobs_and_expires_old_requests(isolated_database):
    app, client, provider, job = world(isolated_database)
    adv(provider, job, "dispatched"); adv(provider, job, "arrived"); adv(provider, job, "started")
    adv(client, job, "client_confirmed"); adv(provider, job, "done")
    past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
    conn = dbmod.get_conn(); conn.execute("UPDATE jobs SET hard_timeout_deadline=? WHERE job_id=?", (past, job)); conn.commit(); conn.close()
    assert sweeper.run_once() is True
    html = page(client, f"/jobs/{job}")
    assert "completed automatically" in html.lower() and "Completed" in html
    pid = H.provider_id(isolated_database)
    H.post(client, "/request/new", f"/request/new?provider={pid}", provider=pid, category="Plumbing", area="Westlands", description="Another job for next week please")
    conn = dbmod.get_conn(); conn.execute("UPDATE service_requests SET created_at=? WHERE status='open'", (past,)); conn.commit(); conn.close()
    sweeper.run_once()
    conn = dbmod.get_conn(); st = conn.execute("SELECT status FROM service_requests ORDER BY request_id DESC").fetchone()[0]; conn.close()
    assert st == "expired"


def test_app_sweeps_at_startup_and_the_loop_starts_once(isolated_database):
    app, client, provider, job = world(isolated_database)
    adv(provider, job, "dispatched"); adv(provider, job, "arrived"); adv(provider, job, "started")
    adv(client, job, "client_confirmed"); adv(provider, job, "done")
    past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
    conn = dbmod.get_conn(); conn.execute("UPDATE jobs SET hard_timeout_deadline=? WHERE job_id=?", (past, job)); conn.commit(); conn.close()
    sweeper._started = True                                           # pretend the loop already runs (no stray thread in tests)
    create_app({"TESTING": True, "RUN_SWEEPER": True, "SECRET_KEY": "k" * 48, "SKIP_DB_INIT": True, "SMS_BACKEND": "none", "RATE_LIMITS_ENABLED": False})
    conn = dbmod.get_conn(); state = conn.execute("SELECT current_state FROM jobs WHERE job_id=?", (job,)).fetchone()[0]; conn.close()
    assert state == "completed_by_timeout"
    assert sweeper.start() is False
    sweeper._started = False


# ------------------------------------------------------------------ admin username + hygiene
def test_admin_can_change_username_with_password(isolated_database):
    app = H.make_app(isolated_database)
    A.mk_admin()
    c, secret = A.enrolled_admin_client(app)
    A.apost(c, "/admin/me/username", "/admin/me", new_username="chief", password="wrong-password-here")
    assert "owner" in page(c, "/admin/me")
    A.apost(c, "/admin/me/username", "/admin/me", new_username="chief", password=A.ADMIN_PW)
    assert "chief" in page(c, "/admin/me")
    c.post("/admin/signout", data={"csrf_token": H.csrf_from(page(c, "/admin/me"))})
    c2, r = A.password_step(app, "chief")
    assert r.headers["Location"].endswith("/admin/mfa")


def test_new_pages_have_no_inline_script_or_style(isolated_database):
    app, client, provider, job = world(isolated_database)
    finish(client, provider, job)
    H.post(client, f"/jobs/{job}/review", f"/jobs/{job}", stars="5", comment="Great work")
    conn = dbmod.get_conn(); cid = conn.execute("SELECT conversation_id FROM conversations").fetchone()[0]; conn.close()
    for who in (client, provider):
        for path in ("/reviews", "/reviews?tab=given", "/jobs?tab=completed", f"/jobs/{job}", "/dashboard", "/settings", f"/messages/{cid}", "/request/new"):
            r = who.get(path)
            if r.status_code != 200:
                continue                                                # provider can't open the client-only request form
            html = r.get_data(as_text=True)
            assert not re.search(r"<script(?![^>]*\bsrc=)", html) and not re.search(r"\sstyle=|\sonclick=", html), path
