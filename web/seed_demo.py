"""Fill an EMPTY database with fake demo data so the site looks alive.

    python -m web.seed_demo            # uses the normal data folder
Demo accounts all use the password:  amber-falcon-river-lamp
NEVER run this against a database with real users.
"""
from backend import database as db
from backend.services import accounts, jobs, marketplace, requests as requests_svc, reviews

PW = "amber-falcon-river-lamp"
PROVIDERS = [
    ("Ben Otieno", "0711000001", "home", "Ben the Plumber", "Westlands", "Fifteen years fixing leaks, blocked drains and bathrooms across Nairobi homes.", [("Plumbing", "Leak repairs", "From KSh 1,500"), ("Plumbing", "Bathroom fitting", "From KSh 6,000")]),
    ("Grace Wanjiru", "0711000002", "home", "Sparkle Clean Co.", "Nairobi CBD", "Reliable deep cleaning for apartments and offices. Eco-friendly products.", [("Cleaning", "Apartment deep clean", "KSh 3,500")]),
    ("Samuel Kiptoo", "0711000003", "home", "Kiptoo Electricals", "Rongai", "Licensed electrician: wiring, sockets, lighting and safe installations.", [("Electrical", "Wiring & sockets", "From KSh 2,000")]),
    ("Faith Achieng", "0711000004", "personal", "Faith Hair Studio", "Kiambu", "Braids, natural hair care and wedding styling. Home visits available.", [("Hair", "Braids & styling", "From KSh 1,200")]),
    ("Peter Mwangi", "0711000005", "home", "Mwangi Painters", "Kitengela", "Interior and exterior painting with a neat, on-time finish.", [("Painting", "Room painting", "From KSh 8,000")]),
    ("Lucy Njeri", "0711000006", "personal", "Lucy Njeri Photography", "Westlands", "Portraits, events and family shoots with quick delivery.", [("Photography", "Event coverage", "From KSh 10,000")]),
]


def main():
    db.init_db()
    ids = []
    for full, phone, family, display, area, bio, services in PROVIDERS:
        ok, pid = accounts.create_account("provider", full, phone, "", PW, PW, True, True, family, "demo")
        assert ok, pid
        accounts.complete_profile(pid, display, area, bio, "", "provider", family)
        for cat, title, rate in services:
            marketplace.add_provider_service(pid, cat, title, "", rate)
        ids.append(pid)
    ok, cid = accounts.create_account("client", "Ann Mwangi", "0711000100", "", PW, PW, True, True, "", "demo")
    assert ok, cid
    accounts.complete_profile(cid, "Ann", "Westlands", "", "", "client", "")
    # one finished, reviewed job so ratings and history are visible
    requests_svc.create_request(cid, "Plumbing", "Kitchen tap leaking badly, needs repair today", "Westlands", "Today", ids[0], "direct")
    rid = requests_svc.list_client_requests(cid)[0]["request_id"]
    ok, jid = jobs.accept_request(ids[0], rid)
    jid = int(jid)
    jobs.set_agreed_price(jid, ids[0], "KSh 2,500")
    for who, action in ((ids[0], "dispatched"), (ids[0], "arrived"), (ids[0], "started"), (cid, "client_confirmed"), (ids[0], "done")):
        jobs.advance(jid, who, action)
    jobs.close_job(jid, cid, "client_confirmed")
    reviews.create_review(jid, cid, 5, "Quick, tidy and fairly priced. Fixed the leak in under an hour.")
    # an in-progress job (live chat) and a pending open request, so active screens have content
    requests_svc.create_request(cid, "Electrical", "Two sockets in the living room stopped working", "Westlands", "This week", ids[2], "direct")
    rid2 = [r for r in requests_svc.list_client_requests(cid) if r["status"] == "open" and r["mode"] == "direct"][0]["request_id"]
    ok, jid2 = jobs.accept_request(ids[2], rid2)
    jobs.advance(int(jid2), ids[2], "dispatched")
    requests_svc.create_request(cid, "Cleaning", "Deep clean for a 2-bedroom apartment before moving in", "Nairobi CBD", "Saturday", "", "open")
    print("Demo data created. Client: 0711000100  Provider: 0711000001  Password:", PW)


if __name__ == "__main__":
    main()
