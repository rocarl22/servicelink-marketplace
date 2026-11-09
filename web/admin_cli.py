"""Server-side admin tools (run on the server console, not through the website).

    python -m web.admin_cli create-admin     # first administrator (only if none exists)
    python -m web.admin_cli reset-mfa NAME   # lost authenticator: forces re-enrolment at next sign-in
    python -m web.admin_cli list             # administrators and whether two-step sign-in is on
"""
import getpass
import sys

from backend import database as db
from backend.services import admin
from backend.services.validation import now_iso


def main(argv):
    if not argv or argv[0] not in ("create-admin", "reset-mfa", "list"):
        print(__doc__)
        return 2
    db.init_db()
    cmd = argv[0]
    if cmd == "create-admin":
        username = input("Admin username: ").strip()
        password = getpass.getpass("Password (12+ characters): ")
        again = getpass.getpass("Repeat password: ")
        ok, message = admin.create_initial_admin(username, password, again)
        print(message)
        if ok:
            print("Next: open /admin/signin - you will be asked to set up your authenticator app.")
        return 0 if ok else 1
    conn = db.get_conn()
    try:
        if cmd == "list":
            for r in conn.execute("SELECT username, role, active, totp_secret FROM admin_users ORDER BY username"):
                print(f"{r['username']:<20} {r['role']:<8} {'active' if r['active'] else 'disabled':<9} 2FA: {'on' if r['totp_secret'] else 'not set up'}")
            return 0
        if len(argv) < 2:
            print("Usage: python -m web.admin_cli reset-mfa USERNAME")
            return 2
        row = conn.execute("SELECT admin_id FROM admin_users WHERE username=?", (argv[1],)).fetchone()
        if not row:
            print("No such administrator.")
            return 1
        conn.execute("UPDATE admin_users SET totp_secret='', totp_last_step=0 WHERE admin_id=?", (row["admin_id"],))
        conn.execute("UPDATE web_admin_sessions SET revoked_at=? WHERE admin_id=? AND revoked_at=''", (now_iso(), row["admin_id"]))
        conn.commit()
        print(f"Two-step sign-in reset for '{argv[1]}'. All their admin sessions were ended; they must enrol again at next sign-in.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
