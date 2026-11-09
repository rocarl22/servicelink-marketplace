# ServiceLink: Marketplace Backend & Web App

ServiceLink is a service marketplace prototype that connects clients with local providers
(plumbers, electricians, cleaners and similar). This repository contains the **Python
backend services, the Flask web app and the test suite**. The business logic lives in
`backend/services/` and is shared by the web app, so it is not tied to any one interface.

The Qt/QML desktop interface of the full project is not included here.

## What is implemented

- **Accounts and sign-in:** client, provider and administrator accounts; bcrypt, Argon2 and PBKDF2 password verification with automatic upgrade of older hashes; password policy
- **Sessions and abuse protection:** idle and absolute session expiry, progressive lockouts, sliding-window rate limiting
- **Two-step verification:** phone one-time codes (`otp.py`) and TOTP for administrators (`web/totp.py`)
- **Marketplace workflow:** service requests, jobs, agreed price tracking, escrow-style payment states, reviews, messaging, notifications, disputes, blocking
- **Safety features:** scam-message screening, upload limits with EXIF stripping, user data export without password hashes
- **Data safety:** SQLite with a schema baseline ledger and integrity-checked online backups
- **Deployment notes:** `deploy/Caddyfile` for HTTPS behind a reverse proxy

`SECURITY_HARDENING.md` lists the hardening measures in more detail.

## Project layout

```
backend/services/   business logic (accounts, jobs, escrow, sessions, ...)
backend/database.py SQLite access and schema
web/                Flask app, views, templates, static files
tests/              unit, integration and web tests
deploy/             Caddy reverse-proxy example
```

## Run the tests

```
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements-web.txt -r requirements-dev.txt
python -m pytest -q
```

Tested on Python 3.13. `web/seed_demo.py` fills an empty database with fake demo accounts
for local use only.

## Status

This is a prototype. It is not hardened for public internet deployment; see
`SECURITY_HARDENING.md` for what would still be needed.
