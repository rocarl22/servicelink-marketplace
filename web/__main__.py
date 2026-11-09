"""Run the site: `python -m web` (waitress, production-grade server, works on Windows)."""
import logging
import os

from .app import create_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

def production_problems(app):
    """Things that must be fixed before this app may start in production."""
    problems = []
    if not app.config["SECURE_COOKIES"]:
        problems.append("SERVICELINK_SECURE_COOKIES is off - production must be served over HTTPS")
    if not app.config.get("TRUSTED_HOSTS"):
        problems.append("SERVICELINK_ALLOWED_HOSTS is not set (e.g. servicelink.example.com)")
    if app.config["SMS_BACKEND"] in ("console", "memory"):
        problems.append("SERVICELINK_SMS_BACKEND=%s would print one-time codes in the server log; "
                        "use africastalking, or none to switch SMS features off" % app.config["SMS_BACKEND"])
    if app.config["SMS_BACKEND"] == "africastalking" and not (app.config["AT_USERNAME"] and app.config["AT_API_KEY"]):
        problems.append("AT_USERNAME and AT_API_KEY are required for the africastalking SMS backend")
    return problems


if __name__ == "__main__":
    app = create_app()
    if app.config["ENV_NAME"] == "production":
        problems = production_problems(app)
        if problems:
            raise SystemExit("Refusing to start in production:\n  - " + "\n  - ".join(problems))
    host = os.environ.get("SERVICELINK_HOST", "127.0.0.1")
    port = int(os.environ.get("SERVICELINK_PORT", "8000"))
    try:
        from waitress import serve
    except ImportError:
        raise SystemExit("Install the server first:  pip install -r requirements-web.txt")
    logging.getLogger("servicelink.web").info("ServiceLink web on http://%s:%d (%s)", host, port, app.config["ENV_NAME"])
    serve(app, host=host, port=port, threads=8, max_request_body_size=256 * 1024)
