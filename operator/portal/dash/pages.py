"""Template loading + the static page registry (path -> rendered HTML)."""

from __future__ import annotations

from dash.config import TEMPLATE_DIR


def load_template(name: str) -> str:
    return (TEMPLATE_DIR / name).read_text(encoding="utf-8")


LOGIN_HTML = load_template("login.html")

# path -> HTML. The shell (portal.html) loads the others into its iframe.
PAGES = {
    "/": load_template("portal.html"),
    "/scope": load_template("scope.html"),
    "/status": load_template("status.html"),
    "/msf": load_template("msf.html"),
    "/objectives": load_template("objectives.html"),
    "/findings": load_template("findings.html"),
    "/activity": load_template("activity.html"),
}
