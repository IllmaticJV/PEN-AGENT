#!/usr/bin/env python3
"""Read-only web dashboard for engagement state.

Stdlib-only HTTP server serving an HTML/CSS/JS dashboard with live updates
via SSE.  No dependencies beyond Python stdlib.  The page markup lives in
templates/ (login.html, dashboard.html) and is loaded at startup.

Authentication:
    If ~/.config/pen-agent/viewer-token exists, the server binds to 0.0.0.0
    and requires the token to access any endpoint.  Without a token file,
    it binds to 127.0.0.1 only (no auth needed).

    Generate a token:  bash operator/state-viewer/generate-token.sh

Usage:
    python3 operator/state-viewer/server.py [--port 8099] [--db engagement/state.db]
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import hmac
import json
import sqlite3
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from pathlib import Path
from urllib.parse import unquote_plus

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_DB = _PROJECT_ROOT / "engagement" / "state.db"
_TOKEN_FILE = Path.home() / ".config" / "pen-agent" / "viewer-token"
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _load_template(name: str) -> str:
    """Load a page template from templates/ (markup kept out of the .py)."""
    return (_TEMPLATE_DIR / name).read_text(encoding="utf-8")

# Session cookie lifetime: 24 hours
_SESSION_MAX_AGE = 86400


def _load_token() -> str | None:
    """Load auth token from disk. Returns None if no token file."""
    if _TOKEN_FILE.exists():
        token = _TOKEN_FILE.read_text().strip()
        if token:
            return token
    return None


def _make_session_cookie(token: str) -> str:
    """Create an HMAC-signed session cookie value: timestamp.signature"""
    ts = str(int(time.time()))
    sig = hmac.new(token.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def _verify_session_cookie(cookie_val: str, token: str) -> bool:
    """Verify HMAC session cookie is valid and not expired."""
    parts = cookie_val.split(".", 1)
    if len(parts) != 2:
        return False
    ts_str, sig = parts
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if time.time() - ts > _SESSION_MAX_AGE:
        return False
    expected = hmac.new(token.encode(), ts_str.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def _get_local_ips() -> list[str]:
    """Return all non-loopback IPv4 addresses on this host."""
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if not ipaddress.ip_address(addr).is_loopback:
                ips.append(addr)
    except Exception:
        pass
    # Fallback: UDP connect trick for hosts where gethostname doesn't resolve
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            addr = s.getsockname()[0]
            s.close()
            if not ipaddress.ip_address(addr).is_loopback:
                ips.append(addr)
        except Exception:
            pass
    return sorted(set(ips))


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def _get_db(db_path: Path) -> sqlite3.Connection | None:
    """Open read-only connection. Returns None if DB doesn't exist."""
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


_EMPTY_STATE = {
    "engagement": None,
    "targets": [],
    "credentials": [],
    "access": [],
    "vulns": [],
    "pivot_map": [],
    "tunnels": [],
    "blocked": [],
    "events": [],
}


def _build_state(db_path: Path) -> dict:
    """Build full state JSON from all tables."""
    conn = _get_db(db_path)
    if conn is None:
        return _EMPTY_STATE
    try:
        eng = _rows(conn, "SELECT * FROM engagement LIMIT 1")
        engagement = eng[0] if eng else None

        targets = _rows(conn, "SELECT * FROM targets ORDER BY id")
        for t in targets:
            t["ports"] = _rows(
                conn,
                "SELECT * FROM ports WHERE target_id = ? ORDER BY port",
                (t["id"],),
            )

        credentials = _rows(conn, "SELECT * FROM credentials ORDER BY id")
        for c in credentials:
            c["tested_against"] = _rows(
                conn,
                "SELECT ca.*, t.ip FROM credential_access ca "
                "JOIN targets t ON t.id = ca.target_id "
                "WHERE ca.credential_id = ?",
                (c["id"],),
            )

        access = _rows(
            conn,
            "SELECT a.*, t.ip FROM access a "
            "JOIN targets t ON t.id = a.target_id ORDER BY a.id",
        )
        vulns = _rows(
            conn,
            "SELECT v.*, t.ip FROM vulns v "
            "LEFT JOIN targets t ON t.id = v.target_id "
            "ORDER BY CASE v.severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 "
            "WHEN 'info' THEN 4 ELSE 5 END, v.id",
        )
        pivot_map = _rows(conn, "SELECT * FROM pivot_map ORDER BY id")
        tunnels = _rows(conn, "SELECT * FROM tunnels ORDER BY id")
        blocked = _rows(
            conn,
            "SELECT b.*, t.ip FROM blocked b "
            "LEFT JOIN targets t ON t.id = b.target_id ORDER BY b.id",
        )
        events = _rows(
            conn,
            "SELECT * FROM state_events ORDER BY id DESC LIMIT 100",
        )

        return {
            "engagement": engagement,
            "targets": targets,
            "credentials": credentials,
            "access": access,
            "vulns": vulns,
            "pivot_map": pivot_map,
            "tunnels": tunnels,
            "blocked": blocked,
            "events": events,
        }
    except sqlite3.OperationalError:
        return _EMPTY_STATE
    finally:
        conn.close()


def _get_events_since(db_path: Path, since: int) -> list[dict]:
    conn = _get_db(db_path)
    if conn is None:
        return []
    try:
        return _rows(
            conn,
            "SELECT * FROM state_events WHERE id > ? ORDER BY id",
            (since,),
        )
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTML pages
# ---------------------------------------------------------------------------

LOGIN_HTML = _load_template("login.html")

DASHBOARD_HTML = _load_template("dashboard.html")


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    db_path: Path = _DEFAULT_DB
    auth_token: str | None = None  # None = no auth required

    def log_message(self, fmt, *args):
        pass

    def _is_authenticated(self) -> bool:
        """Check if request has valid auth (cookie or Bearer header)."""
        if self.auth_token is None:
            return True

        # Check Authorization header (for curl / API clients)
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            candidate = auth_header[7:].strip()
            if hmac.compare_digest(candidate, self.auth_token):
                return True

        # Check session cookie
        cookie_header = self.headers.get("Cookie", "")
        if cookie_header:
            c = cookies.SimpleCookie()
            try:
                c.load(cookie_header)
            except cookies.CookieError:
                return False
            if "session" in c:
                return _verify_session_cookie(c["session"].value, self.auth_token)

        return False

    def _require_auth(self) -> bool:
        """Returns True if request is authenticated. Sends 401/redirect if not."""
        if self._is_authenticated():
            return True
        # For API endpoints, return 401 JSON
        if self.path.startswith("/api/"):
            self._json({"error": "unauthorized"}, 401)
            return False
        # For page requests, redirect to login
        self.send_response(302)
        self.send_header("Location", "/login")
        self.end_headers()
        return False

    def _json(self, data: dict | list, status: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body_str: str, status: int = 200):
        body = body_str.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Login page is always accessible
        if self.path.startswith("/login"):
            if self.auth_token is None:
                # No auth configured, redirect to dashboard
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._html(LOGIN_HTML)
            return

        if not self._require_auth():
            return

        if self.path == "/":
            self._html(DASHBOARD_HTML)

        elif self.path == "/api/state":
            self._json(_build_state(self.db_path))

        elif self.path.startswith("/api/events"):
            since = 0
            if "since=" in self.path:
                try:
                    since = int(self.path.split("since=")[1].split("&")[0])
                except ValueError:
                    pass
            self._json(_get_events_since(self.db_path, since))

        elif self.path == "/api/stream":
            if not self._is_authenticated():
                self._json({"error": "unauthorized"}, 401)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            last_full = 0
            last_event_id = 0
            try:
                while True:
                    now = time.time()
                    if now - last_full >= 10:
                        data = _build_state(self.db_path)
                        self.wfile.write(
                            f"data: {json.dumps({'type': 'state', 'payload': data}, default=str)}\n\n".encode()
                        )
                        self.wfile.flush()
                        last_full = now
                        if data["events"]:
                            last_event_id = max(e["id"] for e in data["events"])
                    else:
                        events = _get_events_since(self.db_path, last_event_id)
                        if events:
                            last_event_id = max(e["id"] for e in events)
                            self.wfile.write(
                                f"data: {json.dumps({'type': 'events', 'payload': events}, default=str)}\n\n".encode()
                            )
                            self.wfile.flush()
                    time.sleep(2)
            except (BrokenPipeError, ConnectionResetError):
                pass

        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/login":
            if self.auth_token is None:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return

            # Read form body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode() if content_length else ""

            # Parse token= from application/x-www-form-urlencoded
            submitted = ""
            for part in body.split("&"):
                if part.startswith("token="):
                    submitted = unquote_plus(part[6:])
                    break

            if hmac.compare_digest(submitted, self.auth_token):
                cookie_val = _make_session_cookie(self.auth_token)
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie",
                    f"session={cookie_val}; HttpOnly; SameSite=Strict; Max-Age={_SESSION_MAX_AGE}; Path=/",
                )
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header("Location", "/login?fail=1")
                self.end_headers()
        else:
            self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description="PEN-AGENT state viewer")
    parser.add_argument(
        "--port", type=int, default=8099, help="Listen port (default: 8099)"
    )
    parser.add_argument("--db", type=str, default=None, help="Path to state.db")
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else _DEFAULT_DB
    Handler.db_path = db_path

    token = _load_token()
    Handler.auth_token = token

    if token:
        bind_addr = "0.0.0.0"
        print(f"auth: token loaded from {_TOKEN_FILE}")
    else:
        bind_addr = "127.0.0.1"
        print("auth: no token file — binding to localhost only (no auth required)")

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((bind_addr, args.port), Handler)
    print(f"state-viewer: http://{bind_addr}:{args.port}")
    if bind_addr == "0.0.0.0":
        for ip in _get_local_ips():
            print(f"  remote:     http://{ip}:{args.port}")
        print(
            f"\nIf your VM uses NAT, access via http://localhost:{args.port} on the host"
        )
        print(
            f"after adding a port forwarding rule (host {args.port} -> guest {args.port})."
        )
    print(f"database: {db_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
