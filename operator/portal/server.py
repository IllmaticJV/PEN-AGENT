#!/usr/bin/env python3
"""PEN-AGENT operator portal — one tabbed web view.

Merges what used to be two separate dashboards (state-viewer + msf-console)
into a single server/port/login with three tabs, each an isolated sub-page:

  Objective & Scope  (/scope)  — engagement/scope.md + scope.allow + meta
  Status             (/status) — live engagement state from state.db
  MSF Logs           (/msf)    — live session/listener list + per-session
                                 command logs (read-only; interact in the tmux
                                 msfconsole, not here)

Read-only. Stdlib HTTP + SSE; the MSF tab uses pymetasploit3 to read the live
session/job list, so this runs via `uv run` (see start.sh). Page markup lives
in templates/.

Auth: if ~/.config/pen-agent/viewer-token exists, binds 0.0.0.0 and requires
the token (login cookie or `Authorization: Bearer <token>`); otherwise binds
127.0.0.1 only. Generate one: bash operator/portal/generate-token.sh

Usage:
    uv run --directory operator/portal python server.py [--port 8099]
    (or: bash operator/portal/start.sh)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import sqlite3
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_DB = _PROJECT_ROOT / "engagement" / "state.db"
_MSF_CFG = _PROJECT_ROOT / "engagement" / "msfrpc.yaml"
_SCOPE_MD = _PROJECT_ROOT / "engagement" / "scope.md"
_SCOPE_ALLOW = _PROJECT_ROOT / "engagement" / "scope.allow"
_SESSION_LOG_DIR = _PROJECT_ROOT / "engagement" / "evidence" / "msf-sessions"
_CONSOLE_SPOOL = _PROJECT_ROOT / "engagement" / "evidence" / "msf-console.log"
_OPERATOR_SESSIONS = _PROJECT_ROOT / "engagement" / "operator-sessions.json"
_TOKEN_FILE = Path.home() / ".config" / "pen-agent" / "viewer-token"
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_SESSION_MAX_AGE = 86400  # 24h

_NOT_CONFIGURED = (
    "Metasploit RPC not configured for this engagement (engagement/msfrpc.yaml "
    "missing). Start it with ./run.sh."
)
_NOT_CONNECTED = (
    "Failed to connect to msfrpcd. Ensure the C2 is running (tmux attach -t "
    "pen-msf, or pgrep -f msfrpcd) and engagement/msfrpc.yaml is correct."
)


def _load_template(name: str) -> str:
    return (_TEMPLATE_DIR / name).read_text(encoding="utf-8")


# ── Auth helpers ─────────────────────────────────────────────────────────────
def _load_token() -> str | None:
    if _TOKEN_FILE.exists():
        token = _TOKEN_FILE.read_text().strip()
        if token:
            return token
    return None


def _make_session_cookie(token: str) -> str:
    ts = str(int(time.time()))
    sig = hmac.new(token.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def _verify_session_cookie(cookie_val: str, token: str) -> bool:
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
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if not ipaddress.ip_address(addr).is_loopback:
                ips.append(addr)
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return sorted(set(ips))


# ── Objective & scope (file-based) ───────────────────────────────────────────
def _build_scope() -> dict:
    scope_md = ""
    try:
        if _SCOPE_MD.exists():
            scope_md = _SCOPE_MD.read_text(errors="replace")
    except OSError:
        pass
    allow = []
    try:
        if _SCOPE_ALLOW.exists():
            for line in _SCOPE_ALLOW.read_text(errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    allow.append(line)
    except OSError:
        pass
    engagement = None
    conn = _get_db(_DEFAULT_DB)
    if conn is not None:
        try:
            rows = _rows(conn, "SELECT * FROM engagement LIMIT 1")
            engagement = rows[0] if rows else None
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
    return {"scope_md": scope_md, "scope_allow": allow, "engagement": engagement}


# ── State (state.db, read-only) ──────────────────────────────────────────────
def _get_db(db_path: Path) -> sqlite3.Connection | None:
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


_EMPTY_STATE = {
    "engagement": None, "targets": [], "credentials": [], "access": [],
    "vulns": [], "pivot_map": [], "tunnels": [], "blocked": [], "events": [],
}


def _build_state(db_path: Path) -> dict:
    conn = _get_db(db_path)
    if conn is None:
        return _EMPTY_STATE
    try:
        eng = _rows(conn, "SELECT * FROM engagement LIMIT 1")
        engagement = eng[0] if eng else None
        targets = _rows(conn, "SELECT * FROM targets ORDER BY id")
        for t in targets:
            t["ports"] = _rows(
                conn, "SELECT * FROM ports WHERE target_id = ? ORDER BY port", (t["id"],)
            )
        credentials = _rows(conn, "SELECT * FROM credentials ORDER BY id")
        for c in credentials:
            c["tested_against"] = _rows(
                conn,
                "SELECT ca.*, t.ip FROM credential_access ca "
                "JOIN targets t ON t.id = ca.target_id WHERE ca.credential_id = ?",
                (c["id"],),
            )
        access = _rows(
            conn,
            "SELECT a.*, t.ip FROM access a JOIN targets t ON t.id = a.target_id ORDER BY a.id",
        )
        vulns = _rows(
            conn,
            "SELECT v.*, t.ip FROM vulns v LEFT JOIN targets t ON t.id = v.target_id "
            "ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, v.id",
        )
        pivot_map = _rows(conn, "SELECT * FROM pivot_map ORDER BY id")
        tunnels = _rows(conn, "SELECT * FROM tunnels ORDER BY id")
        blocked = _rows(
            conn,
            "SELECT b.*, t.ip FROM blocked b LEFT JOIN targets t ON t.id = b.target_id ORDER BY b.id",
        )
        events = _rows(conn, "SELECT * FROM state_events ORDER BY id DESC LIMIT 100")
        return {
            "engagement": engagement, "targets": targets, "credentials": credentials,
            "access": access, "vulns": vulns, "pivot_map": pivot_map,
            "tunnels": tunnels, "blocked": blocked, "events": events,
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
        return _rows(conn, "SELECT * FROM state_events WHERE id > ? ORDER BY id", (since,))
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


# ── Metasploit (live session/job list via RPC + file-based logs) ─────────────
def _load_reserved_sessions() -> dict:
    try:
        if _OPERATOR_SESSIONS.exists():
            data = json.loads(_OPERATOR_SESSIONS.read_text())
            if isinstance(data, dict) and isinstance(data.get("reserved"), dict):
                return data["reserved"]
    except Exception:
        pass
    return {}


def _parse_msf_config(path: Path) -> dict:
    cfg: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        cfg[key.strip().lower()] = value.strip().strip('"').strip("'")
    return cfg


class _MsfState:
    """Caches the RPC client used only to read the live session/job list."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.client = None

    def get_client(self):
        with self.lock:
            if not _MSF_CFG.exists():
                return None
            if self.client is not None:
                try:
                    self.client.core.version
                    return self.client
                except Exception:
                    self.client = None
            try:
                from pymetasploit3.msfrpc import MsfRpcClient

                cfg = _parse_msf_config(_MSF_CFG)
                client = MsfRpcClient(
                    cfg.get("password", ""),
                    server=cfg.get("host", "127.0.0.1"),
                    port=int(cfg.get("port", "55553")),
                    username=cfg.get("user", "msf"),
                    ssl=str(cfg.get("ssl", "true")).lower() in ("1", "true", "yes"),
                )
                client.core.version
                self.client = client
                return client
            except Exception:
                self.client = None
                return None

    def require_client(self):
        if not _MSF_CFG.exists():
            return None, _NOT_CONFIGURED
        client = self.get_client()
        if client is None:
            return None, _NOT_CONNECTED
        return client, None

    def list_sessions(self) -> dict:
        client, err = self.require_client()
        if err:
            return {"error": err}
        try:
            reserved = _load_reserved_sessions()
            out = []
            for sid, meta in client.sessions.list.items():
                out.append({
                    "session_id": str(sid),
                    "type": meta.get("type"),
                    "platform": meta.get("platform"),
                    "via_exploit": meta.get("via_exploit"),
                    "tunnel_peer": meta.get("tunnel_peer"),
                    "info": meta.get("info"),
                    "operator_reserved": str(sid) in reserved,
                })
            return {"sessions": out, "count": len(out)}
        except Exception as e:
            return {"error": str(e)}

    def list_jobs(self) -> dict:
        client, err = self.require_client()
        if err:
            return {"error": err}
        try:
            out = [{"job_id": str(jid), "name": name} for jid, name in client.jobs.list.items()]
            return {"jobs": out, "count": len(out)}
        except Exception as e:
            return {"error": str(e)}

    def status(self) -> dict:
        if not _MSF_CFG.exists():
            return {"configured": False, "connected": False, "error": _NOT_CONFIGURED}
        if self.get_client() is None:
            return {"configured": True, "connected": False, "error": _NOT_CONNECTED}
        return {"configured": True, "connected": True}

    def session_log(self, session_id: str, max_records: int = 500) -> dict:
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(session_id)) or "unknown"
        path = _SESSION_LOG_DIR / f"{safe}.jsonl"
        if not path.exists():
            return {"session_id": str(session_id), "records": []}
        records = []
        try:
            for line in path.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError as e:
            return {"session_id": str(session_id), "records": [], "error": str(e)}
        return {"session_id": str(session_id), "records": records[-max_records:]}

    def console_log(self, max_bytes: int = 60000) -> dict:
        if not _CONSOLE_SPOOL.exists():
            return {"data": ""}
        try:
            with _CONSOLE_SPOOL.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                return {"data": f.read().decode(errors="replace")}
        except OSError as e:
            return {"data": "", "error": str(e)}


_msf = _MsfState()


# ── Pages ────────────────────────────────────────────────────────────────────
LOGIN_HTML = _load_template("login.html")
PORTAL_HTML = _load_template("portal.html")
SCOPE_HTML = _load_template("scope.html")
STATUS_HTML = _load_template("status.html")
MSF_HTML = _load_template("msf.html")

_PAGES = {"/": PORTAL_HTML, "/scope": SCOPE_HTML, "/status": STATUS_HTML, "/msf": MSF_HTML}


# ── HTTP handler ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    db_path: Path = _DEFAULT_DB
    auth_token: str | None = None

    def log_message(self, fmt, *args):
        pass

    def _is_authenticated(self) -> bool:
        if self.auth_token is None:
            return True
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            if hmac.compare_digest(auth_header[7:].strip(), self.auth_token):
                return True
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
        if self._is_authenticated():
            return True
        if self.path.startswith("/api/"):
            self._json({"error": "unauthorized"}, 401)
            return False
        self.send_response(302)
        self.send_header("Location", "/login")
        self.end_headers()
        return False

    def _json(self, data, status: int = 200):
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
        if self.path.startswith("/login"):
            if self.auth_token is None:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._html(LOGIN_HTML)
            return

        if not self._require_auth():
            return

        path = urlparse(self.path).path
        if path in _PAGES:
            self._html(_PAGES[path])
        elif path == "/api/scope":
            self._json(_build_scope())
        elif path == "/api/state":
            self._json(_build_state(self.db_path))
        elif path == "/api/events":
            qs = parse_qs(urlparse(self.path).query)
            try:
                since = int((qs.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            self._json(_get_events_since(self.db_path, since))
        elif path == "/api/sessions":
            self._json(_msf.list_sessions())
        elif path == "/api/jobs":
            self._json(_msf.list_jobs())
        elif path == "/api/session/log":
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("id") or [""])[0]
            self._json(_msf.session_log(sid) if sid else {"error": "id required"},
                       200 if sid else 400)
        elif path == "/api/console/log":
            self._json(_msf.console_log())
        elif path == "/api/stream":
            self._state_stream()
        elif path == "/api/msf/stream":
            self._msf_stream()
        else:
            self.send_error(404)

    def _sse_open(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

    def _state_stream(self):
        if not self._is_authenticated():
            self._json({"error": "unauthorized"}, 401)
            return
        self._sse_open()
        last_full = 0.0
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

    def _msf_stream(self):
        if not self._is_authenticated():
            self._json({"error": "unauthorized"}, 401)
            return
        self._sse_open()
        try:
            while True:
                status = _msf.status()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'status', **status})}\n\n".encode()
                )
                sessions = _msf.list_sessions()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'sessions', 'payload': sessions.get('sessions', [])})}\n\n".encode()
                )
                jobs = _msf.list_jobs()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'jobs', 'payload': jobs.get('jobs', [])})}\n\n".encode()
                )
                self.wfile.flush()
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        if self.path == "/login":
            if self.auth_token is None:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode() if length else ""
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
            return
        self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description="PEN-AGENT operator portal")
    parser.add_argument("--port", type=int, default=8099, help="Listen port (default: 8099)")
    parser.add_argument("--db", type=str, default=None, help="Path to state.db")
    args = parser.parse_args()

    Handler.db_path = Path(args.db) if args.db else _DEFAULT_DB
    token = _load_token()
    Handler.auth_token = token
    bind_addr = "0.0.0.0" if token else "127.0.0.1"
    if token:
        print(f"auth: token loaded from {_TOKEN_FILE}")
    else:
        print("auth: no token file — binding to localhost only (no auth required)")

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((bind_addr, args.port), Handler)
    print(f"portal: http://{bind_addr}:{args.port}")
    if bind_addr == "0.0.0.0":
        for ip in _get_local_ips():
            print(f"  remote:   http://{ip}:{args.port}")
    print(f"database: {Handler.db_path}")
    print(f"msfrpc:   {_MSF_CFG} ({'found' if _MSF_CFG.exists() else 'missing'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
