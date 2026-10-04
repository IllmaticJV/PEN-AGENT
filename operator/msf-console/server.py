#!/usr/bin/env python3
"""Operator READ-ONLY viewer for PEN-AGENT's Metasploit C2.

metasploit-server (the MCP server teammates use) and this viewer connect to
the *same* RPC instance via engagement/msfrpc.yaml. Sessions and jobs belong
to that Framework instance, so this page shows the live session/listener list
the agents are driving, plus a per-session command log (the commands the
agents ran on each session and their output, recorded by metasploit-server to
engagement/evidence/msf-sessions/<id>.jsonl) and the shared console spool.

It is deliberately READ-ONLY: the RPC/web console can't do interactive session
attach (`sessions -i` crashes inside an RPC console), so interaction happens in
the real msfconsole that c2-up.sh runs in tmux — `tmux attach -t pen-msf` is a
full console sharing this exact Framework. This page is for observing.

Stdlib HTTP server with the HTML/CSS/JS frontend in templates/ (login.html,
console.html), live updates via SSE — same shape as operator/state-viewer.
The one non-stdlib dependency is pymetasploit3 (the RPC client, used only to
read the live session/job list), so this runs via `uv run` rather than bare
python3; see start.sh.

Authentication: reuses operator/state-viewer's token file
(~/.config/pen-agent/viewer-token). If present, this server binds 0.0.0.0 and
requires it; otherwise it binds 127.0.0.1 only.

Usage:
    uv run --directory operator/msf-console python server.py [--port 8100]
    (or: bash operator/msf-console/start.sh)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_MSF_CFG = _PROJECT_ROOT / "engagement" / "msfrpc.yaml"
_SESSION_LOG_DIR = _PROJECT_ROOT / "engagement" / "evidence" / "msf-sessions"
_CONSOLE_SPOOL = _PROJECT_ROOT / "engagement" / "evidence" / "msf-console.log"
_TOKEN_FILE = Path.home() / ".config" / "pen-agent" / "viewer-token"  # shared with state-viewer
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _load_template(name: str) -> str:
    """Load a page template from templates/ (markup kept out of the .py)."""
    return (_TEMPLATE_DIR / name).read_text(encoding="utf-8")

_SESSION_MAX_AGE = 86400  # 24h, matches state-viewer

_NOT_CONFIGURED = (
    "Metasploit RPC not configured for this engagement. Start it with "
    "./run.sh (auto-starts msfrpcd + writes engagement/msfrpc.yaml), or run "
    "msfrpcd manually and create engagement/msfrpc.yaml (see "
    "tools/metasploit-server/README.md)."
)
_NOT_CONNECTED = (
    "Failed to connect to msfrpcd. Ensure the daemon is running "
    "(pgrep -f msfrpcd) and engagement/msfrpc.yaml is correct."
)


# ---------------------------------------------------------------------------
# Auth (identical to operator/state-viewer/server.py — same token file)
# ---------------------------------------------------------------------------


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
            addr = s.getsockname()[0]
            s.close()
            if not ipaddress.ip_address(addr).is_loopback:
                ips.append(addr)
        except Exception:
            pass
    return sorted(set(ips))


# ---------------------------------------------------------------------------
# Metasploit RPC (shared client + one persistent console)
# ---------------------------------------------------------------------------


def _parse_config(path: Path) -> dict:
    """Minimal flat `key: value` parser (avoids a YAML dependency)."""
    cfg: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        cfg[key.strip().lower()] = value.strip().strip('"').strip("'")
    return cfg


class _MsfState:
    """Caches the RPC client and one long-lived console across requests."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.client = None
        self.console = None

    def get_client(self):
        with self.lock:
            if not _MSF_CFG.exists():
                return None
            if self.client is not None:
                try:
                    self.client.core.version  # cheap liveness probe
                    return self.client
                except Exception:
                    self.client = None
                    self.console = None
            try:
                from pymetasploit3.msfrpc import MsfRpcClient

                cfg = _parse_config(_MSF_CFG)
                client = MsfRpcClient(
                    cfg.get("password", ""),
                    server=cfg.get("host", "127.0.0.1"),
                    port=int(cfg.get("port", "55553")),
                    username=cfg.get("user", "msf"),
                    ssl=str(cfg.get("ssl", "true")).lower() in ("1", "true", "yes"),
                )
                client.core.version  # force auth/connect now
                self.client = client
                return client
            except Exception:
                self.client = None
                return None

    def require_client(self):
        """Returns (client, None) or (None, error_message)."""
        if not _MSF_CFG.exists():
            return None, _NOT_CONFIGURED
        client = self.get_client()
        if client is None:
            return None, _NOT_CONNECTED
        return client, None

    def session_log(self, session_id: str, max_records: int = 500) -> dict:
        """Read the per-session command log the metasploit-server MCP writes
        (engagement/evidence/msf-sessions/<id>.jsonl) — commands the agents ran
        on this session and their output. Read-only; no RPC, no stream-steal."""
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
        """Tail the shared msfconsole spool (what the operator typed in tmux and
        its output), if SessionLogging/spool is enabled by c2-up.sh."""
        if not _CONSOLE_SPOOL.exists():
            return {"data": ""}
        try:
            with _CONSOLE_SPOOL.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                data = f.read().decode(errors="replace")
            return {"data": data}
        except OSError as e:
            return {"data": "", "error": str(e)}

    def list_sessions(self) -> dict:
        client, err = self.require_client()
        if err:
            return {"error": err}
        try:
            out = []
            for sid, meta in client.sessions.list.items():
                out.append(
                    {
                        "session_id": str(sid),
                        "type": meta.get("type"),
                        "platform": meta.get("platform"),
                        "via_exploit": meta.get("via_exploit"),
                        "tunnel_peer": meta.get("tunnel_peer"),
                        "info": meta.get("info"),
                    }
                )
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
        client = self.get_client()
        if client is None:
            return {"configured": True, "connected": False, "error": _NOT_CONNECTED}
        return {"configured": True, "connected": True}


_msf = _MsfState()


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

LOGIN_HTML = _load_template("login.html")

CONSOLE_HTML = _load_template("console.html")


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    auth_token: str | None = None

    def log_message(self, fmt, *args):
        pass

    def _is_authenticated(self) -> bool:
        if self.auth_token is None:
            return True
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            candidate = auth_header[7:].strip()
            if hmac.compare_digest(candidate, self.auth_token):
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

        if self.path == "/":
            self._html(CONSOLE_HTML)
        elif self.path == "/api/status":
            self._json(_msf.status())
        elif self.path == "/api/sessions":
            self._json(_msf.list_sessions())
        elif self.path == "/api/jobs":
            self._json(_msf.list_jobs())
        elif self.path.startswith("/api/session/log"):
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("id") or [""])[0]
            if not sid:
                self._json({"error": "id required"}, 400)
            else:
                self._json(_msf.session_log(sid))
        elif self.path == "/api/console/log":
            self._json(_msf.console_log())
        elif self.path == "/api/stream":
            if not self._is_authenticated():
                self._json({"error": "unauthorized"}, 401)
                return
            self._stream()
        else:
            self.send_error(404)

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        # Read-only viewer: push the live session/job list + connection status.
        # Interaction happens in the real tmux msfconsole, not here.
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

        # Read-only viewer — no write endpoints. /login is the only POST.
        self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description="PEN-AGENT Metasploit operator console")
    parser.add_argument("--port", type=int, default=8100, help="Listen port (default: 8100)")
    args = parser.parse_args()

    token = _load_token()
    Handler.auth_token = token

    bind_addr = "0.0.0.0" if token else "127.0.0.1"
    if token:
        print(f"auth: token loaded from {_TOKEN_FILE}")
    else:
        print("auth: no token file — binding to localhost only (no auth required)")
        print(f"       (generate one: bash operator/state-viewer/generate-token.sh — shared)")

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((bind_addr, args.port), Handler)
    print(f"msf-console: http://{bind_addr}:{args.port}")
    if bind_addr == "0.0.0.0":
        for ip in _get_local_ips():
            print(f"  remote:     http://{ip}:{args.port}")
    print(f"msfrpc config: {_MSF_CFG} ({'found' if _MSF_CFG.exists() else 'missing'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
