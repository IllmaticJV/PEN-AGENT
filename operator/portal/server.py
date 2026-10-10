#!/usr/bin/env python3
"""PEN-AGENT operator portal — one tabbed web view.

A single read-only server/port/login with one tab per sub-page:

  Objective & Scope  (/scope)      scope.md + scope.allow + engagement meta
  Objective Tracker  (/objectives) objectives.json (operator can toggle status)
  Status             (/status)     live engagement state from state.db
  Attack Graph       (/status?view=graph)
  Activity           (/activity)   teammate roster/health (top) + live state_events
                                   feed (data: /api/team + /api/activity)
  Findings           (/findings)   engagement/findings/*.json (collapsible)
  C2 / MSF Logs      (/msf)        live session/listener list + per-session logs

The nav shell also raises a lead-parked strip (data: /api/lead) across all
tabs when actionable findings are sitting unacted in state.db.

Stdlib HTTP + SSE; the MSF tab uses pymetasploit3 to read the live session/job
list, so this runs via `uv run` (see start.sh). Page markup lives in templates/;
the data layer and helpers live in the dash/ package — this module is just the
HTTP layer (routing, SSE, auth wiring, main).

Auth: if ~/.config/pen-agent/viewer-token exists, binds 0.0.0.0 and requires
the token (login cookie or `Authorization: Bearer <token>`); otherwise binds
127.0.0.1 only. Generate one: bash operator/portal/generate-token.sh

Usage:
    uv run --directory operator/portal python server.py [--port 8099]
    (or: bash operator/portal/start.sh)
"""

from __future__ import annotations

import argparse
import hmac
import json
import re
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlparse

from dash import activity, auth, config, findings, lead, msf, objectives, scope, shelllogs, state, team
from dash.pages import LOGIN_HTML, PAGES


class Handler(BaseHTTPRequestHandler):
    db_path: Path = config.DEFAULT_DB
    auth_token: str | None = None

    def log_message(self, fmt, *args):
        pass

    # ── auth ─────────────────────────────────────────────────────────────────
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
                return auth.verify_session_cookie(c["session"].value, self.auth_token)
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

    # ── response helpers ─────────────────────────────────────────────────────
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

    # ── GET ──────────────────────────────────────────────────────────────────
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
        if path in PAGES:
            self._html(PAGES[path])
        elif path == "/api/scope":
            self._json(scope.build())
        elif path == "/api/objectives":
            self._json(objectives.build())
        elif path == "/api/state":
            self._json(state.build_state(self.db_path))
        elif path == "/api/team":
            self._json(team.build(self.db_path))
        elif path == "/api/findings":
            self._json(findings.build())
        elif path == "/api/activity":
            self._json(activity.build(self.db_path))
        elif path == "/api/lead":
            self._json(lead.build(self.db_path))
        elif path == "/api/events":
            qs = parse_qs(urlparse(self.path).query)
            try:
                since = int((qs.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            self._json(state.get_events_since(self.db_path, since))
        elif path == "/api/sessions":
            self._json(msf.STATE.list_sessions())
        elif path == "/api/jobs":
            self._json(msf.STATE.list_jobs())
        elif path == "/api/session/log":
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("id") or [""])[0]
            self._json(msf.STATE.session_log(sid) if sid else {"error": "id required"},
                       200 if sid else 400)
        elif path == "/api/modules":
            self._json(msf.STATE.list_module_calls())
        elif path == "/api/module/log":
            qs = parse_qs(urlparse(self.path).query)
            cid = (qs.get("id") or [""])[0]
            self._json(msf.STATE.module_log(cid) if cid else {"error": "id required"},
                       200 if cid else 400)
        elif path == "/api/console/log":
            self._json(msf.STATE.console_log())
        elif path == "/api/shell/sessions":
            self._json(shelllogs.list_sessions())
        elif path == "/api/shell/log":
            qs = parse_qs(urlparse(self.path).query)
            name = (qs.get("file") or [""])[0]
            self._json(shelllogs.session_log(name) if name
                       else {"error": "file required"},
                       200 if name else 400)
        elif path == "/api/shell/commands":
            self._json(shelllogs.command_log())
        elif path == "/api/stream":
            self._state_stream()
        elif path == "/api/msf/stream":
            self._msf_stream()
        else:
            self.send_error(404)

    # ── SSE ──────────────────────────────────────────────────────────────────
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
                    data = state.build_state(self.db_path)
                    self.wfile.write(
                        f"data: {json.dumps({'type': 'state', 'payload': data}, default=str)}\n\n".encode()
                    )
                    self.wfile.flush()
                    last_full = now
                    if data["events"]:
                        last_event_id = max(e["id"] for e in data["events"])
                else:
                    events = state.get_events_since(self.db_path, last_event_id)
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
                status = msf.STATE.status()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'status', **status})}\n\n".encode()
                )
                sessions = msf.STATE.list_sessions()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'sessions', 'payload': sessions.get('sessions', [])})}\n\n".encode()
                )
                jobs = msf.STATE.list_jobs()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'jobs', 'payload': jobs.get('jobs', [])})}\n\n".encode()
                )
                modules = msf.STATE.list_module_calls()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'modules', 'payload': modules.get('calls', [])})}\n\n".encode()
                )
                shells = shelllogs.list_sessions()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'shells', 'payload': shells.get('sessions', [])})}\n\n".encode()
                )
                self.wfile.flush()
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ── POST ─────────────────────────────────────────────────────────────────
    def do_POST(self):
        if self.path.startswith("/api/"):
            if not self._is_authenticated():
                self._json({"error": "unauthorized"}, 401)
                return
            # Simple CSRF guard: require the fetch-only header. Browsers
            # won't attach it on a cross-site <form>-POST, and token-auth
            # consumers (curl / portal JS) set it explicitly.
            if self.headers.get("X-Requested-With") != "pen-agent-portal":
                self._json({"error": "missing X-Requested-With"}, 400)
                return
            parsed = urlparse(self.path)
            path = parsed.path
            m = re.match(r"^/api/objectives/(\d+)$", path)
            if m:
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length).decode(errors="replace") if length else ""
                try:
                    body = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    self._json({"error": "invalid json"}, 400)
                    return
                status = str(body.get("status", "")).strip()
                note = body.get("note")
                if note is not None and not isinstance(note, str):
                    self._json({"error": "note must be a string"}, 400)
                    return
                if note is not None and len(note) > 500:
                    self._json({"error": "note too long (max 500 chars)"}, 400)
                    return
                result = objectives.update_from_portal(int(m.group(1)), status, note)
                self._json(result, 400 if result.get("error") else 200)
                return
            self._json({"error": "not found"}, 404)
            return

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
                cookie_val = auth.make_session_cookie(self.auth_token)
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie",
                    f"session={cookie_val}; HttpOnly; SameSite=Strict; Max-Age={config.SESSION_MAX_AGE}; Path=/",
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

    Handler.db_path = Path(args.db) if args.db else config.DEFAULT_DB
    token = auth.load_token()
    Handler.auth_token = token
    bind_addr = "0.0.0.0" if token else "127.0.0.1"
    if token:
        print(f"auth: token loaded from {config.TOKEN_FILE}")
    else:
        print("auth: no token file — binding to localhost only (no auth required)")

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((bind_addr, args.port), Handler)
    print(f"portal: http://{bind_addr}:{args.port}")
    if bind_addr == "0.0.0.0":
        for ip in auth.get_local_ips():
            print(f"  remote:   http://{ip}:{args.port}")
    print(f"database: {Handler.db_path}")
    print(f"msfrpc:   {config.MSF_CFG} ({'found' if config.MSF_CFG.exists() else 'missing'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
