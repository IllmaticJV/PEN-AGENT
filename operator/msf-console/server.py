#!/usr/bin/env python3
"""Operator web console for PEN-AGENT's shared Metasploit RPC instance.

metasploit-server (the MCP server teammates use) and this viewer both connect
to the *same* msfrpcd daemon via engagement/msfrpc.yaml. Metasploit sessions
and jobs belong to that daemon's Framework instance, not to whichever RPC
client created them — so this page shows the live session list the agent is
driving, and the embedded console is a real msfconsole running inside that
same instance: commands typed here (`sessions -l`, `sessions -i 1`, any
module) see and affect the exact sessions the agent sees, live.

Single-file HTTP server, inline HTML/CSS/JS frontend, live updates via SSE —
same shape as operator/state-viewer. The one non-stdlib dependency is
pymetasploit3 (the RPC client), so this runs via `uv run` rather than bare
python3; see start.sh.

Authentication: reuses operator/state-viewer's token file
(~/.config/pen-agent/viewer-token). If present, this server binds 0.0.0.0 and
requires it; otherwise it binds 127.0.0.1 only. This console is equivalent to
local msfconsole access to the engagement's C2 — treat the token the same way
you would an SSH key to the attackbox.

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
import socket
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote_plus

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_MSF_CFG = _PROJECT_ROOT / "engagement" / "msfrpc.yaml"
_TOKEN_FILE = Path.home() / ".config" / "pen-agent" / "viewer-token"  # shared with state-viewer

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

    def get_console(self, client):
        """Returns the shared console, creating it if needed."""
        with self.lock:
            if self.console is None:
                self.console = client.consoles.console()
            return self.console

    def reset_console(self):
        with self.lock:
            if self.console is not None and self.client is not None:
                try:
                    self.client.consoles.destroy(self.console.cid)
                except Exception:
                    pass
            self.console = None

    def write(self, command: str) -> dict:
        client, err = self.require_client()
        if err:
            return {"error": err}
        with self.lock:
            for attempt in (1, 2):
                try:
                    console = self.get_console(client)
                    console.write(command)
                    return {"ok": True}
                except Exception as e:
                    self.reset_console()
                    if attempt == 2:
                        return {"error": str(e)}
        return {"error": "unreachable"}

    def read(self) -> dict:
        client, err = self.require_client()
        if err:
            return {"data": "", "prompt": "", "busy": False, "error": err}
        with self.lock:
            try:
                console = self.get_console(client)
                chunk = console.read()
                return {
                    "data": chunk.get("data", ""),
                    "prompt": chunk.get("prompt", ""),
                    "busy": bool(chunk.get("busy", False)),
                }
            except Exception as e:
                self.reset_console()
                return {"data": "", "prompt": "", "busy": False, "error": str(e)}

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

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>msf-console — login</title>
<style>
body{background:#0b0d10;color:#c9d1d9;font-family:ui-monospace,Menlo,Consolas,monospace;
     display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#14181d;border:1px solid #2a2f37;border-radius:8px;padding:28px 32px}
h1{font-size:15px;color:#8ab4f8;margin:0 0 16px}
input{background:#0b0d10;border:1px solid #2a2f37;color:#c9d1d9;padding:8px 10px;
      border-radius:6px;width:280px;font-family:inherit}
button{margin-top:12px;background:#2563eb;color:#fff;border:none;border-radius:6px;
       padding:8px 14px;cursor:pointer;font-family:inherit}
.err{color:#f85149;font-size:13px;margin-top:8px}
</style></head>
<body>
<form method="POST" action="/login">
  <h1>PEN-AGENT &middot; msf-console</h1>
  <input type="password" name="token" placeholder="viewer token" autofocus>
  <div><button type="submit">Enter</button></div>
  <div class="err" id="err"></div>
</form>
<script>
if (location.search.includes("fail=1")) document.getElementById("err").textContent = "Invalid token.";
</script>
</body></html>"""

CONSOLE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PEN-AGENT &middot; msf-console</title>
<style>
:root{--bg:#0b0d10;--panel:#14181d;--border:#2a2f37;--fg:#c9d1d9;--dim:#6e7681;
      --accent:#8ab4f8;--green:#3fb950;--red:#f85149;--amber:#d29922}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,Menlo,Consolas,monospace;
     height:100vh;display:flex;flex-direction:column}
header{padding:10px 16px;border-bottom:1px solid var(--border);display:flex;
       align-items:center;gap:14px;flex-shrink:0}
header h1{font-size:14px;margin:0;color:var(--accent);font-weight:600}
#status{font-size:12px;padding:2px 8px;border-radius:10px;border:1px solid var(--border)}
#status.ok{color:var(--green);border-color:var(--green)}
#status.bad{color:var(--red);border-color:var(--red)}
main{flex:1;display:flex;min-height:0}
#side{width:340px;border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0}
section{padding:10px 14px;border-bottom:1px solid var(--border)}
section h2{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);margin:0 0 8px}
table{width:100%;border-collapse:collapse;font-size:12px}
td{padding:3px 4px;border-bottom:1px solid #1c2127;vertical-align:top}
td.id{color:var(--accent);cursor:pointer;white-space:nowrap}
td.id:hover{text-decoration:underline}
.empty{color:var(--dim);font-size:12px;padding:4px}
#termwrap{flex:1;display:flex;flex-direction:column;min-width:0}
#term{flex:1;overflow-y:auto;padding:12px 14px;white-space:pre-wrap;word-break:break-all;
      font-size:13px;line-height:1.45}
#inputrow{display:flex;border-top:1px solid var(--border);padding:8px 12px;gap:8px;flex-shrink:0}
#prompt{color:var(--green);white-space:pre}
#cmd{flex:1;background:transparent;border:none;color:var(--fg);font-family:inherit;
     font-size:13px;outline:none}
#hint{font-size:11px;color:var(--dim);padding:0 14px 8px}
button.reset{background:transparent;border:1px solid var(--border);color:var(--dim);
             border-radius:6px;font-size:11px;padding:3px 8px;cursor:pointer;font-family:inherit}
button.reset:hover{color:var(--red);border-color:var(--red)}
</style></head>
<body>
<header>
  <h1>msf-console</h1>
  <span id="status">connecting&hellip;</span>
  <span style="flex:1"></span>
  <button class="reset" onclick="resetConsole()">reset console</button>
</header>
<main>
  <div id="side">
    <section>
      <h2>Sessions</h2>
      <table id="sessions"><tbody></tbody></table>
      <div class="empty" id="sessions-empty">none yet</div>
    </section>
    <section>
      <h2>Jobs</h2>
      <table id="jobs"><tbody></tbody></table>
      <div class="empty" id="jobs-empty">none yet</div>
    </section>
  </div>
  <div id="termwrap">
    <div id="term"></div>
    <div id="inputrow">
      <span id="prompt">msf &gt;</span>
      <input id="cmd" autofocus autocomplete="off" spellcheck="false">
    </div>
    <div id="hint">Enter to run &middot; &uarr;/&darr; history &middot; this is a real msfconsole on
      the engagement's shared msfrpcd — <code>sessions -i &lt;id&gt;</code> interacts with whatever
      the agent opened, live.</div>
  </div>
</main>
<script>
const term = document.getElementById('term');
const cmdEl = document.getElementById('cmd');
const statusEl = document.getElementById('status');
let history = [], histIdx = -1;

function append(text) {
  if (!text) return;
  term.textContent += text;
  term.scrollTop = term.scrollHeight;
}

function setStatus(connected, msg) {
  statusEl.textContent = msg || (connected ? 'connected' : 'disconnected');
  statusEl.className = connected ? 'ok' : 'bad';
}

function renderTable(id, emptyId, rows, cols) {
  const tbody = document.querySelector('#' + id + ' tbody');
  tbody.innerHTML = '';
  document.getElementById(emptyId).style.display = rows.length ? 'none' : 'block';
  for (const row of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = cols.map((c, i) =>
      `<td class="${i === 0 ? 'id' : ''}">${(row[c] ?? '').toString().replace(/</g,'&lt;')}</td>`
    ).join('');
    if (cols[0] === 'session_id') {
      tr.querySelector('td.id').onclick = () => runCommand('sessions -i ' + row.session_id);
    }
    tbody.appendChild(tr);
  }
}

function runCommand(cmd) {
  append('\\n' + cmd + '\\n');
  fetch('/api/console/write', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({command: cmd})
  }).then(r => r.json()).then(j => { if (j.error) append('[error] ' + j.error + '\\n'); });
}

function resetConsole() {
  fetch('/api/console/reset', {method: 'POST'})
    .then(() => append('\\n[console reset]\\n'));
}

cmdEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const cmd = cmdEl.value;
    if (cmd.trim() !== '') { history.push(cmd); histIdx = history.length; }
    cmdEl.value = '';
    runCommand(cmd);
  } else if (e.key === 'ArrowUp') {
    if (histIdx > 0) { histIdx--; cmdEl.value = history[histIdx] || ''; }
    e.preventDefault();
  } else if (e.key === 'ArrowDown') {
    if (histIdx < history.length) { histIdx++; cmdEl.value = history[histIdx] || ''; }
    e.preventDefault();
  }
});

const es = new EventSource('/api/stream');
es.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.type === 'console') {
    if (msg.error) setStatus(false, msg.error);
    else { setStatus(true); append(msg.data); }
  } else if (msg.type === 'sessions') {
    renderTable('sessions', 'sessions-empty', msg.payload,
      ['session_id', 'type', 'info']);
  } else if (msg.type === 'jobs') {
    renderTable('jobs', 'jobs-empty', msg.payload, ['job_id', 'name']);
  } else if (msg.type === 'status') {
    setStatus(msg.connected, msg.connected ? 'connected' : (msg.error || 'disconnected'));
  }
};
es.onerror = () => setStatus(false, 'stream lost — retrying');
</script>
</body></html>"""


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

        last_slow = 0.0
        try:
            while True:
                chunk = _msf.read()
                if chunk.get("data") or chunk.get("error"):
                    self.wfile.write(
                        f"data: {json.dumps({'type': 'console', **chunk})}\n\n".encode()
                    )
                    self.wfile.flush()

                now = time.time()
                if now - last_slow >= 2:
                    last_slow = now
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
                time.sleep(0.4)
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

        if not self._require_auth():
            return

        if self.path == "/api/console/write":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode() if length else "{}"
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._json({"error": "invalid JSON body"}, 400)
                return
            command = str(payload.get("command", ""))
            if not command.endswith("\n"):
                command += "\n"
            self._json(_msf.write(command))
        elif self.path == "/api/console/reset":
            _msf.reset_console()
            self._json({"ok": True})
        else:
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
