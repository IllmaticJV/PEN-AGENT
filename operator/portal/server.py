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
from datetime import datetime, timezone
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
_MODULE_LOG_DIR = _PROJECT_ROOT / "engagement" / "evidence" / "msf-modules"
_CONSOLE_SPOOL = _PROJECT_ROOT / "engagement" / "evidence" / "msf-console.log"
_SHELL_LOG_DIR = _PROJECT_ROOT / "engagement" / "evidence"
_SHELL_CMD_LOG = _PROJECT_ROOT / "engagement" / "evidence" / "shell-commands.log"
_OPERATOR_SESSIONS = _PROJECT_ROOT / "engagement" / "operator-sessions.json"
_OBJECTIVES_JSON = _PROJECT_ROOT / "engagement" / "objectives.json"
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


def _build_objectives() -> dict:
    """Return objectives.json merged with a live re-parse of scope.md so the
    portal can show NEW objectives the operator just added before the lead
    has re-run init_objectives. Status/note come from objectives.json;
    anything only in scope.md shows up as status=pending with a flag."""
    import sys as _sys
    _parser_dir = _PROJECT_ROOT / "tools" / "objectives"
    if str(_parser_dir) not in _sys.path:
        _sys.path.insert(0, str(_parser_dir))
    try:
        import parse_scope  # type: ignore
    except Exception:
        parse_scope = None

    stored = {"objectives": [], "parsed_at": None}
    try:
        if _OBJECTIVES_JSON.exists():
            data = json.loads(_OBJECTIVES_JSON.read_text(errors="replace"))
            if isinstance(data, dict) and isinstance(data.get("objectives"), list):
                stored = data
    except (OSError, json.JSONDecodeError):
        pass

    live = []
    if parse_scope is not None and _SCOPE_MD.exists():
        try:
            live = parse_scope.parse_file(_SCOPE_MD)
        except Exception:
            live = []

    stored_by_id = {int(o.get("id", -1)): o for o in stored["objectives"]}
    merged = []
    unsynced = False
    if live:
        for item in live:
            s = stored_by_id.get(int(item["id"]))
            if s:
                merged.append({
                    "id": item["id"],
                    "text": item["text"],
                    "status": s.get("status", "pending"),
                    "note": s.get("note", ""),
                    "updated_at": s.get("updated_at", ""),
                    "unsynced": s.get("text") != item["text"],
                })
                if s.get("text") != item["text"]:
                    unsynced = True
            else:
                merged.append({
                    "id": item["id"], "text": item["text"],
                    "status": "pending", "note": "", "updated_at": "",
                    "unsynced": True,
                })
                unsynced = True
        if len(stored["objectives"]) > len(live):
            unsynced = True
    else:
        merged = stored["objectives"]

    counts = {"pending": 0, "in_progress": 0, "done": 0,
              "blocked": 0, "skipped": 0}
    for o in merged:
        counts[o.get("status", "pending")] = counts.get(o.get("status", "pending"), 0) + 1
    total = len(merged)
    completed = counts["done"]
    percent = int(round(100 * completed / total)) if total else 0
    return {
        "objectives": merged,
        "counts": counts,
        "total": total,
        "completed": completed,
        "percent": percent,
        "parsed_at": stored.get("parsed_at"),
        "unsynced": unsynced,
    }


_VALID_OBJ_STATUS = ("pending", "in_progress", "done", "blocked", "skipped")
_OBJ_WRITE_LOCK = threading.Lock()


def _update_objective_from_portal(objective_id: int, status: str,
                                  note: str | None = None) -> dict:
    """Operator-driven objective toggle. Writes engagement/objectives.json
    with the same schema the state-server MCP uses so the lead's live view
    stays coherent.

    Serialised through a module-level lock to avoid portal threads racing
    each other; the lead's MCP writes are a separate process and lose
    races by last-write-wins (acceptable for a one-operator tracker).
    Atomic on-disk: writes to a sibling .tmp and renames into place.
    """
    if status not in _VALID_OBJ_STATUS:
        return {"error": f"status must be one of {_VALID_OBJ_STATUS}"}
    with _OBJ_WRITE_LOCK:
        data: dict = {"objectives": [], "parsed_at": None}
        if _OBJECTIVES_JSON.exists():
            try:
                parsed = json.loads(_OBJECTIVES_JSON.read_text(errors="replace"))
                if isinstance(parsed, dict) and isinstance(parsed.get("objectives"), list):
                    data = parsed
            except (OSError, json.JSONDecodeError) as e:
                return {"error": f"objectives.json unreadable: {e}"}
        found = None
        for obj in data.get("objectives", []):
            if int(obj.get("id", 0)) == int(objective_id):
                found = obj
                break
        if found is None:
            return {"error": f"objective_id {objective_id} not found "
                             "(portal only toggles already-parsed objectives — "
                             "add new ones to scope.md and have the lead run "
                             "init_objectives)"}
        now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        found["status"] = status
        if note is not None:
            found["note"] = note
        found["updated_at"] = now
        try:
            tmp = _OBJECTIVES_JSON.with_suffix(_OBJECTIVES_JSON.suffix + ".tmp")
            tmp.write_text(json.dumps(data, indent=2) + "\n")
            tmp.replace(_OBJECTIVES_JSON)
        except OSError as e:
            return {"error": f"save failed: {e}"}
        return {"status": "updated", "objective": found}


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

    def list_module_calls(self, max_entries: int = 100) -> dict:
        """Return recent MSF module-call setup records (newest-first).

        Each entry is the FIRST record of a per-call JSONL file
        (engagement/evidence/msf-modules/<id>-<slug>.jsonl, written by the
        metasploit-server MCP). Carries just enough for the sidebar listing:
        call_id, timestamp, tool, module path, and job_id (so the Jobs table
        can cross-link to the matching setup log).
        """
        if not _MODULE_LOG_DIR.exists():
            return {"calls": []}
        try:
            # Newest-first by call_id (the integer prefix in the filename).
            files = sorted(
                _MODULE_LOG_DIR.glob("*.jsonl"),
                key=lambda p: int(p.name.split("-", 1)[0]) if p.name.split("-", 1)[0].isdigit() else 0,
                reverse=True,
            )[:max_entries]
        except OSError:
            return {"calls": []}
        out = []
        for p in files:
            try:
                first = p.read_text(errors="replace").splitlines()[0]
                rec = json.loads(first)
            except (OSError, IndexError, json.JSONDecodeError):
                continue
            out.append({
                "id": p.stem,                        # <call_id>-<slug>
                "call_id": rec.get("call_id"),
                "ts": rec.get("ts", ""),
                "tool": rec.get("tool", ""),
                "module": rec.get("module", ""),
                "module_type": rec.get("module_type", ""),
                "job_id": rec.get("job_id"),
            })
        return {"calls": out}

    def module_log(self, call_file_id: str) -> dict:
        """Return the full JSONL for one module-call setup log.

        `call_file_id` is the filename stem (<call_id>-<slug>), exactly what
        list_module_calls returns in `id`. Also accepts a bare numeric
        call_id — resolved by prefix match. For cross-linking from the Jobs
        table, callers can pass `job:<job_id>` to look up by job_id instead.
        """
        if not _MODULE_LOG_DIR.exists():
            return {"id": call_file_id, "records": []}
        path: Path | None = None
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(call_file_id))

        if safe.startswith("job_"):
            # Caller wants the call that produced this job_id — scan files.
            jid = safe[4:]
            for p in _MODULE_LOG_DIR.glob("*.jsonl"):
                try:
                    first = p.read_text(errors="replace").splitlines()[0]
                    if json.loads(first).get("job_id") == jid:
                        path = p
                        break
                except (OSError, IndexError, json.JSONDecodeError):
                    continue
        else:
            candidate = _MODULE_LOG_DIR / f"{safe}.jsonl"
            if candidate.exists():
                path = candidate
            elif safe.isdigit():
                # Numeric-only call_id — prefix match the first file we see.
                for p in _MODULE_LOG_DIR.glob(f"{safe}-*.jsonl"):
                    path = p
                    break

        if path is None or not path.exists():
            return {"id": call_file_id, "records": []}

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
            return {"id": call_file_id, "records": [], "error": str(e)}
        return {"id": path.stem, "path": str(path), "records": records}

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


# ── Shell-server read-side (operator visibility into non-MSF sessions) ──────
# Shell-server writes a per-session live log at
# engagement/evidence/shell-<session_id>-<label>.log and appends every
# send_command to engagement/evidence/shell-commands.log. The portal reads
# those files directly — shell-server itself doesn't expose HTTP.
_SHELL_LOG_RE = re.compile(r"^shell-([^-]+)-(.+)\.log$")


def _shell_list_sessions() -> dict:
    """Scan engagement/evidence for shell-<sid>-<label>.log files.

    Returns newest-first by mtime so the active session floats to the top.
    """
    if not _SHELL_LOG_DIR.exists():
        return {"sessions": []}
    out = []
    try:
        for p in _SHELL_LOG_DIR.glob("shell-*.log"):
            m = _SHELL_LOG_RE.match(p.name)
            if not m:
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            out.append({
                "session_id": m.group(1),
                "label": m.group(2),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "mtime_iso": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat(timespec="seconds"),
                "file": p.name,
            })
    except OSError:
        return {"sessions": []}
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return {"sessions": out}


def _shell_session_log(file_name: str, max_bytes: int = 128 * 1024) -> dict:
    """Return the tail of a single shell-session live log.

    `file_name` is validated against the shell-*.log pattern so a crafted
    `../` can't walk out of the evidence dir. Falls back to the whole file
    when it's smaller than max_bytes.
    """
    if not _SHELL_LOG_RE.match(file_name):
        return {"data": "", "error": "invalid file name"}
    p = _SHELL_LOG_DIR / file_name
    try:
        p = p.resolve()
    except OSError:
        return {"data": "", "error": "resolve failed"}
    try:
        if not str(p).startswith(str(_SHELL_LOG_DIR.resolve())):
            return {"data": "", "error": "out of scope"}
    except OSError:
        return {"data": "", "error": "resolve failed"}
    if not p.exists():
        return {"data": "", "error": "not found"}
    try:
        with p.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return {"data": f.read().decode(errors="replace"), "size": size}
    except OSError as e:
        return {"data": "", "error": str(e)}


def _shell_command_log(max_bytes: int = 64 * 1024) -> dict:
    """Return the tail of the shared shell-commands.log — a one-liner-per-
    command log across all shell-server sessions. Useful as a global
    activity feed above the per-session views."""
    if not _SHELL_CMD_LOG.exists():
        return {"data": ""}
    try:
        with _SHELL_CMD_LOG.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return {"data": f.read().decode(errors="replace"), "size": size}
    except OSError as e:
        return {"data": "", "error": str(e)}


_msf = _MsfState()


# ── Pages ────────────────────────────────────────────────────────────────────
LOGIN_HTML = _load_template("login.html")
PORTAL_HTML = _load_template("portal.html")
SCOPE_HTML = _load_template("scope.html")
STATUS_HTML = _load_template("status.html")
MSF_HTML = _load_template("msf.html")
OBJECTIVES_HTML = _load_template("objectives.html")

_PAGES = {"/": PORTAL_HTML, "/scope": SCOPE_HTML, "/status": STATUS_HTML,
          "/msf": MSF_HTML, "/objectives": OBJECTIVES_HTML}


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
        elif path == "/api/objectives":
            self._json(_build_objectives())
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
        elif path == "/api/modules":
            self._json(_msf.list_module_calls())
        elif path == "/api/module/log":
            qs = parse_qs(urlparse(self.path).query)
            cid = (qs.get("id") or [""])[0]
            self._json(_msf.module_log(cid) if cid else {"error": "id required"},
                       200 if cid else 400)
        elif path == "/api/console/log":
            self._json(_msf.console_log())
        elif path == "/api/shell/sessions":
            self._json(_shell_list_sessions())
        elif path == "/api/shell/log":
            qs = parse_qs(urlparse(self.path).query)
            name = (qs.get("file") or [""])[0]
            self._json(_shell_session_log(name) if name
                       else {"error": "file required"},
                       200 if name else 400)
        elif path == "/api/shell/commands":
            self._json(_shell_command_log())
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
                modules = _msf.list_module_calls()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'modules', 'payload': modules.get('calls', [])})}\n\n".encode()
                )
                shells = _shell_list_sessions()
                self.wfile.write(
                    f"data: {json.dumps({'type': 'shells', 'payload': shells.get('sessions', [])})}\n\n".encode()
                )
                self.wfile.flush()
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError):
            pass

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
                result = _update_objective_from_portal(int(m.group(1)), status, note)
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
