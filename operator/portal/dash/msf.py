"""Metasploit RPC read-side (live session/job list) + file-based MSF logs."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path

from dash.config import (
    CONSOLE_SPOOL, MODULE_LOG_DIR, MSF_CFG, NOT_CONFIGURED, NOT_CONNECTED,
    OPERATOR_SESSIONS, SESSION_LOG_DIR,
)


def load_reserved_sessions() -> dict:
    try:
        if OPERATOR_SESSIONS.exists():
            data = json.loads(OPERATOR_SESSIONS.read_text())
            if isinstance(data, dict) and isinstance(data.get("reserved"), dict):
                return data["reserved"]
    except Exception:
        pass
    return {}


def parse_msf_config(path: Path) -> dict:
    cfg: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        cfg[key.strip().lower()] = value.strip().strip('"').strip("'")
    return cfg


class MsfState:
    """Caches the RPC client used only to read the live session/job list."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.client = None

    def get_client(self):
        with self.lock:
            if not MSF_CFG.exists():
                return None
            if self.client is not None:
                try:
                    self.client.core.version
                    return self.client
                except Exception:
                    self.client = None
            try:
                from pymetasploit3.msfrpc import MsfRpcClient

                cfg = parse_msf_config(MSF_CFG)
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
        if not MSF_CFG.exists():
            return None, NOT_CONFIGURED
        client = self.get_client()
        if client is None:
            return None, NOT_CONNECTED
        return client, None

    def list_sessions(self) -> dict:
        client, err = self.require_client()
        if err:
            return {"error": err}
        try:
            reserved = load_reserved_sessions()
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
        if not MSF_CFG.exists():
            return {"configured": False, "connected": False, "error": NOT_CONFIGURED}
        if self.get_client() is None:
            return {"configured": True, "connected": False, "error": NOT_CONNECTED}
        return {"configured": True, "connected": True}

    def session_log(self, session_id: str, max_records: int = 500) -> dict:
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(session_id)) or "unknown"
        path = SESSION_LOG_DIR / f"{safe}.jsonl"
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
        if not MODULE_LOG_DIR.exists():
            return {"calls": []}
        try:
            # Newest-first by call_id (the integer prefix in the filename).
            files = sorted(
                MODULE_LOG_DIR.glob("*.jsonl"),
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
        if not MODULE_LOG_DIR.exists():
            return {"id": call_file_id, "records": []}
        path: Path | None = None
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(call_file_id))

        if safe.startswith("job_"):
            # Caller wants the call that produced this job_id — scan files.
            jid = safe[4:]
            for p in MODULE_LOG_DIR.glob("*.jsonl"):
                try:
                    first = p.read_text(errors="replace").splitlines()[0]
                    if json.loads(first).get("job_id") == jid:
                        path = p
                        break
                except (OSError, IndexError, json.JSONDecodeError):
                    continue
        else:
            candidate = MODULE_LOG_DIR / f"{safe}.jsonl"
            if candidate.exists():
                path = candidate
            elif safe.isdigit():
                # Numeric-only call_id — prefix match the first file we see.
                for p in MODULE_LOG_DIR.glob(f"{safe}-*.jsonl"):
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
        if not CONSOLE_SPOOL.exists():
            return {"data": ""}
        try:
            with CONSOLE_SPOOL.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                return {"data": f.read().decode(errors="replace")}
        except OSError as e:
            return {"data": "", "error": str(e)}


# Module-level singleton — the Handler drives this to read the live MSF state.
STATE = MsfState()
