"""Per-teammate token usage + roster/health.

Token metrics come from the Claude Code transcripts the TeammateIdle hook
copies to engagement/evidence/logs/<ts>-teammate-<name>-<sessionid>.jsonl —
each line carries message.usage and message.model. The hook re-copies a
growing transcript on every idle, so only the latest snapshot per session is
counted. Roster/health enriches each teammate with live signals read from
state.db (last activity, blocked items) and the AUP sentinel files the hook
drops when a teammate's context is content-filtered.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from dash import state
from dash.config import EVIDENCE_DIR, TEAMMATE_LOG_DIR

_TRANSCRIPT_CACHE: dict = {}  # path -> (mtime, size, parsed)
_FNAME_RE = re.compile(r"^(\d{8}T\d{6}Z)-teammate-(.+)\.jsonl$")
_ACTIVE_WINDOW_S = 300  # a teammate seen in state_events within 5 min reads "active"


def _sanitize_hook_id(s: str) -> str:
    """Mirror save-teammate-log.sh: tr -cd 'a-zA-Z0-9-' | head -c 20."""
    return re.sub(r"[^a-zA-Z0-9-]", "", s or "")[:20]


def _parse_transcript(path: Path) -> dict | None:
    """Sum token/turn/tool metrics from one JSONL transcript. Cached by mtime+size."""
    try:
        st = path.stat()
    except OSError:
        return None
    key = str(path)
    cached = _TRANSCRIPT_CACHE.get(key)
    if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
        return cached[2]
    agg = {
        "input": 0, "output": 0, "cache_write": 0, "cache_read": 0,
        "turns": 0, "tool_calls": 0, "models": set(), "session_id": None,
    }
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                if agg["session_id"] is None:
                    sid = o.get("sessionId") or o.get("session_id")
                    if sid:
                        agg["session_id"] = sid
                msg = o.get("message")
                if not isinstance(msg, dict):
                    continue
                u = msg.get("usage")
                if isinstance(u, dict):
                    agg["input"] += u.get("input_tokens") or 0
                    agg["output"] += u.get("output_tokens") or 0
                    agg["cache_write"] += u.get("cache_creation_input_tokens") or 0
                    agg["cache_read"] += u.get("cache_read_input_tokens") or 0
                    agg["turns"] += 1
                    m = msg.get("model")
                    if m and m != "<synthetic>":
                        agg["models"].add(m)
                content = msg.get("content")
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "tool_use":
                            agg["tool_calls"] += 1
    except OSError:
        return None
    _TRANSCRIPT_CACHE[key] = (st.st_mtime, st.st_size, agg)
    return agg


def _health_signals(db_path: Path) -> tuple[dict, dict, set]:
    """Return (last_active_by_agent, blocked_count_by_agent, aup_flagged_names)."""
    last_active: dict[str, str] = {}
    blocked: dict[str, int] = {}
    conn = state.get_db(db_path)
    if conn is not None:
        try:
            for r in state.rows(
                conn, "SELECT agent, MAX(created_at) AS last FROM state_events "
                "WHERE agent != '' GROUP BY agent"):
                last_active[r["agent"]] = r["last"]
            for r in state.rows(
                conn, "SELECT blocked_by, COUNT(*) AS n FROM blocked "
                "WHERE blocked_by != '' GROUP BY blocked_by"):
                blocked[r["blocked_by"]] = r["n"]
        except Exception:
            pass
        finally:
            conn.close()
    flagged = set()
    try:
        for p in EVIDENCE_DIR.glob("aup-*.flag"):
            flagged.add(p.stem[len("aup-"):])
    except OSError:
        pass
    return last_active, blocked, flagged


def _age_seconds(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(tz=timezone.utc) - dt).total_seconds()


def build(db_path: Path) -> dict:
    if not TEAMMATE_LOG_DIR.exists():
        return {"available": False,
                "reason": "No engagement/evidence/logs directory yet.",
                "totals": {}, "teammates": [], "roster": {}}
    files = sorted(TEAMMATE_LOG_DIR.glob("*.jsonl"))
    if not files:
        return {"available": False,
                "reason": "No teammate transcripts captured yet.",
                "totals": {}, "teammates": [], "roster": {}}

    # Keep only the latest snapshot per (name, session) — the hook re-copies a
    # growing transcript on each idle, so earlier files are subsets.
    latest: dict = {}  # (name, session) -> (ts_str, path, name)
    for path in files:
        m = _FNAME_RE.match(path.name)
        if not m:
            continue
        ts_str, rest = m.group(1), m.group(2)  # rest = <name>-<safeid>
        parsed = _parse_transcript(path)
        if parsed is None:
            continue
        sid = parsed.get("session_id")
        safeid = _sanitize_hook_id(sid) if sid else ""
        if safeid and rest.endswith("-" + safeid):
            name = rest[: -(len(safeid) + 1)] or "unknown"
        elif "-" in rest:
            name = rest.rsplit("-", 1)[0]  # fall back: last token is the id
        else:
            name = rest
        gkey = (name, sid or path.name)
        prev = latest.get(gkey)
        if prev is None or ts_str > prev[0]:
            latest[gkey] = (ts_str, path, name)

    per: dict = {}  # name -> aggregate
    for (name, sid), (ts_str, path, nm) in latest.items():
        p = _parse_transcript(path)
        if not p:
            continue
        a = per.setdefault(nm, {
            "name": nm, "input": 0, "output": 0, "cache_write": 0,
            "cache_read": 0, "turns": 0, "tool_calls": 0, "sessions": 0,
            "models": set(),
        })
        for k in ("input", "output", "cache_write", "cache_read", "turns", "tool_calls"):
            a[k] += p[k]
        a["sessions"] += 1
        a["models"] |= p["models"]

    last_active, blocked, flagged = _health_signals(db_path)
    roster = {"active": 0, "idle": 0, "flagged": 0, "alerts": []}

    teammates = []
    for a in per.values():
        total = a["input"] + a["output"] + a["cache_write"] + a["cache_read"]
        name = a["name"]
        la = last_active.get(name)
        age = _age_seconds(la)
        is_flagged = name in flagged
        if is_flagged:
            status = "flagged"
            roster["flagged"] += 1
            roster["alerts"].append(name)
        elif age is not None and age <= _ACTIVE_WINDOW_S:
            status = "active"
            roster["active"] += 1
        else:
            status = "idle"
            roster["idle"] += 1
        teammates.append({
            **a, "total": total, "models": sorted(a["models"]),
            "status": status, "last_active": la, "blocked": blocked.get(name, 0),
            "aup": is_flagged,
        })
    teammates.sort(key=lambda x: x["total"], reverse=True)

    keys = ("input", "output", "cache_write", "cache_read", "total", "turns", "tool_calls")
    totals = {k: sum(t[k] for t in teammates) for k in keys}
    totals["teammates"] = len(teammates)
    return {"available": True, "totals": totals, "teammates": teammates, "roster": roster}
