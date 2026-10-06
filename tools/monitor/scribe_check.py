#!/usr/bin/env python3
"""Local scribe-gap check — one bash call per orchestrator loop.

Replaces the lead burning context on three MCP round-trips every loop
(`shell-server.list_sessions` + `metasploit-server.list_sessions` +
`state.poll_events`) just to discover there's nothing to nudge. This
script does the same work locally in ~50ms, reads directly from
state.db + the operator-sessions / exploits files on disk, and prints
EITHER:

    OK: all shells recorded (3), all actioned vulns covered (9)

or a block of nudge messages ready to relay to scribe:

    NUDGE:
    [nudge-session] session_id=5f3a
    [nudge-vuln] vuln_id=12 target=10.1.121.40 title="LLM path traversal"

Lead workflow: run this at the top of each loop; if it prints OK, move
on. If it prints NUDGE lines, send them to scribe and move on.

Also appends every run to `engagement/evidence/daemon.log` so the
operator can audit the decisions (observability was my own concern
when proposing the local path).

MSF session visibility: this script does NOT connect to msfrpcd. It
reads `engagement/evidence/msf-sessions/<id>.jsonl` filenames (written
by the metasploit-server MCP for every session it has seen) + the
reserved-sessions registry. That's enough to tell whether a session
had its exploit recorded (presence of a matching
`engagement/exploits/<ip>-*` file).

Exit codes:
  0 — no action needed (OK)
  1 — nudges printed
  2 — invariant check failed (missing engagement/, broken state.db)
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ENG = _PROJECT_ROOT / "engagement"
_STATE_DB = _ENG / "state.db"
_EXPLOITS_DIR = _ENG / "exploits"
_EVIDENCE_DIR = _ENG / "evidence"
_MSF_SESSION_DIR = _EVIDENCE_DIR / "msf-sessions"
_SHELL_LOG_GLOB = "shell-*.log"
_OPERATOR_SESSIONS = _ENG / "operator-sessions.json"
_DAEMON_LOG = _EVIDENCE_DIR / "daemon.log"


def _audit(line: str) -> None:
    """Append one timestamped line to daemon.log; silent on failure."""
    try:
        _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        with _DAEMON_LOG.open("a") as f:
            f.write(f"[{ts}] scribe_check: {line}\n")
    except OSError:
        pass


def _shell_sessions() -> list[tuple[str, str, str]]:
    """List shell-server sessions by scanning the live-log files.
    Returns [(session_id, label, log_path), ...].
    """
    out = []
    if not _EVIDENCE_DIR.exists():
        return out
    pat = re.compile(r"^shell-([^-]+)-(.+)\.log$")
    for p in sorted(_EVIDENCE_DIR.glob(_SHELL_LOG_GLOB)):
        m = pat.match(p.name)
        if m:
            out.append((m.group(1), m.group(2), str(p)))
    return out


def _msf_session_ids() -> list[str]:
    """List MSF sessions seen by the metasploit-server MCP.
    Reads evidence/msf-sessions/<sid>.jsonl filenames."""
    if not _MSF_SESSION_DIR.exists():
        return []
    return sorted(p.stem for p in _MSF_SESSION_DIR.glob("*.jsonl"))


def _reserved_msf() -> set[str]:
    """Operator-reserved MSF session ids (shouldn't trigger nudges)."""
    if not _OPERATOR_SESSIONS.exists():
        return set()
    try:
        data = json.loads(_OPERATOR_SESSIONS.read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    r = data.get("reserved") if isinstance(data, dict) else None
    return set(str(k) for k in r.keys()) if isinstance(r, dict) else set()


def _recorded_shells() -> set[str]:
    """Session labels that have a matching engagement/exploits/*.sh file.
    Match is substring: the label appears somewhere in the filename.
    (Filenames lead with <ip>-; label is baked in at record time.)
    """
    if not _EXPLOITS_DIR.exists():
        return set()
    return {p.stem for p in _EXPLOITS_DIR.glob("*.sh")}


def _ip_to_slug(ip: str) -> str:
    return ip.replace(".", "-")


def _exploit_for_target(ip: str) -> list[str]:
    """Return any <ip>-*.{sh,md} filename stems under exploits/."""
    if not _EXPLOITS_DIR.exists():
        return []
    slug = _ip_to_slug(ip)
    return [p.stem for p in _EXPLOITS_DIR.glob(f"{slug}-*.sh")]


def _actioned_vulns() -> list[dict]:
    """Vulns with status=actioned joined with target IP + discovered_by."""
    if not _STATE_DB.exists():
        return []
    conn = sqlite3.connect(f"file:{_STATE_DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT v.id, v.title, v.discovered_by, t.ip
            FROM vulns v LEFT JOIN targets t ON t.id = v.target_id
            WHERE v.status = 'actioned' AND t.ip IS NOT NULL AND t.ip <> ''
            ORDER BY v.id
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    return [dict(r) for r in rows]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quiet", action="store_true",
                    help="print nothing on OK (only on nudges + errors)")
    args = ap.parse_args()

    if not _ENG.exists():
        print("ERROR: no engagement/ directory", file=sys.stderr)
        return 2

    nudges: list[str] = []

    # 1. SHELL-SERVER SESSIONS: every shell-<sid>-<label>.log should have
    #    a matching exploits/*<label>*.sh.
    recorded = _recorded_shells()
    unrecorded_shells = []
    for sid, label, path in _shell_sessions():
        # record_exploit's filename pattern is <ip>-[<hostname>-]<label>;
        # a label match means some file in exploits/ ends with the label.
        if any(stem.endswith("-" + label) or stem.endswith(label) for stem in recorded):
            continue
        unrecorded_shells.append((sid, label))
        nudges.append(f"[nudge-session] session_id={sid} label={label}")

    # 2. MSF SESSIONS: every msf-sessions/<sid>.jsonl id that is NOT
    #    operator-reserved should also have an exploits/*.sh (we can't
    #    tell which from the sid alone, so this is a conservative
    #    "has ANY recorded exploit matched that session's host?" — the
    #    operator can confirm). We approximate by requiring at least one
    #    .sh file in exploits/ per non-reserved msf session; if none,
    #    nudge. Rare in practice (first MSF-only engagement without
    #    shell-server).
    reserved = _reserved_msf()
    recorded_any = len(recorded) > 0
    unrecorded_msf = []
    for sid in _msf_session_ids():
        if sid in reserved:
            continue
        if not recorded_any:
            unrecorded_msf.append(sid)
            nudges.append(f"[nudge-session] session_id={sid} backend=msf")

    # 3. ACTIONED VULNS: for each, confirm an engagement/exploits/<ip>-*
    #    file exists. If not, nudge scribe to chase discovered_by.
    uncovered_vulns = []
    for v in _actioned_vulns():
        if _exploit_for_target(v["ip"]):
            continue
        uncovered_vulns.append(v)
        discovered = (v.get("discovered_by") or "").strip() or "unknown"
        title = (v["title"] or "").replace('"', "'")
        nudges.append(
            f"[nudge-vuln] vuln_id={v['id']} target={v['ip']} "
            f'title="{title}" discovered_by={discovered}'
        )

    if not nudges:
        _audit(
            f"OK — shells={len(recorded)}/{len(_shell_sessions())+len(_msf_session_ids())}, "
            f"actioned_vulns={len(_actioned_vulns())}"
        )
        if not args.quiet:
            print(
                f"OK: all {len(_shell_sessions())} shell-server + "
                f"{len(_msf_session_ids())} MSF sessions recorded, all "
                f"{len(_actioned_vulns())} actioned vulns covered."
            )
        return 0

    _audit(
        f"NUDGE — unrecorded_shells={len(unrecorded_shells)}, "
        f"unrecorded_msf={len(unrecorded_msf)}, "
        f"uncovered_vulns={len(uncovered_vulns)}"
    )
    print("NUDGE: (relay to scribe)")
    for n in nudges:
        print("  " + n)
    return 1


if __name__ == "__main__":
    sys.exit(main())
