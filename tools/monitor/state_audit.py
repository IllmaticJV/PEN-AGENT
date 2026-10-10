#!/usr/bin/env python3
"""Local state-hygiene audit — one bash call per orchestrator loop.

The lead does a handful of deterministic state.db checks in-context every
loop (Post-Task Checkpoint + Decision Logic): is a vuln stuck at `found`
after it already produced downstream access/creds? Are there credentials
nobody has tested yet? Did a credential from a named technique land without
a `via_vuln_id`? Are there blocked items eligible for retry, or identified
pivots nobody took? Those are all pure queries — compute them here so the
lead's turns stay short and it can juggle more teammates.

This does NOT replace the stall sweep: detecting a silent/wedged teammate
needs the task list + message timestamps, which live in the lead's session,
not in state.db. Run `scribe_check.py` and `objective_match.py` alongside
this for the shell-recording and objective-tracker halves.

Read-only. stdlib only. Always exits 0 (advisory). Prints EITHER:

    OK: state coherent — 9 vulns, 6 creds, 4 access, nothing stale

or a grouped list of items with the ready-to-relay action for each, e.g.:

    STALE VULNS (status=found but already produced downstream — close the loop):
      [update-vuln] id=12 status=actioned   # 10.1.121.40 "LLM path traversal"
    UNTESTED CREDENTIALS (no credential_access row — route cred-sweep/spray):
      cred #7 svc_sql (password, cracked) from "kerberoast"

Usage:
  python3 tools/monitor/state_audit.py [--db engagement/state.db] [--quiet]
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB = _ROOT / "engagement" / "state.db"
_DAEMON_LOG = _ROOT / "engagement" / "evidence" / "daemon.log"

# Source strings that imply an active technique produced the credential, so a
# missing via_vuln_id is a real provenance gap (mirrors the lead's
# TECHNIQUE-VULN AUDIT). Operator-provided creds legitimately have no vuln.
_TECHNIQUE_HINTS = (
    "secretsdump", "kerberoast", "asreproast", "dcsync", "ntds", "lsass", "sam",
    "dump", "crack", "hashcat", "spray", "inject", "sqli", "responder", "relay",
    "tgs", "tgt", "extract", "decrypt", "dpapi", "mimikatz", "roast",
)


def _rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def audit(db_path: Path) -> tuple[list[str], dict]:
    """Return (list of report sections, counts). Empty list = all clear."""
    if not db_path.exists():
        return (["(no state.db yet — nothing to audit)"], {})
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    out: list[str] = []
    try:
        counts = {
            "vulns": conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0],
            "creds": conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0],
            "access": conn.execute("SELECT COUNT(*) FROM access").fetchone()[0],
        }

        # 1. Vulns stuck at 'found' that already produced downstream — the lead's
        #    "close the loop" step. A found vuln with access/creds/vulns pointing
        #    back at it was actioned; its status just never got updated.
        stale = _rows(conn, """
            SELECT v.id, v.title, t.ip FROM vulns v
            LEFT JOIN targets t ON t.id = v.target_id
            WHERE v.status = 'found' AND (
              EXISTS(SELECT 1 FROM access a WHERE a.via_vuln_id = v.id) OR
              EXISTS(SELECT 1 FROM credentials c WHERE c.via_vuln_id = v.id) OR
              EXISTS(SELECT 1 FROM vulns v2 WHERE v2.via_vuln_id = v.id))
            ORDER BY v.id""")
        if stale:
            lines = ["STALE VULNS (status=found but already produced downstream — close the loop):"]
            for v in stale:
                lines.append(f'  [update-vuln] id={v["id"]} status=actioned   '
                             f'# {v["ip"] or "?"} "{v["title"]}"')
            out.append("\n".join(lines))

        # 2. Credentials never tested against any target (no credential_access row).
        untested = _rows(conn, """
            SELECT c.id, c.username, c.secret_type, c.cracked, c.source
            FROM credentials c
            WHERE NOT EXISTS(SELECT 1 FROM credential_access ca WHERE ca.credential_id = c.id)
            ORDER BY c.id""")
        if untested:
            lines = ["UNTESTED CREDENTIALS (no credential_access row — route cred-sweep/spray):"]
            for c in untested:
                cracked = "cracked" if c["cracked"] else "uncracked"
                src = f' from "{c["source"]}"' if c["source"] else ""
                lines.append(f'  cred #{c["id"]} {c["username"]} '
                             f'({c["secret_type"]}, {cracked}){src}')
            out.append("\n".join(lines))

        # 3. Credentials from a named technique but with no via_vuln_id — the
        #    TECHNIQUE-VULN AUDIT. Operator-provided creds are excluded by the
        #    technique-hint filter.
        no_prov = _rows(conn, """
            SELECT c.id, c.username, c.source FROM credentials c
            WHERE c.via_vuln_id IS NULL AND c.source != ''
            ORDER BY c.id""")
        tech_gap = [c for c in no_prov
                    if any(h in (c["source"] or "").lower() for h in _TECHNIQUE_HINTS)]
        if tech_gap:
            lines = ["CREDS MISSING TECHNIQUE PROVENANCE (source names a technique but no via_vuln_id):"]
            for c in tech_gap:
                lines.append(f'  cred #{c["id"]} {c["username"]} from "{c["source"]}"'
                             f'  → add the technique as a vuln, then [update-cred] via_vuln_id')
            out.append("\n".join(lines))

        # 4. Orphan access — no provenance link at all (breaks the chain graph).
        orphan = _rows(conn, """
            SELECT a.id, a.username, a.method, t.ip FROM access a
            LEFT JOIN targets t ON t.id = a.target_id
            WHERE a.via_credential_id IS NULL AND a.via_access_id IS NULL
              AND a.via_vuln_id IS NULL
            ORDER BY a.id""")
        if orphan:
            lines = ["ORPHAN ACCESS (no via_* provenance — chain graph has a gap):"]
            for a in orphan:
                lines.append(f'  access #{a["id"]} {a["username"]}@{a["ip"] or "?"} '
                             f'via {a["method"] or "?"}  → set via_credential_id / via_vuln_id')
            out.append("\n".join(lines))

        # 5. Blocked items eligible for retry (retry=later/with_context).
        retryable = _rows(conn, """
            SELECT b.id, b.technique, b.retry, b.reason, t.ip FROM blocked b
            LEFT JOIN targets t ON t.id = b.target_id
            WHERE b.retry IN ('later', 'with_context')
            ORDER BY b.id""")
        if retryable:
            lines = ["RETRYABLE BLOCKS (re-route when context allows):"]
            for b in retryable:
                lines.append(f'  blocked #{b["id"]} {b["technique"]} @ {b["ip"] or "?"} '
                             f'(retry={b["retry"]}) — {b["reason"]}')
            out.append("\n".join(lines))

        # 6. Identified pivots nobody actioned.
        pivots = _rows(conn, """
            SELECT id, source, destination, method FROM pivot_map
            WHERE status = 'identified' ORDER BY id""")
        if pivots:
            lines = ["UNACTIONED PIVOTS (identified but not taken — route pivoting-tunneling):"]
            for p in pivots:
                lines.append(f'  pivot #{p["id"]} {p["source"]} → {p["destination"]} '
                             f'({p["method"] or "?"})')
            out.append("\n".join(lines))

        return out, counts
    except sqlite3.OperationalError as e:
        return ([f"(state.db not readable: {e})"], {})
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="State-hygiene audit for the orchestrator loop")
    ap.add_argument("--db", default=str(_DEFAULT_DB), help="Path to state.db")
    ap.add_argument("--quiet", action="store_true",
                    help="Print nothing when the state is coherent (exit 0 either way)")
    args = ap.parse_args()

    sections, counts = audit(Path(args.db))
    if sections and counts:
        report = "ATTENTION:\n" + "\n".join(sections)
    elif counts:
        report = (f'OK: state coherent — {counts.get("vulns", 0)} vulns, '
                  f'{counts.get("creds", 0)} creds, {counts.get("access", 0)} access, '
                  f'nothing stale')
    else:
        report = sections[0] if sections else "OK: nothing to audit"

    try:
        _DAEMON_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _DAEMON_LOG.open("a") as f:
            ts = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
            f.write(f"[{ts}] state_audit: {report.splitlines()[0]}\n")
    except OSError:
        pass

    if args.quiet and report.startswith("OK:"):
        return
    print(report)


if __name__ == "__main__":
    main()
