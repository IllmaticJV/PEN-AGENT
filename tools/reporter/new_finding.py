#!/usr/bin/env python3
"""Pre-populate engagement/findings/<id>.json from state.db for a vuln.

Why: every actioned vuln MUST produce an OffSec-style finding JSON per
CLAUDE.md § Finding Reports (enforced by export_report.py --strict).
Half the fields are mechanical — target, title, severity, affected
IPs, engagement name — and come straight from state.db. The teammate's
real job is `steps_to_reproduce` + `verification` + `impact`
narrative; everything else is boilerplate the LLM shouldn't be typing.

This script reads state.db for a given vuln_id and writes a skeleton
with:
- All mechanical fields filled in
- Placeholders marked `TODO:` for teammate-authored sections
- Correct enum values (verification.status=plausible by default so
  the schema passes even if the teammate forgets to flip to confirmed)
- `placeholders.ATTACKBOX` and the IP as a starting point
- A sensible `id` like RR-2026-007 using the vuln_id

Usage:
  python3 tools/reporter/new_finding.py <vuln_id>
                                        [--out engagement/findings/<N>.json]
                                        [--force]

Teammate workflow:
  1. Just actioned vuln N. Run `new_finding.py N`.
  2. Open the file, fill in steps_to_reproduce + verification + impact.
  3. Done — export_report.py --strict will accept it.
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
_STATE_DB = _PROJECT_ROOT / "engagement" / "state.db"
_FINDINGS_DIR = _PROJECT_ROOT / "engagement" / "findings"


# Map state.db vuln_type → finding classification hints. Loose; teammate
# refines. Covers the common cases the orchestrator routes to.
_VULN_TYPE_HINTS = {
    "ssrf": {"category": "server-side-request-forgery",
             "cwe": ["CWE-918"], "owasp_llm": [],
             "mitre_atlas": [], "ai300": []},
    "rce": {"category": "remote-code-execution",
            "cwe": ["CWE-77", "CWE-94"], "owasp_llm": [],
            "mitre_atlas": [], "ai300": []},
    "sqli": {"category": "sql-injection",
             "cwe": ["CWE-89"], "owasp_llm": [],
             "mitre_atlas": [], "ai300": []},
    "auth_bypass": {"category": "authentication-bypass",
                    "cwe": ["CWE-287", "CWE-306"], "owasp_llm": [],
                    "mitre_atlas": [], "ai300": []},
    "path_traversal": {"category": "path-traversal",
                       "cwe": ["CWE-22"], "owasp_llm": [],
                       "mitre_atlas": [], "ai300": []},
    "prompt_injection": {"category": "prompt-injection",
                         "cwe": ["CWE-77", "CWE-20"],
                         "owasp_llm": ["LLM01:2025 Prompt Injection"],
                         "mitre_atlas": ["AML.T0051 LLM Prompt Injection"],
                         "ai300": []},
    "info_disclosure": {"category": "information-disclosure",
                        "cwe": ["CWE-200"], "owasp_llm": [],
                        "mitre_atlas": [], "ai300": []},
    "credential_recovery": {"category": "credential-recovery",
                            "cwe": ["CWE-522"], "owasp_llm": [],
                            "mitre_atlas": [], "ai300": []},
    "ad_abuse": {"category": "ad-privilege-escalation",
                 "cwe": ["CWE-284", "CWE-269"], "owasp_llm": [],
                 "mitre_atlas": [], "ai300": []},
}


def _get_vuln(vuln_id: int) -> dict | None:
    if not _STATE_DB.exists():
        print(f"ERROR: {_STATE_DB} not found. Run init_engagement first.",
              file=sys.stderr)
        return None
    conn = sqlite3.connect(f"file:{_STATE_DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT v.*, t.ip AS target_ip, t.hostname AS target_hostname
            FROM vulns v LEFT JOIN targets t ON t.id = v.target_id
            WHERE v.id = ?
            """,
            (vuln_id,),
        ).fetchone()
        if row is None:
            return None
        v = dict(row)
        v["engagement_name"] = ""
        try:
            e = conn.execute("SELECT name FROM engagement LIMIT 1").fetchone()
            if e:
                v["engagement_name"] = e["name"] or ""
        except sqlite3.OperationalError:
            pass
        return v
    finally:
        conn.close()


def _derive_id(vuln_id: int) -> str:
    """RR-YYYY-NNN: matches the prompt-injection example's shape."""
    year = datetime.now().year
    return f"RR-{year}-{vuln_id:03d}"


def _skeleton(vuln: dict) -> dict:
    ip = vuln.get("target_ip") or "UNKNOWN"
    hostname = vuln.get("target_hostname") or ""
    title = vuln.get("title") or "Untitled vulnerability"
    severity = vuln.get("severity") or "medium"
    vuln_type = (vuln.get("vuln_type") or "").lower()
    hints = _VULN_TYPE_HINTS.get(vuln_type, {})
    discovered_by = vuln.get("discovered_by") or "unknown"

    affected_target = {"ip": ip}
    if hostname:
        affected_target["hostname"] = hostname

    return {
        "id": _derive_id(int(vuln["id"])),
        "state_vuln_id": int(vuln["id"]),
        "title": title,
        "severity": severity,
        "confidence": "medium",  # teammate flips to confirmed when verified
        "classification": {
            "category": hints.get("category", "TODO: pick category"),
            "cwe": hints.get("cwe", []),
            "owasp_llm": hints.get("owasp_llm", []),
            "mitre_atlas": hints.get("mitre_atlas", []),
            "ai300_module": hints.get("ai300", []),
        },
        "affected": {"targets": [affected_target]},
        "summary": vuln.get("details") or f"TODO: 1-2 sentence summary of {title}.",
        "impact": "TODO: concrete business impact — what can an attacker do with this?",
        "prerequisites": "TODO: what access / preconditions did you need?",
        "placeholders": {
            "ATTACKBOX": "TODO: operator's attack-box IP (e.g. 10.80.121.1)",
            "TARGET": ip,
        },
        "steps_to_reproduce": [
            {
                "step": 1,
                "instruction": "TODO: first command you actually ran.",
                "command": "TODO: copy-paste exact command",
                "expected_result": "TODO: what should happen",
                "actual_result": "TODO: what did happen",
                "evidence_ref": "engagement/evidence/TODO.txt",
            }
        ],
        "verification": {
            "status": "plausible",  # flip to confirmed when oracle fires
            "oracle_type": "model-judgement",
            "oracle": ("TODO: describe the OBJECTIVE proof — out-of-band "
                       "callback, exfiltrated canary, state change. "
                       "'model-judgement' alone cannot support 'confirmed'."),
            "verified_by": f"{discovered_by} teammate",
            "false_positive_checks": [
                "TODO: alternative explanations ruled out",
            ],
        },
        "remediation": {
            "short": "TODO: one-line fix recommendation.",
            "details": "TODO: longer remediation guidance.",
        },
        "references": [],
        "notes": f"Skeleton generated by new_finding.py from state.db vuln #{vuln['id']}; "
                 f"filled by {discovered_by}. Replace every TODO before export.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("vuln_id", type=int, help="state.db vulns.id")
    ap.add_argument("--out", default="",
                    help="output path (default engagement/findings/<vuln_id>.json)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing finding file")
    ap.add_argument("--stdout", action="store_true",
                    help="print to stdout instead of writing a file")
    args = ap.parse_args()

    vuln = _get_vuln(args.vuln_id)
    if vuln is None:
        print(f"ERROR: vuln_id {args.vuln_id} not found in state.db",
              file=sys.stderr)
        return 2

    doc = _skeleton(vuln)

    if args.stdout:
        print(json.dumps(doc, indent=2))
        return 0

    out_path = Path(args.out) if args.out else _FINDINGS_DIR / f"{args.vuln_id}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and not args.force:
        print(f"ERROR: {out_path} already exists. Pass --force to overwrite.",
              file=sys.stderr)
        return 1
    out_path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"Wrote {out_path}")
    print(f"id: {doc['id']}   target: {vuln.get('target_ip')}   "
          f"severity: {doc['severity']}   confidence: {doc['confidence']}")
    print("Fill in every TODO (steps_to_reproduce, verification oracle, "
          "impact, placeholders.ATTACKBOX) and update confidence/verification.status "
          "when the oracle fires.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
