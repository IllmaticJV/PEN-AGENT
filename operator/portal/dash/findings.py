"""Confirmed findings — one OffSec-style JSON per vuln under engagement/findings/.

Read-only. The schema is owned by tools/reporter/finding.schema.json; the
portal just surfaces whatever is on disk, sorted by severity, for a
collapsible overview. Malformed files are skipped rather than failing the tab.
"""

from __future__ import annotations

import json

from dash.config import FINDINGS_DIR

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build() -> dict:
    if not FINDINGS_DIR.exists():
        return {"available": False,
                "reason": "No engagement/findings directory yet.",
                "findings": [], "counts": {}, "total": 0, "confirmed": 0}
    files = sorted(FINDINGS_DIR.glob("*.json"))
    findings = []
    for p in files:
        try:
            f = json.loads(p.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(f, dict):
            continue
        f["_file"] = p.name
        findings.append(f)
    if not findings:
        return {"available": False,
                "reason": "No findings written yet — teammates export one per "
                          "confirmed vuln to engagement/findings/.",
                "findings": [], "counts": {}, "total": 0, "confirmed": 0}

    findings.sort(key=lambda f: (
        _SEV_ORDER.get(str(f.get("severity", "")).lower(), 5),
        str(f.get("id", "")),
    ))
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        s = str(f.get("severity", "")).lower()
        if s in counts:
            counts[s] += 1
    confirmed = sum(
        1 for f in findings
        if isinstance(f.get("verification"), dict)
        and f["verification"].get("status") == "confirmed"
    )
    return {
        "available": True,
        "findings": findings,
        "counts": counts,
        "total": len(findings),
        "confirmed": confirmed,
    }
