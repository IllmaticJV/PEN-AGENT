"""Live activity feed — state_events rendered newest-first with a category tag.

state_events is the engagement's timeline (every target/vuln/credential/access/
pivot/blocked write emits one). This presents it as a chronological feed; the
category drives the icon/colour in the UI. Updates (event_type ending in
`_update`) are tagged so the feed can de-emphasise them against first
discoveries.
"""

from __future__ import annotations

from pathlib import Path

from dash import state


def _categorize(event_type: str) -> str:
    t = (event_type or "").lower()
    if "vuln" in t:
        return "vuln"
    if "cred" in t:
        return "credential"
    if "access" in t:
        return "access"
    if "pivot" in t or "tunnel" in t:
        return "pivot"
    if "block" in t:
        return "blocked"
    if "target" in t or "port" in t:
        return "recon"
    return "other"


def build(db_path: Path, limit: int = 250) -> dict:
    conn = state.get_db(db_path)
    if conn is None:
        return {"available": False, "reason": "state.db not found yet.", "events": []}
    try:
        rows = state.rows(
            conn, "SELECT * FROM state_events ORDER BY id DESC LIMIT ?", (limit,)
        )
    except Exception:
        rows = []
    finally:
        conn.close()
    for e in rows:
        et = e.get("event_type", "")
        e["category"] = _categorize(et)
        e["is_update"] = et.endswith("_update")
    return {"available": True, "events": rows, "count": len(rows)}
