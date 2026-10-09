"""Objective tracker read + operator-driven toggle (engagement/objectives.json)."""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timezone

from dash.config import OBJECTIVES_JSON, PROJECT_ROOT, SCOPE_MD

VALID_STATUS = ("pending", "in_progress", "done", "blocked", "skipped")
_WRITE_LOCK = threading.Lock()


def build() -> dict:
    """Return objectives.json merged with a live re-parse of scope.md so the
    portal can show NEW objectives the operator just added before the lead
    has re-run init_objectives. Status/note come from objectives.json;
    anything only in scope.md shows up as status=pending with a flag."""
    _parser_dir = PROJECT_ROOT / "tools" / "objectives"
    if str(_parser_dir) not in sys.path:
        sys.path.insert(0, str(_parser_dir))
    try:
        import parse_scope  # type: ignore
    except Exception:
        parse_scope = None

    stored = {"objectives": [], "parsed_at": None}
    try:
        if OBJECTIVES_JSON.exists():
            data = json.loads(OBJECTIVES_JSON.read_text(errors="replace"))
            if isinstance(data, dict) and isinstance(data.get("objectives"), list):
                stored = data
    except (OSError, json.JSONDecodeError):
        pass

    live = []
    if parse_scope is not None and SCOPE_MD.exists():
        try:
            live = parse_scope.parse_file(SCOPE_MD)
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


def update_from_portal(objective_id: int, status: str,
                       note: str | None = None) -> dict:
    """Operator-driven objective toggle. Writes engagement/objectives.json
    with the same schema the state-server MCP uses so the lead's live view
    stays coherent.

    Serialised through a module-level lock to avoid portal threads racing
    each other; the lead's MCP writes are a separate process and lose
    races by last-write-wins (acceptable for a one-operator tracker).
    Atomic on-disk: writes to a sibling .tmp and renames into place.
    """
    if status not in VALID_STATUS:
        return {"error": f"status must be one of {VALID_STATUS}"}
    with _WRITE_LOCK:
        data: dict = {"objectives": [], "parsed_at": None}
        if OBJECTIVES_JSON.exists():
            try:
                parsed = json.loads(OBJECTIVES_JSON.read_text(errors="replace"))
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
            tmp = OBJECTIVES_JSON.with_suffix(OBJECTIVES_JSON.suffix + ".tmp")
            tmp.write_text(json.dumps(data, indent=2) + "\n")
            tmp.replace(OBJECTIVES_JSON)
        except OSError as e:
            return {"error": f"save failed: {e}"}
        return {"status": "updated", "objective": found}
