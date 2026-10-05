"""State MCP server — objective tracker.

Objectives are the numbered list under OBJECTIVES: in engagement/scope.md
(the lab's success criteria). We parse them at engagement start and track
per-objective status (pending | in_progress | done | blocked | skipped)
in engagement/objectives.json so the lead can mark progress and the
operator portal can render a tracker.

objectives.json schema:
    {
      "objectives": [
        {"id": 1, "text": "...", "status": "pending",
         "note": "", "updated_at": "<iso>"},
        ...
      ],
      "parsed_at": "<iso>"
    }

The text field is the SOURCE OF TRUTH re-parsed from scope.md on every
init_objectives call (so if the operator fixes a typo in scope.md the
tracker picks it up). Status and note persist across re-parses when the
objective count matches; a change in count resets state (treated as a
scope change — operator should re-review).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import common

# Make the shared parser importable regardless of cwd.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "tools" / "objectives"))
import parse_scope  # noqa: E402


_VALID_STATUS = ("pending", "in_progress", "done", "blocked", "skipped")


def _paths() -> tuple[Path, Path]:
    engagement_dir = common.DB_PATH.parent
    return engagement_dir / "scope.md", engagement_dir / "objectives.json"


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def _load() -> dict:
    _, obj_path = _paths()
    if not obj_path.exists():
        return {"objectives": [], "parsed_at": None}
    try:
        data = json.loads(obj_path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {"objectives": [], "parsed_at": None}
    if not isinstance(data, dict) or not isinstance(data.get("objectives"), list):
        return {"objectives": [], "parsed_at": None}
    return data


def _save(data: dict) -> None:
    _, obj_path = _paths()
    obj_path.parent.mkdir(parents=True, exist_ok=True)
    obj_path.write_text(json.dumps(data, indent=2) + "\n")


def register(mcp) -> None:

    @mcp.tool()
    def init_objectives() -> str:
        """Parse OBJECTIVES: from engagement/scope.md and seed objectives.json.

        Safe to call multiple times. If the objective COUNT matches what's
        already in objectives.json, existing status/note are preserved and
        only the text is refreshed from scope.md. If the count changes,
        state is reset to pending (scope change — re-review).

        Call this at engagement start after scope.md is written. Returns
        the current list.
        """
        scope_md, _ = _paths()
        parsed = parse_scope.parse_file(scope_md)
        existing = _load()
        existing_objs = existing.get("objectives") or []
        now = _now()
        if parsed and existing_objs and len(parsed) == len(existing_objs):
            # Preserve state; refresh text only.
            merged = []
            for new, old in zip(parsed, existing_objs):
                merged.append({
                    "id": new["id"],
                    "text": new["text"],
                    "status": old.get("status", "pending"),
                    "note": old.get("note", ""),
                    "updated_at": old.get("updated_at", now),
                })
            data = {"objectives": merged, "parsed_at": now}
        else:
            data = {
                "objectives": [
                    {"id": o["id"], "text": o["text"], "status": "pending",
                     "note": "", "updated_at": now}
                    for o in parsed
                ],
                "parsed_at": now,
            }
        _save(data)
        return json.dumps({
            "status": "initialized",
            "count": len(data["objectives"]),
            "objectives": data["objectives"],
        })

    @mcp.tool()
    def list_objectives() -> str:
        """Return the objectives.json contents (ids, text, status, note)."""
        return json.dumps(_load())

    @mcp.tool()
    def update_objective(objective_id: int = 0, status: str = "",
                         note: str = "") -> str:
        """Mark progress on an objective.

        Args:
            objective_id: 1-based id from list_objectives. Required.
            status: pending | in_progress | done | blocked | skipped. Required.
            note: optional operator-visible note (why blocked / what's done /
                  the finding_id proving completion). Appended to history-ish
                  by overwriting the current note; keep concise.
        """
        if objective_id <= 0:
            return json.dumps({"error": "objective_id (>=1) is required."})
        if status not in _VALID_STATUS:
            return json.dumps({
                "error": f"status must be one of {_VALID_STATUS}, got '{status}'.",
            })
        data = _load()
        for obj in data.get("objectives", []):
            if int(obj.get("id", 0)) == int(objective_id):
                obj["status"] = status
                if note:
                    obj["note"] = note
                obj["updated_at"] = _now()
                _save(data)
                return json.dumps({"status": "updated", "objective": obj})
        return json.dumps({"error": f"objective_id {objective_id} not found."})
