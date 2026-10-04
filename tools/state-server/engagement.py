"""State MCP server — engagement lifecycle (init/close)."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
)
import common  # for common.DB_PATH (patched in tests)
from schema import init_db


def register(mcp) -> None:
    @mcp.tool()
    def init_engagement(name: str = "", mode: str = "ctf") -> str:
        """Initialize the engagement state database.

        Creates engagement/state.db with the full schema. Safe to call
        multiple times — uses CREATE TABLE IF NOT EXISTS.

        Args:
            name: Optional engagement name.
            mode: Engagement mode — 'ctf' (default) or 'pentest'.
        """
        if mode not in ("ctf", "pentest"):
            return json.dumps(
                {"error": f"Invalid mode '{mode}'. Must be 'ctf' or 'pentest'."}
            )
        common.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = init_db(common.DB_PATH)
        try:
            # Insert singleton engagement row if not exists
            existing = conn.execute("SELECT id FROM engagement WHERE id = 1").fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO engagement (id, name, mode) VALUES (1, ?, ?)",
                    (name, mode),
                )
            else:
                updates = ["mode = ?"]
                params: list[str] = [mode]
                if name:
                    updates.append("name = ?")
                    params.append(name)
                conn.execute(
                    f"UPDATE engagement SET {', '.join(updates)} WHERE id = 1",
                    params,
                )
            conn.commit()
        finally:
            conn.close()
        return json.dumps(
            {
                "status": "initialized",
                "db_path": str(common.DB_PATH),
                "name": name,
                "mode": mode,
            },
            indent=2,
        )

    @mcp.tool()
    def close_engagement() -> str:
        """Mark the engagement as closed."""
        with _get_db() as conn:
            conn.execute(
                f"UPDATE engagement SET status = 'closed', "
                f"closed_at = {_now_sql()} WHERE id = 1"
            )
            conn.commit()
            return json.dumps({"status": "closed"})

