"""State MCP server — pivot & blocked-technique writes."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
)


def register(mcp) -> None:
    @mcp.tool()
    def add_pivot(
        source: str,
        destination: str,
        method: str = "",
        status: str = "identified",
        discovered_by: str = "",
        notes: str = "",
    ) -> str:
        """Add a pivot path (what leads where).

        Args:
            source: Source (e.g., "SQLi on 10.10.10.5:/search").
            destination: Destination (e.g., "DB creds for 10.10.10.1:mssql").
            method: How the pivot works.
            status: Status: identified, actioned, blocked.
            discovered_by: Skill that identified this path.
            notes: Additional notes.
        """
        err = _validate_enum("status", status, "pivot_status")
        if err:
            return err
        with _get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO pivot_map "
                "(source, destination, method, status, discovered_by, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (source, destination, method, status, discovered_by, notes),
            )
            pivot_id = cursor.lastrowid
            _emit_event(
                conn,
                "pivot",
                pivot_id,
                f"{source} -> {destination}",
                discovered_by,
            )
            conn.commit()
            return json.dumps(
                {
                    "pivot_id": pivot_id,
                    "source": source,
                    "destination": destination,
                    "status": status,
                },
                indent=2,
            )

    @mcp.tool()
    def update_pivot(
        id: int,
        status: str = "",
        notes: str = "",
    ) -> str:
        """Update a pivot path status.

        Args:
            id: Pivot ID.
            status: Updated status (identified/actioned/blocked).
            notes: Updated notes.
        """
        if status:
            err = _validate_enum("status", status, "pivot_status")
            if err:
                return err
        with _get_db() as conn:
            updates = []
            params: list = []
            if status:
                updates.append("status = ?")
                params.append(status)
            if notes:
                updates.append("notes = ?")
                params.append(notes)

            if not updates:
                return "No fields to update."

            params.append(id)
            conn.execute(
                f"UPDATE pivot_map SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "pivot_update", id, f"pivot #{id} -> {status}")
            conn.commit()
            return json.dumps({"pivot_id": id, "updated": True})

    @mcp.tool()
    def add_blocked(
        technique: str,
        reason: str,
        ip: str = "",
        retry: str = "no",
        notes: str = "",
        blocked_by: str = "",
    ) -> str:
        """Record a blocked/failed technique attempt.

        Args:
            technique: Technique that was attempted (e.g., "kerberoasting").
            reason: Why it failed.
            ip: Target IP (empty = not host-specific).
            retry: Retry assessment: no, later, with_context.
            notes: Additional notes.
            blocked_by: Skill that was blocked.
        """
        err = _validate_enum("retry", retry, "retry")
        if err:
            return err
        with _get_db() as conn:
            target_id = None
            if ip:
                target_id = _resolve_target_id(conn, ip)
                if target_id is None:
                    return f"ERROR: Target '{ip}' not found. Add the target first."

            cursor = conn.execute(
                "INSERT INTO blocked "
                "(target_id, technique, reason, retry, notes, blocked_by) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (target_id, technique, reason, retry, notes, blocked_by),
            )
            blocked_id = cursor.lastrowid
            summary = technique
            if ip:
                summary += f" on {ip}"
            summary += f" | {reason} [{retry}]"
            _emit_event(conn, "blocked", blocked_id, summary, blocked_by)
            conn.commit()
            return json.dumps(
                {
                    "blocked_id": blocked_id,
                    "technique": technique,
                    "retry": retry,
                },
                indent=2,
            )

