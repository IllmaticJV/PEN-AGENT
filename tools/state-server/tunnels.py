"""State MCP server — tunnel writes."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
)


def register(mcp) -> None:
    @mcp.tool()
    def add_tunnel(
        tunnel_type: str = "other",
        pivot_host: str = "",
        target_subnet: str = "",
        local_endpoint: str = "",
        remote_endpoint: str = "",
        requires_proxychains: bool = False,
        notes: str = "",
        created_by: str = "",
    ) -> str:
        """Record an established tunnel.

        Args:
            tunnel_type: Tunnel type: ssh_local, ssh_dynamic, ssh_remote,
                        ssh_tun, sshuttle, ligolo, chisel, socat, other.
            pivot_host: Host being pivoted through.
            target_subnet: Target subnet reachable via tunnel (e.g., "172.16.0.0/24").
            local_endpoint: Local endpoint (e.g., "socks5://127.0.0.1:1080",
                           "ligolo0 TUN", "127.0.0.1:8080").
            remote_endpoint: Remote endpoint on/through the pivot.
            requires_proxychains: True if tools need proxychains (SOCKS-based),
                                 false for transparent tunnels (sshuttle, ligolo, ssh_tun).
            notes: Additional notes.
            created_by: Skill/agent that created this tunnel.
        """
        with _get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO tunnels "
                "(tunnel_type, pivot_host, target_subnet, local_endpoint, "
                "remote_endpoint, requires_proxychains, notes, created_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tunnel_type,
                    pivot_host,
                    target_subnet,
                    local_endpoint,
                    remote_endpoint,
                    1 if requires_proxychains else 0,
                    notes,
                    created_by,
                ),
            )
            tunnel_id = cursor.lastrowid
            proxy_note = "proxychains" if requires_proxychains else "transparent"
            summary = f"{tunnel_type} via {pivot_host} → {target_subnet} ({proxy_note})"
            _emit_event(conn, "tunnel", tunnel_id, summary, created_by)
            conn.commit()
            return json.dumps(
                {
                    "tunnel_id": tunnel_id,
                    "tunnel_type": tunnel_type,
                    "pivot_host": pivot_host,
                    "target_subnet": target_subnet,
                    "requires_proxychains": requires_proxychains,
                },
                indent=2,
            )

    @mcp.tool()
    def update_tunnel(
        id: int,
        status: str = "",
        notes: str = "",
    ) -> str:
        """Update a tunnel (e.g., mark as down or closed).

        Args:
            id: Tunnel ID.
            status: Updated status (active/down/closed).
            notes: Updated notes.
        """
        if status:
            err = _validate_enum("status", status, "tunnel_status")
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

            updates.append(f"updated_at = {_now_sql()}")
            params.append(id)
            conn.execute(
                f"UPDATE tunnels SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "tunnel_update", id, f"tunnel #{id} -> {status}")
            conn.commit()
            return json.dumps({"tunnel_id": id, "updated": True})

