"""State MCP server — target & port writes."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
)


def register(mcp) -> None:
    @mcp.tool()
    def add_target(
        ip: str,
        hostname: str = "",
        os: str = "",
        role: str = "",
        notes: str = "",
        discovered_by: str = "",
        ports: str = "",
    ) -> str:
        """Add or update a target host. Upserts on ip.

        Args:
            ip: IP address (primary identifier).
            hostname: Associated hostname (e.g., "DC01.corp.local").
                     Use when host is an IP and you discover a hostname.
            os: Operating system (e.g., "Ubuntu 22.04", "Windows Server 2019").
            role: Role (e.g., "DC", "Web", "DB").
            notes: Additional notes.
            discovered_by: Skill that discovered this target.
            ports: JSON array of port objects, each with: port (int),
                   protocol (str, default "tcp"), state (str, default "open"),
                   service (str), banner (str).
                   Example: [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]
        """
        with _get_db() as conn:
            existing = conn.execute(
                "SELECT id FROM targets WHERE ip = ?", (ip,)
            ).fetchone()

            if existing:
                target_id = existing["id"]
                updates = []
                params: list = []
                if hostname:
                    updates.append("hostname = ?")
                    params.append(hostname)
                if os:
                    updates.append("os = ?")
                    params.append(os)
                if role:
                    updates.append("role = ?")
                    params.append(role)
                if notes:
                    updates.append("notes = ?")
                    params.append(notes)
                if discovered_by:
                    updates.append("discovered_by = ?")
                    params.append(discovered_by)
                if updates:
                    updates.append(f"updated_at = {_now_sql()}")
                    params.append(target_id)
                    conn.execute(
                        f"UPDATE targets SET {', '.join(updates)} WHERE id = ?",
                        params,
                    )
            else:
                cursor = conn.execute(
                    "INSERT INTO targets (ip, hostname, os, role, notes, discovered_by) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (ip, hostname, os, role, notes, discovered_by),
                )
                target_id = cursor.lastrowid

            # Process ports if provided
            if ports:
                port_list = json.loads(ports) if isinstance(ports, str) else ports
                for p in port_list:
                    port_num = p["port"]
                    protocol = p.get("protocol", "tcp")
                    state = p.get("state", "open")
                    service = p.get("service", "")
                    banner = p.get("banner", "")
                    conn.execute(
                        "INSERT INTO ports (target_id, port, protocol, state, service, banner) "
                        "VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(target_id, port, protocol) DO UPDATE SET "
                        "state = excluded.state, "
                        "service = CASE WHEN excluded.service != '' THEN excluded.service ELSE ports.service END, "
                        "banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE ports.banner END",
                        (target_id, port_num, protocol, state, service, banner),
                    )

            action = "updated" if existing else "created"
            _emit_event(conn, "target", target_id, f"{ip} ({action})", discovered_by)
            conn.commit()
            return json.dumps(
                {
                    "target_id": target_id,
                    "ip": ip,
                    "action": action,
                },
                indent=2,
            )

    @mcp.tool()
    def update_target(
        ip: str,
        hostname: str = "",
        os: str = "",
        role: str = "",
        notes: str = "",
    ) -> str:
        """Update fields on an existing target.

        Args:
            ip: Target IP to update (must exist). Use the IP or
               hostname that was used when the target was added.
            hostname: Associated hostname (e.g., "DC01.corp.local").
            os: New OS value (empty = no change).
            role: New role value (empty = no change).
            notes: New notes value (empty = no change).
        """
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, ip)
            if target_id is None:
                return f"ERROR: Target '{ip}' not found."

            updates = []
            params: list = []
            if hostname:
                updates.append("hostname = ?")
                params.append(hostname)
            if os:
                updates.append("os = ?")
                params.append(os)
            if role:
                updates.append("role = ?")
                params.append(role)
            if notes:
                updates.append("notes = ?")
                params.append(notes)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(target_id)
            conn.execute(
                f"UPDATE targets SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            conn.commit()
            return json.dumps({"target_id": target_id, "ip": ip, "updated": True})

    @mcp.tool()
    def add_port(
        ip: str,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service: str = "",
        banner: str = "",
    ) -> str:
        """Add a port to an existing target. Upserts on (target, port, protocol).

        Args:
            ip: Target IP (must exist).
            port: Port number.
            protocol: Protocol (default "tcp").
            state: Port state (default "open").
            service: Service name (e.g., "http", "ssh").
            banner: Service banner/version string.
        """
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, ip)
            if target_id is None:
                return f"ERROR: Target '{ip}' not found. Add the target first."

            conn.execute(
                "INSERT INTO ports (target_id, port, protocol, state, service, banner) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(target_id, port, protocol) DO UPDATE SET "
                "state = excluded.state, "
                "service = CASE WHEN excluded.service != '' THEN excluded.service ELSE ports.service END, "
                "banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE ports.banner END",
                (target_id, port, protocol, state, service, banner),
            )
            conn.commit()
            return json.dumps(
                {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                }
            )

