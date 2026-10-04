"""State MCP server — access writes."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
    _restore_vulns_for_access,
)


def register(mcp) -> None:
    @mcp.tool()
    def add_access(
        ip: str,
        access_type: str = "shell",
        username: str = "",
        privilege: str = "user",
        method: str = "",
        session_ref: str = "",
        via_credential_id: int | None = None,
        via_access_id: int | None = None,
        via_vuln_id: int | None = None,
        technique_id: str = "",
        chain_order: int = 0,
        discovered_by: str = "",
        notes: str = "",
    ) -> str:
        """Record a new foothold/access on a target.

        Args:
            ip: Target IP (must exist in targets table).
            access_type: Type of access: shell, ssh, winrm, rdp, web_shell, smb,
                        db, token, vpn, other.
            username: User/account that has access.
            privilege: Privilege level: user, admin, root, system, service,
                      domain_admin, other.
            method: How access was gained (e.g., "XXE -> webshell -> rev shell").
            session_ref: Reference to shell-server session ID if applicable.
            via_credential_id: Credential ID used to gain this access
                              (for chain provenance). None = no credential used.
            via_access_id: Access ID this was escalated from (for privesc
                          chains on the same host). None = initial access.
            via_vuln_id: Vuln ID that was actioned to gain this access
                        (for chain provenance). None = no specific vuln.
            technique_id: ATT&CK technique ID (e.g., "T1021.006" for WinRM).
                         Empty = fill in later during reporting.
            chain_order: Flow graph level (0 = auto-order from provenance).
            discovered_by: Skill that gained access.
            notes: Additional notes.
        """
        err = _validate_enum("access_type", access_type, "access_type")
        if err:
            return err
        err = _validate_enum("privilege", privilege, "privilege")
        if err:
            return err
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, ip)
            if target_id is None:
                return f"ERROR: Target '{ip}' not found."

            cursor = conn.execute(
                "INSERT INTO access "
                "(target_id, access_type, username, privilege, method, "
                "session_ref, via_credential_id, via_access_id, via_vuln_id, "
                "technique_id, chain_order, discovered_by, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target_id,
                    access_type,
                    username,
                    privilege,
                    method,
                    session_ref,
                    via_credential_id,
                    via_access_id,
                    via_vuln_id,
                    technique_id,
                    chain_order,
                    discovered_by,
                    notes,
                ),
            )
            access_id = cursor.lastrowid
            _emit_event(
                conn,
                "access",
                access_id,
                f"{username}@{ip} [{privilege}] via {access_type}",
                discovered_by,
            )
            conn.commit()
            return json.dumps(
                {
                    "access_id": access_id,
                    "ip": ip,
                    "access_type": access_type,
                    "privilege": privilege,
                },
                indent=2,
            )

    @mcp.tool()
    def update_access(
        id: int,
        active: bool | None = None,
        username: str = "",
        access_type: str = "",
        privilege: str = "",
        notes: str = "",
        via_credential_id: int | None = None,
        via_access_id: int | None = None,
        via_vuln_id: int | None = None,
        technique_id: str = "",
        in_graph: int | None = None,
        chain_order: int | None = None,
    ) -> str:
        """Update access record (e.g., revoke, fix provenance, toggle graph).

        When access is revoked (active=false), sibling vulns that were pruned
        from the flow graph when this access's actioned vulns succeeded are
        restored — making alternative paths visible again.

        Args:
            id: Access record ID.
            active: Set to false to mark access as revoked.
            username: Fix username post-creation.
            access_type: Fix access type post-creation (shell, rdp, ssh, smb, etc.).
            privilege: Updated privilege level.
            notes: Additional notes.
            via_credential_id: Fix credential provenance post-creation.
            via_access_id: Fix access chain provenance post-creation.
            via_vuln_id: Fix vuln provenance post-creation.
            technique_id: Set ATT&CK technique ID.
            in_graph: Override graph visibility (1=show, 0=hide).
            chain_order: Explicit column position in the flow graph (1-based,
                        left-to-right). 0 = auto-compute via BFS.
        """
        with _get_db() as conn:
            updates = []
            params: list = []
            if active is not None:
                updates.append("active = ?")
                params.append(1 if active else 0)
            if username:
                updates.append("username = ?")
                params.append(username)
            if access_type:
                updates.append("access_type = ?")
                params.append(access_type)
            if privilege:
                updates.append("privilege = ?")
                params.append(privilege)
            if notes:
                updates.append("notes = ?")
                params.append(notes)
            if via_credential_id is not None:
                updates.append("via_credential_id = ?")
                params.append(via_credential_id)
            if via_access_id is not None:
                updates.append("via_access_id = ?")
                params.append(via_access_id)
            if via_vuln_id is not None:
                updates.append("via_vuln_id = ?")
                params.append(via_vuln_id)
            if technique_id:
                updates.append("technique_id = ?")
                params.append(technique_id)
            if in_graph is not None:
                updates.append("in_graph = ?")
                params.append(in_graph)
            if chain_order is not None:
                updates.append("chain_order = ?")
                params.append(chain_order)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(id)
            conn.execute(
                f"UPDATE access SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "access_update", id, f"access #{id} updated")

            # When access is revoked, restore sibling vulns that were pruned
            # when actioned vulns from this access succeeded
            restored = 0
            if active is False:
                restored = _restore_vulns_for_access(conn, id)

            conn.commit()
            result: dict = {"access_id": id, "updated": True}
            if restored:
                result["siblings_restored"] = restored
            return json.dumps(result)

