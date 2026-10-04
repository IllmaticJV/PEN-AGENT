"""State MCP server — vulnerability writes."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
    _prune_sibling_vulns, _restore_sibling_vulns,
)


def register(mcp) -> None:
    @mcp.tool()
    def add_vuln(
        title: str,
        ip: str,
        vuln_type: str = "",
        status: str = "found",
        severity: str = "medium",
        details: str = "",
        evidence_path: str = "",
        via_access_id: int | None = None,
        via_credential_id: int | None = None,
        via_vuln_id: int | None = None,
        technique_id: str = "",
        chain_order: int = 0,
        discovered_by: str = "",
    ) -> str:
        """Add a confirmed vulnerability.

        Deduplicates on (target_id, title). If a vuln with the same title
        already exists for the same target, returns the existing record
        instead of creating a duplicate.

        Args:
            title: Short vulnerability title (e.g., "SQLi in /search parameter").
            ip: Target IP (required — must match an existing target).
            vuln_type: Vulnerability class (e.g., "sqli", "xss", "rce").
            status: Status: found, actioned, blocked.
            severity: Severity: info, low, medium, high, critical.
            details: Technical details.
            evidence_path: Path to evidence file in engagement/evidence/.
            via_access_id: Access ID that led to finding this vuln
                          (for chain provenance). None = unauthenticated/recon.
            via_credential_id: Credential ID that led to finding this vuln
                              (e.g., password reuse discovered by spraying a
                              cracked credential). None = not credential-sourced.
            via_vuln_id: Parent vuln ID for vuln-to-vuln provenance (e.g.,
                        "NTLM coercion found via LFI"). None = not vuln-sourced.
            technique_id: ATT&CK technique ID (e.g., "T1190" for exploit
                         public-facing app). Empty = unknown.
            discovered_by: Skill that found this vulnerability.
        """
        err = _validate_enum("status", status, "vuln_status")
        if err:
            return err
        err = _validate_enum("severity", severity, "severity")
        if err:
            return err
        with _get_db() as conn:
            if not ip:
                return "ERROR: ip is required. Every vuln must be associated with a target."
            target_id = _resolve_target_id(conn, ip)
            if target_id is None:
                return f"ERROR: Target '{ip}' not found. Add the target first."

            # Dedup: exact title match on same target — hard block
            existing = conn.execute(
                "SELECT id, status, severity, title FROM vulns "
                "WHERE target_id = ? AND title = ?",
                (target_id, title),
            ).fetchone()

            if existing:
                return json.dumps(
                    {
                        "vuln_id": existing["id"],
                        "status": "duplicate_skipped",
                        "existing_status": existing["status"],
                        "existing_severity": existing["severity"],
                        "existing_title": existing["title"],
                        "submitted_title": title,
                    },
                    indent=2,
                )

            # Soft dedup: same vuln_type on same target — insert but warn.
            # Two SQLi on different endpoints are legitimate; two LFI with
            # different wording are probably the same. The server can't
            # judge, so it inserts and flags for the orchestrator to review.
            type_match = None
            if vuln_type:
                type_match = conn.execute(
                    "SELECT id, title FROM vulns WHERE target_id = ? AND vuln_type = ?",
                    (target_id, vuln_type),
                ).fetchone()

            cursor = conn.execute(
                "INSERT INTO vulns "
                "(target_id, title, vuln_type, status, severity, "
                "details, evidence_path, via_access_id, via_credential_id, "
                "via_vuln_id, technique_id, chain_order, discovered_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target_id,
                    title,
                    vuln_type,
                    status,
                    severity,
                    details,
                    evidence_path,
                    via_access_id,
                    via_credential_id,
                    via_vuln_id,
                    technique_id,
                    chain_order,
                    discovered_by,
                ),
            )
            vuln_id = cursor.lastrowid
            summary = f"{title} [{severity}]"
            if ip:
                summary += f" on {ip}"
            _emit_event(conn, "vuln", vuln_id, summary, discovered_by)
            conn.commit()
            result = {
                "vuln_id": vuln_id,
                "title": title,
                "severity": severity,
                "status": status,
            }
            if type_match:
                result["warning"] = "possible_duplicate"
                result["existing_vuln_id"] = type_match["id"]
                result["existing_title"] = type_match["title"]
            return json.dumps(
                result,
                indent=2,
            )

    @mcp.tool()
    def update_vuln(
        id: int,
        status: str = "",
        severity: str = "",
        details: str = "",
        in_graph: int | None = None,
        via_access_id: int | None = None,
        via_credential_id: int | None = None,
        via_vuln_id: int | None = None,
        technique_id: str = "",
        chain_order: int | None = None,
    ) -> str:
        """Update vulnerability (e.g., change status, fix provenance, toggle graph).

        When status changes to 'actioned', sibling 'found' vulns from the
        same access point are automatically hidden from the flow graph
        (in_graph=0). When status changes to 'blocked', hidden siblings are
        restored if no other actioned path exists.

        Args:
            id: Vulnerability ID.
            status: Updated status (found/actioned/blocked).
            severity: Updated severity.
            details: Updated details.
            in_graph: Override graph visibility (1=show, 0=hide). Normally
                     managed automatically by the prune/restore logic.
            via_access_id: Fix access provenance post-creation.
            via_credential_id: Fix credential provenance post-creation.
            via_vuln_id: Set parent vuln for vuln-to-vuln provenance.
            technique_id: Set ATT&CK technique ID.
            chain_order: Explicit column position in the flow graph (1-based,
                        left-to-right). 0 = auto-compute via BFS.
        """
        if status:
            err = _validate_enum("status", status, "vuln_status")
            if err:
                return err
        if severity:
            err = _validate_enum("severity", severity, "severity")
            if err:
                return err
        with _get_db() as conn:
            updates = []
            params: list = []
            if status:
                updates.append("status = ?")
                params.append(status)
            if severity:
                updates.append("severity = ?")
                params.append(severity)
            if details:
                updates.append("details = ?")
                params.append(details)
            if in_graph is not None:
                updates.append("in_graph = ?")
                params.append(in_graph)
            if via_access_id is not None:
                updates.append("via_access_id = ?")
                params.append(via_access_id)
            if via_credential_id is not None:
                updates.append("via_credential_id = ?")
                params.append(via_credential_id)
            if via_vuln_id is not None:
                updates.append("via_vuln_id = ?")
                params.append(via_vuln_id)
            if technique_id:
                updates.append("technique_id = ?")
                params.append(technique_id)
            if chain_order is not None:
                updates.append("chain_order = ?")
                params.append(chain_order)

            if not updates:
                return "No fields to update."

            updates.append(f"updated_at = {_now_sql()}")
            params.append(id)
            conn.execute(
                f"UPDATE vulns SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            summary = f"vuln #{id}"
            if status:
                summary += f" -> {status}"
            _emit_event(conn, "vuln_update", id, summary)

            # Auto-prune/restore sibling vulns based on status transition
            pruned = 0
            restored = 0
            if status == "actioned":
                pruned = _prune_sibling_vulns(conn, id)
            elif status == "blocked":
                restored = _restore_sibling_vulns(conn, id)

            conn.commit()
            result: dict = {"vuln_id": id, "updated": True}
            if pruned:
                result["siblings_pruned"] = pruned
            if restored:
                result["siblings_restored"] = restored
            return json.dumps(result)

