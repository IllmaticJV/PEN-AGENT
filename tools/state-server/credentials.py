"""State MCP server — credential writes."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
)


def register(mcp) -> None:
    @mcp.tool()
    def add_credential(
        username: str = "",
        secret: str = "",
        secret_type: str = "password",
        domain: str = "",
        source: str = "",
        via_access_id: int | None = None,
        via_vuln_id: int | None = None,
        chain_order: int = 0,
        discovered_by: str = "",
    ) -> str:
        """Add a credential (password, hash, key, token, etc.).

        Deduplicates on (username, secret_type, secret). Returns existing
        record if duplicate found.

        Args:
            username: Username or account name.
            secret: The credential value (password, hash, key, token).
            secret_type: Type of secret: password, ntlm_hash, net_ntlm,
                        aes_key, kerberos_tgt, kerberos_tgs, dcc2,
                        ssh_key, token, certificate, webapp_hash,
                        dpapi, other.
            domain: Domain (for AD credentials).
            source: Where this credential was found.
            via_access_id: Access ID that led to finding this credential
                          (for chain provenance). None = provided/external.
            via_vuln_id: Vuln ID that led to capturing this credential
                        (e.g., LFI coercion → hash capture). None if not
                        from a vuln.
            chain_order: Flow graph level (0 = auto-order from provenance).
            discovered_by: Skill that found this credential.
        """
        err = _validate_enum("secret_type", secret_type, "secret_type")
        if err:
            return err
        with _get_db() as conn:
            if not secret:
                return "ERROR: secret is required. Use targets.notes for username-only lists."

            existing = conn.execute(
                "SELECT id FROM credentials "
                "WHERE LOWER(username) = LOWER(?) AND secret_type = ? "
                "AND LOWER(secret) = LOWER(?)",
                (username, secret_type, secret),
            ).fetchone()
            if existing:
                return json.dumps(
                    {
                        "credential_id": existing["id"],
                        "status": "duplicate_skipped",
                        "username": username,
                        "secret_type": secret_type,
                        "domain": domain,
                    },
                    indent=2,
                )
            cursor = conn.execute(
                "INSERT INTO credentials "
                "(username, secret, secret_type, domain, source, via_access_id, "
                "via_vuln_id, chain_order, discovered_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    username,
                    secret,
                    secret_type,
                    domain,
                    source,
                    via_access_id,
                    via_vuln_id,
                    chain_order,
                    discovered_by,
                ),
            )
            cred_id = cursor.lastrowid
            summary = (
                f"{domain}\\{username} ({secret_type})"
                if domain
                else f"{username} ({secret_type})"
            )
            _emit_event(conn, "credential", cred_id, summary, discovered_by)
            conn.commit()
            return json.dumps(
                {
                    "credential_id": cred_id,
                    "username": username,
                    "secret_type": secret_type,
                    "domain": domain,
                },
                indent=2,
            )

    @mcp.tool()
    def update_credential(
        id: int,
        cracked: bool | None = None,
        secret: str = "",
        notes: str = "",
        via_access_id: int | None = None,
        via_vuln_id: int | None = None,
        in_graph: int | None = None,
        chain_order: int | None = None,
    ) -> str:
        """Update a credential (e.g., mark as cracked, add provenance).

        Args:
            id: Credential ID.
            cracked: Set to true when the hash has been cracked.
            secret: Updated secret value (e.g., cracked plaintext).
            notes: Additional notes.
            via_access_id: Link credential to the access that discovered it
                          (settable post-creation for provenance fixes).
            via_vuln_id: Link credential to the vuln that produced it
                        (settable post-creation for provenance fixes).
            in_graph: Override graph visibility (1=show, 0=hide). Use to
                     suppress hash rows when a cracked plaintext exists.
            chain_order: Explicit column position in the flow graph (1-based,
                        left-to-right). 0 = auto-compute via BFS.
        """
        with _get_db() as conn:
            updates = []
            params: list = []
            if cracked is not None:
                updates.append("cracked = ?")
                params.append(1 if cracked else 0)
            if secret:
                updates.append("secret = ?")
                params.append(secret)
            if notes:
                updates.append("notes = ?")
                params.append(notes)
            if via_access_id is not None:
                updates.append("via_access_id = ?")
                params.append(via_access_id)
            if via_vuln_id is not None:
                updates.append("via_vuln_id = ?")
                params.append(via_vuln_id)
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
                f"UPDATE credentials SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            _emit_event(conn, "credential_update", id, f"credential #{id} updated")
            conn.commit()
            return json.dumps({"credential_id": id, "updated": True})

    @mcp.tool()
    def test_credential(
        credential_id: int,
        ip: str,
        service: str,
        works: bool,
        tested_by: str = "",
    ) -> str:
        """Record whether a credential works against a target/service.

        Upserts on (credential_id, target_id, service).

        Args:
            credential_id: ID of the credential to test.
            ip: Target IP (must exist in targets table).
            service: Service tested (e.g., "smb", "ssh", "rdp", "winrm", "web").
            works: Whether the credential authenticated successfully.
            tested_by: Skill that performed the test.
        """
        with _get_db() as conn:
            target_id = _resolve_target_id(conn, ip)
            if target_id is None:
                return f"ERROR: Target '{ip}' not found."

            conn.execute(
                "INSERT INTO credential_access "
                "(credential_id, target_id, service, works, tested_by) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(credential_id, target_id, service) DO UPDATE SET "
                "works = excluded.works, "
                "tested_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), "
                "tested_by = excluded.tested_by",
                (credential_id, target_id, service, 1 if works else 0, tested_by),
            )
            result_str = "works" if works else "fails"
            _emit_event(
                conn,
                "credential_test",
                credential_id,
                f"cred #{credential_id} {result_str} on {ip}:{service}",
                tested_by,
            )
            conn.commit()
            return json.dumps(
                {
                    "credential_id": credential_id,
                    "ip": ip,
                    "service": service,
                    "works": works,
                }
            )

