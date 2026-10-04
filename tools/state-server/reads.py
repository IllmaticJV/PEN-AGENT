"""State MCP server — read/query tools."""

from __future__ import annotations

import json
import sqlite3  # noqa: F401 — used by some tool bodies
from common import (  # noqa: F401 — re-exported helpers used across tools
    DB_PATH, _get_db, _validate_enum, _emit_event,
    _resolve_target_id, _rows_to_dicts, _now_sql, _VALID_ENUMS,
)


def register(mcp) -> None:
    @mcp.tool()
    def get_state_summary(max_lines: int = 200) -> str:
        """Get compact markdown summary of engagement state.

        Returns the same format as the old state.md — a compact snapshot
        of targets, credentials, access, vulns, pivot map, and blocked items.
        Capped at max_lines to prevent context bloat.

        Args:
            max_lines: Maximum lines in the summary (default 200).
        """
        try:
            db = _get_db()
        except FileNotFoundError:
            return "No engagement state database found. Run init_engagement() first."

        with db as conn:
            sections: list[str] = ["# Engagement State\n"]

            # Engagement metadata
            eng = conn.execute(
                "SELECT name, status, created_at, mode FROM engagement WHERE id = 1"
            ).fetchone()
            if eng:
                sections.append(
                    f"**Mode: {eng['mode']}** | Status: {eng['status']} | Created: {eng['created_at']}\n"
                )

            # Targets
            sections.append("## Targets\n")
            targets = conn.execute(
                "SELECT t.id, t.ip, t.hostname, t.os, t.role FROM targets t ORDER BY t.id"
            ).fetchall()
            for t in targets:
                ports = conn.execute(
                    "SELECT port, protocol, service FROM ports "
                    "WHERE target_id = ? ORDER BY port",
                    (t["id"],),
                ).fetchall()
                port_str = ",".join(
                    f"{p['port']}/{p['protocol']}"
                    if p["protocol"] != "tcp"
                    else str(p["port"])
                    for p in ports
                )
                svc_str = ",".join(p["service"] for p in ports if p["service"])
                host_display = t["ip"]
                if t["hostname"]:
                    host_display += f" ({t['hostname']})"
                parts = [host_display]
                if t["os"]:
                    parts.append(t["os"])
                if t["role"]:
                    parts.append(t["role"])
                if port_str:
                    parts.append(port_str)
                if svc_str:
                    parts.append(f"({svc_str})")
                sections.append(f"- {' | '.join(parts)}")
            if not targets:
                sections.append("_(none)_")
            sections.append("")

            # Credentials — skip uncracked capture hashes (net_ntlm, kerberos_tgs,
            # dcc2, webapp_hash) to keep summary compact. They're still in the DB
            # and visible via get_credentials(). Show them once cracked.
            sections.append("## Credentials\n")
            creds = conn.execute(
                "SELECT id, username, secret, secret_type, domain, cracked, notes "
                "FROM credentials "
                "WHERE cracked = 1 "
                "   OR secret_type NOT IN ('net_ntlm', 'kerberos_tgs', 'dcc2', 'webapp_hash') "
                "ORDER BY id"
            ).fetchall()
            for c in creds:
                display_secret = c["secret"]
                if c["secret_type"] not in ("password",) and len(display_secret) > 32:
                    display_secret = display_secret[:32] + "..."
                parts = []
                if c["domain"]:
                    parts.append(f"{c['domain']}\\{c['username']}")
                else:
                    parts.append(c["username"])
                parts.append(f"{display_secret} ({c['secret_type']})")
                if c["cracked"]:
                    parts.append("[cracked]")
                # Show where it works
                access_rows = conn.execute(
                    "SELECT t.ip, ca.service, ca.works FROM credential_access ca "
                    "JOIN targets t ON ca.target_id = t.id "
                    "WHERE ca.credential_id = ?",
                    (c["id"],),
                ).fetchall()
                works_on = [
                    f"{r['ip']}:{r['service']}" for r in access_rows if r["works"]
                ]
                fails_on = [
                    f"{r['ip']}:{r['service']}" for r in access_rows if not r["works"]
                ]
                if works_on:
                    parts.append(f"works: {', '.join(works_on)}")
                if fails_on:
                    parts.append(f"fails: {', '.join(fails_on)}")
                if c["notes"]:
                    parts.append(c["notes"])
                sections.append(f"- {' | '.join(parts)}")
            if not creds:
                sections.append("_(none)_")
            # Note hidden uncracked hashes
            hidden = conn.execute(
                "SELECT COUNT(*) as cnt FROM credentials "
                "WHERE cracked = 0 AND secret_type IN ('net_ntlm', 'kerberos_tgs', 'dcc2', 'webapp_hash')"
            ).fetchone()["cnt"]
            if hidden:
                sections.append(
                    f"_({hidden} uncracked hash(es) hidden — use get_credentials() to view)_"
                )
            sections.append("")

            # Access
            sections.append("## Access\n")
            accesses = conn.execute(
                "SELECT a.*, t.ip FROM access a "
                "JOIN targets t ON a.target_id = t.id "
                "WHERE a.active = 1 ORDER BY a.id"
            ).fetchall()
            for a in accesses:
                parts = [
                    a["ip"],
                    f"{a['username']} via {a['access_type']}",
                    f"[{a['privilege']}]",
                ]
                if a["method"]:
                    parts.append(f"from {a['method']}")
                if a["session_ref"]:
                    parts.append(f"session:{a['session_ref']}")
                if a["notes"]:
                    parts.append(a["notes"])
                sections.append(f"- {' | '.join(parts)}")
            # Also show revoked access
            revoked = conn.execute(
                "SELECT a.*, t.ip FROM access a "
                "JOIN targets t ON a.target_id = t.id "
                "WHERE a.active = 0 ORDER BY a.id"
            ).fetchall()
            for a in revoked:
                sections.append(
                    f"- ~~{a['ip']} | {a['username']} via {a['access_type']}~~ [revoked]"
                )
            if not accesses and not revoked:
                sections.append("_(none)_")
            sections.append("")

            # Vulns
            sections.append("## Vulns\n")
            vulns = conn.execute(
                "SELECT v.*, t.ip FROM vulns v "
                "LEFT JOIN targets t ON v.target_id = t.id "
                "ORDER BY v.id"
            ).fetchall()
            for v in vulns:
                host = v["ip"] or "unknown"
                parts = [
                    f"{v['title']} [{v['status']}]",
                    f"[{v['severity']}]",
                    host,
                ]
                if v["details"]:
                    parts.append(v["details"][:80])
                sections.append(f"- {' | '.join(parts)}")
            if not vulns:
                sections.append("_(none)_")
            sections.append("")

            # Pivot Map
            sections.append("## Pivot Map\n")
            pivots = conn.execute("SELECT * FROM pivot_map ORDER BY id").fetchall()
            for p in pivots:
                parts = [
                    f"{p['source']} -> {p['destination']}",
                    f"via {p['method']}" if p["method"] else "",
                    f"[{p['status']}]",
                ]
                if p["notes"]:
                    parts.append(p["notes"])
                sections.append(f"- {' | '.join(pt for pt in parts if pt)}")
            if not pivots:
                sections.append("_(none)_")
            sections.append("")

            # Tunnels
            sections.append("## Tunnels\n")
            if conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='tunnels'"
            ).fetchone():
                tunnels = conn.execute(
                    "SELECT * FROM tunnels WHERE status != 'closed' ORDER BY id"
                ).fetchall()
                for tun in tunnels:
                    proxy_note = (
                        "(proxychains required)"
                        if tun["requires_proxychains"]
                        else "(transparent)"
                    )
                    parts = [
                        tun["tunnel_type"],
                        f"via {tun['pivot_host']}" if tun["pivot_host"] else "",
                        f"→ {tun['target_subnet']}" if tun["target_subnet"] else "→ *",
                    ]
                    if tun["local_endpoint"]:
                        parts.append(tun["local_endpoint"])
                    parts.append(f"[{tun['status']}]")
                    parts.append(proxy_note)
                    if tun["notes"]:
                        parts.append(tun["notes"])
                    sections.append(f"- {' | '.join(pt for pt in parts if pt)}")
                if not tunnels:
                    sections.append("_(none)_")
            else:
                sections.append("_(none)_")
            sections.append("")

            # Blocked
            sections.append("## Blocked\n")
            blocked = conn.execute(
                "SELECT b.*, t.ip FROM blocked b "
                "LEFT JOIN targets t ON b.target_id = t.id "
                "ORDER BY b.id"
            ).fetchall()
            for b in blocked:
                host = b["ip"] or ""
                parts = [b["technique"]]
                if host:
                    parts.append(host)
                parts.append(b["reason"])
                parts.append(f"[{b['retry']}]")
                if b["notes"]:
                    parts.append(b["notes"])
                sections.append(f"- {' | '.join(parts)}")
            if not blocked:
                sections.append("_(none)_")

            result = "\n".join(sections)
            lines = result.split("\n")
            if len(lines) > max_lines:
                lines = lines[:max_lines]
                lines.append(f"\n_(truncated at {max_lines} lines)_")
            return "\n".join(lines)

    @mcp.tool()
    def get_targets(ip: str = "") -> str:
        """Get targets with their ports and services.

        Args:
            ip: Filter by IP (empty = all targets).
        """
        with _get_db() as conn:
            if ip:
                targets = conn.execute(
                    "SELECT * FROM targets WHERE ip = ?", (ip,)
                ).fetchall()
            else:
                targets = conn.execute("SELECT * FROM targets ORDER BY id").fetchall()

            result = []
            for t in targets:
                t_dict = dict(t)
                ports = conn.execute(
                    "SELECT port, protocol, state, service, banner FROM ports "
                    "WHERE target_id = ? ORDER BY port",
                    (t["id"],),
                ).fetchall()
                t_dict["ports"] = _rows_to_dicts(ports)
                result.append(t_dict)

            return json.dumps(result, indent=2)

    @mcp.tool()
    def get_credentials(untested_only: bool = False) -> str:
        """Get credentials with tested-against information.

        Args:
            untested_only: If true, only return credentials that haven't been
                          tested against all known target/service combinations.
        """
        with _get_db() as conn:
            creds = conn.execute("SELECT * FROM credentials ORDER BY id").fetchall()

            result = []
            for c in creds:
                c_dict = dict(c)
                access_rows = conn.execute(
                    "SELECT ca.*, t.ip FROM credential_access ca "
                    "JOIN targets t ON ca.target_id = t.id "
                    "WHERE ca.credential_id = ?",
                    (c["id"],),
                ).fetchall()
                c_dict["tested_against"] = _rows_to_dicts(access_rows)

                if untested_only:
                    # Count total target/service combos vs tested
                    tested_count = len(access_rows)
                    total_targets = conn.execute(
                        "SELECT COUNT(*) as cnt FROM targets"
                    ).fetchone()["cnt"]
                    if tested_count >= total_targets and total_targets > 0:
                        continue

                result.append(c_dict)

            return json.dumps(result, indent=2)

    @mcp.tool()
    def get_access(target: str = "", active_only: bool = True) -> str:
        """Get current footholds/access.

        Args:
            target: Filter by target host (empty = all).
            active_only: Only return active sessions (default true).
        """
        with _get_db() as conn:
            query = (
                "SELECT a.*, t.ip FROM access a JOIN targets t ON a.target_id = t.id"
            )
            conditions = []
            params: list = []

            if target:
                conditions.append("t.ip = ?")
                params.append(target)
            if active_only:
                conditions.append("a.active = 1")

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY a.id"

            rows = conn.execute(query, params).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_vulns(status: str = "", target: str = "") -> str:
        """Get vulnerabilities.

        Args:
            status: Filter by status (found/actioned/blocked, empty = all).
            target: Filter by target host (empty = all).
        """
        with _get_db() as conn:
            query = "SELECT v.*, t.ip FROM vulns v LEFT JOIN targets t ON v.target_id = t.id"
            conditions = []
            params: list = []

            if status:
                conditions.append("v.status = ?")
                params.append(status)
            if target:
                conditions.append("t.ip = ?")
                params.append(target)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY v.id"

            rows = conn.execute(query, params).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_pivot_map(status: str = "") -> str:
        """Get pivot map edges.

        Args:
            status: Filter by status (identified/actioned/blocked, empty = all).
        """
        with _get_db() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM pivot_map WHERE status = ? ORDER BY id",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM pivot_map ORDER BY id").fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_blocked(target: str = "") -> str:
        """Get blocked techniques.

        Args:
            target: Filter by target host (empty = all).
        """
        with _get_db() as conn:
            if target:
                rows = conn.execute(
                    "SELECT b.*, t.ip FROM blocked b "
                    "LEFT JOIN targets t ON b.target_id = t.id "
                    "WHERE t.ip = ? ORDER BY b.id",
                    (target,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT b.*, t.ip FROM blocked b "
                    "LEFT JOIN targets t ON b.target_id = t.id "
                    "ORDER BY b.id"
                ).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_tunnels(status: str = "", pivot_host: str = "") -> str:
        """Get active tunnels.

        Args:
            status: Filter by status (active/down/closed, empty = all).
            pivot_host: Filter by pivot host (empty = all).
        """
        with _get_db() as conn:
            # Backward compat: check table exists
            if not conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='tunnels'"
            ).fetchone():
                return json.dumps([])

            query = "SELECT * FROM tunnels"
            conditions = []
            params: list = []

            if status:
                conditions.append("status = ?")
                params.append(status)
            if pivot_host:
                conditions.append("pivot_host = ?")
                params.append(pivot_host)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY id"

            rows = conn.execute(query, params).fetchall()
            return json.dumps(_rows_to_dicts(rows), indent=2)

    @mcp.tool()
    def get_chain() -> str:
        """Walk provenance links to build the access chain.

        Reconstructs how initial credentials led to access sessions,
        which yielded new credentials, which unlocked further access.
        Returns an ordered list of chain steps plus any orphaned records
        that have no provenance links.
        """
        with _get_db() as conn:
            creds = {
                r["id"]: dict(r)
                for r in conn.execute(
                    "SELECT c.id, c.username, c.secret_type, c.domain, "
                    "c.via_access_id, c.source FROM credentials c"
                ).fetchall()
            }
            accesses = {
                r["id"]: dict(r)
                for r in conn.execute(
                    "SELECT a.id, a.username, a.access_type, a.privilege, "
                    "a.method, a.via_credential_id, a.via_access_id, "
                    "a.via_vuln_id, a.active, "
                    "t.ip FROM access a JOIN targets t ON a.target_id = t.id"
                ).fetchall()
            }
            vulns = [
                dict(r)
                for r in conn.execute(
                    "SELECT v.id, v.title, v.vuln_type, v.status, v.severity, "
                    "v.via_access_id, v.via_credential_id, v.via_vuln_id, "
                    "t.ip FROM vulns v "
                    "LEFT JOIN targets t ON v.target_id = t.id"
                ).fetchall()
            ]

            # BFS from roots
            steps: list[dict] = []
            visited_creds: set[int] = set()
            visited_access: set[int] = set()
            step_num = 0

            def add_cred(cid: int, depth: int, via_type: str = "", via_id: int = 0):
                nonlocal step_num
                if cid in visited_creds:
                    return
                visited_creds.add(cid)
                c = creds[cid]
                step_num += 1
                label = (
                    c["domain"] + "\\" + c["username"] if c["domain"] else c["username"]
                )
                label += f" ({c['secret_type']})"
                steps.append(
                    {
                        "step": step_num,
                        "type": "credential",
                        "id": cid,
                        "label": label,
                        "depth": depth,
                        **(
                            {"via": {"type": via_type, "id": via_id}}
                            if via_type
                            else {}
                        ),
                    }
                )
                # Follow: access records that used this credential
                for a in accesses.values():
                    if a.get("via_credential_id") == cid:
                        add_access(a["id"], depth + 1, "credential", cid)

            visited_vulns: set[int] = set()
            vulns_by_id = {v["id"]: v for v in vulns}

            def add_vuln(vid: int, depth: int, via_type: str = "", via_id: int = 0):
                nonlocal step_num
                if vid in visited_vulns:
                    return
                visited_vulns.add(vid)
                v = vulns_by_id[vid]
                step_num += 1
                steps.append(
                    {
                        "step": step_num,
                        "type": "vuln",
                        "id": vid,
                        "label": f"{v['title']} [{v['severity']}]",
                        "depth": depth,
                        "status": v["status"],
                        **(
                            {"via": {"type": via_type, "id": via_id}}
                            if via_type
                            else {}
                        ),
                    }
                )
                # Follow: access gained by actioning this vuln
                for a in accesses.values():
                    if a.get("via_vuln_id") == vid:
                        add_access(a["id"], depth + 1, "vuln", vid)
                # Follow: credentials captured via this vuln
                for c in creds.values():
                    if c.get("via_vuln_id") == vid:
                        add_cred(c["id"], depth + 1, "vuln", vid)
                # Follow: vuln-to-vuln chains (e.g., SSRF → RCE escalation)
                for v2 in vulns:
                    if v2.get("via_vuln_id") == vid and v2["id"] not in visited_vulns:
                        add_vuln(v2["id"], depth + 1, "vuln", vid)

            def add_access(aid: int, depth: int, via_type: str = "", via_id: int = 0):
                nonlocal step_num
                if aid in visited_access:
                    return
                visited_access.add(aid)
                a = accesses[aid]
                step_num += 1
                label = (
                    f"{a['username']}@{a['ip']} [{a['privilege']}] {a['access_type']}"
                )
                steps.append(
                    {
                        "step": step_num,
                        "type": "access",
                        "id": aid,
                        "label": label,
                        "depth": depth,
                        "active": bool(a.get("active")),
                        **(
                            {"via": {"type": via_type, "id": via_id}}
                            if via_type
                            else {}
                        ),
                    }
                )
                # Follow: credentials found via this access
                for c in creds.values():
                    if c.get("via_access_id") == aid:
                        add_cred(c["id"], depth + 1, "access", aid)
                # Follow: access escalations from this access (privesc chains)
                for a2 in accesses.values():
                    if a2.get("via_access_id") == aid:
                        add_access(a2["id"], depth + 1, "access", aid)
                # Follow: vulns found via this access
                for v in vulns:
                    if v.get("via_access_id") == aid and v["id"] not in visited_vulns:
                        add_vuln(v["id"], depth + 1, "access", aid)

            # Root credentials: no via_access_id and no via_vuln_id (provided/initial)
            for cid, c in creds.items():
                if not c.get("via_access_id") and not c.get("via_vuln_id"):
                    add_cred(cid, 0)

            # Root accesses: no via_credential_id, no via_access_id, no via_vuln_id
            for aid, a in accesses.items():
                if (
                    not a.get("via_credential_id")
                    and not a.get("via_access_id")
                    and not a.get("via_vuln_id")
                ):
                    add_access(aid, 0)

            # Root vulns: no via_access_id and no via_vuln_id (unauthenticated/
            # recon-discovered) that have downstream links
            for vid, v in vulns_by_id.items():
                if (
                    vid not in visited_vulns
                    and not v.get("via_access_id")
                    and not v.get("via_vuln_id")
                ):
                    # Only add as root if it has downstream links
                    has_downstream = (
                        any(a.get("via_vuln_id") == vid for a in accesses.values())
                        or any(c.get("via_vuln_id") == vid for c in creds.values())
                        or any(v2.get("via_vuln_id") == vid for v2 in vulns)
                    )
                    if has_downstream:
                        add_vuln(vid, 0)

            # Orphans: records not reached by BFS
            orphan_creds = [
                {
                    "type": "credential",
                    "id": cid,
                    "label": f"{c['username']} ({c['secret_type']})",
                }
                for cid, c in creds.items()
                if cid not in visited_creds
            ]
            orphan_access = [
                {"type": "access", "id": aid, "label": f"{a['username']}@{a['ip']}"}
                for aid, a in accesses.items()
                if aid not in visited_access
            ]
            orphan_vulns = [
                {"type": "vuln", "id": vid, "label": f"{v['title']} [{v['severity']}]"}
                for vid, v in vulns_by_id.items()
                if vid not in visited_vulns
            ]

            return json.dumps(
                {
                    "chain": steps,
                    "orphans": orphan_creds + orphan_access + orphan_vulns,
                },
                indent=2,
            )

    @mcp.tool()
    def poll_events(since_id: int = 0, limit: int = 50) -> str:
        """Poll for state events since a checkpoint.

        Returns new events written by agents plus a cursor for the next call.
        Use this for real-time monitoring of findings as they happen — call
        repeatedly with the returned cursor.

        Args:
            since_id: Last event ID seen (0 = from the beginning).
            limit: Maximum events to return (default 50).
        """
        try:
            db = _get_db()
        except FileNotFoundError:
            return json.dumps({"events": [], "cursor": 0, "count": 0})

        with db as conn:
            # Backward compat: check table exists (older DBs without v2 schema)
            if not conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='state_events'"
            ).fetchone():
                return json.dumps({"events": [], "cursor": 0, "count": 0})

            rows = conn.execute(
                "SELECT * FROM state_events WHERE id > ? ORDER BY id LIMIT ?",
                (since_id, limit),
            ).fetchall()
            events = _rows_to_dicts(rows)
            cursor = events[-1]["id"] if events else since_id
            return json.dumps(
                {"events": events, "cursor": cursor, "count": len(events)},
                indent=2,
            )

    # ------------------------------------------------------------------
    # Write tools
    # ------------------------------------------------------------------

