"""Shared helpers for the state MCP server.

DB connection, enum validation, event emission, and row helpers used by every
tool module. DB_PATH lives here as the single source of truth; _get_db() reads
it at call time, so tests patch common.DB_PATH to point at a temp database.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

# ---------------------------------------------------------------------------
# Enum validation — catch bad values before they hit SQLite CHECK constraints
# ---------------------------------------------------------------------------
_VALID_ENUMS: dict[str, tuple[str, ...]] = {
    "secret_type": (
        "password",
        "ntlm_hash",
        "net_ntlm",
        "aes_key",
        "kerberos_tgt",
        "kerberos_tgs",
        "dcc2",
        "ssh_key",
        "token",
        "certificate",
        "webapp_hash",
        "dpapi",
        "other",
    ),
    "access_type": (
        "shell",
        "ssh",
        "winrm",
        "rdp",
        "web_shell",
        "smb",
        "db",
        "token",
        "vpn",
        "c2",
        "other",
    ),
    "privilege": (
        "user",
        "admin",
        "root",
        "system",
        "service",
        "domain_admin",
        "other",
    ),
    "vuln_status": ("found", "actioned", "blocked"),
    "severity": ("info", "low", "medium", "high", "critical"),
    "pivot_status": ("identified", "actioned", "blocked"),
    "retry": ("no", "later", "with_context"),
    "tunnel_status": ("active", "down", "closed"),
}


def _validate_enum(field: str, value: str, enum_key: str) -> str | None:
    """Return an ERROR string if value is not in the allowed set, else None."""
    valid = _VALID_ENUMS[enum_key]
    if value not in valid:
        return f"ERROR: Invalid {field}={value!r}. Valid values: {', '.join(valid)}"
    return None


# Resolve engagement directory relative to the project root, not the server's
# own directory.  uv run --directory changes cwd to tools/state-server/, so
# bare Path("engagement/...") would land artifacts inside the tools tree.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = _PROJECT_ROOT / "engagement" / "state.db"


@contextmanager
def _get_db():
    """Open connection to the state database with guaranteed cleanup."""
    if not DB_PATH.exists():
        raise FileNotFoundError(
            "No engagement state database found. "
            "The orchestrator must call init_engagement() first."
        )
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        yield conn
    finally:
        conn.close()


def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    """Convert sqlite3.Row objects to plain dicts for JSON serialization."""
    return [dict(row) for row in rows]


def _resolve_target_id(conn: sqlite3.Connection, ip: str) -> int | None:
    """Look up target_id by ip or hostname. Returns None if not found."""
    row = conn.execute(
        "SELECT id FROM targets WHERE ip = ? OR hostname = ?", (ip, ip)
    ).fetchone()
    return row["id"] if row else None


def _now_sql() -> str:
    """SQLite expression for current UTC timestamp."""
    return "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"


def _emit_event(
    conn: sqlite3.Connection,
    event_type: str,
    record_id: int,
    summary: str,
    agent: str = "",
) -> None:
    """Insert a state_events row inside the current transaction.

    Called by all write tools so agents and the orchestrator can poll for
    real-time findings via poll_events().  Silently skips if the table
    doesn't exist (older DBs without the v2 schema).
    """
    try:
        conn.execute(
            "INSERT INTO state_events (event_type, record_id, summary, agent) "
            "VALUES (?, ?, ?, ?)",
            (event_type, record_id, summary, agent),
        )
    except sqlite3.OperationalError:
        pass  # table doesn't exist in older DBs — skip silently


# ---------------------------------------------------------------------------
# Attack-graph coherence — prune/restore sibling vulns so the flow graph only
# shows the path actually taken.  Shared by vulns.py (vuln status changes) and
# access.py (access revocation).
# ---------------------------------------------------------------------------
def _prune_sibling_vulns(conn: sqlite3.Connection, actioned_vuln_id: int) -> int:
    """Set in_graph=0 on sibling 'found' vulns sharing the same via_access_id.

    When a vuln is actioned, the alternative findings from the same access
    point are noise in the flow graph. Prune them so only the actioned path
    is visible. Returns count of pruned vulns.
    """
    row = conn.execute(
        "SELECT via_access_id, target_id FROM vulns WHERE id = ?",
        (actioned_vuln_id,),
    ).fetchone()
    if not row or not row["via_access_id"]:
        return 0
    cursor = conn.execute(
        f"UPDATE vulns SET in_graph = 0, updated_at = {_now_sql()} "
        "WHERE via_access_id = ? AND target_id = ? AND id != ? "
        "AND status = 'found' AND in_graph = 1",
        (row["via_access_id"], row["target_id"], actioned_vuln_id),
    )
    count = cursor.rowcount
    if count:
        _emit_event(
            conn,
            "vuln_prune",
            actioned_vuln_id,
            f"Pruned {count} sibling vuln(s) (vuln #{actioned_vuln_id} actioned)",
        )
    return count


def _restore_sibling_vulns(conn: sqlite3.Connection, vuln_id: int) -> int:
    """Restore in_graph=1 on sibling vulns when an actioned path fails.

    Called when a vuln is blocked or its parent access is revoked. Only
    restores if no other actioned vuln exists from the same access point.
    Returns count of restored vulns.
    """
    row = conn.execute(
        "SELECT via_access_id, target_id FROM vulns WHERE id = ?",
        (vuln_id,),
    ).fetchone()
    if not row or not row["via_access_id"]:
        return 0
    # Only restore if no other actioned vuln exists from same access
    other = conn.execute(
        "SELECT id FROM vulns WHERE via_access_id = ? AND target_id = ? "
        "AND id != ? AND status = 'actioned'",
        (row["via_access_id"], row["target_id"], vuln_id),
    ).fetchone()
    if other:
        return 0
    cursor = conn.execute(
        f"UPDATE vulns SET in_graph = 1, updated_at = {_now_sql()} "
        "WHERE via_access_id = ? AND target_id = ? "
        "AND status = 'found' AND in_graph = 0",
        (row["via_access_id"], row["target_id"]),
    )
    count = cursor.rowcount
    if count:
        _emit_event(
            conn,
            "vuln_restore",
            vuln_id,
            f"Restored {count} sibling vuln(s) (vuln #{vuln_id} path abandoned)",
        )
    return count


def _restore_vulns_for_access(conn: sqlite3.Connection, access_id: int) -> int:
    """Restore sibling vulns for all actioned vulns under a revoked access."""
    rows = conn.execute(
        "SELECT id FROM vulns WHERE via_access_id = ? AND status = 'actioned'",
        (access_id,),
    ).fetchall()
    total = 0
    for row in rows:
        total += _restore_sibling_vulns(conn, row["id"])
    return total

