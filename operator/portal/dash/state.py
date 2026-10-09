"""state.db readers (read-only)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

EMPTY_STATE = {
    "engagement": None, "targets": [], "credentials": [], "access": [],
    "vulns": [], "pivot_map": [], "tunnels": [], "blocked": [], "events": [],
}


def get_db(db_path: Path) -> sqlite3.Connection | None:
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def rows(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def build_state(db_path: Path) -> dict:
    conn = get_db(db_path)
    if conn is None:
        return EMPTY_STATE
    try:
        eng = rows(conn, "SELECT * FROM engagement LIMIT 1")
        engagement = eng[0] if eng else None
        targets = rows(conn, "SELECT * FROM targets ORDER BY id")
        for t in targets:
            t["ports"] = rows(
                conn, "SELECT * FROM ports WHERE target_id = ? ORDER BY port", (t["id"],)
            )
        credentials = rows(conn, "SELECT * FROM credentials ORDER BY id")
        for c in credentials:
            c["tested_against"] = rows(
                conn,
                "SELECT ca.*, t.ip FROM credential_access ca "
                "JOIN targets t ON t.id = ca.target_id WHERE ca.credential_id = ?",
                (c["id"],),
            )
        access = rows(
            conn,
            "SELECT a.*, t.ip FROM access a JOIN targets t ON t.id = a.target_id ORDER BY a.id",
        )
        vulns = rows(
            conn,
            "SELECT v.*, t.ip FROM vulns v LEFT JOIN targets t ON t.id = v.target_id "
            "ORDER BY CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, v.id",
        )
        pivot_map = rows(conn, "SELECT * FROM pivot_map ORDER BY id")
        tunnels = rows(conn, "SELECT * FROM tunnels ORDER BY id")
        blocked = rows(
            conn,
            "SELECT b.*, t.ip FROM blocked b LEFT JOIN targets t ON t.id = b.target_id ORDER BY b.id",
        )
        events = rows(conn, "SELECT * FROM state_events ORDER BY id DESC LIMIT 100")
        return {
            "engagement": engagement, "targets": targets, "credentials": credentials,
            "access": access, "vulns": vulns, "pivot_map": pivot_map,
            "tunnels": tunnels, "blocked": blocked, "events": events,
        }
    except sqlite3.OperationalError:
        return EMPTY_STATE
    finally:
        conn.close()


def get_events_since(db_path: Path, since: int) -> list[dict]:
    conn = get_db(db_path)
    if conn is None:
        return []
    try:
        return rows(conn, "SELECT * FROM state_events WHERE id > ? ORDER BY id", (since,))
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
