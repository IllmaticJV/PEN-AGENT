"""Objective & scope (file-based: scope.md + scope.allow + engagement row)."""

from __future__ import annotations

import sqlite3

from dash import state
from dash.config import DEFAULT_DB, SCOPE_ALLOW, SCOPE_MD


def build() -> dict:
    scope_md = ""
    try:
        if SCOPE_MD.exists():
            scope_md = SCOPE_MD.read_text(errors="replace")
    except OSError:
        pass
    allow = []
    try:
        if SCOPE_ALLOW.exists():
            for line in SCOPE_ALLOW.read_text(errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    allow.append(line)
    except OSError:
        pass
    engagement = None
    conn = state.get_db(DEFAULT_DB)
    if conn is not None:
        try:
            eng = state.rows(conn, "SELECT * FROM engagement LIMIT 1")
            engagement = eng[0] if eng else None
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
    return {"scope_md": scope_md, "scope_allow": allow, "engagement": engagement}
