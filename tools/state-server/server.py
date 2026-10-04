"""MCP server for SQLite-backed engagement state management.

Single-mode server — all tools (read + write) are always available.
Every agent and the orchestrator connect to the same instance.

All write operations emit state_events rows for real-time monitoring
via poll_events(). Deduplication is built into add_vuln() and
add_credential() to handle concurrent writes from multiple agents.

The tools are grouped into focused modules, each exposing a
``register(mcp)`` function; this file wires them onto one FastMCP
instance. Shared helpers (DB connection, enum validation, event
emission) live in ``common.py``.

    common.py        — DB_PATH, _get_db, enum validation, _emit_event, ...
    reads.py         — read/query tools (get_*, poll_events, get_chain)
    engagement.py    — init/close lifecycle
    targets.py       — add/update target, add_port
    credentials.py   — add/update credential, test_credential
    access.py        — add/update access
    vulns.py         — add/update vuln
    pivots.py        — add/update pivot, add_blocked
    tunnels.py       — add/update tunnel

Usage:
    uv run python server.py
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import access
import credentials
import engagement
import pivots
import reads
import targets
import tunnels
import vulns


def create_server() -> FastMCP:
    """Create and configure the state MCP server."""
    mcp = FastMCP(
        "pen-agent-state",
        instructions=(
            "Provides engagement state management for PEN-AGENT. "
            "Full read/write access to engagement state. Use write tools "
            "to record targets, credentials, access, vulns, pivots, and "
            "blocked items. Use get_state_summary() for a compact overview."
        ),
    )

    # Each module registers its @mcp.tool() functions onto the shared server.
    reads.register(mcp)
    engagement.register(mcp)
    targets.register(mcp)
    credentials.register(mcp)
    access.register(mcp)
    vulns.register(mcp)
    pivots.register(mcp)
    tunnels.register(mcp)

    return mcp


def main() -> None:
    server = create_server()
    server.run()


if __name__ == "__main__":
    main()
