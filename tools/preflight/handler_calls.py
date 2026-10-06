#!/usr/bin/env python3
"""Emit the MCP start_handler calls for every entry in index.json.

A bash script can't call MCP tools — only an agent can. This bridges
the gap: generate the exact
`mcp__metasploit-server__start_handler(payload=…, lhost=…, lport=…)`
invocation per pre-baked payload so shell-mgr can read, iterate, and
spin them all up on activation.

Usage:
  python3 tools/preflight/handler_calls.py            # prints one call per line
  python3 tools/preflight/handler_calls.py --json     # [{payload,lhost,lport}, …]
  python3 tools/preflight/handler_calls.py --missing  # only entries whose
                                                      # handler isn't live
                                                      # (needs --running <ids>)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


_INDEX = Path(__file__).resolve().parent.parent.parent / "engagement" / "payloads" / "index.json"


def _load() -> list[dict]:
    if not _INDEX.exists():
        print(f"ERROR: {_INDEX} not found. Run gen_payloads.sh first.",
              file=sys.stderr)
        sys.exit(2)
    return json.loads(_INDEX.read_text())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true",
                    help="emit a JSON array instead of per-line calls")
    args = ap.parse_args()

    entries = _load()

    if args.json:
        print(json.dumps([
            {"name": e["name"], "payload": e["payload"],
             "lhost": e["callback"].rsplit(":", 1)[0],
             "lport": int(e["lport"])}
            for e in entries
        ], indent=2))
        return 0

    # Per-line, copy-pasteable
    print(f"# {len(entries)} handler(s) to start — one per pre-baked payload.")
    print("# Call each via the metasploit-server MCP (safe to re-run; the MCP's")
    print("# start_handler dedupes on payload+LHOST+LPORT).")
    print()
    for e in entries:
        lhost, lport = e["callback"].rsplit(":", 1)
        print(
            f'mcp__metasploit-server__start_handler('
            f'payload="{e["payload"]}", lhost="{lhost}", lport={lport})'
            f'   # {e["name"]}'
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
