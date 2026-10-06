#!/usr/bin/env python3
"""Compare two nmap XMLs → only emit the DELTA (new/changed ports) + state writes.

Why: on a staged full scan the net-enum teammate's second pass (`-p-`)
duplicates most of the quick scan's results. Running `nmap_ingest` on
both wastes tokens: the quick scan's output is already in context, and
the lead only needs to see what CHANGED.

This script compares two parsed nmap XMLs by (ip, proto, port) and
emits:
  - === DELTA SUMMARY === listing NEW hosts, NEW open ports per host,
    service/version CHANGES, hosts that went DOWN
  - === STATE WRITES === just [add-port] / [add-target] for the new
    rows — nothing for ports already recorded by the first ingest

Usage:
  python3 tools/ingestors/nmap_delta.py <OLD xml> <NEW xml>
                                        [--no-writes | --writes-only]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Reuse the parser from nmap_ingest to stay consistent.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nmap_ingest  # noqa: E402


def _by_host(data: dict) -> dict:
    out = {}
    for h in data["hosts"]:
        key = h["ip"]
        out[key] = {
            "ip": h["ip"],
            "hostname": h["hostname"],
            "os": h["os"],
            "ports": {(p["proto"], p["port"]): p for p in h["ports"]},
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("old", help="earlier nmap XML")
    ap.add_argument("new", help="later nmap XML")
    ap.add_argument("--no-writes", action="store_true")
    ap.add_argument("--writes-only", action="store_true")
    args = ap.parse_args()

    old_p, new_p = Path(args.old), Path(args.new)
    for p in (old_p, new_p):
        if not p.exists():
            print(f"ERROR: {p} not found", file=sys.stderr)
            return 2

    old = _by_host(nmap_ingest._parse(old_p))
    new = _by_host(nmap_ingest._parse(new_p))

    new_hosts = sorted(set(new) - set(old))
    gone_hosts = sorted(set(old) - set(new))
    common = sorted(set(new) & set(old))

    new_ports: dict[str, list[dict]] = {}
    changed_ports: dict[str, list[tuple[dict, dict]]] = {}
    for ip in common:
        o_ports = old[ip]["ports"]
        n_ports = new[ip]["ports"]
        added = [p for key, p in n_ports.items() if key not in o_ports]
        if added:
            new_ports[ip] = sorted(added, key=lambda x: (x["proto"], x["port"]))
        changed = []
        for key, p in n_ports.items():
            if key in o_ports and p["banner"] and p["banner"] != o_ports[key]["banner"]:
                changed.append((o_ports[key], p))
        if changed:
            changed_ports[ip] = changed

    # Build summary + writes
    summary_lines = ["=== DELTA SUMMARY ==="]
    summary_lines.append(f"old: {old_p}  ({len(old)} hosts)")
    summary_lines.append(f"new: {new_p}  ({len(new)} hosts)")
    summary_lines.append("")

    if new_hosts:
        summary_lines.append(f"NEW HOSTS ({len(new_hosts)}):")
        for ip in new_hosts:
            h = new[ip]
            svcs = ", ".join(f"{p['port']}/{p['service'] or '?'}"
                             for p in sorted(h["ports"].values(),
                                             key=lambda x: (x["proto"], x["port"]))[:8])
            summary_lines.append(f"  {ip}  {h['hostname'] or '-'}  {svcs}")
    if gone_hosts:
        summary_lines.append(f"\nGONE HOSTS ({len(gone_hosts)}):")
        for ip in gone_hosts:
            summary_lines.append(f"  {ip}  {old[ip]['hostname'] or '-'}")
    if new_ports:
        summary_lines.append(f"\nNEW PORTS on existing hosts "
                             f"({sum(len(v) for v in new_ports.values())} total):")
        for ip, ports in new_ports.items():
            svcs = ", ".join(f"{p['port']}/{p['service'] or '?'}"
                             + (f" ({p['banner'][:20]})" if p['banner'] else "")
                             for p in ports[:12])
            summary_lines.append(f"  {ip}  {svcs}")
    if changed_ports:
        summary_lines.append(f"\nSERVICE/VERSION CHANGES "
                             f"({sum(len(v) for v in changed_ports.values())}):")
        for ip, pairs in changed_ports.items():
            for old_p_r, new_p_r in pairs[:6]:
                summary_lines.append(
                    f"  {ip}  {new_p_r['port']}/{new_p_r['proto']}  "
                    f"'{old_p_r['banner']}' → '{new_p_r['banner']}'"
                )
    if not any((new_hosts, gone_hosts, new_ports, changed_ports)):
        summary_lines.append("No differences. Nothing to relay.")

    # Writes: only for genuinely new rows (new hosts, new ports)
    writes = ["=== STATE WRITES (relay to state-mgr) ==="]
    for ip in new_hosts:
        h = new[ip]
        parts = [f"ip={ip}"]
        if h["hostname"]:
            parts.append(f"hostname={h['hostname']}")
        if h["os"]:
            parts.append(f'os="{h["os"]}"')
        writes.append("[add-target] " + " ".join(parts))
        for p in sorted(h["ports"].values(), key=lambda x: (x["proto"], x["port"])):
            pparts = [f"ip={ip}", f"port={p['port']}", f"proto={p['proto']}",
                      f"service={p['service'] or 'unknown'}"]
            if p["banner"]:
                pparts.append(f'version="{p["banner"]}"')
            writes.append("[add-port] " + " ".join(pparts))
    for ip, ports in new_ports.items():
        for p in ports:
            pparts = [f"ip={ip}", f"port={p['port']}", f"proto={p['proto']}",
                      f"service={p['service'] or 'unknown'}"]
            if p["banner"]:
                pparts.append(f'version="{p["banner"]}"')
            writes.append("[add-port] " + " ".join(pparts))

    if args.writes_only:
        if len(writes) == 1:
            print("# (no new state writes — delta was empty or only changes)")
        else:
            print("\n".join(writes))
        return 0

    print("\n".join(summary_lines))
    if not args.no_writes and len(writes) > 1:
        print()
        print("\n".join(writes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
