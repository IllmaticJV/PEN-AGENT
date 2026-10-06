#!/usr/bin/env python3
"""Local nmap XML → compact summary + state-mgr messages.

Why: raw nmap output (full `nmap -sVC -p-` on a /24) is ~2-20 KB of
structured data that the LLM would otherwise ingest just to turn around
and send a handful of [add-target]/[add-port] messages to state-mgr.
This pre-processes locally so the teammate sees a short markdown table
PLUS ready-to-send state-mgr command lines. Token savings: typically 10x
on a scan report, and the state writes are deterministic (no LLM
transcription errors).

Usage:
  python3 tools/ingestors/nmap_ingest.py <path/to/nmap.xml> [--limit N] [--no-writes]

Teammate pattern:
  1. Run nmap via mcp__nmap-server__nmap_scan (saves XML to
     engagement/evidence/nmap-<target>.xml).
  2. python3 tools/ingestors/nmap_ingest.py <that path>
  3. Relay the SUMMARY to the lead and the STATE WRITES to state-mgr.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


# Services we almost never want to flood state.db with on big scans.
# The teammate can still request them explicitly by passing --all.
_NOISY_PORTS = {}  # keep empty — teammates/the lead decide what's noise.


def _parse(xml_path: Path) -> dict:
    """Pull just what state.db + the summary care about. No deps."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    out: dict = {
        "cmd": root.get("args", ""),
        "started": root.get("startstr", root.get("start", "")),
        "elapsed": "",
        "hosts_up": 0,
        "hosts_total": 0,
        "hosts": [],
    }
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            out["elapsed"] = finished.get("elapsed", "")
        hosts_el = runstats.find("hosts")
        if hosts_el is not None:
            out["hosts_up"] = int(hosts_el.get("up", "0") or 0)
            out["hosts_total"] = int(hosts_el.get("total", "0") or 0)

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                addr = a.get("addr", "")
                break
        if not addr:
            continue
        hostname = ""
        hns = host.find("hostnames")
        if hns is not None:
            hn = hns.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_name = ""
        os_el = host.find("os")
        if os_el is not None:
            best = None
            for m in os_el.findall("osmatch"):
                acc = int(m.get("accuracy", "0") or 0)
                if best is None or acc > best[0]:
                    best = (acc, m.get("name", ""))
            if best:
                os_name = best[1]

        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = p.find("service")
                svc_name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                extra = svc.get("extrainfo", "") if svc is not None else ""
                banner_parts = [x for x in (product, version, extra) if x]
                banner = " ".join(banner_parts)
                ports.append({
                    "port": int(p.get("portid", "0") or 0),
                    "proto": p.get("protocol", "tcp"),
                    "service": svc_name,
                    "banner": banner,
                })
        ports.sort(key=lambda x: (x["proto"], x["port"]))
        out["hosts"].append({
            "ip": addr, "hostname": hostname, "os": os_name, "ports": ports,
        })
    out["hosts"].sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    return out


def _os_short(os_name: str) -> str:
    """Collapse 'Linux 5.4 - 5.11' → 'Linux 5.4-5.11'; fall back as-is."""
    s = os_name.strip()
    s = re.sub(r"\s*-\s*", "-", s)
    return s[:30]


def _service_cell(ports: list[dict], limit_per_host: int) -> str:
    """Compact one-liner for the summary table: '22/ssh, 80/http (nginx)'."""
    bits = []
    for p in ports[:limit_per_host]:
        svc = p["service"] or "?"
        tag = f"{p['port']}/{svc}"
        if p["banner"]:
            tag += f" ({p['banner'][:30]})"
        bits.append(tag)
    if len(ports) > limit_per_host:
        bits.append(f"+{len(ports) - limit_per_host} more")
    return ", ".join(bits)


def _format_summary(data: dict, limit: int) -> str:
    lines = []
    cmd = data.get("cmd", "")
    lines.append(f"=== SUMMARY ===")
    lines.append(f"cmd:     {cmd}")
    lines.append(f"up:      {data['hosts_up']} / {data['hosts_total']} hosts  "
                 f"(elapsed {data['elapsed']}s)")
    lines.append("")
    if not data["hosts"]:
        lines.append("No live hosts.")
        return "\n".join(lines)
    rows = []
    for h in data["hosts"][:limit] if limit else data["hosts"]:
        rows.append((h["ip"], h["hostname"] or "-", _os_short(h["os"]) or "-",
                     _service_cell(h["ports"], 6)))
    widths = [max(len(r[i]) for r in rows + [("IP", "HOST", "OS", "SERVICES")])
              for i in range(4)]
    def row(cells): return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"
    sep = "|" + "|".join("-" * (w + 2) for w in widths) + "|"
    lines.append(row(("IP", "HOST", "OS", "SERVICES")))
    lines.append(sep)
    for r in rows:
        lines.append(row(r))
    if limit and len(data["hosts"]) > limit:
        lines.append(f"... +{len(data['hosts']) - limit} more hosts (re-run "
                     f"with --limit 0 to show all)")
    return "\n".join(lines)


def _format_writes(data: dict) -> str:
    """Pre-formatted state-mgr messages: one line per [add-target]/[add-port].
    Teammates relay these verbatim; no LLM transcription of ports/versions.
    """
    out = ["=== STATE WRITES (relay to state-mgr) ==="]
    for h in data["hosts"]:
        parts = [f"ip={h['ip']}"]
        if h["hostname"]:
            parts.append(f"hostname={h['hostname']}")
        if h["os"]:
            parts.append(f'os="{_os_short(h["os"])}"')
        out.append(f"[add-target] " + " ".join(parts))
        for p in h["ports"]:
            port_parts = [f"ip={h['ip']}", f"port={p['port']}",
                          f"proto={p['proto']}", f"service={p['service'] or 'unknown'}"]
            if p["banner"]:
                port_parts.append(f'version="{p["banner"]}"')
            out.append(f"[add-port] " + " ".join(port_parts))
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("xml_path", help="nmap XML output file")
    ap.add_argument("--limit", type=int, default=30,
                    help="truncate summary table to N hosts (0 = all)")
    ap.add_argument("--no-writes", action="store_true",
                    help="skip the state-mgr command block")
    ap.add_argument("--writes-only", action="store_true",
                    help="emit only the state-mgr command block")
    args = ap.parse_args()

    p = Path(args.xml_path)
    if not p.exists():
        print(f"ERROR: {p} not found", file=sys.stderr)
        return 2
    try:
        data = _parse(p)
    except ET.ParseError as e:
        print(f"ERROR: invalid nmap XML: {e}", file=sys.stderr)
        return 2

    if args.writes_only:
        print(_format_writes(data))
        return 0

    print(_format_summary(data, args.limit))
    if not args.no_writes:
        print()
        print(_format_writes(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
