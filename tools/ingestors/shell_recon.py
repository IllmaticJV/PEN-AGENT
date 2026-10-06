#!/usr/bin/env python3
"""Parse `shell_recon.sh` output → structured summary + state-mgr writes.

Companion to tools/payloads/shell_recon.sh (and its PowerShell sibling).
After catching a new shell, the teammate runs ONE send_command with the
recon payload (deterministic, delimited output), captures the result,
pipes it here. We extract: hostname, user, uid/gid, OS, kernel, IPs,
interesting local info — then emit:

  === SUMMARY ===
    hostname / user (uid) @ 10.80.121.10
    OS: Ubuntu 22.04.4 LTS   kernel: 5.15.0-100
    ifaces: eth0 10.80.121.10/24, eth1 10.1.121.5/24
    sudo:   (ALL : ALL) NOPASSWD: /usr/bin/apt
    docker: yes
    ...

  === STATE WRITES (relay to state-mgr) ===
    [update-target] ip=10.80.121.10 hostname=gitlab os="Ubuntu 22.04.4 LTS"
    [add-pivot] from_ip=10.80.121.10 to_subnet=10.1.121.0/24 pivot_type=dual-nic

Also writes raw payload output to engagement/evidence/recon-<ip>-<ts>.txt
if --save is given.

Usage:
  python3 tools/ingestors/shell_recon.py <recon-output.txt> --ip 10.80.121.10
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path


_SECT_RE = re.compile(r"^=== (?P<name>[A-Z_]+) ===$")


def _parse(text: str) -> dict:
    sections: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        m = _SECT_RE.match(line)
        if m:
            cur = m.group("name")
            sections[cur] = []
            continue
        if cur:
            sections[cur].append(line.rstrip())
    return sections


def _one(sections: dict, name: str) -> str:
    v = sections.get(name) or []
    for line in v:
        s = line.strip()
        if s:
            return s
    return ""


def _ifaces(sections: dict) -> list[tuple[str, str]]:
    """From `ip -o -4 addr` style output: [('eth0','10.80.121.10/24'), ...]."""
    out = []
    for line in sections.get("IFACES", []):
        s = line.strip()
        if not s:
            continue
        # Linux `ip -o -4 addr`: "2: eth0    inet 10.80.121.10/24 ..."
        m = re.search(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", s)
        if m:
            iface, cidr = m.group(1), m.group(2)
            if not cidr.startswith("127."):
                out.append((iface, cidr))
            continue
        # Windows `ipconfig` style: "   IPv4 Address.......: 10.1.121.60"
        m = re.search(r"IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", s)
        if m:
            out.append(("iface", f"{m.group(1)}/32"))
    return out


def _pivot_cidrs(this_ip: str, ifaces: list[tuple[str, str]]) -> list[str]:
    """Any CIDR we see on an interface whose network does NOT contain
    this_ip is a candidate pivot subnet (we're dual-NIC into it)."""
    try:
        src = ipaddress.ip_address(this_ip)
    except (ValueError, TypeError):
        return []
    out = []
    for _, cidr in ifaces:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if src not in net:
            out.append(str(net))
    return sorted(set(out))


def _format_summary(sections: dict, ip: str) -> str:
    user = _one(sections, "WHOAMI")
    uid = _one(sections, "ID")
    hostname = _one(sections, "HOSTNAME")
    os_name = _one(sections, "OS")
    kernel = _one(sections, "KERNEL")
    sudo = sections.get("SUDO", [])
    docker = _one(sections, "DOCKER")
    world_writable = sections.get("WORLD_WRITABLE_INTERESTING", [])
    ifaces = _ifaces(sections)
    pivots = _pivot_cidrs(ip, ifaces)

    lines = ["=== SUMMARY ==="]
    hbit = hostname or "(no hostname)"
    lines.append(f"{hbit} / {user or '?'} ({uid or 'uid?'}) @ {ip}")
    if os_name or kernel:
        lines.append(f"OS: {os_name or '?'}" + (f"   kernel: {kernel}" if kernel else ""))
    if ifaces:
        lines.append("ifaces: " + ", ".join(f"{i} {c}" for i, c in ifaces))
    if pivots:
        lines.append("pivot cand: " + ", ".join(pivots))
    if sudo:
        s = next((x.strip() for x in sudo if x.strip()), "")
        if s and "may not" not in s.lower() and "not allowed" not in s.lower():
            lines.append(f"sudo:   {s[:120]}")
    if docker:
        lines.append(f"docker: {docker}")
    if world_writable:
        n = sum(1 for x in world_writable if x.strip())
        if n:
            lines.append(f"ww-paths: {n} interesting world-writable paths "
                         f"(see raw output)")
    return "\n".join(lines)


def _format_writes(sections: dict, ip: str) -> str:
    out = ["=== STATE WRITES (relay to state-mgr) ==="]
    hostname = _one(sections, "HOSTNAME")
    os_name = _one(sections, "OS")
    parts = [f"ip={ip}"]
    if hostname:
        parts.append(f"hostname={hostname}")
    if os_name:
        parts.append(f'os="{os_name}"')
    out.append("[update-target] " + " ".join(parts))

    ifaces = _ifaces(sections)
    for cidr in _pivot_cidrs(ip, ifaces):
        out.append(f"[add-pivot] from_ip={ip} to_subnet={cidr} pivot_type=dual-nic")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="recon output (stdin accepted with '-')")
    ap.add_argument("--ip", required=True,
                    help="target IP (state.db target.ip) — needed to key the writes")
    ap.add_argument("--save", action="store_true",
                    help="also copy raw output to engagement/evidence/recon-<ip>.txt")
    ap.add_argument("--writes-only", action="store_true")
    args = ap.parse_args()

    text = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(errors="replace")
    sections = _parse(text)
    if not sections:
        print("ERROR: no `=== SECTION ===` headers found. Did you run the "
              "shell_recon.sh/.ps1 payload?", file=sys.stderr)
        return 2

    if args.save:
        from datetime import datetime
        p = (Path(__file__).resolve().parent.parent.parent /
             "engagement" / "evidence" /
             f"recon-{args.ip}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.txt")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        print(f"(raw saved to {p})\n", file=sys.stderr)

    if args.writes_only:
        print(_format_writes(sections, args.ip))
        return 0

    print(_format_summary(sections, args.ip))
    print()
    print(_format_writes(sections, args.ip))
    return 0


if __name__ == "__main__":
    sys.exit(main())
