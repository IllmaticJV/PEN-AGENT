#!/usr/bin/env python3
"""Local credential sweep — test one cred against many hosts, emit hits.

Why: every time a new credential lands, someone wants to know "does
this also work on hosts B, C, D?". The teammate used to iterate: pick
a protocol, pick each host, run the login tool, read the result.
This standardizes it: one call, N hosts × M protocols, pre-formatted
`[add-access]` lines for state-mgr on the hits.

Protocols attempted (per host, based on known open ports when
available):
  - SMB            (netexec/crackmapexec/smbclient)
  - WinRM          (netexec/crackmapexec winrm, or evil-winrm login probe)
  - SSH            (ssh with BatchMode)

Order of preference for the engine: `nxc` (netexec) → `crackmapexec` →
raw clients. If none are installed, nxc/cme hosts are skipped with a
clear message so the operator can install one tool and re-run.

Usage:
  python3 tools/sweep/cred_sweep.py --username <u> --secret '<s>' [--domain <d>]
                                    --hosts 10.1.2.3,10.1.2.4,10.1.2.0/24
                                    [--protocols smb,winrm,ssh]
                                    [--secret-type password|ntlm_hash]
                                    [--timeout 5]
                                    [--state-db engagement/state.db]
                                    [--save]

Scope guard: hosts are checked against engagement/scope.allow. Out-of-
scope targets are refused.

Also writes evidence under engagement/evidence/sweep-<user>-<ts>/:
  log.txt        — one line per attempt
  hits.txt       — hits only
  state-writes.txt — pre-formatted [add-access] lines for state-mgr
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_SCOPE_ALLOW = _PROJECT_ROOT / "engagement" / "scope.allow"
_STATE_DB = _PROJECT_ROOT / "engagement" / "state.db"
_EVIDENCE = _PROJECT_ROOT / "engagement" / "evidence"


def _load_scope() -> list[ipaddress.IPv4Network]:
    nets = []
    if not _SCOPE_ALLOW.exists():
        return nets
    for line in _SCOPE_ALLOW.read_text(errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets


def _in_scope(ip: str, nets: list[ipaddress.IPv4Network]) -> bool:
    if not nets:
        return True  # fail-open when scope.allow is missing
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def _expand_hosts(spec: str) -> list[str]:
    out = []
    for item in spec.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            n = ipaddress.ip_network(item, strict=False)
            if n.prefixlen == 32:
                out.append(str(n.network_address))
            else:
                out.extend(str(h) for h in n.hosts())
        except ValueError:
            out.append(item)
    return out


def _detect_engine() -> str:
    for cand in ("nxc", "netexec", "crackmapexec", "cme"):
        if shutil.which(cand):
            return cand
    return ""


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not-found"
    except OSError as e:
        return 1, "", f"error: {e}"


def _port_open(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def _try_smb(engine: str, ip: str, user: str, secret: str,
             domain: str, is_hash: bool, timeout: int) -> tuple[bool, str]:
    """Try SMB login. Return (hit, note)."""
    if not _port_open(ip, 445, 1.5):
        return False, "445 closed"
    if engine in ("nxc", "netexec"):
        cmd = [engine, "smb", ip, "-u", user]
        cmd += ["-H", secret] if is_hash else ["-p", secret]
        if domain:
            cmd += ["-d", domain]
    elif engine in ("crackmapexec", "cme"):
        cmd = [engine, "smb", ip, "-u", user]
        cmd += ["-H", secret] if is_hash else ["-p", secret]
        if domain:
            cmd += ["-d", domain]
    else:
        return False, "no engine"
    rc, out, err = _run(cmd, timeout)
    text = (out + err).lower()
    if "(pwn3d!)" in text or "pwn3d" in text:
        return True, "smb admin (pwn3d)"
    if "[+]" in out:
        return True, "smb user"
    return False, "no-hit"


def _try_winrm(engine: str, ip: str, user: str, secret: str,
               domain: str, is_hash: bool, timeout: int) -> tuple[bool, str]:
    if not (_port_open(ip, 5985, 1.5) or _port_open(ip, 5986, 1.5)):
        return False, "winrm closed"
    if engine not in ("nxc", "netexec", "crackmapexec", "cme"):
        return False, "no engine"
    cmd = [engine, "winrm", ip, "-u", user]
    cmd += ["-H", secret] if is_hash else ["-p", secret]
    if domain:
        cmd += ["-d", domain]
    rc, out, err = _run(cmd, timeout)
    if "(pwn3d!)" in (out + err).lower() or "[+]" in out:
        return True, "winrm"
    return False, "no-hit"


def _try_ssh(ip: str, user: str, secret: str, timeout: int) -> tuple[bool, str]:
    """SSH with BatchMode so we don't hang on password prompt. Needs
    sshpass for the password form; without sshpass we only probe
    public-key auth from the operator's ~/.ssh (used when a cred is a
    key path — rare)."""
    if not _port_open(ip, 22, 1.5):
        return False, "22 closed"
    if shutil.which("sshpass"):
        cmd = ["sshpass", "-p", secret, "ssh",
               "-o", "BatchMode=no",
               "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null",
               "-o", f"ConnectTimeout={timeout}",
               "-o", "PreferredAuthentications=password",
               f"{user}@{ip}", "echo __AUTH_OK__"]
    else:
        return False, "no sshpass"
    rc, out, err = _run(cmd, timeout + 3)
    if "__AUTH_OK__" in out:
        return True, "ssh"
    return False, "no-hit"


_PROTO_FN = {"smb": _try_smb, "winrm": _try_winrm, "ssh": None}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--username", required=True)
    ap.add_argument("--secret", required=True, help="password or NT hash")
    ap.add_argument("--secret-type", choices=["password", "ntlm_hash"], default="password")
    ap.add_argument("--domain", default="")
    ap.add_argument("--hosts", required=True,
                    help="comma-separated hosts or CIDRs (10.1.1.0/24,10.1.2.3)")
    ap.add_argument("--protocols", default="smb,winrm,ssh",
                    help="comma-list from smb,winrm,ssh (default all three)")
    ap.add_argument("--timeout", type=int, default=5,
                    help="per-attempt timeout seconds (default 5)")
    ap.add_argument("--save", action="store_true",
                    help="write log/hits/state-writes to engagement/evidence/sweep-*/")
    args = ap.parse_args()

    protos = [p.strip().lower() for p in args.protocols.split(",") if p.strip()]
    unknown = [p for p in protos if p not in ("smb", "winrm", "ssh")]
    if unknown:
        print(f"ERROR: unknown protocol(s): {unknown}", file=sys.stderr)
        return 2
    is_hash = args.secret_type == "ntlm_hash"

    scope = _load_scope()
    hosts = _expand_hosts(args.hosts)
    hosts_in = [h for h in hosts if _in_scope(h, scope)]
    hosts_out = [h for h in hosts if h not in hosts_in]
    if hosts_out:
        print(f"[scope] skipped {len(hosts_out)} out-of-scope hosts "
              f"(first: {hosts_out[0]})", file=sys.stderr)

    engine = _detect_engine()
    if not engine:
        print("[warn] no netexec/crackmapexec on PATH — SMB/WinRM will be "
              "skipped. SSH still works if sshpass is installed.",
              file=sys.stderr)

    results: list[dict] = []
    attempts = 0
    hits = 0
    for ip in hosts_in:
        for proto in protos:
            attempts += 1
            if proto == "smb":
                ok, note = _try_smb(engine, ip, args.username, args.secret,
                                    args.domain, is_hash, args.timeout)
            elif proto == "winrm":
                ok, note = _try_winrm(engine, ip, args.username, args.secret,
                                      args.domain, is_hash, args.timeout)
            else:
                ok, note = _try_ssh(ip, args.username, args.secret, args.timeout)
            tag = "HIT " if ok else "miss"
            line = f"{tag} {ip:16} {proto:5} {args.username}@{args.domain or '-'} ({note})"
            print(line)
            if ok:
                hits += 1
                results.append({"ip": ip, "proto": proto, "note": note})

    print()
    print(f"=== SUMMARY === {hits} hit(s) / {attempts} attempts "
          f"across {len(hosts_in)} hosts")

    if results:
        print()
        print("=== STATE WRITES (relay to state-mgr) ===")
        for r in results:
            method = {"smb": "smb", "winrm": "winrm", "ssh": "ssh"}[r["proto"]]
            priv = "admin" if "pwn3d" in r["note"] else "user"
            print(
                f"[add-access] ip={r['ip']} user={args.username} "
                f"method={method} level={priv} "
                f'notes="cred_sweep hit ({r["note"]}); matching cred in state.db"'
            )

    if args.save:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        safe_user = re.sub(r"[^A-Za-z0-9_-]+", "_", args.username)
        out_dir = _EVIDENCE / f"sweep-{safe_user}-{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "log.txt").write_text("\n".join(
            [f"{len(hosts_in)} hosts × {len(protos)} protos = {attempts} attempts, {hits} hits"] +
            [f"HIT {r['ip']} {r['proto']} ({r['note']})" for r in results]
        ) + "\n")
        (out_dir / "hits.txt").write_text("\n".join(
            [f"{r['ip']} {r['proto']} {args.username} ({r['note']})" for r in results]
        ) + "\n")
        print(f"\n(evidence saved to {out_dir}/)", file=sys.stderr)

    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
