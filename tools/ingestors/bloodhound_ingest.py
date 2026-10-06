#!/usr/bin/env python3
"""Local BloodHound JSON / ZIP → compact summary + state-mgr batch.

Why: BloodHound dumps 6-8 JSON files (computers, users, groups, ous,
gpos, domains, containers) totalling 100 KB – 20 MB on real AD estates.
Having the LLM wade through them to pick out Domain Admin members,
Kerberoastable users, unconstrained delegation hosts, and ACL abuses
is pure boilerplate — the shape is deterministic. This script pulls
the handful of signals that drive the next move, emits a SUMMARY for
the lead and pre-formatted state-mgr writes:

  [add-target] for every computer not already in state.db
  [add-vuln]   for high-risk attributes:
                 unconstrained_delegation=True
                 asreproastable=True (DONT_REQ_PREAUTH)
                 kerberoastable (hasspn=True + domain user)
                 admincount=True on a non-privileged user
  [add-cred]   placeholder=hashed, source="BloodHound <role>" for members
               of high-value groups (DA / EA / Schema Admins) so follow-up
               cracking has a target list

Supported inputs:
  - A directory of BloodHound Community JSON files
  - A `.zip` from SharpHound / bloodhound-python
  - A single JSON file (one of computers.json / users.json / groups.json)

Both legacy BloodHound and BloodHound Community Edition (CE) field
shapes are handled where possible.

Usage:
  python3 tools/ingestors/bloodhound_ingest.py <path>
                                               [--limit N]
                                               [--no-writes | --writes-only]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path


_KINDS = ("computers", "users", "groups", "domains", "ous", "gpos", "containers")


def _load_inputs(path: Path) -> dict[str, list]:
    """Return {kind: [objects]} from a dir, zip, or single file."""
    out: dict[str, list] = {k: [] for k in _KINDS}

    def _absorb(data) -> None:
        if not isinstance(data, dict):
            return
        meta = data.get("meta") or {}
        kind = (meta.get("type") or "").lower()  # legacy marker
        objs = data.get("data") if isinstance(data.get("data"), list) else []
        # BloodHound CE puts {"computers":[...]} directly:
        for k in _KINDS:
            if isinstance(data.get(k), list):
                out[k].extend(data[k])
        if kind in out and objs:
            out[kind].extend(objs)

    if path.is_dir():
        for p in sorted(path.glob("*.json")):
            try:
                _absorb(json.loads(p.read_text(errors="replace")))
            except (OSError, json.JSONDecodeError):
                continue
    elif path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    _absorb(json.loads(z.read(name).decode(errors="replace")))
                except (zipfile.BadZipFile, json.JSONDecodeError):
                    continue
    elif path.is_file():
        try:
            _absorb(json.loads(path.read_text(errors="replace")))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: {path}: {e}", file=sys.stderr)
    return out


def _computers(data: list) -> list[dict]:
    out = []
    for c in data:
        props = c.get("Properties") or c.get("properties") or {}
        name = props.get("name") or c.get("Name") or ""
        ip = props.get("ipaddr") or props.get("ipaddresses") or ""
        if isinstance(ip, list):
            ip = ip[0] if ip else ""
        os_ = props.get("operatingsystem") or ""
        unconstr = bool(props.get("unconstraineddelegation", False))
        allow_delegate = props.get("allowedtodelegate") or []
        enabled = props.get("enabled", True)
        out.append({
            "name": name, "ip": ip or "", "os": os_,
            "unconstrained": unconstr,
            "constrained_targets": allow_delegate if isinstance(allow_delegate, list) else [],
            "enabled": enabled,
        })
    return out


def _users(data: list) -> list[dict]:
    out = []
    for u in data:
        props = u.get("Properties") or u.get("properties") or {}
        name = props.get("name") or u.get("Name") or ""
        enabled = props.get("enabled", True)
        hasspn = bool(props.get("hasspn", False))
        admincount = bool(props.get("admincount", False))
        dontreqpre = bool(props.get("dontreqpreauth", False))
        out.append({
            "name": name, "enabled": enabled,
            "kerberoastable": hasspn,
            "asreproastable": dontreqpre,
            "admincount": admincount,
        })
    return out


def _group_members(data: list, group_name: str) -> list[str]:
    """Return SAMAccountName-ish members of a group by display-name match."""
    target = group_name.lower()
    for g in data:
        name = ((g.get("Properties") or g.get("properties") or {}).get("name") or "").lower()
        if not (name.startswith(target + "@") or name == target):
            continue
        members = g.get("Members") or g.get("members") or []
        out = []
        for m in members:
            if isinstance(m, dict):
                mn = m.get("ObjectIdentifier") or m.get("name") or ""
                # BH-CE often stores "USER@DOMAIN" in `MemberName`
                mn = m.get("MemberName", mn)
                out.append(str(mn))
            elif isinstance(m, str):
                out.append(m)
        return out
    return []


def _dedupe_users(data: list) -> list[str]:
    seen = set()
    out = []
    for u in data:
        name = ((u.get("Properties") or u.get("properties") or {}).get("name") or u.get("Name") or "").strip()
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out


def _format_summary(parsed: dict, limit: int) -> str:
    comps = _computers(parsed["computers"])
    users = _users(parsed["users"])
    da_members = _group_members(parsed["groups"], "DOMAIN ADMINS")
    ea_members = _group_members(parsed["groups"], "ENTERPRISE ADMINS")

    kerb = [u["name"] for u in users if u["kerberoastable"] and u["enabled"]]
    asrep = [u["name"] for u in users if u["asreproastable"] and u["enabled"]]
    unconstr = [c["name"] for c in comps if c["unconstrained"]]
    constr = [(c["name"], c["constrained_targets"]) for c in comps
              if c["constrained_targets"]]

    lines = ["=== SUMMARY ==="]
    lines.append(f"computers:   {len(comps)}  (enabled: {sum(1 for c in comps if c['enabled'])})")
    lines.append(f"users:       {len(users)}  (enabled: {sum(1 for u in users if u['enabled'])})")
    lines.append(f"groups:      {len(parsed['groups'])}")
    lines.append("")
    lines.append(f"Domain Admins ({len(da_members)}): " + ", ".join(da_members[:limit]) +
                 (f" +{len(da_members)-limit} more" if len(da_members) > limit else ""))
    if ea_members:
        lines.append(f"Enterprise Admins ({len(ea_members)}): " +
                     ", ".join(ea_members[:limit]))
    lines.append("")
    lines.append(f"Kerberoastable  ({len(kerb)}): " + ", ".join(kerb[:limit]) +
                 (f" +{len(kerb)-limit} more" if len(kerb) > limit else ""))
    lines.append(f"ASREP-roastable ({len(asrep)}): " + ", ".join(asrep[:limit]) +
                 (f" +{len(asrep)-limit} more" if len(asrep) > limit else ""))
    lines.append(f"Unconstrained delegation ({len(unconstr)}): " +
                 ", ".join(unconstr[:limit]))
    if constr:
        lines.append(f"Constrained delegation ({len(constr)}): " +
                     ", ".join(n for n, _ in constr[:limit]))
    return "\n".join(lines)


def _slug(s: str) -> str:
    """DOMAIN\\user → user; USER@DOMAIN → user."""
    s = str(s)
    if "\\" in s:
        s = s.split("\\", 1)[1]
    if "@" in s and not s.startswith("$"):
        s = s.split("@", 1)[0]
    return s


def _escape(s: str) -> str:
    return str(s).replace('"', '\\"')


def _format_writes(parsed: dict) -> str:
    comps = _computers(parsed["computers"])
    users = _users(parsed["users"])
    da_members = {_slug(m) for m in _group_members(parsed["groups"], "DOMAIN ADMINS")}

    out = ["=== STATE WRITES (relay to state-mgr) ==="]

    # [add-target] for each computer that has an IP
    for c in comps:
        if not c["ip"]:
            continue
        parts = [f"ip={c['ip']}", f"hostname={_slug(c['name'])}"]
        if c["os"]:
            parts.append(f'os="{_escape(c["os"])}"')
        parts.append(f'role="AD computer{" (disabled)" if not c["enabled"] else ""}"')
        out.append("[add-target] " + " ".join(parts))

    # [add-vuln] for high-risk attributes (ip may be unknown; skip ip= when so)
    def _vuln(ip: str, title: str, vuln_type: str, severity: str):
        p = [f"ip={ip}" if ip else 'ip=""', f'title="{_escape(title)}"',
             f"vuln_type={vuln_type}", f"severity={severity}",
             'details="imported from BloodHound"']
        return "[add-vuln] " + " ".join(p)

    for c in comps:
        if c["unconstrained"]:
            out.append(_vuln(c["ip"] or "",
                             f"Unconstrained delegation on {_slug(c['name'])}",
                             "ad_abuse", "high"))
        if c["constrained_targets"]:
            tgt_str = ", ".join(_slug(t) for t in c["constrained_targets"][:5])
            out.append(_vuln(c["ip"] or "",
                             f"Constrained delegation on {_slug(c['name'])} → {tgt_str}",
                             "ad_abuse", "high"))

    for u in users:
        if not u["enabled"]:
            continue
        if u["kerberoastable"] and u["name"]:
            sev = "high" if _slug(u["name"]) in da_members else "medium"
            out.append(_vuln("", f"Kerberoastable account {_slug(u['name'])}",
                             "ad_abuse", sev))
        if u["asreproastable"] and u["name"]:
            out.append(_vuln("", f"ASREP-roastable account {_slug(u['name'])}",
                             "ad_abuse", "high"))

    # Capture Domain Admin member usernames as placeholder credentials so
    # cracking has a target list.
    for m in sorted(da_members):
        if not m or m.startswith("S-1-"):
            continue
        out.append(
            f'[add-cred] username={m} secret_type=other secret="(unknown — DA)" '
            f'source="BloodHound Domain Admins member"'
        )
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="BloodHound JSON dir / .zip / single .json")
    ap.add_argument("--limit", type=int, default=10,
                    help="truncate member/user lists in SUMMARY (default 10)")
    ap.add_argument("--no-writes", action="store_true")
    ap.add_argument("--writes-only", action="store_true")
    args = ap.parse_args()

    p = Path(args.path)
    if not p.exists():
        print(f"ERROR: {p} not found", file=sys.stderr)
        return 2
    parsed = _load_inputs(p)
    total = sum(len(v) for v in parsed.values())
    if total == 0:
        print("ERROR: no BloodHound JSON objects found. Check the file / zip "
              "actually came from SharpHound / bloodhound-python.", file=sys.stderr)
        return 2

    if args.writes_only:
        print(_format_writes(parsed))
        return 0

    print(_format_summary(parsed, args.limit))
    if not args.no_writes:
        print()
        print(_format_writes(parsed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
