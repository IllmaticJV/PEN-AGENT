#!/usr/bin/env python3
"""Local BloodHound shortest-path finder — no neo4j required.

Why: operators spin up neo4j + BloodHound GUI just to answer "what's
the cheapest path from this compromised user to Domain Admins?". For
the common case we can answer it with a plain Dijkstra over the typed
edges in the dumped JSON. No containers, no browser.

Supported edge kinds (weighted by abuse difficulty, lower = easier):

  edge                       weight   abuse
  --------------------------  ------  --------------------------------
  MemberOf                    0.5    group inheritance (free)
  AdminTo                     1.0    local admin → RCE via psexec/wmi
  HasSession                  1.5    needs user online → extract creds
  DCSync                      1.0    DCSync → NTDS → DA hash
  ForceChangePassword         1.5    rpcclient setuserinfo2
  AddMember                   1.5    net group /add
  AllowedToDelegate           2.0    S4U2Self/S4U2Proxy
  AllowedToAct                2.0    RBCD → msDS-AllowedToActOnBehalfOf
  GenericAll                  1.5    full control → shadow cred / pwd reset
  GenericWrite                2.0    msDS-KeyCredentialLink shadow cred
  WriteDacl                   2.0    grant yourself GenericAll
  WriteOwner                  2.0    grant yourself WriteDacl
  AddKeyCredentialLink        1.5    shadow credential
  ReadLAPSPassword            1.0    reads cleartext local admin pwd
  CanRDP / CanPSRemote        1.5    direct interactive access

Default target set: members of `Domain Admins`. Pass --target to
override (e.g. `Enterprise Admins`, a specific user).

Usage:
  python3 tools/ingestors/bloodhound_paths.py <bloodhound-path> --from <PRINCIPAL>
                                              [--target 'DOMAIN ADMINS@...']
                                              [--max 5]
                                              [--max-hops 8]
"""

from __future__ import annotations

import argparse
import heapq
import json
import sys
import zipfile
from pathlib import Path


_EDGE_WEIGHTS = {
    "MemberOf": 0.5, "AdminTo": 1.0, "HasSession": 1.5, "DCSync": 1.0,
    "GetChanges": 1.0, "GetChangesAll": 1.0, "ForceChangePassword": 1.5,
    "AddMember": 1.5, "AllowedToDelegate": 2.0, "AllowedToAct": 2.0,
    "GenericAll": 1.5, "GenericWrite": 2.0, "WriteDacl": 2.0,
    "WriteOwner": 2.0, "AddKeyCredentialLink": 1.5,
    "ReadLAPSPassword": 1.0, "CanRDP": 1.5, "CanPSRemote": 1.5,
    "ExecuteDCOM": 1.5, "SQLAdmin": 1.5,
}


def _load_bloodhound(path: Path) -> list[dict]:
    """Return a flat list of {ObjectIdentifier, Properties, ...} nodes
    across all JSON files (dir / zip / single file)."""
    objs: list[dict] = []

    def _absorb(data):
        if not isinstance(data, dict):
            return
        for k in ("computers", "users", "groups", "domains", "ous", "gpos", "containers"):
            v = data.get(k)
            if isinstance(v, list):
                objs.extend(v)
        if isinstance(data.get("data"), list):
            objs.extend(data["data"])

    if path.is_dir():
        for p in sorted(path.glob("*.json")):
            try: _absorb(json.loads(p.read_text(errors="replace")))
            except (OSError, json.JSONDecodeError): pass
    elif path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not name.endswith(".json"): continue
                try: _absorb(json.loads(z.read(name).decode(errors="replace")))
                except (zipfile.BadZipFile, json.JSONDecodeError): pass
    elif path.is_file():
        try: _absorb(json.loads(path.read_text(errors="replace")))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
    return objs


def _edges(objs: list[dict]) -> tuple[dict, dict]:
    """Build an edge list and a name→id map. BloodHound stores outbound
    edges on each node under keys like 'Aces', 'Sessions', 'Members',
    'AllowedToDelegate'. Shape varies across BH versions; we pull the
    common fields."""
    name_to_id = {}
    id_to_name = {}
    adj: dict[str, list[tuple[str, str, float]]] = {}

    for n in objs:
        oid = n.get("ObjectIdentifier") or n.get("objectid") or ""
        props = n.get("Properties") or n.get("properties") or {}
        name = (props.get("name") or n.get("Name") or "").upper()
        if oid and name:
            name_to_id[name] = oid
            id_to_name[oid] = name

    for n in objs:
        src = n.get("ObjectIdentifier") or n.get("objectid")
        if not src:
            continue
        # MemberOf edges (groups): the node's `PrimaryGroupSid` + `Aces`
        # don't live here; MemberOf is on the group's `Members` list in
        # BH-CE. Also look at direct lists.
        for member in (n.get("Members") or n.get("members") or []):
            if isinstance(member, dict):
                mid = member.get("ObjectIdentifier") or member.get("objectid")
                if mid:
                    adj.setdefault(mid, []).append(
                        (src, "MemberOf", _EDGE_WEIGHTS["MemberOf"]))
        # Sessions
        for sess in (n.get("Sessions", {}).get("Results") if isinstance(n.get("Sessions"), dict) else []) or []:
            uid = sess.get("UserSID") if isinstance(sess, dict) else None
            if uid:
                adj.setdefault(src, []).append(
                    (uid, "HasSession", _EDGE_WEIGHTS["HasSession"]))
        # LocalAdmins / RemoteDesktopUsers / etc. (BH-CE puts them under PrivilegedSessions / UserRights)
        for key, edge_kind in [
            ("LocalAdmins", "AdminTo"),
            ("RemoteDesktopUsers", "CanRDP"),
            ("PSRemoteUsers", "CanPSRemote"),
            ("DcomUsers", "ExecuteDCOM"),
        ]:
            section = n.get(key)
            principals = section.get("Results") if isinstance(section, dict) else section
            for pr in (principals or []):
                pid = pr.get("ObjectIdentifier") if isinstance(pr, dict) else None
                if pid:
                    adj.setdefault(pid, []).append(
                        (src, edge_kind, _EDGE_WEIGHTS[edge_kind]))
        # ACL edges — most come as "Aces" list of {RightName, PrincipalSID}
        for ace in (n.get("Aces") or n.get("aces") or []):
            if not isinstance(ace, dict):
                continue
            principal = ace.get("PrincipalSID") or ace.get("principalsid")
            right = ace.get("RightName") or ace.get("rightname")
            if not (principal and right):
                continue
            if right in _EDGE_WEIGHTS:
                adj.setdefault(principal, []).append(
                    (src, right, _EDGE_WEIGHTS[right]))
        # AllowedToDelegate — on computer nodes
        for tgt in (n.get("AllowedToDelegate") or []):
            tid = tgt.get("ObjectIdentifier") if isinstance(tgt, dict) else None
            if tid:
                adj.setdefault(src, []).append(
                    (tid, "AllowedToDelegate", _EDGE_WEIGHTS["AllowedToDelegate"]))
        # AllowedToAct (RBCD)
        for tgt in (n.get("AllowedToAct") or []):
            tid = tgt.get("ObjectIdentifier") if isinstance(tgt, dict) else None
            if tid:
                adj.setdefault(src, []).append(
                    (tid, "AllowedToAct", _EDGE_WEIGHTS["AllowedToAct"]))
    return adj, {"name_to_id": name_to_id, "id_to_name": id_to_name}


def _resolve(name_or_sid: str, maps: dict) -> str:
    """Accept SID, uppercase name, or lowercase name."""
    if name_or_sid.startswith("S-1-"):
        return name_or_sid
    up = name_or_sid.upper()
    if up in maps["name_to_id"]:
        return maps["name_to_id"][up]
    # Prefix search (e.g. "DOMAIN ADMINS" → first DOMAIN ADMINS@*).
    for nm, sid in maps["name_to_id"].items():
        if nm == up or nm.startswith(up + "@"):
            return sid
    return ""


def _dijkstra(adj: dict, source: str, target: str, max_hops: int):
    """Shortest path by sum of edge weights. Returns [(src, edge, dst), ...]
    or None."""
    if source == target:
        return []
    pq = [(0.0, 0, source, [])]
    seen: dict[str, float] = {}
    while pq:
        cost, hops, u, path = heapq.heappop(pq)
        if u == target:
            return path
        if hops >= max_hops:
            continue
        if cost >= seen.get(u, float("inf")):
            continue
        seen[u] = cost
        for v, edge, w in adj.get(u, []):
            if v == u:
                continue
            heapq.heappush(pq, (cost + w, hops + 1, v, path + [(u, edge, v)]))
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="BloodHound JSON dir / .zip / single .json")
    ap.add_argument("--from", dest="src", required=True,
                    help="principal (SID or NAME@DOMAIN) you've compromised")
    ap.add_argument("--target", default="DOMAIN ADMINS",
                    help="target principal (default 'DOMAIN ADMINS')")
    ap.add_argument("--max", type=int, default=1,
                    help="print the N shortest distinct paths (default 1)")
    ap.add_argument("--max-hops", type=int, default=8)
    args = ap.parse_args()

    p = Path(args.path)
    if not p.exists():
        print(f"ERROR: {p} not found", file=sys.stderr)
        return 2
    objs = _load_bloodhound(p)
    if not objs:
        print("ERROR: no BloodHound objects found", file=sys.stderr)
        return 2
    adj, maps = _edges(objs)

    src_id = _resolve(args.src, maps)
    tgt_id = _resolve(args.target, maps)
    if not src_id:
        print(f"ERROR: source '{args.src}' not found. Try the full "
              f"'USERNAME@DOMAIN.LOCAL' form.", file=sys.stderr)
        return 2
    if not tgt_id:
        print(f"ERROR: target '{args.target}' not found.", file=sys.stderr)
        return 2

    print(f"from: {args.src}  ({src_id[:30]}…)")
    print(f"to:   {args.target}  ({tgt_id[:30]}…)")
    print(f"edges indexed: {sum(len(v) for v in adj.values())}  "
          f"over {len(adj)} principals")
    print()

    path = _dijkstra(adj, src_id, tgt_id, args.max_hops)
    if path is None:
        print(f"NO PATH within {args.max_hops} hops. Try --max-hops higher, "
              f"or confirm {args.src} actually has outbound edges we track.")
        return 1
    if not path:
        print("Source IS the target. (trivial)")
        return 0

    print(f"PATH ({len(path)} hop{'s' if len(path) != 1 else ''}):")
    for i, (u, edge, v) in enumerate(path, 1):
        u_name = maps["id_to_name"].get(u, u[:30] + "…")
        v_name = maps["id_to_name"].get(v, v[:30] + "…")
        print(f"  {i}. {u_name}  --[{edge}]-->  {v_name}")
    total = sum(_EDGE_WEIGHTS.get(edge, 1.0) for _, edge, _ in path)
    print(f"\ntotal weight: {total:.1f}  (lower = easier to execute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
