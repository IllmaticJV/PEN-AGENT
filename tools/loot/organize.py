#!/usr/bin/env python3
"""Move dumped files into engagement/loot/<ip>/<kind>/<basename> + sidecar.

Why: dumped files (SAM hives, SSH keys, DB backups, PCAPs, config
dumps, memory snapshots) land all over `engagement/evidence/` with
drive-by names, and later nobody can find the one that mattered. This
imposes one layout: by host, then by kind, with a .meta sidecar
recording where it came from and when.

Usage:
  python3 tools/loot/organize.py <path> --ip <target_ip>
                                        [--kind creds|config|dump|backup|key|pcap|binary|other]
                                        [--source "<how it was obtained>"]
                                        [--notes "<freeform>"]
                                        [--copy]              # keep the original
                                        [--rehome <subdir>]   # non-default subpath

Default lands at: engagement/loot/<ip>/<kind>/<basename>
Sidecar `.meta.json` next to it carries: original_path, ip, kind,
source, notes, sha256, size, mtime, moved_at.

If `--kind` is omitted, we guess from the filename / content:
  .key / id_rsa / .pem                 → key
  SAM / NTDS.dit / .hive / .dmp        → dump
  .yaml .yml .ini .conf .toml .env     → config
  .sql .bak .sqlite .db                → backup
  .pcap .pcapng                        → pcap
  .exe .dll .so .elf                   → binary
  .txt with hash-ish lines             → creds
  else                                 → other
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_LOOT_ROOT = _PROJECT_ROOT / "engagement" / "loot"
_VALID_KINDS = ("creds", "config", "dump", "backup", "key", "pcap", "binary", "other")


def _guess_kind(path: Path) -> str:
    n = path.name.lower()
    if any(n.endswith(ext) for ext in (".key", ".pem")) or "id_rsa" in n or "id_ed25519" in n:
        return "key"
    if any(x in n for x in ("sam", "ntds.dit", ".hive", ".dmp", "lsass")):
        return "dump"
    if any(n.endswith(ext) for ext in (".yaml", ".yml", ".ini", ".conf", ".toml", ".env", ".cfg", ".properties")):
        return "config"
    if any(n.endswith(ext) for ext in (".sql", ".bak", ".sqlite", ".db", ".tar", ".tar.gz", ".zip")):
        return "backup"
    if any(n.endswith(ext) for ext in (".pcap", ".pcapng")):
        return "pcap"
    if any(n.endswith(ext) for ext in (".exe", ".dll", ".so", ".elf")):
        return "binary"
    # Peek at the first few lines for hash-ish structure.
    try:
        head = path.read_bytes()[:4096].decode(errors="replace")
    except OSError:
        head = ""
    hash_lines = [l for l in head.splitlines()[:20] if re.search(r"[a-fA-F0-9]{20,}", l)]
    if len(hash_lines) >= 3:
        return "creds"
    return "other"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")[:100] or "unnamed"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="file to organize (dirs: pass each file)")
    ap.add_argument("--ip", required=True,
                    help="target IP this loot came from")
    ap.add_argument("--kind", choices=_VALID_KINDS, default="",
                    help="override auto-detection")
    ap.add_argument("--source", default="",
                    help="brief how-it-was-obtained note (goes in the sidecar)")
    ap.add_argument("--notes", default="")
    ap.add_argument("--copy", action="store_true",
                    help="copy instead of move (keep original in place)")
    ap.add_argument("--rehome", default="",
                    help="subpath under <kind>/ (e.g. 'local-admins/jdoe')")
    args = ap.parse_args()

    try:
        ipaddress.IPv4Address(args.ip)
    except (ValueError, TypeError):
        print(f"ERROR: --ip must be a valid IPv4, got '{args.ip}'", file=sys.stderr)
        return 2

    src = Path(args.path)
    if not src.exists():
        print(f"ERROR: {src} not found", file=sys.stderr)
        return 2
    if not src.is_file():
        print(f"ERROR: {src} is a directory; pass individual files",
              file=sys.stderr)
        return 2

    kind = args.kind or _guess_kind(src)
    sub = Path(args.rehome) if args.rehome else Path()
    dest_dir = _LOOT_ROOT / args.ip / kind / sub
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / _slug(src.name)
    # Avoid clobber: suffix with ts if collides and content differs.
    if dest.exists() and _sha256(dest) != _sha256(src):
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
        dest = dest.with_name(f"{dest.stem}.{ts}{dest.suffix}")

    sha = _sha256(src)
    try:
        if args.copy or dest.exists():
            shutil.copy2(src, dest)
        else:
            shutil.move(str(src), dest)
    except OSError as e:
        print(f"ERROR: couldn't place {dest}: {e}", file=sys.stderr)
        return 2

    meta = {
        "original_path": str(src.resolve()) if args.copy else str(src),
        "ip": args.ip,
        "kind": kind,
        "source": args.source,
        "notes": args.notes,
        "sha256": sha,
        "size": dest.stat().st_size,
        "moved_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
    }
    (dest.parent / (dest.name + ".meta.json")).write_text(
        json.dumps(meta, indent=2) + "\n"
    )

    rel = dest.relative_to(_PROJECT_ROOT)
    print(f"placed: {rel}")
    print(f"kind:   {kind}" + ("  (auto-detected)" if not args.kind else ""))
    print(f"sha256: {sha[:16]}…")
    print(f"meta:   {rel.parent / (dest.name + '.meta.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
