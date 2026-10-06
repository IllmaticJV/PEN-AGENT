#!/usr/bin/env python3
"""Local credential-dump ingester → state-mgr batch.

Why: secretsdump / GetUserSPNs / hashcat --show / responder dumps all
end up as [add-cred] messages. Doing it in-LLM wastes tokens and risks
transcription errors on hashes. This parses the common formats locally
and emits pre-formatted state-mgr commands the teammate relays
verbatim.

Supported formats (auto-detected per line, so mixed files work):
  - impacket secretsdump SAM/NTDS lines:
      user:rid:lmhash:nthash:::              → secret_type=ntlm_hash
  - secretsdump kerberos keys (`:aes256-cts-...:`, `:aes128-...:`,
    `:des-cbc-md5:`)                         → secret_type=aes_key / other
  - secretsdump cleartext (CLEARTEXT) lines  → secret_type=password
  - impacket GetUserSPNs (`$krb5tgs$23$...`) → secret_type=kerberos_tgs
    (ASREP: `$krb5asrep$23$...`)             → kerberos_tgt
  - hashcat --show (`hash:plaintext`)        → secret_type=password
    (also detects :: or $ in the hash side)
  - plain `username:password` lines (no $,:: in secret) → password
  - LAPS / jsonl `{"username":"..","password":".."}` → password

Usage:
  python3 tools/ingestors/cred_ingest.py <path> [--source "<label>"]
                                                [--domain <d>]
                                                [--writes-only]

Teammate pattern (same as nmap_ingest):
  1. Save tool output to engagement/evidence/<name>.txt
  2. Run this; relay SUMMARY to the lead, STATE WRITES to state-mgr.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


# NTLM pair: aad3b435b51404eeaad3b435b51404ee: + 32-hex nt hash
_SAM_RE = re.compile(
    r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::\s*$"
)
# Kerberos key line: user:aes256-cts-hmac-sha1-96:<hex>
_KRB_KEY_RE = re.compile(
    r"^(?P<user>[^:]+):(?P<etype>aes256-cts[^:]*|aes128-cts[^:]*|des-cbc-md5|des3-cbc-sha1):(?P<key>[a-fA-F0-9]+)\s*$"
)
# secretsdump cleartext marker
_CLEAR_RE = re.compile(
    r"^(?P<user>[^:]+):CLEARTEXT:(?P<secret>.+?)\s*$"
)
_KRB_TGS_RE = re.compile(r"^\$krb5tgs\$")
_KRB_ASREP_RE = re.compile(r"^\$krb5asrep\$")
# hashcat --show: hash:plaintext (not a secretsdump line)
_HASHCAT_SHOW_RE = re.compile(r"^(?P<hash>[^\s]+):(?P<plain>.+)$")
# plain user:pass (no colons/dollars in secret)
_UPASS_RE = re.compile(r"^(?P<user>[^\s:]+):(?P<secret>[^\s:$]+)\s*$")

# Users we never record (skip accounts whose hashes are universally present
# but we rarely want state.db noise for the first ingest).
_SKIP_USERS = {"Guest", "DefaultAccount", "WDAGUtilityAccount"}


def _split_domain(user: str) -> tuple[str, str]:
    """`DOMAIN\\user` or `user@DOMAIN` → (domain, user). Else ("", user)."""
    if "\\" in user:
        d, u = user.split("\\", 1)
        return d, u
    if "@" in user and user.count("@") == 1 and not user.startswith("$"):
        u, d = user.split("@", 1)
        return d, u
    return "", user


def _detect_kerb_type(blob: str) -> str:
    if _KRB_TGS_RE.match(blob):
        return "kerberos_tgs"
    if _KRB_ASREP_RE.match(blob):
        return "kerberos_tgt"
    return ""


def _parse(text: str, default_domain: str) -> list[dict]:
    """Walk lines, emit cred dicts {domain, user, secret, secret_type, extra}."""
    creds: list[dict] = []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        # 1. JSON per-line
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                obj = None
            if obj and isinstance(obj, dict):
                u = obj.get("username") or obj.get("user") or ""
                p = obj.get("password") or obj.get("secret") or ""
                if u and p:
                    d = obj.get("domain", default_domain)
                    creds.append({"domain": d, "user": u, "secret": p,
                                  "secret_type": "password", "extra": ""})
                    continue

        # 2. SAM/NTDS NTLM
        m = _SAM_RE.match(line)
        if m:
            user_full = m.group("user")
            d, u = _split_domain(user_full)
            if u in _SKIP_USERS:
                continue
            nt = m.group("nt").lower()
            creds.append({
                "domain": d or default_domain, "user": u,
                "secret": nt, "secret_type": "ntlm_hash",
                "extra": f"rid={m.group('rid')}",
            })
            continue

        # 3. Kerberos key material
        m = _KRB_KEY_RE.match(line)
        if m:
            user_full = m.group("user")
            d, u = _split_domain(user_full)
            if u in _SKIP_USERS:
                continue
            etype = m.group("etype")
            stype = "aes_key" if "aes" in etype else "other"
            creds.append({
                "domain": d or default_domain, "user": u,
                "secret": m.group("key"), "secret_type": stype,
                "extra": f"etype={etype}",
            })
            continue

        # 4. CLEARTEXT
        m = _CLEAR_RE.match(line)
        if m:
            d, u = _split_domain(m.group("user"))
            creds.append({
                "domain": d or default_domain, "user": u,
                "secret": m.group("secret"), "secret_type": "password",
                "extra": "cleartext",
            })
            continue

        # 5. Kerberos TGS/ASREP (hashcat-compatible). Format:
        #   $krb5tgs$<etype>$*<user>$<DOMAIN>$<spn>*$<hash>
        #   $krb5asrep$<etype>$<user>@<DOMAIN>:<hash>
        kt = _detect_kerb_type(line)
        if kt:
            parts = line.split("$")
            user = ""
            domain = default_domain
            if kt == "kerberos_tgs" and len(parts) >= 6:
                user = parts[3].lstrip("*")
                domain = parts[4] or default_domain
            elif kt == "kerberos_tgt" and len(parts) >= 4:
                field = parts[3]
                if "@" in field:
                    user, rest = field.split("@", 1)
                    if ":" in rest:
                        domain = rest.split(":", 1)[0]
            creds.append({
                "domain": domain, "user": user or "(unknown)",
                "secret": line, "secret_type": kt, "extra": "crackable",
            })
            continue

        # 6. hashcat --show (hash:plain). Must look like a hex/base64 hash.
        m = _HASHCAT_SHOW_RE.match(line)
        if m:
            h = m.group("hash")
            p = m.group("plain")
            if (len(h) >= 16 and re.match(r"^[A-Fa-f0-9$]+$", h)) or h.startswith("$"):
                # Treat as a cracked record; user unknown without correlation.
                creds.append({
                    "domain": default_domain, "user": "(hash-only)",
                    "secret": p, "secret_type": "password",
                    "extra": f"hashcat_show hash={h[:16]}…",
                })
                continue

        # 7. plain user:pass
        m = _UPASS_RE.match(line)
        if m:
            d, u = _split_domain(m.group("user"))
            creds.append({
                "domain": d or default_domain, "user": u,
                "secret": m.group("secret"), "secret_type": "password",
                "extra": "",
            })
            continue

    return creds


def _dedupe(creds: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for c in creds:
        key = (c["domain"].lower(), c["user"].lower(), c["secret"], c["secret_type"])
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _format_summary(creds: list[dict], source: str) -> str:
    by_type: dict[str, int] = {}
    for c in creds:
        by_type[c["secret_type"]] = by_type.get(c["secret_type"], 0) + 1
    lines = ["=== SUMMARY ==="]
    lines.append(f"source:  {source}")
    lines.append(f"total:   {len(creds)} credentials")
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        lines.append(f"  {t:16} {n}")
    lines.append("")
    sample = creds[:8]
    if sample:
        lines.append("sample (first 8):")
        for c in sample:
            full = f"{c['domain']}\\{c['user']}" if c["domain"] else c["user"]
            secret_short = c["secret"] if len(c["secret"]) <= 24 else c["secret"][:21] + "…"
            lines.append(f"  {full:30} {c['secret_type']:12} {secret_short}")
        if len(creds) > 8:
            lines.append(f"  ... +{len(creds) - 8} more")
    return "\n".join(lines)


def _escape(s: str) -> str:
    return s.replace('"', '\\"')


def _format_writes(creds: list[dict], source_label: str) -> str:
    out = ["=== STATE WRITES (relay to state-mgr) ==="]
    for c in creds:
        parts = [
            f'username={c["user"]}',
            f'secret_type={c["secret_type"]}',
            f'secret="{_escape(c["secret"])}"',
        ]
        if c["domain"]:
            parts.append(f'domain={c["domain"]}')
        src = source_label
        if c["extra"]:
            src = f"{source_label} ({c['extra']})"
        parts.append(f'source="{_escape(src)}"')
        out.append(f"[add-cred] " + " ".join(parts))
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="dump file (stdin accepted with '-')")
    ap.add_argument("--source", default="",
                    help="free-text source label for state.db (e.g. 'DC01 secretsdump')")
    ap.add_argument("--domain", default="",
                    help="default domain when the dump doesn't carry one (e.g. 'KETHALIS')")
    ap.add_argument("--writes-only", action="store_true")
    ap.add_argument("--no-writes", action="store_true")
    args = ap.parse_args()

    text = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(errors="replace")
    source_label = args.source or (args.path if args.path != "-" else "stdin")

    creds = _dedupe(_parse(text, args.domain))
    if not creds:
        print("No credentials parsed. Check the input format — supported: "
              "secretsdump SAM/NTDS, Kerberos keys, CLEARTEXT, GetUserSPNs, "
              "hashcat --show, plain user:pass, JSON-per-line.", file=sys.stderr)
        return 1

    if args.writes_only:
        print(_format_writes(creds, source_label))
        return 0

    print(_format_summary(creds, source_label))
    if not args.no_writes:
        print()
        print(_format_writes(creds, source_label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
