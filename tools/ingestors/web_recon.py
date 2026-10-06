#!/usr/bin/env python3
"""Parse web_recon.sh output → compact summary + state-mgr writes.

Companion to tools/payloads/web_recon.sh. One `=== SECTION ===` dump
in, one summary + batch of state-mgr writes out:

  === SUMMARY ===
    http://10.80.121.10:8080/  →  200 (12.3KB in 0.41s)
    server: nginx/1.24.0        powered-by: GitLab-CE
    title:  GitLab · Sign in
    frameworks: gitlab-logo, csrf-token
    cookies: _gitlab_session (HttpOnly, Secure, SameSite=Lax)
    tls: CN=gitlab.kethalis.local  SAN=gitlab.kethalis.local,10.80.121.10
    robots.txt: 12 disallowed paths (see raw)

  === STATE WRITES (relay to state-mgr) ===
    [update-target] ip=10.80.121.10 role="web (gitlab-ce)"
    [add-port] ip=10.80.121.10 port=8080 proto=tcp service=http version="nginx 1.24.0 (GitLab-CE)"

Usage:
  python3 tools/ingestors/web_recon.py <output> --url <URL>
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


_SECT_RE = re.compile(r"^=== (?P<name>[A-Z_]+) ===$")


def _parse(text: str) -> dict:
    out: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        m = _SECT_RE.match(line)
        if m:
            cur = m.group("name"); out[cur] = []; continue
        if cur: out[cur].append(line.rstrip())
    return out


def _first(sections: dict, name: str) -> str:
    v = sections.get(name) or []
    for line in v:
        if line.strip(): return line.strip()
    return ""


def _lines(sections: dict, name: str) -> list[str]:
    return [l for l in (sections.get(name) or []) if l.strip()]


def _fingerprint(sections: dict) -> dict:
    out = {"server": "", "powered_by": "", "generator": "", "frameworks": []}
    for line in _lines(sections, "FINGERPRINT"):
        low = line.lower()
        if low.startswith("server:"):
            out["server"] = line.split(":", 1)[1].strip()
        elif low.startswith("x-powered-by:"):
            out["powered_by"] = line.split(":", 1)[1].strip()
        elif low.startswith("x-generator:"):
            out["generator"] = line.split(":", 1)[1].strip()
        elif line.startswith("---"):
            continue
        else:
            # Body-side framework token (one per line after ---)
            if line.strip():
                out["frameworks"].append(line.strip())
    meta = _first(sections, "META_GENERATOR")
    if meta:
        m = re.search(r'content="([^"]+)"', meta)
        if m: out["generator"] = m.group(1)
    return out


def _cookies(sections: dict) -> list[str]:
    cs = []
    for line in _lines(sections, "COOKIES"):
        m = re.search(r"set-cookie:\s*([^=;]+)=", line, re.I)
        if m:
            flags = [f.strip() for f in line.split(";")[1:] if f.strip()]
            flag_tags = []
            for f in flags:
                low = f.lower()
                if low == "httponly": flag_tags.append("HttpOnly")
                elif low == "secure": flag_tags.append("Secure")
                elif low.startswith("samesite="): flag_tags.append(f"SameSite={f.split('=',1)[1]}")
            tag = f"{m.group(1).strip()}"
            if flag_tags: tag += " (" + ", ".join(flag_tags) + ")"
            cs.append(tag)
    return cs


def _status_bits(sections: dict) -> tuple[str, str, str]:
    s = _first(sections, "STATUS")
    # "200 12345b 0.410s https://.../"
    parts = s.split()
    code = parts[0] if parts else "?"
    size = parts[1] if len(parts) > 1 else "?"
    time_ = parts[2] if len(parts) > 2 else "?"
    return code, size, time_


def _tls_cn_san(sections: dict) -> tuple[str, str]:
    cn = san = ""
    for line in _lines(sections, "TLS"):
        if "subject=" in line:
            m = re.search(r"CN\s*=\s*([^,/]+)", line)
            if m: cn = m.group(1).strip()
        if "X509v3 Subject Alternative Name" in line or "DNS:" in line:
            dns = re.findall(r"DNS:([^,\s]+)", line)
            ips = re.findall(r"IP Address:([^,\s]+)", line)
            parts = dns + ips
            if parts: san = ",".join(parts[:6])
    return cn, san


def _dominant_product(fp: dict) -> str:
    """Pick a 1-line product tag for role / version. Simple heuristic."""
    tags = []
    for src in (fp["generator"], fp["powered_by"], fp["server"]):
        if src: tags.append(src)
    body_tags = []
    for f in fp["frameworks"]:
        if "gitlab" in f.lower(): body_tags.append("GitLab")
        elif "wp-content" in f or "wp-includes" in f: body_tags.append("WordPress")
        elif "/_next/" in f or "__NEXT_DATA__" in f: body_tags.append("Next.js")
        elif "jenkins" in f.lower(): body_tags.append("Jenkins")
        elif "data-react-" in f: body_tags.append("React")
    tag = ", ".join(dict.fromkeys(body_tags + tags))[:120]
    return tag


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="web_recon output (- for stdin)")
    ap.add_argument("--url", required=True, help="URL the recon ran against")
    ap.add_argument("--writes-only", action="store_true")
    args = ap.parse_args()

    text = sys.stdin.read() if args.path == "-" else Path(args.path).read_text(errors="replace")
    sections = _parse(text)
    if not sections:
        print("ERROR: no `=== SECTION ===` markers — did you run web_recon.sh?",
              file=sys.stderr)
        return 2

    pu = urlparse(args.url)
    host = pu.hostname or ""
    port = pu.port or (443 if pu.scheme == "https" else 80)
    try:
        ipaddress.ip_address(host)
        ip = host
    except ValueError:
        ip = ""  # hostname-only URL; teammate supplies IP via state.db

    fp = _fingerprint(sections)
    code, size, elapsed = _status_bits(sections)
    cookies = _cookies(sections)
    title = _first(sections, "TITLE")
    cn, san = _tls_cn_san(sections)
    product = _dominant_product(fp)

    out = ["=== SUMMARY ==="]
    out.append(f"{args.url}  →  {code} ({size} in {elapsed})")
    if fp["server"] or fp["powered_by"] or fp["generator"]:
        out.append(f"server: {fp['server'] or '-'}" +
                   (f"   powered-by: {fp['powered_by']}" if fp["powered_by"] else "") +
                   (f"   generator: {fp['generator']}" if fp["generator"] else ""))
    if title:
        out.append(f"title:  {title[:120]}")
    if fp["frameworks"]:
        out.append("frameworks: " + ", ".join(fp["frameworks"][:6]))
    if cookies:
        out.append("cookies: " + "; ".join(cookies[:6]))
    if cn or san:
        out.append(f"tls: " + (f"CN={cn}" if cn else "") +
                   (f"  SAN={san}" if san else ""))
    robots_count = len([l for l in _lines(sections, "ROBOTS")
                        if l.lower().startswith("disallow:")])
    if robots_count:
        out.append(f"robots.txt: {robots_count} disallowed paths")

    if not args.writes_only:
        print("\n".join(out))

    writes = ["=== STATE WRITES (relay to state-mgr) ==="]
    if ip:
        if product:
            writes.append(f"[update-target] ip={ip} "
                          f'role="web ({product})"' )
        else:
            writes.append(f"[update-target] ip={ip} role=\"web\"")
        version_str = ""
        if fp["server"]:
            version_str = fp["server"]
            if fp["powered_by"]:
                version_str += f" ({fp['powered_by']})"
        pparts = [f"ip={ip}", f"port={port}", "proto=tcp",
                  f"service={'https' if pu.scheme == 'https' else 'http'}"]
        if version_str:
            pparts.append(f'version="{version_str}"')
        writes.append("[add-port] " + " ".join(pparts))
    else:
        writes.append(f"# URL host '{host}' is a hostname — "
                      f"look up its IP in state.db and attach the writes manually.")

    if args.writes_only:
        print("\n".join(writes))
        return 0
    print()
    print("\n".join(writes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
