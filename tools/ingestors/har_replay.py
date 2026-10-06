#!/usr/bin/env python3
"""HAR → runnable bash curl script. Replays a browser-captured flow.

Why: when the operator captures a working auth / exploit flow in the
browser (DevTools "Export HAR" or Burp → copy as HAR) it's a 200 KB
JSON blob. The teammate just needs to re-run the sequence
end-to-end, substituting the dynamic bits (session cookie, CSRF
token, bearer, path params). Hand it to an LLM and it eats tokens
and often transcribes URL-encodings wrong.

This builds a `.sh` of ordered `curl` calls:
  - Preserves order, Method, URL, headers (minus auto-set ones),
    body (form / JSON / raw).
  - Uses a single `-b <cookiejar>` + `-c <cookiejar>` so cookies set
    by one request carry to the next.
  - Pulls CSRF-ish tokens out of HTML responses (meta name="csrf-token",
    hidden input `name="authenticity_token"`, etc.) into bash vars so
    the subsequent request can reference them.
  - Marks obviously-sensitive values as `${LHOST}` / `${BEARER}` /
    `${SESSION}` placeholders when they appear to be dynamic.

Also emits a `.md` sidecar listing what to override at re-trigger and
which responses to assert on (status codes, redirect targets).

Usage:
  python3 tools/ingestors/har_replay.py <in.har> <out.sh>
                                        [--filter <regex-URL>]
                                        [--only-xhr]
                                        [--placeholders KEY=VALUE,...]
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path


_SKIP_REQ_HEADERS = {
    "host", "content-length", "connection", "accept-encoding",
    "if-modified-since", "if-none-match", "cache-control", "pragma",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "dnt", "upgrade-insecure-requests",
}


def _sh(s: str) -> str:
    return shlex.quote(s)


def _bash_var(name: str) -> str:
    """URL/token-looking value → bash var reference. Simple heuristic."""
    return "${" + re.sub(r"[^A-Z0-9_]", "_", name.upper()) + "}"


def _extract_token_regex(resp_text: str) -> dict[str, str]:
    """Pull a few common CSRF/token patterns from an HTML/text body."""
    out = {}
    patterns = [
        (r'name="csrf-token"\s+content="([^"]+)"', "CSRF_TOKEN"),
        (r'name="authenticity_token"\s+value="([^"]+)"', "CSRF_TOKEN"),
        (r'<input[^>]+name="_token"[^>]+value="([^"]+)"', "CSRF_TOKEN"),
        (r'"csrf_token"\s*:\s*"([^"]+)"', "CSRF_TOKEN"),
        (r'XSRF-TOKEN=([^;]+)', "XSRF_TOKEN"),
        (r'Bearer\s+([A-Za-z0-9._-]{20,})', "BEARER"),
    ]
    for pat, name in patterns:
        m = re.search(pat, resp_text or "")
        if m and name not in out:
            out[name] = m.group(1)
    return out


def _header_dict(headers: list) -> dict[str, str]:
    out = {}
    for h in headers or []:
        n = (h.get("name") or "").lower()
        if n and n not in _SKIP_REQ_HEADERS and not n.startswith(":"):
            out[h["name"]] = h.get("value", "")
    return out


def _body_block(req: dict) -> str | None:
    pd = req.get("postData") or {}
    mime = (pd.get("mimeType") or "").lower()
    if "text" in pd and pd["text"]:
        return pd["text"]
    params = pd.get("params") or []
    if params:
        if "application/x-www-form-urlencoded" in mime:
            return "&".join(f"{p.get('name','')}={p.get('value','')}" for p in params)
        if "multipart/form-data" in mime:
            # Fallback — the real multipart boundary is lost in HAR; dump
            # as "-F name=value" via a hint in the script.
            return "__MULTIPART__" + json.dumps(
                [(p.get("name"), p.get("value") or p.get("fileName", "")) for p in params]
            )
    return None


def _build_curl(entry: dict, idx: int, jar: str,
                token_vars: dict[str, str]) -> str:
    req = entry.get("request") or {}
    resp = entry.get("response") or {}
    method = req.get("method", "GET")
    url = req.get("url", "")
    status = resp.get("status", 0)
    headers = _header_dict(req.get("headers") or [])
    body = _body_block(req)

    lines = []
    lines.append(f"# -- request {idx}: {method} {url}   # (recorded response: {status})")
    cmd = ["curl", "-sk", "-o", f"/tmp/resp_{idx}.out", "-w",
           "'%{http_code} %{size_download}b %{time_total}s\\n'",
           "-b", jar, "-c", jar, "-X", method]

    for name, value in headers.items():
        # Swap in bash var when the value matches a token we extracted
        for v_name, v_val in token_vars.items():
            if v_val and v_val in value:
                value = value.replace(v_val, _bash_var(v_name))
        cmd.append("-H")
        cmd.append(_sh(f"{name}: {value}"))

    if body is not None:
        if body.startswith("__MULTIPART__"):
            params = json.loads(body[len("__MULTIPART__"):])
            for n, v in params:
                cmd.append("-F")
                cmd.append(_sh(f"{n}={v}"))
        else:
            # Replace token values inside body too.
            for v_name, v_val in token_vars.items():
                if v_val and v_val in body:
                    body = body.replace(v_val, _bash_var(v_name))
            cmd.append("--data-binary")
            cmd.append(_sh(body))

    cmd.append(_sh(url))
    lines.append(" ".join(cmd))
    lines.append(f"echo \"---> request {idx} done\"")

    # If the entry's response body includes a known CSRF-ish token,
    # extract it into a bash var after this request so subsequent
    # requests can reference ${CSRF_TOKEN} etc.
    rtext = (resp.get("content") or {}).get("text") or ""
    found = _extract_token_regex(rtext)
    for v_name, v_val in found.items():
        lines.append(
            f"{v_name}=$(grep -oE '"
            + {
                "CSRF_TOKEN": r'(?:csrf-token"\\s+content="[^"]+|authenticity_token"\\s+value="[^"]+|_token"\\s+value="[^"]+)',
                "XSRF_TOKEN": r'XSRF-TOKEN=[^;]+',
                "BEARER":     r'Bearer [A-Za-z0-9._-]{20,}',
            }.get(v_name, re.escape(v_val))
            + f"' /tmp/resp_{idx}.out | head -1 | grep -oE '[^\"=]+$')"
        )
        # Keep track so later requests substitute it too.
        token_vars[v_name] = v_val
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("har", help=".har file (DevTools export / Burp 'copy as HAR')")
    ap.add_argument("out_sh", help="output path for the generated .sh")
    ap.add_argument("--filter", default="",
                    help="only keep entries whose URL matches this regex")
    ap.add_argument("--only-xhr", action="store_true",
                    help="skip entries whose Content-Type looks like a static asset")
    ap.add_argument("--placeholders", default="",
                    help="comma-separated KEY=initial substitutions "
                         "(e.g. 'LHOST=10.80.121.1,BEARER=xxx')")
    args = ap.parse_args()

    try:
        har = json.loads(Path(args.har).read_text(errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr); return 2
    entries = (har.get("log") or {}).get("entries") or []
    if not entries:
        print("ERROR: no entries in HAR", file=sys.stderr); return 2

    pattern = re.compile(args.filter) if args.filter else None
    static_mimes = re.compile(r"(image/|font/|text/css|application/javascript|application/woff)")

    kept = []
    for e in entries:
        url = (e.get("request") or {}).get("url", "")
        if pattern and not pattern.search(url):
            continue
        if args.only_xhr:
            mt = ""
            for h in (e.get("response") or {}).get("headers") or []:
                if (h.get("name") or "").lower() == "content-type":
                    mt = h.get("value", ""); break
            if static_mimes.search(mt):
                continue
        kept.append(e)
    if not kept:
        print("ERROR: no entries left after --filter / --only-xhr",
              file=sys.stderr); return 2

    # Pre-seed token vars from --placeholders
    token_vars: dict[str, str] = {}
    for pair in args.placeholders.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            token_vars[k.strip().upper()] = v.strip()

    jar = "/tmp/har_replay.cookies"

    out = ["#!/usr/bin/env bash",
           "# Auto-generated by har_replay.py",
           "# Re-plays a captured browser flow. Override placeholders at run:",
           "#   LHOST=10.80.121.1 BEARER=... bash <this script>",
           "",
           "set -euo pipefail",
           f'rm -f {jar}; true > {jar}',
           ""]
    # Expose any pre-seeded vars
    for k, v in token_vars.items():
        out.append(f'{k}="${{{k}:-{v}}}"')
    out.append("")
    for i, e in enumerate(kept, 1):
        out.append(_build_curl(e, i, jar, token_vars))
        out.append("")

    outp = Path(args.out_sh)
    outp.write_text("\n".join(out))
    outp.chmod(0o755)
    print(f"wrote: {outp}")
    print(f"requests: {len(kept)}")
    if token_vars:
        print("tokens detected / pre-seeded: " + ", ".join(token_vars))
    print()
    print(f"Re-run:  bash {outp}")
    print("Overrides: LHOST=... BEARER=... bash <path>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
