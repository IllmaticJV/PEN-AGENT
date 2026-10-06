#!/usr/bin/env bash
# PEN-AGENT web_recon — one-shot HTTP target triage.
# Companion to shell_recon.sh for web endpoints. Deterministic
# `=== SECTION ===` output that web_recon.py parses.
#
# Usage: bash tools/payloads/web_recon.sh <URL>
#
# Pulls (fast, bounded 15s total): status + headers, body size, title,
# meta generator, cookies, robots.txt, sitemap.xml, security.txt,
# common framework fingerprints, favicon hash, TLS cert subject/SAN
# (https only). Skips external tools unless present (whatweb, httpx).

set -euo pipefail
URL="${1:-}"
if [[ -z "$URL" ]]; then
    echo "usage: web_recon.sh <URL>" >&2; exit 2
fi

CURL=(curl -sk --connect-timeout 5 --max-time 10 -L)

echo "=== URL ==="; echo "$URL"
echo "=== HEAD ==="
"${CURL[@]}" -I "$URL" | head -40

echo "=== STATUS ==="
"${CURL[@]}" -o /dev/null -w "%{http_code} %{size_download}b %{time_total}s %{url_effective}\n" "$URL"

echo "=== TITLE ==="
"${CURL[@]}" "$URL" 2>/dev/null | tr -d '\n' | grep -oE '<title[^>]*>[^<]*</title>' | head -1 | sed -E 's|</?title[^>]*>||g'

echo "=== META_GENERATOR ==="
"${CURL[@]}" "$URL" 2>/dev/null | grep -oE '<meta[^>]+name="generator"[^>]*>' | head -3

echo "=== COOKIES ==="
"${CURL[@]}" -D - -o /dev/null "$URL" | grep -i '^set-cookie:' | head -10

echo "=== ROBOTS ==="
"${CURL[@]}" "${URL%/}/robots.txt" 2>/dev/null | head -40

echo "=== SITEMAP ==="
"${CURL[@]}" "${URL%/}/sitemap.xml" 2>/dev/null | head -20

echo "=== SECURITY_TXT ==="
"${CURL[@]}" "${URL%/}/.well-known/security.txt" 2>/dev/null | head -20

echo "=== FINGERPRINT ==="
body=$("${CURL[@]}" "$URL" 2>/dev/null || true)
headers=$("${CURL[@]}" -I "$URL" 2>/dev/null || true)
# Pull common framework signals via simple grep patterns.
echo "$headers" | grep -iE '^(server|x-powered-by|x-aspnet-version|x-generator|via|x-request-id|x-runtime):' | head -10
echo "---"
# Body-side cheap tells
echo "$body" | grep -oE 'wp-content|wp-includes|/_next/|/static/js/|__NEXT_DATA__|gitlab-logo|gitlab/gon|jenkins-session|csrf-token|data-react-' | sort -u | head -10

echo "=== FAVICON ==="
if command -v md5sum >/dev/null; then
    "${CURL[@]}" "${URL%/}/favicon.ico" 2>/dev/null | md5sum | awk '{print "md5:" $1}'
fi

echo "=== TLS ==="
if [[ "$URL" == https://* ]]; then
    host_port="${URL#https://}"; host_port="${host_port%%/*}"
    host="${host_port%%:*}"
    port="${host_port##*:}"; [[ "$port" == "$host" ]] && port=443
    echo | timeout 5 openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null \
        | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null | head -20 || true
fi

echo "=== WHATWEB ==="
if command -v whatweb >/dev/null; then
    whatweb --colour=never --no-errors -a 3 "$URL" 2>/dev/null | head -4
fi

echo "=== DONE ==="
