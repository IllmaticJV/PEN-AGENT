#!/usr/bin/env bash
# Launch PEN-AGENT: starts shell-server, then Claude Code.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${SHELL_SSE_PORT:-8022}"

# Parse run.sh-specific flags, pass the rest to claude
claude_args=()
for arg in "$@"; do
    case "$arg" in
        --yolo)       claude_args+=("--dangerously-skip-permissions") ;;
        *)            claude_args+=("$arg") ;;
    esac
done

skill="/pen-agent-ctf"

# Check for existing shell-server with active sessions
if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
    status=$(curl -s "http://127.0.0.1:${PORT}/status" 2>/dev/null || echo '{}')
    count=$(echo "$status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)

    if [[ "$count" -gt 0 ]]; then
        echo "[shell-server] ${count} active session(s) from previous run:"
        echo "$status" | python3 -c "
import sys, json
from datetime import datetime, timezone
data = json.load(sys.stdin)
for s in data.get('sessions', []):
    t = datetime.fromisoformat(s['connected_at'].replace('Z','+00:00'))
    age = datetime.now(timezone.utc) - t
    hrs, rem = divmod(int(age.total_seconds()), 3600)
    mins = rem // 60
    if hrs > 0:
        elapsed = f'{hrs}h{mins}m ago'
    else:
        elapsed = f'{mins}m ago'
    print(f\"  - {s['id']} ({s['label']}, {s['addr']}, {elapsed})\")
" 2>/dev/null
        echo ""
        read -rp "  [k]eep sessions / [c]lear all / [r]estart server? [k/c/r] " choice
        case "${choice,,}" in
            c)
                curl -s -X POST "http://127.0.0.1:${PORT}/clear" >/dev/null 2>&1
                echo "  Sessions cleared."
                ;;
            r)
                pkill -f "shell-server.*server.py" 2>/dev/null || true
                sleep 1
                bash tools/shell-server/start.sh
                echo "  Server restarted."
                ;;
            *)
                echo "  Keeping sessions."
                ;;
        esac
    fi
else
    bash tools/shell-server/start.sh
fi

# Detect and start Metasploit RPC (C2 backend)
if command -v msfrpcd &>/dev/null && command -v msfconsole &>/dev/null; then
    export PEN_AGENT_MSF_AVAILABLE=1
    echo "[c2] Metasploit detected"
    MSF_CFG="engagement/msfrpc.yaml"
    MSF_PORT="${MSF_RPC_PORT:-55553}"
    if pgrep -f "msfrpcd" &>/dev/null && [[ ! -f "$MSF_CFG" ]]; then
        # msfrpcd is running but nothing records its credentials — almost
        # always an orphaned daemon from a previous run/engagement (it's a
        # detached background process, so it outlives the session that
        # started it). Restart it clean rather than leaving metasploit-server
        # and msf-console unable to connect to a daemon nobody can log into.
        echo "[c2] msfrpcd is running but engagement/msfrpc.yaml is missing — stale daemon from a previous run, restarting with fresh credentials"
        pkill -f "msfrpcd" 2>/dev/null || true
        sleep 1
    fi
    if ! pgrep -f "msfrpcd" &>/dev/null; then
        mkdir -p engagement
        MSF_PASS="${MSF_RPC_PASSWORD:-$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)}"
        msfrpcd -P "$MSF_PASS" -U msf -a 127.0.0.1 -p "$MSF_PORT" &>/dev/null &
        cat > "$MSF_CFG" <<YAML
host: 127.0.0.1
port: ${MSF_PORT}
user: msf
password: ${MSF_PASS}
ssl: true
YAML
        chmod 600 "$MSF_CFG"
        echo "[c2] msfrpcd started on 127.0.0.1:${MSF_PORT} (config: ${MSF_CFG})"
        sleep 2  # brief wait for RPC to bind
    else
        echo "[c2] msfrpcd already running"
    fi
    # Start metasploit-server MCP
    bash tools/metasploit-server/start.sh 2>/dev/null && echo "[c2] Metasploit MCP ready" \
        || echo "[c2] Metasploit MCP failed to start (check engagement/msfrpc.yaml)"
else
    echo "[c2] Metasploit not found — shell-server only (install metasploit-framework for C2)"
fi

exec claude "${claude_args[@]}" \
    --append-system-prompt "On activation, immediately invoke the skill: ${skill}"
