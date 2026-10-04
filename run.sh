#!/usr/bin/env bash
# Launch PEN-AGENT: starts shell-server + skill-router (+ Metasploit if
# installed), then Claude Code.
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

# Start skill-router as a shared SSE daemon (loads the embedding model once,
# so every agent-team teammate connects to one warm instance instead of
# standing up its own slow copy). Backgrounded so its model load doesn't
# delay launch — the readiness wait lives in start.sh.
echo "[skill-router] starting (loads embedding model, may take ~30s)…"
if bash tools/skill-router/start.sh; then
    echo "[skill-router] ready (SSE on 127.0.0.1:${SKILL_ROUTER_SSE_PORT:-8023})"
else
    echo "[skill-router] WARNING: failed to start — teammates won't be able to load skills." >&2
    echo "               Check the index: uv run --directory tools/skill-router python indexer.py" >&2
fi

# Detect and start Metasploit (C2 backend). c2-up.sh prefers an interactive
# msfconsole+msgrpc in tmux (full operator console: `tmux attach -t pen-msf`)
# and falls back to headless msfrpcd without tmux. Agents connect over RPC
# either way (engagement/msfrpc.yaml).
if command -v msfconsole &>/dev/null; then
    export PEN_AGENT_MSF_AVAILABLE=1
    echo "[c2] Metasploit detected"
    if bash tools/metasploit-server/c2-up.sh; then
        bash tools/metasploit-server/start.sh 2>/dev/null && echo "[c2] Metasploit MCP ready" \
            || echo "[c2] Metasploit MCP failed to start (check engagement/msfrpc.yaml)"
    else
        echo "[c2] C2 backend did not start — see messages above; continuing with shell-server"
    fi
else
    echo "[c2] Metasploit not found — shell-server only (install metasploit-framework for C2)"
fi

exec claude "${claude_args[@]}" \
    --append-system-prompt "On activation, immediately invoke the skill: ${skill}"
