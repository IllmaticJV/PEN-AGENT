#!/usr/bin/env bash
# Launch PEN-AGENT: starts shell-server + skill-router (+ Metasploit if
# installed), then Claude Code.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${SHELL_SSE_PORT:-8022}"

# Parse run.sh-specific flags, pass the rest to claude
CLEAN_START=0
claude_args=()
for arg in "$@"; do
    case "$arg" in
        --yolo)        claude_args+=("--dangerously-skip-permissions") ;;
        --clean-start) CLEAN_START=1 ;;
        *)             claude_args+=("$arg") ;;
    esac
done

skill="/pen-agent-ctf"

# --clean-start: tear down anything left over from a previous run that would
# otherwise be silently reused — the MCP SSE daemons are idempotent-by-port, so
# a stale instance (pointing at old engagement state/creds) keeps serving unless
# we kill it. Also drops the Metasploit C2 (tmux console + any headless daemon),
# orphaned pen-agent containers, and the runtime C2 coordination files that are
# tied to the now-dead Framework. Engagement DATA (state.db, findings, scope,
# evidence) is left untouched.
clean_start() {
    echo "[clean-start] tearing down stale PEN-AGENT services…"
    for svc in shell-server skill-router metasploit-server; do
        pkill -f "${svc}.*server.py" 2>/dev/null && echo "  stopped ${svc}" || true
    done
    pkill -f "operator/portal.*server.py" 2>/dev/null && echo "  stopped operator portal" || true
    for sess in "${PEN_AGENT_MSF_TMUX:-pen-msf}" "${PEN_AGENT_PORTAL_TMUX:-pen-portal}"; do
        if command -v tmux &>/dev/null && tmux has-session -t "$sess" 2>/dev/null; then
            tmux kill-session -t "$sess" 2>/dev/null && echo "  killed tmux session ($sess)" || true
        fi
    done
    pkill -f msfrpcd 2>/dev/null && echo "  stopped msfrpcd" || true
    if command -v docker &>/dev/null; then
        local orphans; orphans="$(docker ps --filter name=pen-agent- -q 2>/dev/null)"
        if [[ -n "$orphans" ]]; then
            docker kill $orphans >/dev/null 2>&1 && echo "  killed orphaned pen-agent container(s)" || true
        fi
    fi
    # Regenerated on fresh start; operator-sessions.json is cleared because its
    # session IDs refer to the old Framework and MSF reuses small session IDs —
    # a stale reservation would wrongly block a new session that reuses the ID.
    rm -f engagement/msfrpc.yaml engagement/.msf-init.rc engagement/operator-sessions.json 2>/dev/null || true
    sleep 1  # let listener sockets free before the start scripts re-bind
    echo "[clean-start] done — starting fresh."
}

[[ "$CLEAN_START" == 1 ]] && clean_start

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

# Auto-start the operator portal (scope · status · MSF logs) in its own tmux
# session so it's always up without a second manual command. Idempotent:
# skips if the session already exists or something already holds the port.
start_portal() {
    local sess="${PEN_AGENT_PORTAL_TMUX:-pen-portal}"
    local pport="${PORTAL_PORT:-8099}"
    if ! command -v uv &>/dev/null; then
        echo "[portal] uv not found — start manually once installed: bash operator/portal/start.sh"
        return
    fi
    if ! command -v tmux &>/dev/null; then
        echo "[portal] tmux not found — run it in the foreground: bash operator/portal/start.sh"
        return
    fi
    if tmux has-session -t "$sess" 2>/dev/null; then
        echo "[portal] already running in tmux '${sess}' → http://127.0.0.1:${pport}"
        return
    fi
    if ss -tln 2>/dev/null | grep -q ":${pport} "; then
        echo "[portal] port ${pport} already in use — not starting a second instance"
        return
    fi
    tmux new-session -d -s "$sess" "bash '$(pwd)/operator/portal/start.sh'"
    echo "[portal] started in tmux '${sess}' → http://127.0.0.1:${pport}  (attach: tmux attach -t ${sess})"
}
start_portal

exec claude "${claude_args[@]}" \
    --append-system-prompt "On activation, immediately invoke the skill: ${skill}"
