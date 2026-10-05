#!/usr/bin/env bash
# Launch PEN-AGENT: starts shell-server + skill-router (+ Metasploit if
# installed), then Claude Code.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${SHELL_SSE_PORT:-8022}"
# Where generate-token.sh writes the portal token (must match server.py's path).
TOKEN_FILE="${HOME}/.config/pen-agent/viewer-token"

# Parse run.sh-specific flags, pass the rest to claude
CLEAN_START=0
claude_args=()
for arg in "$@"; do
    case "$arg" in
        --yolo|--dangerously-skip-permissions)
            echo "run.sh: '$arg' is not supported — PEN-AGENT runs in standard" >&2
            echo "        permission mode only. MCP tools are pre-allowed in" >&2
            echo "        .claude/settings.json; extend its 'allow' list to cut prompts" >&2
            echo "        (see /fewer-permission-prompts)." >&2
            exit 2 ;;
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

# The two slow daemons — skill-router (loads an embedding model, ~30s) and the
# Metasploit C2 (msfconsole load, up to ~90s) — are independent, so bring them
# up in PARALLEL and wait once, instead of in series. Cuts launch time to about
# the slower of the two. (shell-server above is already up; it may prompt, so
# it stays in the foreground before this.)
_start_skill_router() {
    echo "[skill-router] starting (loads embedding model, may take ~30s)…"
    if bash tools/skill-router/start.sh; then
        echo "[skill-router] ready (SSE on 127.0.0.1:${SKILL_ROUTER_SSE_PORT:-8023})"
    else
        echo "[skill-router] WARNING: failed to start — teammates won't be able to load skills." >&2
        echo "               Check the index: uv run --directory tools/skill-router python indexer.py" >&2
    fi
}
# c2-up.sh prefers an interactive msfconsole+msgrpc in tmux (full operator
# console: `tmux attach -t pen-msf`), falls back to headless msfrpcd without
# tmux. Agents connect over RPC either way (engagement/msfrpc.yaml).
_start_c2() {
    echo "[c2] Metasploit detected"
    if bash tools/metasploit-server/c2-up.sh; then
        bash tools/metasploit-server/start.sh 2>/dev/null && echo "[c2] Metasploit MCP ready" \
            || echo "[c2] Metasploit MCP failed to start (check engagement/msfrpc.yaml)"
    else
        echo "[c2] C2 backend did not start — see messages above; continuing with shell-server"
    fi
}

_start_skill_router & sr_pid=$!
c2_pid=""
if command -v msfconsole &>/dev/null; then
    export PEN_AGENT_MSF_AVAILABLE=1   # set in THIS shell so it reaches claude
    _start_c2 & c2_pid=$!
else
    echo "[c2] Metasploit not found — shell-server only (install metasploit-framework for C2)"
fi
wait "$sr_pid" 2>/dev/null || true
[[ -n "$c2_pid" ]] && { wait "$c2_pid" 2>/dev/null || true; }

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

# `exec claude` launches a full-screen TUI that hides this startup scrollback —
# including the portal URL and operator token. Persist the access details to a
# file the operator can read at any time (e.g. from a second terminal, or by
# asking Claude to `cat` it), and print them as the LAST thing before Claude so
# they reappear the moment the TUI exits.
write_access_summary() {
    local pport="${PORTAL_PORT:-8099}"
    local out_dir="${HOME}/.config/pen-agent"
    local out="${out_dir}/portal-access.txt"
    mkdir -p "$out_dir" 2>/dev/null || true
    {
        echo "PEN-AGENT — operator portal access"
        echo "generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo
        if [[ -s "$TOKEN_FILE" ]]; then
            local host_ip; host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
            echo "Portal (token required):"
            echo "  local:   http://127.0.0.1:${pport}"
            [[ -n "$host_ip" ]] && echo "  remote:  http://${host_ip}:${pport}"
            echo "  token:   $(cat "$TOKEN_FILE")"
        else
            echo "Portal (localhost-only, no auth):"
            echo "  http://127.0.0.1:${pport}"
            echo "  (run 'bash operator/portal/generate-token.sh' for remote access + a token)"
        fi
        echo
        echo "Attach to the live consoles:"
        echo "  portal → tmux attach -t ${PEN_AGENT_PORTAL_TMUX:-pen-portal}"
        command -v msfconsole &>/dev/null \
            && echo "  msf    → tmux attach -t ${PEN_AGENT_MSF_TMUX:-pen-msf}"
    } > "$out" 2>/dev/null || true
    chmod 600 "$out" 2>/dev/null || true

    echo
    echo "────────────────────────────────────────────────────────────"
    cat "$out" 2>/dev/null || true
    echo
    echo "  Saved to ${out}"
    echo "  Lost it after Claude starts?  cat ${out}"
    echo "────────────────────────────────────────────────────────────"
    echo
}
write_access_summary

exec claude "${claude_args[@]}" \
    --append-system-prompt "On activation, immediately invoke the skill: ${skill}"
