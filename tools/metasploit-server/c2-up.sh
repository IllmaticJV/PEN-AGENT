#!/usr/bin/env bash
# Bring up the Metasploit C2 backend for PEN-AGENT and record its RPC creds.
#
# Preferred: an interactive msfconsole running the msgrpc plugin inside tmux —
# ONE Framework instance, so `tmux attach -t <session>` is a full, real
# msfconsole sharing the exact sessions/jobs the agents drive over RPC. That
# means `sessions -i`, the meterpreter interactive prompt, tab-complete and
# scrollback all work for the operator, which the RPC/web console cannot do.
#
# Falls back to a headless msfrpcd when tmux is unavailable (agents still work
# via RPC, but there is no live operator console — install tmux for that).
#
# Idempotent: if the C2 is already up AND engagement/msfrpc.yaml exists, does
# nothing. A running instance with no recorded creds is treated as stale (an
# orphan from a previous run) and restarted so clients can actually log in.
#
# Env:
#   MSF_RPC_PORT        RPC port (default 55553)
#   MSF_RPC_PASSWORD    RPC password (default: random 24 chars)
#   PEN_AGENT_MSF_TMUX  tmux session name (default pen-msf)
#   ENGAGEMENT_DIR      engagement dir (default engagement)
#
# Exit: 0 C2 up / already up · 2 msfconsole not found · 3 no way to start RPC
set -euo pipefail

ENGAGEMENT_DIR="${ENGAGEMENT_DIR:-engagement}"
CFG="${ENGAGEMENT_DIR}/msfrpc.yaml"
PORT="${MSF_RPC_PORT:-55553}"
TMUX_SESSION="${PEN_AGENT_MSF_TMUX:-pen-msf}"

command -v msfconsole &>/dev/null || { echo "[c2] msfconsole not found on PATH"; exit 2; }
mkdir -p "${ENGAGEMENT_DIR}/evidence/msf-sessions"

_gen_pass() { head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24; }
_port_up()  { (echo >"/dev/tcp/127.0.0.1/${PORT}") &>/dev/null; }
_wait_rpc() { local n="${1:-60}"; while ((n-- > 0)); do _port_up && return 0; sleep 1; done; return 1; }

_write_cfg() {
    cat > "$CFG" <<YAML
host: 127.0.0.1
port: ${PORT}
user: msf
password: ${1}
ssl: true
YAML
    chmod 600 "$CFG"
}

# ── Preferred path: interactive msfconsole + msgrpc in tmux ──────────────────
if command -v tmux &>/dev/null; then
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null && [[ ! -f "$CFG" ]]; then
        echo "[c2] msf console in tmux '${TMUX_SESSION}' has no recorded creds — stale, restarting"
        tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
        sleep 1
    fi
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        echo "[c2] msf console already running in tmux '${TMUX_SESSION}' (attach: tmux attach -t ${TMUX_SESSION})"
        exit 0
    fi
    PASS="${MSF_RPC_PASSWORD:-$(_gen_pass)}"
    ABS_ENG="$(cd "$ENGAGEMENT_DIR" && pwd)"
    RC="${ABS_ENG}/.msf-init.rc"
    # Resource file avoids all shell-quoting pain for the -x string. It holds
    # the RPC password, so lock it down; engagement/ is gitignored.
    cat > "$RC" <<RC
spool ${ABS_ENG}/evidence/msf-console.log
setg SessionLogging true
load msgrpc ServerHost=127.0.0.1 ServerPort=${PORT} User=msf Pass=${PASS} SSL=true
RC
    chmod 600 "$RC"
    tmux new-session -d -s "$TMUX_SESSION" "msfconsole -q -r '${RC}'"
    _write_cfg "$PASS"
    echo "[c2] msfconsole+msgrpc starting in tmux '${TMUX_SESSION}' on 127.0.0.1:${PORT}"
    echo "[c2]   full interactive console → tmux attach -t ${TMUX_SESSION}   (detach: Ctrl-b then d)"
    # Framework load + plugin bind is slow (tens of seconds on first run).
    if _wait_rpc 90; then
        echo "[c2] RPC listening on 127.0.0.1:${PORT}"
    else
        echo "[c2] WARNING: RPC not listening after 90s — msfconsole may still be loading; check: tmux attach -t ${TMUX_SESSION}"
    fi
    exit 0
fi

# ── Fallback: headless msfrpcd (no live operator console) ────────────────────
if command -v msfrpcd &>/dev/null; then
    if pgrep -f "msfrpcd" &>/dev/null && [[ ! -f "$CFG" ]]; then
        echo "[c2] msfrpcd running without recorded creds — stale, restarting"
        pkill -f "msfrpcd" 2>/dev/null || true
        sleep 1
    fi
    if pgrep -f "msfrpcd" &>/dev/null; then
        echo "[c2] msfrpcd already running"
        exit 0
    fi
    echo "[c2] tmux not found — starting headless msfrpcd (no live console; install tmux for full msfconsole usability)"
    PASS="${MSF_RPC_PASSWORD:-$(_gen_pass)}"
    msfrpcd -P "$PASS" -U msf -a 127.0.0.1 -p "$PORT" &>/dev/null &
    _write_cfg "$PASS"
    echo "[c2] msfrpcd started on 127.0.0.1:${PORT}"
    _wait_rpc 30 || true
    exit 0
fi

echo "[c2] msfconsole found but neither tmux nor msfrpcd available — cannot start RPC"
exit 3
