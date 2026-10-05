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
# Self-healing: the msgrpc listener is a child of the console, so if the
# console dies the backend dies with it. The tmux session therefore runs a
# supervisor loop that relaunches msfconsole if it exits — a console crash (or
# an accidental `exit`) heals itself within ~3s. The RPC rebinds on the SAME
# port/password, so the already-running metasploit-server MCP reconnects with
# no change. (Only a tmux-server kill or a container/VM reset takes the whole
# session down; recover from that by re-running this script — see below.)
#
# Idempotent + recovery: if the tmux session is alive it does nothing. If it's
# gone but engagement/msfrpc.yaml exists (the console died and took the RPC
# with it), re-running this script RELAUNCHES reusing the recorded password and
# port, so the MCP's creds stay valid and it reconnects cleanly — no need to
# restart the whole run.sh. A session with no recorded creds is treated as a
# stale orphan and restarted fresh.
#
# NOTE: live sessions live in the Framework's memory, so any relaunch (self-heal
# or recovery) starts a fresh Framework — in-flight sessions are not resurrected.
# For workspace durability (hosts/loot/creds across relaunches) run `msfdb init`
# once so msfconsole auto-connects its PostgreSQL DB; without it the C2 still
# works, just with no persistent workspace (harmless warning in framework.log).
#
# Env:
#   MSF_RPC_PORT        RPC port (default 55553; the recorded port wins on recovery)
#   MSF_RPC_PASSWORD    RPC password (overrides the recorded one; else reused, else random)
#   PEN_AGENT_MSF_TMUX  tmux session name (default pen-msf)
#   ENGAGEMENT_DIR      engagement dir (default engagement)
#
# Exit: 0 C2 up / already up · 2 msfconsole not found · 3 no way to start RPC
set -euo pipefail

ENGAGEMENT_DIR="${ENGAGEMENT_DIR:-engagement}"
CFG="${ENGAGEMENT_DIR}/msfrpc.yaml"
PORT="${MSF_RPC_PORT:-55553}"
TMUX_SESSION="${PEN_AGENT_MSF_TMUX:-pen-msf}"
RESTORE_HANDLERS=0

# --restore: after the C2 is up (fresh or already running), call the MCP's
# restore_handlers() tool which re-registers every handler recorded in
# engagement/msf-handlers-snapshot.json. See snapshot_handlers() docstring
# in server.py for the full flow; also run.sh --c2-restart.
for arg in "$@"; do
    case "$arg" in
        --restore) RESTORE_HANDLERS=1 ;;
        *) echo "[c2] unknown flag: $arg (supported: --restore)" >&2; exit 2 ;;
    esac
done

command -v msfconsole &>/dev/null || { echo "[c2] msfconsole not found on PATH"; exit 2; }
mkdir -p "${ENGAGEMENT_DIR}/evidence/msf-sessions"

_gen_pass() { head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24; }
_port_up()  { (echo >"/dev/tcp/127.0.0.1/${PORT}") &>/dev/null; }
_wait_rpc() { local n="${1:-60}"; while ((n-- > 0)); do _port_up && return 0; sleep 1; done; return 1; }

# --restore: ask the metasploit-server MCP to re-register handlers from the
# snapshot file written by snapshot_handlers() before the restart. Payloads
# built by generate_payload have retry attributes baked in by default, so
# their meterpreter sessions reconnect to the new handlers on their own.
# The MCP's SSE server (default 8024) is up once start.sh / run.sh brought
# it in; the call is best-effort and never fails the C2 bring-up.
_maybe_restore() {
    [[ "$RESTORE_HANDLERS" == 1 ]] || return 0
    local snap="${ENGAGEMENT_DIR}/msf-handlers-snapshot.json"
    if [[ ! -s "$snap" ]]; then
        echo "[c2] --restore: no snapshot at $snap, nothing to do"
        return 0
    fi
    local sse_port="${MSF_SSE_PORT:-8024}"
    local n=30
    while ((n-- > 0)); do
        (echo >"/dev/tcp/127.0.0.1/${sse_port}") &>/dev/null && break
        sleep 1
    done
    if ! (echo >"/dev/tcp/127.0.0.1/${sse_port}") &>/dev/null; then
        echo "[c2] --restore: metasploit-server MCP not listening on ${sse_port}; "\
             "snapshot kept at $snap — rerun 'bash tools/metasploit-server/start.sh' then "\
             "ask the lead to call restore_handlers() via the MCP" >&2
        return 0
    fi
    echo "[c2] --restore: asking MCP to re-register handlers from $snap"
    # The MCP's /mcp SSE endpoint speaks JSON-RPC 2.0 over SSE; the simplest
    # cross-platform invocation is python with the mcp client. Fall back to a
    # one-liner hint if that stack isn't installed in this shell's PATH.
    if command -v uv &>/dev/null; then
        uv run --directory tools/metasploit-server --quiet python - <<'PY' 2>&1 | sed 's/^/[c2]   /' || true
import anyio, json, os, sys
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession
async def _call():
    port = int(os.environ.get("MSF_SSE_PORT", "8024"))
    url = f"http://127.0.0.1:{port}/sse"
    async with sse_client(url) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool("restore_handlers", {})
            for c in res.content:
                if hasattr(c, "text"): print(c.text)
try:
    anyio.run(_call)
except Exception as e:
    print(f"restore_handlers RPC failed: {e}", file=sys.stderr)
    sys.exit(1)
PY
    else
        echo "[c2]   uv not on PATH; snapshot preserved — ask the lead to invoke restore_handlers() via the MCP."
    fi
}

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

# Reuse the recorded RPC password/port if msfrpc.yaml already exists, so a
# relaunch (recovery after the console died) keeps the same creds and the
# already-running MCP reconnects without a config change. MSF_RPC_PASSWORD
# overrides; a missing file falls back to a fresh random password.
_resolve_creds() {
    local existing_pass="" existing_port=""
    if [[ -f "$CFG" ]]; then
        existing_pass="$(sed -n 's/^[[:space:]]*password:[[:space:]]*//p' "$CFG" | head -1)"
        existing_port="$(sed -n 's/^[[:space:]]*port:[[:space:]]*//p' "$CFG" | head -1)"
        [[ -n "$existing_port" ]] && PORT="$existing_port"
    fi
    PASS="${MSF_RPC_PASSWORD:-${existing_pass:-$(_gen_pass)}}"
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
        _maybe_restore
        exit 0
    fi
    _resolve_creds
    ABS_ENG="$(cd "$ENGAGEMENT_DIR" && pwd)"
    RC="${ABS_ENG}/.msf-init.rc"
    # Resource file avoids all shell-quoting pain for the -r arg. It holds the
    # RPC password, so lock it down; engagement/ is gitignored.
    cat > "$RC" <<RC
spool ${ABS_ENG}/evidence/msf-console.log
setg SessionLogging true
load msgrpc ServerHost=127.0.0.1 ServerPort=${PORT} User=msf Pass=${PASS} SSL=true
RC
    chmod 600 "$RC"
    # Supervisor loop: if msfconsole exits (crash, or an accidental `exit`),
    # relaunch it on the same creds so the RPC comes back and the MCP
    # reconnects. Stop the C2 deliberately with: tmux kill-session -t <session>
    # (or run.sh --clean-start), not by exiting the console.
    tmux new-session -d -s "$TMUX_SESSION" \
        "while true; do msfconsole -q -r '${RC}'; echo '[c2] msfconsole exited — relaunching in 3s (stop with: tmux kill-session -t ${TMUX_SESSION})'; sleep 3; done"
    _write_cfg "$PASS"
    echo "[c2] msfconsole+msgrpc starting in tmux '${TMUX_SESSION}' on 127.0.0.1:${PORT} (auto-restarts if it exits)"
    echo "[c2]   full interactive console → tmux attach -t ${TMUX_SESSION}   (detach: Ctrl-b then d)"
    # Framework load + plugin bind is slow (tens of seconds on first run).
    if _wait_rpc 90; then
        echo "[c2] RPC listening on 127.0.0.1:${PORT}"
    else
        echo "[c2] WARNING: RPC not listening after 90s — msfconsole may still be loading; check: tmux attach -t ${TMUX_SESSION}"
    fi
    _maybe_restore
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
    _resolve_creds
    msfrpcd -P "$PASS" -U msf -a 127.0.0.1 -p "$PORT" &>/dev/null &
    _write_cfg "$PASS"
    echo "[c2] msfrpcd started on 127.0.0.1:${PORT}"
    _wait_rpc 30 || true
    _maybe_restore
    exit 0
fi

echo "[c2] msfconsole found but neither tmux nor msfrpcd available — cannot start RPC"
exit 3
