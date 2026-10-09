#!/usr/bin/env bash
# Claude Code SessionStart hook for PEN-AGENT.
#
# Prints a short engagement-context banner on each new session so the
# operator sees the environment is live (or not): scope.allow IPs,
# C2 backend in play, operator portal URL, and a warning when
# engagement/ is missing or scope.allow is absent (= scope
# enforcement OFF across all MCP servers).
#
# Always exits 0 — the hook is informational, never blocks Claude.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT" 2>/dev/null || exit 0

echo
echo "─── PEN-AGENT session ───"

if [[ ! -d engagement ]]; then
    echo "  no engagement/ dir — this is a fresh checkout or pre-setup state."
    echo "  Invoke /pen-agent-ctf to start a new engagement."
    echo
    exit 0
fi

# Scope enforcement — the single most important thing to show.
if [[ -f engagement/scope.allow ]]; then
    allow_count=$(grep -cvE '^(\s*#|\s*$)' engagement/scope.allow 2>/dev/null || echo 0)
    allow_preview=$(grep -vE '^(\s*#|\s*$)' engagement/scope.allow 2>/dev/null \
                    | head -5 | tr '\n' ' ')
    echo "  scope.allow: $allow_count entries — $allow_preview"
    if [[ "$allow_count" -gt 5 ]]; then
        echo "               …plus $((allow_count - 5)) more"
    fi
else
    echo "  ⚠ scope.allow MISSING — scope enforcement is OFF across all MCP"
    echo "    servers (every target allowed). Orchestrator will write one on"
    echo "    engagement init; if you're mid-engagement, this is a bug."
fi

# C2 backend
if [[ -f engagement/msfrpc.yaml ]]; then
    echo "  C2 backend: metasploit (msfrpc.yaml present)"
elif command -v msfconsole >/dev/null 2>&1; then
    echo "  C2 backend: metasploit available but not started — run.sh will"
    echo "              spin it up on next launch"
else
    echo "  C2 backend: shell-server only (metasploit-framework not installed)"
fi

# Operator portal URL — written by run.sh for later recovery
if [[ -f "$HOME/.config/pen-agent/portal-access.txt" ]]; then
    url=$(grep -m1 '^URL:' "$HOME/.config/pen-agent/portal-access.txt" 2>/dev/null \
          | sed 's/^URL: *//')
    [[ -n "$url" ]] && echo "  portal: $url"
fi

# Preflight-payload status — one line summary, no payload content
if [[ -f engagement/payloads/index.json ]]; then
    count=$(python3 -c "import json;print(len(json.load(open('engagement/payloads/index.json'))))" 2>/dev/null || echo "?")
    xor=$(python3 -c "import json;d=json.load(open('engagement/payloads/index.json'));print('yes' if any(e.get('encoding','none').startswith('xor-') for e in d) else 'no')" 2>/dev/null || echo "?")
    echo "  preflight: $count baked payloads, xor=$xor (never Read these files)"
elif [[ -f engagement/msfrpc.yaml ]]; then
    echo "  preflight: NOT YET RUN — lead's first message to shell-mgr must be"
    echo "             [preflight-payloads] lhost=<IP|iface> before any exploit"
fi

echo "─────────────────────────"
echo
exit 0
