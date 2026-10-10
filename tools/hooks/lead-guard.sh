#!/usr/bin/env bash
# PreToolUse guard — the lead is a ROUTER, never an executor.
#
# Hard-enforces the orchestrator's "DO NOT RUN TOOLS DIRECTLY" rule: the lead
# must not drive a target itself (recon, exploitation, shells). It denies, for
# the lead only:
#   - any call to the five target-touching MCP servers
#     (nmap / metasploit / shell / browser / rdp) — these are teammate-only;
#   - offensive / target-touching CLI via Bash (nmap, nxc, impacket, evil-winrm,
#     sqlmap, hydra, msf*, responder, hashcat, ssh/scp to targets, …).
# Local orchestration Bash (python3 tools/*, ls, date, cp, git, ldapsearch
# base-scope, getent, ip) is untouched.
#
# Lead identification is POSITIVE and fail-safe for teammates: the orchestrator
# writes its own CLAUDE_CODE_SESSION_ID to engagement/.lead-session at init, and
# this hook denies ONLY when the calling session_id equals that marker. A
# teammate has a different session_id, so it is NEVER matched and NEVER blocked.
# No marker yet (pre-init) or marker mismatch → defer to the normal flow; the
# prompt-level rule still applies. Always exits 0.

set -u
INPUT=$(cat)

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT" 2>/dev/null || exit 0

MARKER="engagement/.lead-session"
[ -f "$MARKER" ] || exit 0   # no lead declared yet → defer

SID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)
LEAD=$(head -c 256 "$MARKER" 2>/dev/null | tr -d '[:space:]')
# Guard the lead session only. Teammates (different session_id) → defer/allow.
[ -n "$SID" ] && [ -n "$LEAD" ] && [ "$SID" = "$LEAD" ] || exit 0

TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || true)

deny() {
    jq -n --arg r "$1" \
      '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}' \
      2>/dev/null
    exit 0
}

# Target-touching MCP servers are teammate-only — the lead never drives a target.
case "$TOOL" in
    mcp__nmap-server__*|mcp__metasploit-server__*|mcp__shell-server__*|mcp__browser-server__*|mcp__rdp-server__*)
        deny "Lead is a router, not an executor: '${TOOL}' touches a target. Assign this to a teammate (search_skills + spawn/message the right *-ops/*-enum teammate). The five target-touching MCP servers are teammate-only."
        ;;
esac

# Bash: block offensive / target-touching CLI from the lead. The offensive tool
# must appear as a command word (start of command, or after a pipe / ; / && /
# sudo / env), so paths like tools/ingestors/nmap_ingest.py don't match.
if [ "$TOOL" = "Bash" ]; then
    CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
    if printf '%s' "$CMD" | grep -qiE '(^|[;&|]|&&|\|\||\bsudo|\benv)[[:space:]]*(nmap|masscan|rustscan|ffuf|feroxbuster|gobuster|dirb|dirbuster|nuclei|nikto|wfuzz|sqlmap|hydra|medusa|patator|ncat|netcat|socat|nxc|netexec|crackmapexec|cme|smbmap|rpcclient|enum4linux|impacket-[a-z]+|wmiexec|psexec|smbexec|dcomexec|secretsdump|GetUserSPNs|GetNPUsers|evil-winrm|sshpass|responder|ntlmrelayx|certipy|bloodhound-python|kerbrute|msfconsole|msfvenom|chisel|ligolo|proxychains|ssh|scp|nc|curl|wget)([[:space:]]|$)'; then
        deny "Lead is a router, not an executor: that command runs an offensive / target-touching tool. Assign it to the appropriate teammate; the lead never executes exploitation or recon itself."
    fi
fi

exit 0
