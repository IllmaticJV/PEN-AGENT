#!/usr/bin/env bash
# PostToolUse hook (matcher: mcp__state__get_state_summary) — PEN-AGENT.
#
# The lead runs three deterministic state-hygiene sweeps at the top of every
# orchestrator loop (state_audit / scribe_check / objective_match), each as its
# own Bash tool round-trip inside the turn. This hook runs them automatically
# right after get_state_summary and feeds only the ACTIONABLE output back via
# hookSpecificOutput.additionalContext — so the lead gets the sweep for free,
# every loop, without spending tool calls on it, and never forgets to run it.
#
# Silent when state is coherent: state_audit and scribe_check print nothing on
# OK (--quiet), and objective_match is included only when it has real proposals
# — so quiet loops inject nothing and add no context noise.
#
# Lead only. A spawned teammate/subagent also calls get_state_summary (at
# activation); such a call carries a non-empty agent_id (common hook input
# field, Claude Code >= 2.1.290) and is skipped, so the lead's routing sweep
# never lands in teammate context. If a future runtime omits agent_id on a
# teammate's PostToolUse, the fallback is benign: the teammate would see the
# factual sweep once and still waits for its [TASK] (it never self-routes).
#
# Reads the hook JSON from stdin. ALWAYS exits 0 — the tool already ran, so a
# hook failure must never surface as an error on get_state_summary. PostToolUse
# plain stdout does not reach the model; only the additionalContext JSON does.

set -u

INPUT=$(cat)

# Resolve the repo root from this script's own location so the python helpers
# find engagement/ regardless of the hook's working directory.
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT" 2>/dev/null || exit 0

# Lead-only gate: skip spawned teammates/subagents (non-empty agent_id).
AGENT_ID=$(printf '%s' "$INPUT" | jq -r '.agent_id // empty' 2>/dev/null || true)
[ -n "$AGENT_ID" ] && exit 0

# Nothing to sweep without an engagement DB.
[ -f engagement/state.db ] || exit 0

parts=""
add() {  # $1 = section heading, $2 = body (skipped when empty)
    [ -n "$2" ] || return 0
    parts="${parts}${1}
${2}

"
}

# state_audit: --quiet → silent on OK, "ATTENTION: …" block otherwise.
add "— state hygiene (relay [update-*]/[add-*] to state-mgr) —" \
    "$(python3 tools/monitor/state_audit.py --quiet 2>/dev/null || true)"

# scribe_check: --quiet → silent on OK, "NUDGE: …" block otherwise.
add "— shell/exploit recording (relay nudges to scribe) —" \
    "$(python3 tools/monitor/scribe_check.py --quiet 2>/dev/null || true)"

# objective_match: no --quiet; include only when it emits a real proposal row
# ("| #"), never the "No proposals" / missing-objectives case.
if [ -f engagement/objectives.json ]; then
    obj=$(python3 tools/monitor/objective_match.py 2>/dev/null || true)
    printf '%s' "$obj" | grep -q '| #' 2>/dev/null \
        && add "— objective matches (propose only; confirm before applying) —" "$obj"
fi

# Nothing actionable → inject nothing.
[ -n "$parts" ] || exit 0

CONTEXT="Automatic per-loop state-hygiene sweep (deterministic; tools/monitor/*). These are actionable stragglers already in state.db — act on them per the orchestrator's Decision Logic instead of re-deriving them:

${parts}"

# additionalContext is capped at 10000 chars; stay well under.
CONTEXT=$(printf '%s' "$CONTEXT" | head -c 9000)

jq -n --arg ctx "$CONTEXT" \
   '{hookSpecificOutput:{hookEventName:"PostToolUse",additionalContext:$ctx}}' \
   2>/dev/null || true

exit 0
