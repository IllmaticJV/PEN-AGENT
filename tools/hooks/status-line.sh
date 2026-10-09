#!/usr/bin/env bash
# Claude Code status-line hook for PEN-AGENT.
#
# Emits a one-line engagement summary to the Claude Code status bar on
# every prompt submission. Runs fast (SQLite read + a few counts) so
# it doesn't delay the prompt.
#
# Output format (single line, no trailing newline):
#   [pen-agent] eng=<name> · tgts=N · creds=M · access=K · vulns=xC/yH/zM · <enforce-tag>
#
# When engagement/ is missing: emits "[pen-agent] no engagement".
# When scope.allow is missing: emits "ENF-OFF" so the operator sees
# scope enforcement is disabled.

set -u

# Resolve project root — the hook runs from Claude Code's cwd, which is
# usually the repo root but we re-anchor to be safe.
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT" 2>/dev/null || { printf '[pen-agent] no project'; exit 0; }

DB="engagement/state.db"
SCOPE="engagement/scope.allow"

if [[ ! -d engagement ]]; then
    printf '[pen-agent] no engagement'
    exit 0
fi

if [[ ! -f "$DB" ]]; then
    tag="ENF-OFF"; [[ -f "$SCOPE" ]] && tag="scope"
    printf '[pen-agent] empty · %s' "$tag"
    exit 0
fi

# Pull counts in one SQLite call so this stays fast on long engagements.
counts=$(sqlite3 -separator '|' "file:${DB}?mode=ro" "
  SELECT
    (SELECT name FROM engagement LIMIT 1),
    (SELECT COUNT(*) FROM targets),
    (SELECT COUNT(*) FROM credentials),
    (SELECT COUNT(*) FROM access),
    (SELECT COUNT(*) FROM vulns WHERE severity='critical'),
    (SELECT COUNT(*) FROM vulns WHERE severity='high'),
    (SELECT COUNT(*) FROM vulns WHERE severity='medium');
" 2>/dev/null) || counts=""

if [[ -z "$counts" ]]; then
    tag="ENF-OFF"; [[ -f "$SCOPE" ]] && tag="scope"
    printf '[pen-agent] db-unreadable · %s' "$tag"
    exit 0
fi

IFS='|' read -r name tgts creds access crit high med <<< "$counts"
name="${name:-?}"
# Trim long engagement names so the status line stays readable
if [[ ${#name} -gt 20 ]]; then
    name="${name:0:17}…"
fi

# Scope enforcement tag — ENF-OFF when scope.allow is missing (any
# target-touching MCP would warn and allow everything)
enf_tag="scope"
[[ ! -f "$SCOPE" ]] && enf_tag="ENF-OFF"

# Vuln breakdown — omit zero buckets to save status-line real estate
vuln_parts=""
[[ "$crit" -gt 0 ]] && vuln_parts="${crit}C"
if [[ "$high" -gt 0 ]]; then
    [[ -n "$vuln_parts" ]] && vuln_parts+="/"
    vuln_parts+="${high}H"
fi
if [[ "$med" -gt 0 ]]; then
    [[ -n "$vuln_parts" ]] && vuln_parts+="/"
    vuln_parts+="${med}M"
fi
[[ -z "$vuln_parts" ]] && vuln_parts="0"

printf '[pen-agent] eng=%s · tgts=%s · creds=%s · access=%s · vulns=%s · %s' \
    "$name" "$tgts" "$creds" "$access" "$vuln_parts" "$enf_tag"
