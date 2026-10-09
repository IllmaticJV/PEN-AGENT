# Hooks

Claude Code hook scripts for PEN-AGENT engagement observability. Configured
in `.claude/settings.json` by `install.sh`.

## Scripts

### status-line.sh

`statusLine` hook that emits a one-line engagement summary to the Claude
Code status bar.

**Trigger:** Runs on every prompt submission.

**Output format (single line):**

```
[pen-agent] eng=<name> · tgts=N · creds=M · access=K · vulns=xC/yH/zM · <enforce-tag>
```

- `<enforce-tag>` is `scope` (scope.allow present) or `ENF-OFF` (scope
  enforcement is OFF — every target-touching MCP would warn and allow all)
- Vuln severities with zero counts are omitted to save space; `0` when all empty
- Engagement names over 20 chars are truncated with `…`

**Fallback output:**
- `[pen-agent] no engagement` — no `engagement/` directory
- `[pen-agent] empty · scope` — directory exists but no state.db yet
- `[pen-agent] db-unreadable · <tag>` — state.db present but sqlite read failed

**Performance:** One SQLite read-only call pulls all counts, so the hook adds
negligible latency to prompt submission.

**Dependencies:** `sqlite3` CLI.

### session-start.sh

`SessionStart` hook that prints a multi-line engagement-context banner once
per new Claude Code session.

**Trigger:** Runs on session start.

**Output:**

- **scope.allow** — total entries, preview of first 5, warning when missing
  (scope enforcement OFF across all MCP servers)
- **C2 backend** — `metasploit` (msfrpc.yaml present), `shell-server only`,
  or an intermediate state when `msfconsole` is installed but not launched
- **portal URL** — read from `~/.config/pen-agent/portal-access.txt` if
  present (written by `run.sh`)
- **preflight** — baked-payload count and whether XOR-encoded payloads were
  produced; warns when msfrpc.yaml exists but preflight has NOT YET RUN

Always exits 0 — the hook is informational, never blocks Claude.

### save-teammate-log.sh

`TeammateIdle` hook that copies teammate JSONL transcripts to
`engagement/evidence/logs/` and checks for AUP/content-filter errors.

**Trigger:** Runs automatically when any agent-teams teammate goes idle.

**Behavior:**

1. Reads hook JSON from stdin (`transcript_path`, `session_id`, `teammate_name`)
2. Checks that transcript file and engagement directory exist — exits silently
   if not
3. Copies transcript with filename `{timestamp}-teammate-{name}-{session}.jsonl`
4. **AUP detection:** Scans the last 200 lines of the transcript for content
   filter patterns (content_policy, "I cannot assist", flagged request, etc.)
5. If AUP detected, writes a sentinel file to
   `engagement/evidence/aup-{teammate}.flag` with timestamp, session ID, and
   the matching transcript lines
6. Always exits 0 to never block the teammate

**AUP sentinel files:** The orchestrator should check for
`engagement/evidence/aup-*.flag` files when a teammate goes silent. If found,
the teammate's context is poisoned — dismiss and respawn with a clean context
if needed.

**Dependencies:** `jq` for JSON parsing.

## Configuration

Hooks are configured in `.claude/settings.json` under the `statusLine` and
`hooks` keys. The installer sets both up automatically. Example configuration:

```json
{
  "statusLine": {
    "type": "command",
    "command": "bash tools/hooks/status-line.sh"
  },
  "hooks": {
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash tools/hooks/session-start.sh"
          }
        ]
      }
    ],
    "TeammateIdle": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash tools/hooks/save-teammate-log.sh"
          }
        ]
      }
    ]
  }
}
```
