# Hooks

Claude Code hook scripts for PEN-AGENT engagement logging. Configured in
`.claude/settings.json` by `install.sh`.

## Scripts

### save-teammate-log.sh

TeammateIdle hook that copies teammate JSONL transcripts to
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

Hooks are configured in `.claude/settings.json` under the `hooks` key.
The installer sets this up automatically. Example configuration:

```json
{
  "hooks": {
    "TeammateIdle": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bash /path/to/PEN-AGENT/tools/hooks/save-teammate-log.sh"
          }
        ]
      }
    ]
  }
}
```
