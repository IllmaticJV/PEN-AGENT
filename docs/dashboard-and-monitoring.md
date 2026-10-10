# Dashboard & Monitoring

PEN-AGENT provides real-time visibility through two complementary surfaces: the operator **web portal** for state and progress at a glance, and **tmux split-panes** for watching teammates live.

## Operator portal (`http://127.0.0.1:8099`)

Mostly read-only web view started automatically by `run.sh` in a tmux session (`pen-portal`). Seven tabs, plus a **lead-parked strip** across all tabs (described after the list):

- **Objective & Scope** — the engagement objective + rules of engagement (`engagement/scope.md`), the in-scope allowlist (`scope.allow`), and engagement meta.
- **Objective Tracker** — the parsed `OBJECTIVES:` list rendered as per-objective status cards + a progress hero (`N% complete · M of total done`). **The operator can toggle each objective done / pending straight from the dashboard** (checkbox on the card) — this writes `engagement/objectives.json` directly with the same schema the lead's `mcp__state__update_objective` tool uses, so both views stay coherent. The lead still owns `in_progress` / `blocked` / `skipped` via MCP; the dashboard toggle is the common binary done↔pending flip. Auto-appended note: `"toggled from portal (<iso-ts>)"`.
- **Status** — live engagement state from `state.db`: targets + ports, credentials, access, vulns, pivots, tunnels, event timeline, and the access-chain graph.
- **Attack Graph** — the access-chain / `pivot_map` focus graph with a wired toolbar (zoom / fit / filters / search), a legend, and a minimap.
- **Activity** — the teammate roster/health on top (per-teammate status, current/last action from `state_events`, model, AUP + blocked flags, token spend with a raw / billed-weight toggle) over a live `state_events` feed below.
- **Findings** — the confirmed OffSec-style findings (`engagement/findings/*.json`), collapsible, as written by the teammate that confirmed each vuln.
- **C2 / MSF Logs** — the live Metasploit session + listener/job list, a per-session command log (every command an agent ran, operator-reserved sessions badged), and a Module Calls list showing every `start_handler` / `run_module` / `start_socks_proxy` / `upgrade_to_meterpreter` / `generate_payload` call with options + result. Jobs rows link to the matching module-setup log by `job_id`.

**Lead-parked strip** — a slim band below the nav, raised only when actionable findings are sitting unacted (the symptom of the lead being parked on a per-task approval gate with the operator away). It derives read-only from `state.db` (`dash/lead.py`): an actionable backlog — un-actioned `found` vulns, untested credentials, `identified` pivots, retryable blocks — combined with time since the last `state_events` row. Red = parked (backlog + quiet past ~3 min); amber = a backlog item has aged while the engagement works elsewhere; hidden when the state is clean. Served at `/api/lead`, polled every 8s.

Binds `127.0.0.1` only by default; `bash operator/portal/generate-token.sh` writes an HMAC token to `~/.config/pen-agent/viewer-token`, after which the server binds `0.0.0.0` and requires the token on login (session cookie or `Authorization: Bearer`). Portal writes are CSRF-guarded by a required `X-Requested-With: pen-agent-portal` header.

## Agent Teams (teammate live view)

PEN-AGENT uses [Claude Code agent teams](https://code.claude.com/docs/en/agent-teams) for teammate coordination and visibility. Each teammate runs in its own tmux pane, giving the operator a live view of all parallel work.

**Operator controls:**

- **Watch** — see each teammate's output in its own tmux pane (reasoning, commands, results)
- **Interrupt** — press Escape in a teammate's pane to stop its current turn
- **Redirect** — type directly to any teammate to give new instructions or ask questions
- **Monitor task list** — press Ctrl+T to toggle the shared task list showing all assigned work

For split-pane mode, start Claude Code inside a tmux session. Without tmux, teammates run in-process mode — cycle through them with Shift+Down.

### Setup

Add to `.claude/settings.json` (project-level):

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

## Transcript Capture

Every teammate's full JSONL transcript is automatically saved to `engagement/evidence/logs/` when the teammate finishes. This is the accountability layer — tmux panes show you what teammates are doing in real time, and transcripts give you a permanent record of every tool call, command, and decision each teammate made.

A `TeammateIdle` hook (`tools/hooks/save-teammate-log.sh`) handles this automatically:

1. Claude Code fires the `TeammateIdle` event when a teammate finishes its current task
2. The hook reads the transcript path and teammate name from the event JSON
3. Copies the transcript to `engagement/evidence/logs/{timestamp}-{teammate-name}.jsonl`

No engagement directory = hook exits silently. The retrospective skill parses these logs for post-engagement analysis.

## Configuration

### Hook Setup

The `TeammateIdle` hook is configured in `.claude/settings.json`:

```json
{
  "hooks": {
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

The hook always exits 0 to never block Claude Code, regardless of whether logging succeeds.

### Per-loop state sweep (PostToolUse)

The lead runs three deterministic hygiene sweeps at the top of every
orchestrator loop — `state_audit.py` (stale vulns, untested/unprovenanced
creds, orphan access, retryable blocks, unactioned pivots), `scribe_check.py`
(unrecorded shells/exploits), and `objective_match.py` (objective-tracker
proposals). A `PostToolUse` hook (`tools/hooks/state-sweep.sh`) matched to
`mcp__state__get_state_summary` runs them automatically right after the lead's
summary call and feeds only the **actionable** output back to the lead via
`hookSpecificOutput.additionalContext` — so the lead gets the sweep for free
every loop, without spending tool calls on it, and never forgets to run it.

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "mcp__state__get_state_summary",
        "hooks": [
          {
            "type": "command",
            "command": "bash tools/hooks/state-sweep.sh"
          }
        ]
      }
    ]
  }
}
```

Behaviour:

- **Silent on a coherent loop.** `state_audit`/`scribe_check` print nothing on
  OK (`--quiet`) and `objective_match` is included only when it has real
  proposals, so a clean loop injects no context at all.
- **Lead only.** A spawned teammate also calls `get_state_summary` at
  activation; that call carries a non-empty `agent_id` (common hook input
  field, Claude Code ≥ 2.1.290) and is skipped, so the lead's routing sweep
  never lands in teammate context.
- **Never blocks.** Always exits 0 — `get_state_summary` already returned, so a
  hook failure must not surface as a tool error. (PostToolUse plain stdout does
  not reach the model; only the `additionalContext` JSON does.)

**Existing installs:** `install.sh` writes `.claude/settings.json` only when it
is missing, so an engagement set up before this hook existed must add the
`PostToolUse` block above to its `.claude/settings.json` by hand (or delete the
file and re-run `install.sh`). New installs get it automatically.

### Lead router guard (PreToolUse)

The lead is a router, not an executor — it must never drive a target itself.
A `PreToolUse` hook (`tools/hooks/lead-guard.sh`), matched to the five
target-touching MCP servers (`nmap` / `metasploit` / `shell` / `browser` /
`rdp`) and `Bash`, **hard-blocks** those for the lead: any call to one of those
MCP servers, or an offensive CLI tool in Bash (`nmap`, `nxc`, `impacket-*`,
`evil-winrm`, `sqlmap`, `msfconsole`/`msfvenom`, `responder`, `curl`/`wget` to a
target, …), is denied with a `permissionDecision: deny` telling the lead to
delegate to a teammate.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__(nmap|metasploit|shell|browser|rdp)-server__.*|Bash",
        "hooks": [
          { "type": "command", "command": "bash tools/hooks/lead-guard.sh" }
        ]
      }
    ]
  }
}
```

Lead identification is **positive and fail-safe for teammates**: the
orchestrator writes its own `CLAUDE_CODE_SESSION_ID` to
`engagement/.lead-session` at engagement init, and the hook denies **only** when
the calling `session_id` matches that marker. A teammate has a different
`session_id`, so it is never matched and never blocked; if the marker is absent
(pre-init or misconfig) the hook defers and the prompt-level rule still applies.
Local orchestration Bash (`python3 tools/*`, `ls`, `date`, `cp`, `git`,
`ldapsearch` base-scope, `getent`, `ip`) is untouched. Same existing-installs
caveat as above — add the `PreToolUse` block by hand on an older
`.claude/settings.json`.
