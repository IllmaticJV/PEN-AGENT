# PEN-AGENT

Claude Code skill library for penetration testing and CTF work.

## Engagement Workflow

The orchestrator is invoked via `/pen-agent-ctf` slash command only — not by
natural language triggers. It contains all routing logic, approval gates,
and state management rules. **If you are a teammate** (spawned by a team
lead), **do NOT invoke the orchestrator skill.** Load technique skills via
`mcp__skill-router__get_skill()` instead — never via the Skill tool.

## Token Budget

Every token costs money and latency. Consider token impact when making ANY
change — agent templates, skill text, MCP responses, orchestrator prompts.
Prefer designs that minimize per-invocation token usage without sacrificing
needed functionality. Put hints in tool responses (loaded only when called)
rather than agent templates (loaded every invocation).

**No inline file templates.** Never embed file contents (YAML, shell scripts,
JSON, config files) directly in skill files, agent templates, or orchestrator
prompts. Store templates in `operator/templates/` and reference them by path.

## Architecture

### Orchestrator

PEN-AGENT has one orchestrator, `/pen-agent-ctf` (agent teams — persistent
teammates, peer messaging). It is invoked via slash command only, never by
natural-language triggers.

### Agent Teams (`/pen-agent-ctf`)

The lead session runs the orchestrator skill. There is no team-creation call
— spawning a domain teammate via `Agent` with a `name` parameter (with
`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` set) is what forms the team
implicitly, around the lead's session. The lead assigns tasks via
`TaskCreate`/`TaskUpdate`, and chains vulnerabilities toward impact.
Teammates communicate via `SendMessage` and write to state.db through
state-mgr. All technique skills (80+) are served on-demand via the MCP
skill-router. Teammate spawn templates live in `teammates/`.

### MCP Servers

| Server | Location | Purpose |
|--------|----------|---------|
| skill-router | `tools/skill-router/` | Semantic skill discovery and loading (ChromaDB + embeddings) |
| nmap-server | `tools/nmap-server/` | Dockerized nmap scanning with input validation |
| shell-server | `tools/shell-server/` | TCP listener, reverse shell, local interactive process manager |
| state | `tools/state-server/` | Full read/write engagement state (SQLite) |
| browser-server | `tools/browser-server/` | Headless browser automation |
| rdp-server | `tools/rdp-server/` | Headless RDP automation via aardwolf |
| metasploit-server | `tools/metasploit-server/` | Metasploit RPC wrapper — C2 backend (sessions, modules, pivoting) |
| portal | `operator/portal/` | Read-only operator web portal — tabs for objective/scope, live state.db status, and MSF session logs (not MCP) |

In agent teams mode, **state-mgr** is the sole writer to state.db (LLM-level
dedup + graph coherence). **shell-mgr** owns shell lifecycle (listeners,
processes, upgrades) — teammates message shell-mgr for setup, then interact
with the MCP directly after session handoff. See each server's `README.md`.

## Skill Routing

The orchestrator makes every routing decision. Skills report findings
generically — they do not name next skills. The orchestrator calls
`search_skills(query)` to find technique skills, then spawns/messages the
appropriate teammate.

**Mandatory skill loading**: Never execute a technique without loading the
matching skill via `get_skill()`. Skills contain methodology, payloads, and
troubleshooting that general knowledge does not. `get_skill(name)` returns the
skill's core (methodology + steps + payloads); the **Troubleshooting** section
is omitted to save tokens — when a step fails, fetch it with
`get_skill(name, section="troubleshooting")` (or `section="full"`).

**Built-in sub-agents** (Explore, Plan, general-purpose) do NOT have MCP
access — use them only for local processing, never for target-level work.

## State Management

Engagement state lives in `engagement/state.db` (SQLite, managed by
state-server MCP). Tables: targets, ports, credentials, credential_access,
access, vulns, pivot_map, blocked, tunnels, state_events.

- `get_state_summary()` produces a compact markdown summary for consumption
- Teammates read state directly; all writes go through state-mgr
- The orchestrator polls `poll_events()` for real-time visibility
- Orchestrator uses state summary + pivot map to chain vulns toward impact

## Lessons Learned (persistent)

`knowledge/lessons-learned.md` is a cross-engagement knowledge base that
outlives any single `engagement/`. The orchestrator reads it at engagement start
and injects relevant lessons into teammate briefs; the retrospective appends new
lessons at the end. Lessons are **generalizable only** — tooling flags,
methodology, environment quirks, AI oracles, skill gaps — **never**
target-specific solutions, credentials, IPs, or flags (that would leak
engagement data and let future runs "succeed" by recall instead of method).
This is how PEN-AGENT improves across runs; keep per-engagement detail in
`state.db` / `findings/`.

## Teammate Protocol

This section applies to all domain teammates spawned during engagements.
Infrastructure teammates (state-mgr, shell-mgr) have their own protocols
defined in their templates.

### Task Workflow

1. The lead assigns a task via `SendMessage` starting with `[TASK]`,
   including: skill name, target, and context.
2. Load the skill via `mcp__skill-router__get_skill(name="<skill-name>")`
   — call it directly, not via a subagent. The full skill text MUST be in
   YOUR context window. **Never use the Agent tool or Skill tool to load
   skills.**
   **If `get_skill` isn't resolvable yet, WAIT — do not report blocked on
   the first miss.** skill-router loads an embedding model + ChromaDB on
   startup, so it connects much slower than `state` (seconds vs. tens of
   seconds); if `state` resolves but skill-router doesn't, it's almost
   always still connecting, not down. Call
   `ToolSearch("select:mcp__skill-router__get_skill")` (it waits for a
   still-connecting server) and retry get_skill. Only after it stays
   unresolvable across a real wait (≈60s, a few retries) do you message the
   lead `[blocked] reason="skill-router unavailable"` — then the lead
   re-checks the server (see orchestrator), rather than you silently
   giving up.
3. Execute the skill's methodology end-to-end.
4. Message state-mgr with findings using `[action]` protocol.
5. Message the lead with a structured summary.
6. Mark the task complete. **Wait for next assignment — never self-claim.**

### State Writes via state-mgr

All state writes go through state-mgr. **Do NOT call state write tools
directly** — they are callable but MUST NOT be used. Send structured messages:

```
[add-port] ip=<ip> port=<N> proto=tcp service=<svc>
[add-target] ip=<ip> hostname=<host> os="<os>"
[update-target] ip=<ip> hostname=<host> notes="<notes>"
[add-vuln] ip=<ip> title="<title>" vuln_type=<type> severity=<sev> via_access_id=<N> details="<details>"
[add-cred] username=<user> secret=<secret> secret_type=<type> source="<source>" via_access_id=<N> via_vuln_id=<M>
[add-access] ip=<ip> method=<method> user=<user> level=<level> via_credential_id=<N> via_vuln_id=<V>
[add-blocked] ip=<ip> technique="<name>" reason="<why>" retry=<no|later|with_context>
[add-pivot] from_ip=<ip> to_subnet=<cidr> pivot_type="<type>"
[update-vuln] id=<N> status=actioned details="<details>"
```

Batch multiple writes in one message. Wait for confirmation IDs before
referencing them in later messages.

**SendMessage requires a `summary` field** (5-10 word preview) with every
message to any teammate.

### Finding Reports (OffSec-style, reproducible)

A vuln row in state.db is the attack graph, not the deliverable. The moment you
**confirm** a vuln (it becomes `actioned`), you — the teammate that found it —
MUST also write an OffSec-style finding to `engagement/findings/<id>.json`
conforming to `tools/reporter/finding.schema.json`. Copy the worked example at
`tools/reporter/examples/finding-prompt-injection.json` and fill it in.

Non-negotiable contents (the exporter enforces these):

- **`steps_to_reproduce`** — the COMPLETE, ordered exploit path: every command
  you actually ran to reach the objective, copy-pasteable, each with
  `expected_result`, `actual_result`, and an `evidence_ref` to the saved raw
  output. UI/chat actions give the literal `payload`. Record steps as you go so
  the path is real, not reconstructed from memory.
- **`verification`** — how success was PROVEN independently of your own opinion
  (out-of-band callback, exfiltrated canary, code execution, concrete state
  change). Never mark `status: confirmed` on model judgement alone; use
  `plausible` instead.
- **`placeholders`** — operator-specific values (e.g. `ATTACKBOX`) used in
  commands, so every step is runnable as-is.
- severity, impact, affected target(s), remediation, taxonomy (CWE / OWASP LLM /
  MITRE ATLAS / AI-300 module).

Save the raw output of each exploit step to `engagement/evidence/` and point
`evidence_ref` at it. The lead runs `tools/reporter/export_report.py --strict`
at reporting; a finding with no reproducible command path or no oracle is
rejected and is not considered done.

### Tool Execution

**Bash is the default** for CLI tools — use `dangerouslyDisableSandbox: true`
for network commands. Don't run `which` for Docker-only tools.

**Stay responsive — run long commands in background.** Any command over ~30
seconds: redirect stdout/stderr to `engagement/evidence/`, use
`run_in_background: true`, then use the **Read tool** on the output file
when notified. Do NOT use TaskOutput. Blocking your turn prevents the lead
from messaging you to redirect or abort.

### Operational Rules

- **Stay in scope.** Only act against targets in `engagement/scope.md` /
  `engagement/scope.allow`. The nmap and metasploit MCP servers enforce
  `scope.allow` in code and will refuse out-of-scope targets — if a tool
  returns `OUT OF SCOPE`, do NOT work around it. Stop and report to the lead;
  never edit `scope.allow` to add a target yourself (operator decision only).
- `date '+%Y-%m-%d %H:%M:%S'` for real timestamps — never placeholders
- `curl --connect-timeout 5 --max-time 15` always
- **Never download/clone/install tools.** Missing tool → stop, report, return.
- **Never modify /etc/hosts.** If a hostname doesn't resolve, stop all work
  that depends on it, message the lead with hostname and IP, and wait.
- **Never write custom scripts** to interact with remote services. Use
  installed CLI tools and MCP servers. If a tool fails, report — don't reinvent.
- MCP names: hyphens for servers (`mcp__shell-server__`), underscores for
  tools (`add_vuln`)

### Stall Detection

5+ tool rounds on the same failure with no new info → stop immediately.
Return: what was attempted, what failed, assessment (blocked/retry-later).

### Activation Protocol

On activation (this runs once, before any task):
1. `ToolSearch("select:TaskUpdate,TaskList,TaskGet")` — preload task schemas
   if available. These tools are model-gated and may not resolve on this
   model — an empty result is expected, not an error. If they're absent,
   coordinate with the lead and peers through `SendMessage` only; don't
   retry the search or treat it as a blocker.
2. `ToolSearch("select:mcp__skill-router__get_skill")` — warm up the
   skill-router connection NOW, while the first teammate is initializing,
   so it's ready before any `[TASK]` needs a skill. skill-router is the
   slowest server to come up (embedding model + ChromaDB). If it doesn't
   resolve yet, that's fine at this stage — it's still loading; you'll wait
   on it per Task Workflow step 2 when a task actually arrives. Don't report
   blocked here.
3. `get_state_summary()` — load engagement state
4. Go idle. Your first task arrives as a `SendMessage` starting with `[TASK]`.

### Target Knowledge Ethics

Never use specific knowledge of the current target (CTF writeups,
walkthroughs). Follow the skill methodology as if you've never seen this
target before.

## Engagement Directory

Created by the orchestrator at engagement start:

```
engagement/
  config.yaml       # Operator preferences (scan, proxy, spray, cracking, callback)
  scope.md          # Target scope, credentials, rules of engagement
  scope.allow       # Machine-readable in-scope allowlist (enforced by MCP servers)
  state.db          # SQLite state (managed via state-server MCP)
  dump-state.sh     # Export state.db as markdown
  findings/         # One OffSec-style finding JSON per confirmed vuln (see tools/reporter)
  findings.json     # Consolidated, importable report (export_report.py)
  report.md         # Human-readable OffSec-style report (export_report.py)
  evidence/         # Saved output, responses, dumps
    logs/           # Teammate JSONL transcripts
```

## Skill File Format

Every skill lives at `skills/<category>/<skill-name>/SKILL.md`.

### Frontmatter (required)

```yaml
---
name: skill-name
description: >
  What it does. When to trigger. Negative conditions (when NOT to use).
keywords:
  - technique-specific search terms
  - tool names, CVE IDs, protocol names
tools:
  - tool1
  - tool2
opsec: low|medium|high
---
```

### Body structure

1. **Preamble**: "You are helping a penetration tester with..."
2. **Engagement Logging**: Check for engagement dir, save evidence
3. **State Management**: Read via `get_state_summary()`, report findings
4. **Prerequisites**: Access, tools, conditions
5. **Steps**: Assess → Confirm → Exploit → Escalate/Pivot
6. **Troubleshooting**: Common failures and fixes

### Conventions

- Skill names use kebab-case: `sql-injection-union`, `kerberoasting`
- One technique per skill — split broad topics into focused skills
- Embed critical payloads directly (top 2-3 per variant for 80% coverage)
- OPSEC in description: `low` = passive, `medium` = artifacts, `high` = noisy
- New skills need descriptive frontmatter so `search_skills()` can discover them

## Documentation Rules

| Component | Documentation | Rule |
|-----------|--------------|------|
| Repo root | `README.md` | Update on architecture/installation/behavior changes |
| Docs site | `docs/*.md` | Human-facing reference. `docs/dependencies.md` tracks tool deps. |
| MCP servers | `tools/*/README.md` | **Required.** Update when tools/params/behavior change |
| Skills | `skills/*/SKILL.md` | Self-contained |
| Teammates | `teammates/*.md` | Self-contained (shared behavior in this file § Teammate Protocol) |
| Hooks | `tools/hooks/README.md` | Update when hook scripts change |
| Operator portal | Root `README.md` (Operator portal section) | No per-tool README — one README only. Update when behavior changes |

**Changelog is mandatory.** Every branch merged to main must update
`CHANGELOG.md` under a date heading (`## YYYY-MM-DD`).

## Directory Layout

```
PEN-AGENT/
  CLAUDE.md              # This file
  README.md              # User-facing docs
  install.sh / uninstall.sh
  config.sh              # Pre-engagement config wizard
  teammates/             # Teammate spawn templates (/pen-agent-ctf)
  skills/
    ctf/                 # /pen-agent-ctf orchestrator
    web/ ad/ credential/ privesc/ network/ evasion/ ai/
    post-exploit/ research/ retrospective/
  tools/reporter/        # OffSec-style finding schema + report exporter
  knowledge/             # Persistent cross-engagement lessons-learned
  tools/
    skill-router/ nmap-server/ shell-server/ metasploit-server/
    browser-server/ rdp-server/ state-server/ hooks/
  operator/
    portal/              # Read-only web portal — scope · status · MSF logs (tabs)
    templates/           # File templates (config, scripts)
```

## Permission Mode

Agent teams works in standard permission mode — **not** `--yolo`
(`--dangerously-skip-permissions`). MCP server tools are pre-allowed in
`.claude/settings.json`, which `install.sh` writes once if missing (see
docs/installation.md#permissions) — it never overwrites an existing one. The
orchestrator's approval gates provide human-in-the-loop control; `--yolo`
removes that step along with the permission prompts, leaving only Claude
Code's own safety classifiers between a teammate and the next tool call,
which get stricter the more a session's actions pattern-match sustained
multi-host compromise. Don't reach for `--yolo` to silence MCP permission
prompts — extend the `.claude/settings.json` allowlist instead.

## Installation

```bash
./install.sh          # Symlinks — edits in repo reflect immediately
./install.sh --copy   # Copies — for machines without the repo
./uninstall.sh        # Remove everything
```

Requires [uv](https://docs.astral.sh/uv/), Docker (for nmap), and
Playwright (for browser automation — Chromium installed automatically).
