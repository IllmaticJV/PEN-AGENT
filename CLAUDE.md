# PEN-AGENT

Claude Code skill library for penetration testing and CTF work.

## Engagement Workflow

The orchestrator is invoked via `/pen-agent-ctf` slash command only — not by
natural language triggers. It contains all routing logic, approval gates,
and state management rules. **If you are a teammate** (spawned by a team
lead), **do NOT invoke the orchestrator skill.** Load technique skills via
`mcp__skill-router__get_skill()` instead — never via the Skill tool.

## Token Budget

Every token costs money and latency — this file and the teammate templates
ride in context on every agent turn, so keep them lean. When editing, prefer
designs that minimize per-invocation tokens (put hints in tool responses, not
templates) and never embed file contents inline. Details: `CONTRIBUTING.md`.

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

## Local Helpers (prefer over LLM round-trips)

These stdlib-only scripts replace common LLM-mediated boilerplate.
Prefer them whenever the input/output shape fits — they're faster,
deterministic, and don't burn context on raw tool output.

| Script | Use when |
|---|---|
| `tools/ingestors/nmap_ingest.py <xml>` | After `nmap_scan` — compact summary + `[add-target]`/`[add-port]` batch |
| `tools/ingestors/nmap_delta.py <old> <new>` | Staged scan second pass — only emit new rows |
| `tools/ingestors/cred_ingest.py <dump>` | secretsdump / hashcat / Kerberoast dump → `[add-cred]` batch |
| `tools/ingestors/bloodhound_ingest.py <dir|zip|json>` | BloodHound JSON → AD summary + state writes |
| `tools/ingestors/bloodhound_paths.py <path> --from X [--target Y]` | Shortest attack path to Domain Admins (no neo4j) |
| `tools/ingestors/web_recon.py <output> --url <URL>` | After `web_recon.sh` — HTTP triage summary + state writes |
| `tools/ingestors/har_replay.py <in.har> <out.sh>` | Burp/DevTools HAR → runnable curl replay with cookie jar + CSRF substitution |
| `tools/ingestors/summarize_shell_log.py <path>` | Before reading a long shell/MSF transcript — strips MOTD/prompts, trims recv blocks |
| `tools/ingestors/shell_recon.py <output> --ip X` | After running `tools/payloads/shell_recon.{sh,ps1}` in one send_command |
| `tools/payloads/shell_recon.sh` / `.ps1` | One-shot new-shell triage (whoami/id/os/ifaces/sudo/pivots) |
| `tools/payloads/web_recon.sh <URL>` | One-shot web endpoint triage (status/title/cookies/robots/TLS/fingerprint) |
| `tools/monitor/scribe_check.py` | Lead's per-loop scribe-gap check (replaces 3 MCP round-trips) |
| `tools/monitor/objective_match.py` | Propose objective-tracker updates from state.db (never auto-applies) |
| `tools/reporter/new_finding.py <vuln_id>` | Pre-populate `engagement/findings/<id>.json` skeleton from state.db |
| `tools/exploit-index/lookup.py --cve <id>` | Local CVE → MSF module hint (<1ms); fall through to console search on MISS |
| `tools/crack/crack.sh <hashfile>` | hashcat wrapper — auto-mode, auto-wordlist, evidence to engagement/evidence/crack-*/ |
| `tools/sweep/cred_sweep.py --username U --secret S --hosts C` | One cred × many hosts × SMB/WinRM/SSH; `[add-access]` on hits |
| `tools/loot/organize.py <file> --ip <ip>` | Move a dumped file into `engagement/loot/<ip>/<kind>/` with meta sidecar |

Each script runs `--help` for the full flag set. Scope-guarded ones
(nmap, metasploit, cred_sweep) honor `engagement/scope.allow`.

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

Jumpstart: `python3 tools/reporter/new_finding.py <vuln_id>` writes
`engagement/findings/<vuln_id>.json` pre-populated from state.db
(target, title, severity, affected, classification hints, finding id).
Open it and fill the TODO fields — `steps_to_reproduce`, the
`verification` oracle, `impact`, `placeholders.ATTACKBOX`. Flip
`confidence` / `verification.status` to `confirmed` only when the
oracle actually fires.

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

**Summarize shell transcripts locally before reading them.** For any
`engagement/evidence/shell-*.log` or `engagement/evidence/msf-modules/
*.jsonl` longer than ~100 lines (session recovery, catching up on a
long enum run), pipe through the local summarizer first:
```bash
python3 tools/ingestors/summarize_shell_log.py <path> [--last-n 50]
```
It drops MOTD/prompt noise, trims per-command recv blocks to 30 lines
(with elided counts), collapses identical consecutive outputs, and
handles both shell transcripts and MSF module JSONL. Typically ~50%
smaller; sometimes much more on PTY sessions with heavy banners. Only
read the raw log when you specifically need output the summarizer
elided.

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
- **Known exploits: Metasploit first.** When Metasploit is the C2 (the
  default) and the vector is a named CVE or a versioned service with a public
  exploit, try a matching MSF module first. Check the local index FIRST
  (free, instant) before burning a `console_exec` round-trip:
  `python3 tools/exploit-index/lookup.py --cve <CVE-id>` or
  `--product "<name>" --version <ver>` or `--query <text>`. A `HINT:`
  line names the module to try with `run_module`; a `MISS:` line names
  the exact `console_exec("search ...")` to fall through to. Fall back
  to the manual path (download/compile a PoC from ExploitDB/GitHub per
  the skill) only when both the index and the MSF console search miss,
  a module fails and is ruled out, or the skill has no MSF route. A
  module shell lands straight in the session table.
- **Every actioned exploit MUST be recorded — delegate to scribe.** Two
  forms:
  - **Session-producing** (reverse shell, MSF session, ssh/winrm via
    `start_process`): `send_command` refuses to run on an un-logged
    remote session. Send scribe `[record-exploit]` with the full
    delivery chain
  (session_id, target IP, label, delivery body with every prerequisite:
  login → CSRF → cookies → intermediate requests → payload, references,
  optional python_helper). Scribe calls `record_exploit()` and replies
  `[recorded]` with the paths — then `send_command` is unlocked. Do NOT
  call `record_exploit()` yourself; the dedicated-role pattern (like
  state-mgr) is what keeps every shell recorded. The `delivery` body
  must re-trigger from scratch — if the exploit needs a login, log in;
  if a CSRF token is needed, fetch it; carry cookies; THEN fire the
  payload. Reference `${LHOST}` / `${LPORT}` / `${LABEL}` for the
  callback endpoint (env-overridable at re-trigger); call Python helpers
  via `python3 "${EXPLOITS_DIR}/python/<...>.py"`. `target` MUST contain
  a valid IPv4 — scribe/the tool enforce it so filenames always lead
  with the IP (`<ip>-[<hostname>-]<label>.sh`). Re-establish with
  `bash engagement/exploits/<ip>-[<host>-]<label>.sh` (or
  `LPORT=5555 bash …`). Local processes (ssh/evil-winrm via
  `start_process`) are tracked by shell-server and still need
  `[record-exploit]` (the delivery is the `start_process` command +
  the credential that worked).
  - **Non-session** (file-read RCE, prompt-injection extraction,
    DPAPI decrypt, API-only credential recovery, cert / AD abuse that
    just mutates directory state): send scribe
    `[record-exploit] mode=no-session` with `body=` set to a complete
    standalone bash script that re-runs the exploit from scratch and
    prints the proof artifact to stdout. Scribe calls
    `record_non_session_exploit`; same filename contract
    (`<ip>-[<hostname>-]<label>.sh`), sidecar `.md` tagged
    `kind: non-session`. Lead monitors `poll_events()` for
    `vuln.update → actioned` and nudges scribe when no
    `engagement/exploits/<ip>-*` file exists.
- **Pivoting: NEVER default to MSF SOCKS / autoroute.** The in-Framework
  `auxiliary/server/socks_proxy` has repeatedly broken engagements (dead
  relay wedges the shared RPC → full msfconsole restart). Load the
  `pivoting-tunneling` skill and use chisel / ligolo-ng (with the
  operator-free `pen-agent-ligolo-*` helpers if installed) / sshuttle /
  native SSH `-D`/`-L`. The MCP `start_socks_proxy` tool refuses to run
  unless you pass `confirm_no_alternative=True` with a specific
  `alternative_rejection_reason` — do not reach for that flag unless every
  alternative really is ruled out for this specific pivot (no attackbox
  inbound to pivot; can't drop a binary on target; or MSF modules must route
  transparently without proxychains).
- **Dual MSF sessions per host (one operator + one agent).** Right after a
  foothold on a NEW host, call `mcp__metasploit-server__spawn_operator_session`
  so that host ends up with BOTH a reserved-for-operator session AND a
  separate agent session. The metasploit-server session-driving tools
  (`execute`, `upgrade_to_meterpreter`, `upload`, `download`, `ifconfig`)
  REFUSE to run on a host missing this pair. If the source is Meterpreter,
  `spawn_operator_session` returns `needs_manual` — have the operator catch
  a second callback and call `reserve_operator_session` on it. Load the
  `post-exploit/dual-session-handoff` skill for the full flow. Escape hatch
  (`confirm_single_session_ok=True` + `single_session_reason`) is only for
  hosts that genuinely cannot support a second session; the reason is logged.
- MCP names: hyphens for servers (`mcp__shell-server__`), underscores for
  tools (`add_vuln`)

### Stall Detection

5+ tool rounds on the same failure with no new info → stop immediately.
Return: what was attempted, what failed, assessment (blocked/retry-later).

### Status-Check Probes

If the lead sends `[status-check] silence for Nm — what step are you on?`, reply
immediately with a one-line summary of the step you're currently executing
(e.g. `[status] running nmap -sC on 10.10.14.30, ~90s remaining`), or
`[blocked] reason="<why>"` if you're genuinely stuck. If a long-running tool
call is holding your turn, you can only reply once that call returns — that's
expected; just reply then. Do not treat the probe as a new task and do not
stop the work you were doing — the probe is diagnostic, not an assignment.
The lead sends these when a teammate has gone silent longer than a work-unit
should take; a prompt reply resets the silence timer and the lead keeps
routing around you.

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
  exploits/         # Per reverse shell: <hostname>-<label>.sh (end-to-end re-trigger) + .md (context) + python/<name>.py (optional helpers)
  evidence/         # Saved output, responses, dumps
    logs/           # Teammate JSONL transcripts
```

## Permission Mode

Agent teams runs in **standard permission mode only** — permission-skipping
(`--dangerously-skip-permissions`) is not supported and `run.sh` refuses it.
MCP server tools are pre-allowed in `.claude/settings.json`, which
`install.sh` writes once if missing (see docs/installation.md#permissions) —
it never overwrites an existing one. The orchestrator's approval gates provide
human-in-the-loop control. To cut prompt friction, extend the
`.claude/settings.json` allowlist (see `/fewer-permission-prompts`) rather
than bypassing permissions.

## Contributing to this repo

Editing PEN-AGENT itself (skills, templates, docs, layout, install)? See
`CONTRIBUTING.md` — it holds the skill-file format, documentation rules
(including the **mandatory CHANGELOG update** on every branch merged to main),
the token-budget rules, directory layout, and install steps. Kept out of this
file so it doesn't ride in every agent turn's context.
