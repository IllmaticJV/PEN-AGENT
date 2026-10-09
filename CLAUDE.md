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
| `tools/preflight/gen_payloads.sh --lhost <ip|iface>` | ONCE at engagement init (via shell-mgr `[preflight-payloads]`) — pre-bakes ~13 common msfvenom payloads into `engagement/payloads/` + index.json |
| `tools/preflight/handler_calls.py [--json]` | Emits the exact `start_handler` MCP calls to spin up a handler per baked payload — shell-mgr iterates these after gen_payloads |
| `tools/preflight/pick.py --platform X --arch Y --format Z` | Look up a pre-generated payload (prints path + start_handler call); replaces mid-exploit msfvenom round-trips |

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
directly** — they are callable but MUST NOT be used. Send structured
messages, always carrying `discovered_by=<your-teammate-name>` so
timeline attribution survives even if state-mgr's sender-detection
fallback misses:

```
[add-port] ip=<ip> port=<N> proto=tcp service=<svc> discovered_by=<self>
[add-target] ip=<ip> hostname=<host> os="<os>" discovered_by=<self>
[update-target] ip=<ip> hostname=<host> notes="<notes>"
[add-vuln] ip=<ip> title="<title>" vuln_type=<type> severity=<sev> via_access_id=<N> details="<details>" discovered_by=<self>
[add-cred] username=<user> secret=<secret> secret_type=<type> source="<source>" via_access_id=<N> via_vuln_id=<M> discovered_by=<self>
[add-access] ip=<ip> method=<method> user=<user> level=<level> via_credential_id=<N> via_vuln_id=<V> discovered_by=<self>
[add-blocked] ip=<ip> technique="<name>" reason="<why>" retry=<no|later|with_context> blocked_by=<self>
[add-pivot] from_ip=<ip> to_subnet=<cidr> pivot_type="<type>" discovered_by=<self>
[update-vuln] id=<N> status=actioned details="<details>"
```

Full write contract (every message type, outbound replies,
validation rules) lives at `tools/state-server/WRITES.md` — state-mgr
loads it at activation. Batch multiple writes in one message. Wait
for confirmation IDs before referencing them in later messages.

**SendMessage requires a `summary` field** (5-10 word preview) with every
message to any teammate.

### Finding Reports (OffSec-style, reproducible)

A vuln row in state.db is the attack graph, not the deliverable. The
moment you **confirm** a vuln (it becomes `actioned`), you — the
teammate that found it — MUST also write an OffSec-style finding to
`engagement/findings/<id>.json`.

- **Schema (contract):** `tools/reporter/finding.schema.json` — the
  normative source for required fields, enums, and shape. The
  exporter (`tools/reporter/export_report.py --strict`) rejects any
  finding that misses a required field or lacks a reproduction path.
- **Worked example:** `tools/reporter/examples/finding-prompt-injection.json`
- **Jumpstart:** `python3 tools/reporter/new_finding.py <vuln_id>`
  pre-populates `engagement/findings/<vuln_id>.json` from state.db.
  Fill the TODO fields — `steps_to_reproduce`, `verification`,
  `impact`, `placeholders.ATTACKBOX` — and the exporter will accept it.

Two invariants that don't live in the schema (judgment calls):

- **`verification.status: confirmed`** requires an independent oracle
  (out-of-band callback, exfiltrated canary, concrete state change).
  Never mark `confirmed` on model judgement alone — use `plausible`.
- **Record `steps_to_reproduce` as you go.** The path must be real,
  not reconstructed from memory; point every step's `evidence_ref`
  at a saved file under `engagement/evidence/`.

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

- **Stay in scope.** Only act against targets in `engagement/scope.md`
  / `engagement/scope.allow`. All five target-touching MCP servers
  code-enforce `scope.allow` and refuse out-of-scope targets:
  nmap-server, metasploit-server, browser-server (`browser_open` /
  `browser_navigate` extract the URL host), rdp-server (`rdp_connect`
  checks `host=`), and shell-server (`start_process` pattern-matches
  common CLI shapes — ssh, scp, impacket, evil-winrm, nxc).
  Unparseable `start_process` commands fall through to the operator-
  approval prompt. If a tool returns `OUT OF SCOPE`, do NOT work
  around it — stop and report to the lead; never edit `scope.allow`
  to add a target yourself (operator decision only).
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
- **Every actioned exploit MUST be recorded — delegate to scribe.**
  `send_command` refuses to run on an un-logged remote session, so
  the record must land first. Two forms:
  - **Session-producing** (reverse shell / MSF session / ssh / winrm):
    send scribe `[record-exploit] session_id=… target=<ip> label=…
    delivery=<<<EOD …EOD` carrying the end-to-end delivery chain
    (login → CSRF → cookies → payload). The `delivery` body must
    re-trigger from scratch — do not assume external auth state.
  - **Non-session** (file-read RCE, prompt-injection, DPAPI decrypt,
    cert/AD state mutation): send scribe `[record-exploit]
    mode=no-session` with `body=` as a standalone bash script that
    prints proof to stdout.
  Scribe replies `[recorded]`; only then is `send_command` unlocked.
  **Do NOT call `record_exploit()` yourself** — the dedicated role
  is what keeps every shell recorded. Full field contract (every
  optional field, HEREDOC syntax, filename rules, nudge handling)
  lives at `tools/shell-server/RECORDING.md`; scribe loads it at
  activation.
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
- **Preflight payload bake-off is MANDATORY at engagement init
  (Metasploit backend).** Lead's FIRST message to shell-mgr is
  `[preflight-payloads] lhost=<IP|iface>`; HARD gate — do NOT
  assign any exploitation task that may produce a callback until
  shell-mgr replies `[preflight-ready]`. Teammates then use
  `python3 tools/preflight/pick.py --platform X --arch Y --format Z`
  to grab a baked payload with a live handler. Full flow (what
  gen_payloads bakes, OSEP-starter XOR loaders, failure modes) in
  `tools/preflight/README.md`.
- **Preflight payloads are trusted binary artifacts — never read
  them.** Files under `engagement/payloads/` are raw shellcode,
  XOR-encoded loaders, and OSEP-style PowerShell. NEVER call
  `Read`/`cat`/`less`/`head`/`tail`/`strings` on them, and never
  paste their content into chat — wastes tokens and trips the
  safety classifier. Agent interface is `pick.py` + `index.json`
  (sha256sum against the index value for integrity). Trust the
  `[preflight-ready]` reply — gen_payloads fail-fasts on ≥2
  failures, so a success means the set is good.
- **Dual MSF sessions per host.** After every new foothold, call
  `spawn_operator_session` so the host has both an agent session
  and a reserved-for-operator session. The MSF session-driving
  tools refuse to run on a host missing this pair; code-enforced.
  Load the `dual-session-handoff` skill for the full flow (incl.
  the Meterpreter-origin case and the single-session escape hatch).
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
