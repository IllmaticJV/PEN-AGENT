# PEN-AGENT

Autonomous offensive-security assessment toolkit for Claude Code — for CTF/lab
environments and **AI red teaming**.

<p align="center">
  <img src="docs/banner.png" width="700" alt="PEN-AGENT banner">
</p>

PEN-AGENT turns Claude Code into a coordinated red team. A lead orchestrator runs
recon, maps the attack surface, and routes work to persistent domain teammates
that load technique **skills** on demand, execute them against live targets, and
chain findings toward impact. Engagement state lives in a SQLite graph that
survives context compaction; every target is checked against a code-enforced
scope allowlist; and every confirmed vulnerability is written up as an
OffSec-style finding with a complete, reproducible, command-by-command exploit
path.

Two target domains, one framework:

- **Traditional** — web apps, Active Directory, Linux/Windows privilege
  escalation, network services, pivoting, credential attacks.
- **AI / LLM** — prompt injection, agents, multi-agent/A2A, RAG, embeddings,
  MCP/tool surfaces, the ML supply chain, and AI infrastructure. This set maps
  to the OffSec **AI-300 (OSAI)** syllabus.

## Highlights

- **Agent teams.** A lead orchestrator spawns persistent enum/ops teammates
  (net, web, ad, lin, win, **ai**) that accumulate context across tasks, work in
  parallel, and report findings back for routing.
- **87 skills** across 9 technique categories, served on demand via semantic
  search (RAG over ChromaDB). Includes a dedicated **`ai/`** category for AI red
  teaming.
- **Metasploit C2.** Initial shells are caught by the shell-server, then
  upgraded to Meterpreter for stable transport, file transfer,
  post-exploitation, and pivoting.
- **Code-enforced scope.** The nmap and Metasploit MCP servers refuse any target
  not in `engagement/scope.allow` — scope is a guardrail in code, not a prompt
  the model is trusted to follow.
- **Reproducible, OffSec-style findings.** Each finding ships as importable JSON
  with a step-by-step command path and a verification oracle; the exporter
  rejects self-graded or unreproducible findings.
- **Lessons learned.** A persistent, cross-engagement knowledge base the
  orchestrator reads at start and the retrospective appends to — PEN-AGENT gets
  better across runs.
- **Live state dashboard.** A browser view of the access-chain graph, targets,
  credentials, vulns, and pivots, updating in real time.
- **Metasploit operator console.** A browser view of live sessions/jobs plus
  a real msfconsole on the same shared msfrpcd the agent drives — watch, and
  optionally type into, exactly what it has access to.

## How it works

| Layer | What it is |
|-------|-----------|
| **Orchestrator** | `/pen-agent-ctf` — the team lead. Runs recon, presents the attack surface, routes every task, and chains vulns toward impact. Invoked by slash command only. |
| **Teammates** | Spawn templates in `teammates/`. Enumeration teammates discover and report; operations teammates action a single assigned vuln. Infrastructure teammates (`state-mgr`, `shell-mgr`) own state writes and shell lifecycle. |
| **Skills** | `skills/<category>/<name>/SKILL.md` — self-contained methodology + payloads for one technique. Loaded on demand via the skill-router MCP; never hard-coded into prompts. |
| **MCP servers** | `tools/*` — skill-router (RAG), nmap, shell, state, browser, rdp, and metasploit (C2). |
| **State** | `engagement/state.db` (SQLite) — the attack graph: targets, ports, creds, access, vulns, pivots, tunnels, events. One writer (`state-mgr`) for coherence. |
| **Reporter** | `tools/reporter/` — turns confirmed vulns into OffSec-style findings with reproducible exploit paths. |
| **Knowledge** | `knowledge/lessons-learned.md` — persistent lessons reused across engagements. |

See the [docs site](docs/) for
architecture, the engagement workflow, and the MCP server reference.

## Skills

84 technique/discovery skills across 9 categories, plus the orchestrator and
support skills. Full list: [Skills Reference](docs/skills-reference.md).

| Category | Covers |
|----------|--------|
| `web` (37) | SQLi, XSS, SSTI, SSRF, LFI, XXE, deserialization, JWT, request smuggling, auth/OAuth/2FA, upload, IDOR, CORS, CSRF, race conditions, Tomcat/AJP, source review … |
| `ad` (15) | Discovery, Kerberoasting, delegation, ticket forging, ACL/GPO abuse, ADCS (ESC1–15), coercion/relay, credential dumping, SCCM, trusts, persistence |
| `privesc` (11) | Linux & Windows discovery + sudo/SUID/caps, cron/service, file/path, kernel, tokens, UAC, DLL, credential harvesting |
| `network` (9) | Network recon, SMB/DB/remote-access/infra enumeration, SMB exploitation, container escapes, pivoting/tunneling |
| `ai` (8) | **AI red teaming (OSAI AI-300):** recon, prompt injection, multi-agent/A2A, RAG, embeddings, MCP/tool abuse, ML supply chain, AI infrastructure |
| `credential` (1) | Lockout-safe password spraying |
| `evasion` (1) | AV/EDR evasion, AMSI/ETW, LOLBins |
| `post-exploit` (1) | Offline hash/credential recovery (hashcat/john) |
| `research` (1) | Source-code review / unknown-vector analysis |

## Installation

**Prerequisites:** a Linux VM with pentesting tools,
[Claude Code](https://docs.anthropic.com/en/docs/claude-code),
[uv](https://docs.astral.sh/uv/), and
[Docker](https://docs.docker.com/engine/install/).
Optional: [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
for C2.

```bash
./install.sh          # Symlink-based (edits in the repo reflect immediately)
./install.sh --copy   # Copy-based (standalone machines)
./uninstall.sh        # Remove everything
```

The installer registers the orchestrator skill, installs the MCP servers and the
reporter (via `uv`), indexes `skills/` into ChromaDB for semantic retrieval, and
starts the shell-server. The repo must stay in place — the skill-router reads
`skills/` at runtime.

Check attackbox dependencies (nmap, ffuf, sqlmap, hashcat, impacket, …), and
optionally install the missing ones:

```bash
bash preflight.sh                      # report what's missing
bash preflight.sh --install            # install missing required tools
bash preflight.sh --install --optional # also install the optional set
```

`--install` puts downloaded/non-apt tools under `/opt/PEN-AGENT/tools` (system
packages go via apt) and needs sudo. See [dependencies](docs/dependencies.md)
for the full tool list.

### Agent teams

PEN-AGENT uses [Claude Code agent teams](https://code.claude.com/docs/en/agent-teams),
an experimental CLI feature — not available in every Claude Code surface (e.g.
hosted/cloud sessions don't expose `TeamCreate` or `Agent(team_name=...)`).
Run PEN-AGENT from a local Claude Code CLI session (VM or dedicated pentesting
machine), with `.claude/settings.json` at the repo root enabling the flag — see
[Permissions](#permissions) below, which `.mcp.json` ships with but
`.claude/settings.json` does not (Claude Code won't let a session write its own
permission file, for good reason — you create it once). For split-pane
teammate visibility, start Claude Code inside a `tmux` session.

## Permissions

`.mcp.json` ships in the repo. `.claude/settings.json` does not (and can't be
auto-generated for the reason above) — create it once at the repo root:

```json
{
  "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" },
  "enableAllProjectMcpServers": true,
  "permissions": {
    "allow": [
      "mcp__skill-router__*", "mcp__nmap-server__*", "mcp__shell-server__*",
      "mcp__browser-server__*", "mcp__rdp-server__*", "mcp__state__*",
      "mcp__metasploit-server__*"
    ],
    "deny": ["Bash(sudo *)", "Bash(rm -rf *)"]
  }
}
```

This enables agent teams and pre-approves every MCP tool PEN-AGENT uses, so
**standard permission mode works without `--yolo`** — each teammate's Bash
calls (nmap, hydra, impacket, etc.) still get a normal approval prompt, but
you're not reflexively reaching for `--dangerously-skip-permissions` just to
stop MCP tools from prompting every call.

**Prefer standard mode over `--yolo` for real engagements.** `--yolo` disables
Claude Code's own permission prompts entirely, which also removes the human
approval step that would otherwise interrupt a run before it compounds —
without it, Claude Code's own safety classifiers (separate from PEN-AGENT, not
something this project configures) are the only thing left evaluating
offensive-tool chains, and they get noticeably stricter the more a session's
actions pattern-match sustained multi-host compromise. If you're seeing
sessions break partway through a multi-host engagement, try dropping `--yolo`
first — the "OPERATOR APPROVAL REQUIRED" gate before every task assignment
means you're already approving each step anyway, so the friction is mostly
a few extra Bash prompts, not re-answering the routing question. Extend the
`allow` list above with the specific tool invocations you approve often (see
`/fewer-permission-prompts`) to cut that friction further.

## Running

```bash
./run.sh              # starts shell-server (+ Metasploit if installed) + Claude Code
./run.sh --yolo       # skip permission prompts — avoid for live engagements, see above
```

Send a target (e.g. an IP or a chatbot URL) to activate the orchestrator. It
defines scope, writes the enforced `scope.allow`, loads lessons learned, runs
recon, and presents routing decisions for your approval before assigning work.
Run from an isolated VM or dedicated pentesting machine.

### C2 (Metasploit)

Metasploit is the C2 backend. If `metasploit-framework` is installed, `run.sh`
auto-starts `msfrpcd`, writes `engagement/msfrpc.yaml`, and launches the
metasploit-server MCP — no extra steps. To pin the backend explicitly or wire a
custom C2:

```bash
bash config.sh        # select backend (metasploit | custom), patches .mcp.json
```

## Scope enforcement

Scope is enforced in code. At engagement start the orchestrator writes
`engagement/scope.allow` (IPs, CIDRs, hostnames, `*.wildcards`). The nmap and
metasploit MCP servers validate every target against it and **refuse
out-of-scope targets** — teammates physically cannot scan or exploit a host that
isn't authorized. If the allowlist is absent, enforcement is off (and a warning
is logged); the orchestrator always writes it.

## Findings & reporting

Confirmed vulnerabilities become OffSec-style findings. Each one carries the full
**`steps_to_reproduce`** path — every command the agent ran, copy-pasteable,
with expected/observed results and evidence — plus a **verification oracle**
(callback, exfiltrated canary, code execution, state change) proving success
independent of the model's judgement.

```bash
uv run --directory tools/reporter python export_report.py --strict
# → engagement/findings.json (importable) + engagement/report.md
```

`--strict` rejects findings that are self-graded, have no runnable command, or
lack evidence. Schema and a worked example: `tools/reporter/`.

## State dashboard

```bash
bash operator/state-viewer/start.sh      # http://127.0.0.1:8099
```

A read-only view of the access-chain graph, targets, credentials, access, vulns,
pivots, tunnels, and an event timeline — updating live as teammates work. For
host access when PEN-AGENT runs in a VM, generate a token with
`operator/state-viewer/generate-token.sh`.

## Metasploit operator console

```bash
bash operator/msf-console/start.sh      # http://127.0.0.1:8100
```

Connects to the same `msfrpcd` daemon the `metasploit-server` MCP uses, so the
session/job list here is exactly what the agent sees — live. The embedded
console is a real msfconsole on that shared instance: `sessions -i <id>` drops
you into whatever the agent opened, and anything you run is visible to the
agent's next session/job lookup too. Shares the state dashboard's auth token
(`operator/state-viewer/generate-token.sh`). See `operator/msf-console/README.md`.

## Documentation

- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [Running an Engagement](docs/running-an-engagement.md)
- [MCP Servers](docs/mcp-servers.md)
- [Skills Reference](docs/skills-reference.md) · [Writing Skills](docs/writing-skills.md)

## Disclaimer

**By using PEN-AGENT you accept full responsibility for its actions.** It runs
fully autonomous AI agents that execute offensive security techniques — scanning,
exploitation, credential attacks, privilege escalation, lateral movement, and
attacks against AI systems — against targets you specify.

- **Authorization required.** Do not use against systems without explicit written
  permission. Unauthorized access is illegal under the CFAA (18 U.S.C. § 1030)
  and equivalent laws elsewhere.
- **CTF and lab use.** The orchestrator is a CTF/lab solver with no OPSEC
  considerations — assume all activity is logged and detectable. Skills are
  AI-authored baselines; expect gaps and false positives, and verify findings
  before relying on them. The reporter's reproduction paths and oracles exist
  precisely so you can.
- **Content policy.** Autonomous offensive agents may trigger Anthropic content
  policy warnings on your account. Use at your own risk.
- **No warranty.** Provided as-is. The authors are not liable for any damage,
  data loss, legal consequences, or other harm resulting from its use.
