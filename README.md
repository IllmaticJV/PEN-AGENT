# PEN-AGENT

Autonomous offensive-security assessment toolkit for Claude Code (CTF/lab + AI red teaming).

## Quick start

```bash
git clone https://github.com/IllmaticJV/PEN-AGENT.git
cd PEN-AGENT
./install.sh                            # installs skills, MCP servers, Docker images, .claude/settings.json
bash preflight.sh --install --optional  # installs attackbox tools (nmap, ffuf, impacket, ...)
./run.sh
```

`install.sh` writes `.claude/settings.json` for you if it doesn't already
exist (see [Permissions](#permissions) for what it contains and why it's not
committed to the repo). If it already exists, your copy is left untouched —
re-run `install.sh` any time without fear of it clobbering customization.

Then just talk to it: send a target (an IP, CIDR, or chatbot URL). The
orchestrator defines scope, runs recon, and presents each routing decision for
your approval before assigning work — answer those as they come up.

## Commands

| Command | Does |
|---|---|
| `./install.sh` | Install skills + MCP servers + Docker images (symlinked; `--copy` to snapshot) |
| `./uninstall.sh` | Remove everything install.sh set up |
| `bash preflight.sh [--install] [--optional]` | Check/install attackbox tools (nmap, ffuf, hashcat, impacket, ...) |
| `bash config.sh` | Pre-engagement wizard — scan type, proxy, spray tier, cracking, C2 backend |
| `./run.sh [--yolo]` | Start shell-server + skill-router (+ Metasploit if installed) + Claude Code |
| `uv run --directory tools/reporter python export_report.py --strict` | Export findings → `engagement/findings.json` + `report.md` |
| `bash operator/state-viewer/start.sh` | State dashboard → `http://127.0.0.1:8099` |
| `bash operator/msf-console/start.sh` | Live msfconsole + session/job viewer → `http://127.0.0.1:8100` |

Inside Claude Code, invoke the orchestrator with `/pen-agent-ctf`.

## Permissions

`.mcp.json` ships in the repo. `.claude/settings.json` does not — it may hold
machine-specific customization, and a running Claude Code session can't
safely write its own permission file — so `install.sh` writes it once, only
if missing:

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

This does two things: enables the agent-teams flag the orchestrator requires,
and pre-approves every MCP tool PEN-AGENT uses so standard permission mode
doesn't prompt for every call. If `claude` reports agent-teams unavailable,
confirm the file has `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` set and that you
started a **fresh** session after it was written — the flag is read at
process start, so `claude --resume` on an older session won't pick it up.

**Don't use `--yolo` for real engagements.** It skips Claude Code's own
permission prompts *and* the human-approval step the orchestrator is built
around. Without that, Claude Code's own safety classifiers are the only thing
left between a teammate and its next tool call, and they get stricter the
more a session's actions pattern-match sustained multi-host compromise —
sessions breaking mid-engagement usually trace back to this. Extend the
`allow` list instead (see `/fewer-permission-prompts`) if prompts are the
annoyance.

**Agent teams** requires a local, interactive Claude Code CLI session —
hosted/cloud sessions and non-interactive (`-p`) runs don't spawn persistent
teammates at all, flag or no flag; a named `Agent` call just runs as an
ordinary subagent there. For split-pane teammate visibility, start Claude
Code inside `tmux`.

## Dashboards

Both are Python stdlib HTTP servers (SSE live updates, no frontend build);
each keeps its page markup in a sibling `templates/` directory. They bind
`127.0.0.1` only by default; running
`bash operator/state-viewer/generate-token.sh` writes a shared token to
`~/.config/pen-agent/viewer-token` that makes **both** bind `0.0.0.0` and
require login (`/login` cookie, or `Authorization: Bearer <token>`).

- **State** (`operator/state-viewer/`, port `8099`) — access-chain graph,
  targets, creds, access, vulns, pivots, tunnels, event timeline, all live.
  `--port`/`--db` flags if you need a different port or database path.
- **msf-console** (`operator/msf-console/`, port `8100`) — **read-only** view
  of the same Framework the `metasploit-server` MCP drives (same
  `engagement/msfrpc.yaml`): the live session + listener/job list, a
  **per-session command log** (what the agents ran on each session and its
  output), and the shared console spool. Interaction is deliberately not done
  here — the RPC/web console can't attach to a session (`sessions -i` crashes
  inside it). For a full interactive console, attach the real one (below).
  Needs `engagement/msfrpc.yaml`; shows a clear banner if Metasploit isn't
  reachable rather than erroring.

## C2 backend

Metasploit is the default — `run.sh` auto-detects `metasploit-framework` and
starts the C2 + the metasploit-server MCP with no extra steps, falling back to
shell-server if it isn't installed. Run `bash config.sh` to pin a backend
explicitly or wire a custom C2.

**Full interactive console.** When `tmux` is present, the C2 is an actual
`msfconsole` running the `msgrpc` plugin inside a tmux session — one Framework
instance shared by the operator and the agents. Attach it for a 100% real
console (full `sessions -i`, meterpreter interactive, tab-complete):

```bash
tmux attach -t pen-msf        # detach with Ctrl-b then d
```

The agents drive this same instance over RPC, so sessions/jobs/loot are shared
live. You can work alongside them — the only contention is interacting with the
*same* session's shell at the same instant; use a different session or jump in
when a session is idle (the read-only portal's per-session log lets you watch
without attaching). Without `tmux`, `run.sh` falls back to a headless
`msfrpcd` (agents work; no live operator console — install tmux for that).

## Documentation

- [Architecture](docs/architecture.md) · [Installation](docs/installation.md) ·
  [Running an Engagement](docs/running-an-engagement.md)
- [MCP Servers](docs/mcp-servers.md)
- [Skills Reference](docs/skills-reference.md) · [Writing Skills](docs/writing-skills.md)

---

## What this is

PEN-AGENT turns Claude Code into a coordinated red team: a lead orchestrator
runs recon, maps the attack surface, and routes work to persistent domain
teammates that load technique **skills** on demand, execute them against live
targets, and chain findings toward impact. Covers two domains with one
framework — traditional (web, AD, Linux/Windows privesc, network, pivoting,
credentials) and AI/LLM (prompt injection, agents, RAG, MCP/tool surfaces, ML
supply chain — mapped to the OffSec **AI-300 (OSAI)** syllabus).

| Layer | What it is |
|---|---|
| Orchestrator | `/pen-agent-ctf` — team lead. Recon, routing, vuln chaining. Slash command only. |
| Teammates | `teammates/` spawn templates. Enum teammates discover, ops teammates action one assigned vuln. `state-mgr`/`shell-mgr` own state writes and shell lifecycle. |
| Skills | `skills/<category>/<name>/SKILL.md` — methodology + payloads for one technique, loaded on demand via skill-router, never hard-coded into prompts. |
| MCP servers | `tools/*` — skill-router (RAG), nmap, shell, state, browser, rdp, metasploit. |
| State | `engagement/state.db` (SQLite) — targets, ports, creds, access, vulns, pivots, tunnels, events. One writer (`state-mgr`). |
| Reporter | `tools/reporter/` — confirmed vulns → OffSec-style findings with reproducible exploit paths. |
| Knowledge | `knowledge/lessons-learned.md` — persistent, cross-engagement lessons. |

**84 skills** across 9 categories — web (37), AD (15), privesc (11), network
(9), ai (8), credential/evasion/post-exploit/research (1 each) — plus the
orchestrator and retrospective skills. Full list:
[Skills Reference](docs/skills-reference.md).

**Scope is enforced in code, not prompted.** The orchestrator writes
`engagement/scope.allow` at engagement start; the nmap and metasploit MCP
servers refuse any target not in it. Absent allowlist = enforcement off (and
logged) — the orchestrator always writes one.

**Findings are reproducible.** A confirmed vuln becomes an OffSec-style
finding carrying the complete `steps_to_reproduce` command path (expected vs.
observed, evidence) and a verification oracle (callback, exfiltrated canary,
code execution, state change) independent of the model's own judgement.
`export_report.py --strict` rejects anything self-graded or unreproducible.

## Disclaimer

**By using PEN-AGENT you accept full responsibility for its actions.** It runs
fully autonomous agents that scan, exploit, escalate privilege, move
laterally, and attack AI systems against targets you specify.

- **Authorization required.** No use against systems without explicit written
  permission — unauthorized access is illegal (CFAA 18 U.S.C. § 1030 and
  equivalent laws elsewhere).
- **CTF/lab orchestrator, no OPSEC.** Assume all activity is logged and
  detectable. Skills are AI-authored baselines — verify findings before
  relying on them.
- **May trigger Anthropic content-policy warnings** on your account. Use at
  your own risk.
- **No warranty.** Provided as-is; the authors are not liable for any damage,
  data loss, legal consequences, or other harm from its use.
