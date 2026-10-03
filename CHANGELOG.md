# Changelog

All notable changes to this project will be documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/).

## 2026-10-03

### Changed

- **Refactored README.md** — getting-started commands and interaction first,
  explanatory content ("what this is", architecture tables, disclaimer) moved
  below a divider at the bottom and condensed.
- **Merged the two operator-tool READMEs into the root README.md.**
  `operator/state-viewer/README.md` and `operator/msf-console/README.md` are
  deleted — a single README only, no fractured per-tool docs for these two.
  `tools/*/README.md` (the MCP servers) are unaffected; that rule still
  applies.

### Fixed

- **`.mcp.json` now ships in the repo.** It was referenced throughout
  (`install.sh`'s config-verification step, `config.sh`'s patch logic,
  `docs/mcp-servers.md`'s own documented example, and README's "no manual
  setup" claim) but was never actually committed — every fresh clone was
  silently missing all 7 MCP server registrations (skill-router,
  nmap-server, shell-server, browser-server, rdp-server, state,
  metasploit-server) until an operator built one by hand. `.claude/settings.json`
  has the same gap but can't be shipped the same way — Claude Code won't let
  a session write its own permission file — so docs now give the exact
  content to create it with (agent-teams flag + MCP tool allowlist); see
  README's Permissions section / docs/installation.md#permissions.

### Added

- **Metasploit operator console** (`operator/msf-console/`) — web dashboard
  giving the human operator a live session/job list plus a real, interactive
  msfconsole on the same shared `msfrpcd` instance the `metasploit-server`
  MCP drives. Same shape as `operator/state-viewer` (stdlib HTTP server,
  inline HTML/JS, SSE live updates) and shares its auth token. Start with
  `bash operator/msf-console/start.sh` → `http://127.0.0.1:8100`.

### Changed

- **Metasploit is now the default shell/C2 backend**, not an opt-in: when
  `metasploit-framework` is installed (`msfrpcd`/`msfconsole` on PATH),
  `config.yaml`'s `shell.backend` defaults to `metasploit` instead of
  `shell-server` — covering session interaction, file transfer, *and*
  pivoting (autoroute + SOCKS, promoted to the top of the
  `pivoting-tunneling` skill's decision tree, ahead of Chisel/Ligolo/
  sshuttle). Falls back to `shell-server` automatically whenever Metasploit
  isn't installed or the upgrade/pivot fails — never a hard requirement.
  `config.sh`'s Q5 wizard now defaults to Metasploit (auto-starting
  `msfrpcd` on Enter) whenever it's detected.

## 2026-10-02 — Initial release

Autonomous offensive-security assessment toolkit for Claude Code, for CTF/lab
environments and AI red teaming (OffSec AI-300 / OSAI).

### Orchestration

- Single agent-teams orchestrator (`/pen-agent-ctf`) — a lead that runs recon,
  maps the attack surface, and routes work to persistent enum/ops teammates
  (net, web, ad, lin, win, ai) plus infrastructure teammates (state-mgr,
  shell-mgr) and on-demand specialists (bypass, spray, recover, research).
- Engagement state graph in SQLite (`state-server` MCP), one writer for
  coherence; chains vulnerabilities toward impact.

### Skills

- 84 technique/discovery skills across 9 categories: web, ad, privesc, network,
  credential, evasion, post-exploit, research, and **ai**.
- The `ai` category covers AI red teaming mapped to the OffSec AI-300 syllabus:
  recon, prompt injection, multi-agent/A2A, RAG, embeddings, MCP/tool abuse,
  ML supply chain, and AI infrastructure. Served on demand via the skill-router
  MCP (semantic search over ChromaDB).

### C2 and MCP servers

- Metasploit is the C2 backend (`metasploit-server` MCP wrapping `msfrpcd`):
  catch shells via shell-server, upgrade to Meterpreter for transport, file
  transfer, post-exploitation, and pivoting.
- MCP servers: skill-router, nmap, shell, state, browser, rdp, metasploit.

### Safety and reporting

- **Code-enforced scope** — the nmap and metasploit MCP servers refuse any
  target not in `engagement/scope.allow`.
- **OffSec-style findings** (`tools/reporter/`) — confirmed vulns become
  importable JSON + Markdown with a complete, command-by-command reproduction
  path and a verification oracle; the exporter rejects self-graded or
  unreproducible findings.
- **Persistent lessons learned** (`knowledge/lessons-learned.md`) — generalizable
  lessons reused across engagements.

### Install

- `install.sh` sets up the orchestrator skill, MCP servers, and the reporter,
  and indexes skills into ChromaDB.
- `preflight.sh --install` installs the attackbox toolchain (required by
  default, `--optional` for the rest); downloaded tools live under
  `/opt/PEN-AGENT/tools`, system packages via apt.
