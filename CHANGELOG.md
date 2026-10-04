# Changelog

All notable changes to this project will be documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/).

## 2026-10-04

### Fixed

- **`run.sh` left the msf-console/metasploit-server pair unable to connect
  after a `msfrpcd` daemon outlived its run.** `msfrpcd` is a detached
  background process (`&`), so it survives the Claude Code session that
  started it; a later run finding it already listening would just log
  "msfrpcd already running" and skip writing `engagement/msfrpc.yaml`
  entirely — leaving a daemon nobody has credentials for. Confirmed live:
  `pgrep -af msfrpcd` showed a running daemon while
  `engagement/msfrpc.yaml` didn't exist. `run.sh` (and the equivalent
  branch in `config.sh`, which detected this same case but only offered to
  fall back to shell-server) now kill and restart `msfrpcd` with fresh
  credentials whenever it's found running without a matching config,
  rather than leaving it stranded. Verified with a stubbed `msfrpcd`: old
  PID dies, new PID comes up with a fresh password, config gets written.

### Fixed

- **Teammate names built from a bare IP (e.g. `net-enum-192.168.121.10`)
  were rejected by the real `Agent` tool** — its `name` parameter requires
  `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, which has no dot. Confirmed live:
  `InputValidationError` on spawn. `skills/ctf/SKILL.md` and
  `teammates/README.md` now call out the constraint explicitly and require
  sanitizing (`.` → `-`) before building any name from a target/host.
- **The orchestrator assumed `TaskCreate`/`TaskGet`/`TaskList`/`TaskUpdate`
  are always available whenever agent teams is enabled.** They're actually
  gated per-model (not every current Sonnet/Opus release provides them by
  default) and the orchestrator hit this live, correctly falling back to
  spawn+`SendMessage`-only coordination on its own. Made that fallback
  explicit and first-class instead of relying on improvisation: a new
  "Task List Availability" section in `skills/ctf/SKILL.md` has the lead
  check once via `ToolSearch` and, if absent, track task IDs/ownership in
  its own `active_teammates` bookkeeping instead of making the calls;
  `CLAUDE.md`'s teammate Activation Protocol updated to match (an empty
  `ToolSearch` result is expected, not an error).

### Fixed

- **The orchestrator's agent-teams integration called tools that don't
  exist.** `TeamCreate`, `TeamDelete`, and the `Agent` tool's `team_name`
  parameter — used throughout `skills/ctf/SKILL.md`, `CLAUDE.md`, and
  `teammates/README.md` for team creation, name-collision handling, and
  teardown — are not part of Claude Code's real agent-teams API. The actual
  mechanism: with `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` set, calling
  `Agent` with a `name` parameter (no `team_name`) spawns a persistent
  teammate and the team forms implicitly around the lead's session; team
  state is cleaned up automatically when the session ends. This was the
  actual root cause of "agent-teams tools aren't available in this
  session" even on a correctly configured local CLI session — not an
  environment or settings problem. Rewrote the team-spawn mechanics across
  all three files to match the real API, including the correct resume
  behavior (in-process teammates are not restored by `/resume`) and the
  non-interactive-session (`-p` flag) limitation.

### Added

- **`install.sh` now writes `.claude/settings.json` itself** (agent-teams
  flag + MCP tool allowlist) when it's missing, instead of asking the
  operator to create it by hand. Previously-documented manual heredoc
  copy/paste was error-prone (a malformed hand-edit was reported breaking a
  session). Never overwrites an existing file — only warns if it looks like
  it's missing the keys PEN-AGENT needs. README/docs/CLAUDE.md updated to
  match.


### Fixed

- **All 7 MCP servers crash-looped or failed to start against `mcp` 2.x.**
  Every server's `pyproject.toml` declared `mcp[cli]` with only a lower
  bound, so a fresh resolve picked up the breaking 2.x release (FastMCP
  renamed to MCPServer). `metasploit-server` had no committed `uv.lock` at
  all and broke on every run; the `uv.lock` files added for
  nmap-server/rdp-server/skill-router in the previous fix were themselves
  generated after `mcp` 2.x became available and were silently pinned to
  the broken version. Pinned `mcp[cli]` to `<2.0.0` everywhere, regenerated
  all affected locks (confirmed each server now imports and starts on
  `mcp` 1.30.0/1.26.0), and added the missing `metasploit-server` lock.
- **`pen-agent-shell` Docker image failed to build** —
  `gem install evil-winrm` pulls in `readline-ext`, which needs
  `libreadline-dev` at build time; added it to the Dockerfile.

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
