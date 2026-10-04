# Changelog

All notable changes to this project will be documented in this file. Format
follows [Keep a Changelog](https://keepachangelog.com/).

## 2026-10-04

### Added

- **Dedicated operator sessions — agents and the operator never contend for one
  shell.** metasploit-server can now reserve a session for the human operator;
  all agent-facing session tools (`execute`, `upload`, `download`, `ifconfig`,
  `upgrade_to_meterpreter`, `kill_session`, `start_socks_proxy`) refuse a
  reserved session with `error: operator_reserved`, and `list_sessions()` flags
  it `operator_reserved: true`. New tools: `spawn_operator_session(session_id,
  lhost, lport)` (spawns a second session from a foothold — reliable from a
  shell via `shell_to_meterpreter` — and reserves it), `reserve_operator_session`,
  `release_operator_session`. The shell-mgr-metasploit teammate now calls
  `spawn_operator_session` once per host right after the foothold and treats
  `operator_reserved` sessions as off-limits. Reservation lives in
  `engagement/operator-sessions.json`; the operator console badges reserved
  sessions. (From a Meterpreter-first foothold there's no shell to re-stage, so
  spawn returns `needs_manual` — reserve a manually-caught session instead.)

### Changed

- **Metasploit C2 is now an interactive `msfconsole` (full operator console),
  not a headless `msfrpcd`.** A new shared `tools/metasploit-server/c2-up.sh`
  (used by both `run.sh` and `config.sh`) starts `msfconsole` with the
  `msgrpc` plugin inside a tmux session (`pen-msf`) — one Framework instance,
  so `tmux attach -t pen-msf` is a 100% real console (`sessions -i`,
  meterpreter interactive, tab-complete) while the agents drive the *same*
  instance over RPC. `engagement/msfrpc.yaml` is unchanged, so the
  metasploit-server MCP connects exactly as before. Without tmux, c2-up.sh
  falls back to the old headless `msfrpcd` (agents work; no live console).
  This replaces the web portal's crippled RPC console as the way an operator
  interacts with Metasploit — the RPC/web console cannot attach to a session.
- **msf-console web portal is now a read-only viewer.** It shows the live
  session + listener/job list, a **per-session command log** (every command
  the agents run via `metasploit-server.execute()` is recorded to
  `engagement/evidence/msf-sessions/<id>.jsonl` with its output), and the
  shared console spool. The command input, the RPC console, and the
  `/api/console/write`/`reset` endpoints were removed — interaction belongs in
  the tmux console above. (Supersedes the interactive-portal approach; the
  `sessions -i` crash no longer applies since the portal never attaches.)

### Fixed

- **preflight `--install --optional`: 8 tools that always failed to install.**
  Root causes were wrong install sources, not environment issues:
  - `manspider` → PyPI id is `man-spider` (the un-hyphenated name has no
    distributions).
  - `enum4linux-ng`, `sccmhunter`, `GPOHound` → not on PyPI; now installed
    with a new `pipx_git` helper (`pipx install git+https://…`), which builds
    an isolated venv with deps.
  - `wesng` → the PyPI build ships no console entry point; installed from git
    instead (exposes `wes`).
  - `SSTImap`, `jwt-tool` → not on PyPI and no packaging; cloned and wrapped.
    `git_wrap` now installs a cloned repo's `requirements.txt` into a per-repo
    `--system-site-packages` venv (best-effort, falls back to system python3),
    so these — and the other git-cloned Python tools — have their deps.
  - `domdig` → not a global npm package; new `git_node` helper clones it and
    runs `npm install` in-tree, then wraps `node domdig.js`.
  The re-check and `docs/dependencies.md` install commands were corrected to
  match.

### Added

- **preflight now auto-stages the previously "manual" payloads** with
  `--install --optional`, so they no longer need hand-downloading:
  `ysoserial.jar` (+ a `ysoserial` launcher), `winPEAS.exe`, `mimikatz.exe`,
  `RunasCs.exe`, and the Potato binaries (GodPotato-NET4 / PrintSpoofer64 /
  JuicyPotatoNG / SigmaPotato → `/usr/share/windows-binaries/potatoes/`), plus
  `pspy32`. `gh_release_bin` gained `.zip` support and an x64-preferring
  archive extractor, and a `gh_release_file` variant that stages to an
  arbitrary (system) path. Assets are resolved from each project's latest
  release at run time, so a renamed asset degrades to a clean skip rather than
  staging the wrong file. `Rubeus.exe` and `marshalsec` stay manual — neither
  has an official prebuilt binary.

### Changed

- **Modular refactor of oversized server/dashboard files** (no behavior
  change; integration preserved and verified).
  - `tools/state-server/server.py` (2055 lines, 27 tools in one
    `create_server()`) split by concern into `common.py` (shared DB/enum/
    event helpers + attack-graph prune/restore) plus eight tool modules
    (`reads`, `engagement`, `targets`, `credentials`, `access`, `vulns`,
    `pivots`, `tunnels`), each exposing `register(mcp)`. `server.py` is now
    a thin wiring layer. `DB_PATH` lives in `common.py` as the single patch
    point (tests monkeypatch `common.DB_PATH`). All 30 tests pass; all 27
    tools register identically.
  - `operator/state-viewer` and `operator/msf-console` dashboards: the
    multi-KB inline HTML/CSS/JS page literals moved to sibling `templates/`
    files loaded at startup (`state-viewer` `server.py` 1425→447 lines,
    `msf-console` 652→492). Server logic stays stdlib-only.
  - `tools/shell-server/server.py` (1349 lines) split into `callback.py`
    (callback-IP resolution + reverse-shell payloads), `docker_shell.py`
    (privileged-Docker image config + container lifecycle), and
    `session.py` (Listener/Session primitives, I/O, prompt detection);
    `server.py` (→1024 lines) keeps the stateful listener/session registry,
    threads, and seven MCP tools. All 7 tools register; a loopback
    listener→command→close path was exercised end-to-end.

- **skill-router converted from a per-session stdio server to a shared SSE
  daemon** (like shell-server and metasploit-server). Root cause of spawned
  agent-team teammates being unable to resolve `mcp__skill-router__*` tools:
  stdio MCP servers start one subprocess per session, so every teammate
  stood up its own skill-router and re-paid the sentence-transformer +
  ChromaDB load (tens of seconds) — often never resolving its tools within
  the teammate's lifetime, while instant-start stdio servers (`state`) and
  already-shared SSE servers (`metasploit`, `shell`) resolved fine. Now
  `run.sh`/`install.sh` start one skill-router daemon (`start.sh`, SSE on
  `127.0.0.1:8023`, `SKILL_ROUTER_SSE_PORT`); the model loads once and the
  lead plus every teammate connect to the same warm instance. `.mcp.json`
  switched from a `command` entry to a `url` entry; `HF_HUB_OFFLINE=1`
  (previously set in `.mcp.json`) is now applied in `start.sh`;
  `uninstall.sh` stops the daemon. This fixes the teammate skill-loading
  gap at the source (the earlier wait/retry guidance remains as a safety
  net) and speeds up teammate spawns (no per-teammate model reload). Docs
  (mcp-servers, installation, skill-router README, README command table)
  updated. Not live-booted in this sandbox — the embedding-model download
  is proxy-blocked here — so verify the daemon comes up on first real
  `install.sh`/`run.sh`.

### Fixed

- **Concurrent teammate access to metasploit-server crashed the shared RPC
  connection.** All teammates connect to the one metasploit-server SSE
  instance and share a single pymetasploit3 `MsfRpcClient`. FastMCP runs the
  sync tool handlers in a threadpool, so two teammates calling msf tools at
  the same time drove that client — and its single `requests.Session` and
  console objects — from two threads at once, which pymetasploit3 /
  `requests.Session` are not thread-safe for (interleaved request/response
  framing, shared auth token, shared console IDs → corrupted stream, dropped
  connection). Every RPC-touching tool is now wrapped with `@_serialized`, a
  single reentrant lock, so msf calls run one at a time; `generate_payload`
  (pure msfvenom subprocess, no shared client) is excluded so a long build
  doesn't block live RPC. Verified the decorator preserves the FastMCP tool
  schema (all parameters still exposed) and actually serializes. This is
  per-process — the operator `msf-console` has its own client and `msfrpcd`
  handles multiple distinct clients, so operator + agents can still drive the
  same instance concurrently.

### Fixed

- **Teammates declared themselves blocked on a skill-router race instead of
  waiting.** skill-router loads an embedding model + ChromaDB at startup, so
  it connects far slower than `state` (which just opens a SQLite file). A
  teammate that spawned and immediately tried `get_skill` could find
  skill-router still connecting, and — correctly refusing to run a technique
  without the skill loaded — reported blocked on the *first* miss rather
  than waiting the few extra seconds. Hardened the protocol: the teammate
  Activation Protocol now warms up the skill-router connection at spawn
  (before any task arrives), the Task Workflow waits-and-retries (≈60s) on a
  still-connecting skill-router before escalating, and the orchestrator's
  "If Skill Router Is Unavailable" handling now distinguishes a per-teammate
  race (re-send / respawn that teammate) from the server genuinely being
  down (its own `search_skills` also failing) before alarming the operator.
  Guidance only — no mechanics changed.

### Fixed

- **metasploit-server silently reported handlers as "listening" when
  msfrpcd never bound them.** `module.execute()` over RPC doesn't raise on a
  server-side failure — it returns `{"error": true, ...}` or a null
  `job_id` — and the wrapper read `job_id`/`uuid` straight off that and
  reported success. Root cause of the failure surfaced live: the Meterpreter
  payload option `AutoLoadExtensions`'s RPC-exposed default comes back
  non-scalar, so msfrpcd rejected it ("must be a scalar") and no listener was
  ever created, while `start_handler` still returned `status: "listening"`.
  `start_handler` and `run_module` now set `AutoLoadExtensions` explicitly
  (guarded to payloads that expose it), and all job-starting tools
  (`start_handler`, `upgrade_to_meterpreter`, `start_socks_proxy`,
  `run_module`) route their RPC result through a new `_execute_error()` that
  surfaces error dicts and — for always-background jobs — a null `job_id`,
  returning `ERROR:` instead of a false success. Added unit tests
  (`tests/test_execute_error.py`, 6 cases) covering the exact regression.

### Changed

- **Made Metasploit's default-for-everything role explicit in the shell-mgr
  templates.** The mechanics were already in place (Meterpreter upgrade,
  autoroute+SOCKS pivoting, Meterpreter file transfer), but the wording was
  soft and scattered ("attempt C2 upgrade *if configured*", "*preferred*
  backend"). `teammates/shell-mgr-metasploit.md` now opens with an explicit
  coverage list — Meterpreter is the default for interactive shells, file
  transfer, pivoting/tunneling/proxying, and post-ex, with shell-server
  scoped to initial raw-shell catch and automatic fallback only.
  `teammates/shell-mgr.md` tightened to match (upgrade is the standard path
  for every shell under the default backend, not optional; autoroute+SOCKS
  is the default pivot method). No mechanics changed — clarity only.

### Fixed

- **Falling back from Metasploit to shell-server happened silently.**
  `shell-mgr` already sent `[backend-down]` to the lead when its activation
  health check found the configured backend unreachable, and
  `skills/ctf/SKILL.md`'s prose already said this should "notify the
  operator and block shell-dependent tasks until resolved" — but the
  Orchestrator Loop's message-handling pseudocode had no `from shell-mgr:`
  branch at all, so nothing ever acted on it. Confirmed live: a
  `msfrpc.yaml`-less run used shell-server for the whole engagement without
  ever asking. Added a new **C2 Backend Unavailable** hard stop (asks the
  operator: continue on shell-server, or pause to fix it first) wired into
  the loop, the mandatory hard-stop pre-check, and the Shell Backend Health
  section. Deliberately scoped to the backend being down, not a single
  shell's C2 upgrade failing (that stays silent/automatic, per
  `teammates/shell-mgr-metasploit.md` — one blocked target isn't a reason
  to interrupt the operator).

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
