# Installation

## Prerequisites

Run PEN-AGENT in a dedicated VM, not on your daily driver. PEN-AGENT is [designed so Claude never needs sudo](architecture.md#privilege-boundaries), but it still runs offensive tools, opens listeners, and makes network connections to targets — you want that happening in an isolated environment. A standard pentesting VM (Kali, Parrot, or a minimal Debian/Ubuntu with your tools) works fine.

PEN-AGENT requires the following installed:

| Requirement | Purpose | Install |
|-------------|---------|---------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code/getting-started) | CLI host for skills, agents, and MCP servers | See [Claude Code install docs](https://docs.anthropic.com/en/docs/claude-code/getting-started) |
| [uv](https://docs.astral.sh/uv/) | Python package manager for MCP servers | See [uv install docs](https://docs.astral.sh/uv/getting-started/installation/) |
| [Docker](https://docs.docker.com/engine/install/) | Containerized nmap and pentest toolbox | See [Docker install docs](https://docs.docker.com/engine/install/) |

### Optional: C2 Framework (Metasploit)

PEN-AGENT works out of the box with shell-server (raw TCP reverse shells +
interactive processes). **Metasploit is the C2 backend** — teammates catch
initial shells via shell-server and upgrade them to Meterpreter for stable
transport, file transfer, post-exploitation, and pivoting.

**Step 1 — Install metasploit-framework** (if not already present):
```bash
# Kali / most pentest distros already ship it. Otherwise:
curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
  -o /tmp/msfinstall && chmod +x /tmp/msfinstall && /tmp/msfinstall
```
Verify `msfconsole`, `msfvenom`, and `msfrpcd` are on PATH.

**Step 2 — Launch.** That's it — `run.sh` detects Metasploit, starts `msfrpcd`
on `127.0.0.1:55553`, writes `engagement/msfrpc.yaml` (random RPC password,
mode `0600`), and starts the metasploit-server MCP automatically:
```bash
./run.sh
```
Verify with `pgrep -f msfrpcd`. To pin the backend explicitly, run `./config.sh`
and select `metasploit`.

**Remote msfrpcd** (daemon on a dedicated host): point `engagement/msfrpc.yaml`
at it manually —
```yaml
host: <C2_IP>
port: 55553
user: msf
password: <rpc-password>
ssl: true
```
and start `msfrpcd` there with a matching `-P`/`-U`. The metasploit-server MCP
runs locally and connects over the RPC API.

Custom C2 integration is also supported via operator-provided MCP servers and
reference docs (select `custom` in `config.sh`).

## Install

```bash
git clone https://github.com/IllmaticJV/PEN-AGENT.git
cd PEN-AGENT
./install.sh
```

### What `install.sh` does

The installer runs these steps:

**1. Native skill** — Installs the orchestrator skill to `~/.claude/skills/pen-agent-ctf/`. All other skills (84 discovery + technique skills) are served on-demand via the MCP skill-router.

**2. Teammate templates** — Teammate spawn prompts live in `teammates/` in the repo (not installed globally).

**3. MCP server dependencies** — Runs `uv sync` for the MCP servers (skill-router, nmap-server, shell-server, state-server, browser-server, rdp-server, metasploit-server) and the reporter, installing Python dependencies into isolated `.venv/` directories.

**4. Docker images** — Builds two Docker images:

- `pen-agent-nmap:latest` — Alpine + nmap for containerized scanning
- `pen-agent-shell:latest` — Tools that need persistent sessions or raw sockets (evil-winrm, impacket, chisel, ligolo-ng, socat, Responder, mitm6, tcpdump)

**5. Skill indexing** — Runs the ChromaDB indexer to embed all skills for semantic search. Downloads the `all-MiniLM-L6-v2` embedding model (~80MB) on first run.

**6. Browser setup** — Installs Chromium via Playwright (~150MB) for headless browser automation.

**7. Config verification** — `.mcp.json` ships in the repo. `.claude/settings.json` doesn't (it may hold machine-specific customization) — `install.sh` writes it here, once, only if it's missing; if you already have one, it's left untouched and only checked for the keys PEN-AGENT needs. See [Permissions](#permissions).

### Permissions

`install.sh` writes `.claude/settings.json` at the repo root for you, **once,
only if it doesn't already exist** — it's not committed (may hold
machine-specific customization, and a running session can't safely write its
own permission file), so this is the one piece `install.sh` has to generate
rather than ship:

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

This does two things: enables the agent-teams experimental flag the
orchestrator requires (see [Agent Teams](#agent-teams) below), and
pre-approves every MCP tool PEN-AGENT uses so **standard permission mode is
usable without `--yolo`**. If the file already exists, `install.sh` leaves it
alone and only warns if `enableAllProjectMcpServers` or
`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` look missing — it won't try to merge
into a customized file. Extend `allow` with specific tool invocations you
approve often — see `/fewer-permission-prompts` — to cut prompt friction
further without resorting to `--dangerously-skip-permissions`.

If agent-teams still reports unavailable after this, make sure you started a
**fresh** `claude`/`./run.sh` session — the flag is read at process start, so
`claude --resume` on a session started before the file existed won't pick it
up.

**Prefer standard mode over `--yolo` for real engagements.** `--yolo` removes
Claude Code's own permission prompts — and with them, the human approval step
that would otherwise interrupt a run before it compounds. What's left
evaluating offensive-tool chains is Claude Code's own safety classifiers
(separate from PEN-AGENT; this project doesn't configure them), which get
noticeably stricter the more a session's actions pattern-match sustained
multi-host compromise. If a session breaks down partway through a multi-host
engagement, try dropping `--yolo` first. PEN-AGENT already gates every task
assignment on `AskUserQuestion` operator approval, so standard mode mostly
adds a few Bash prompts per task, not a second approval for the same
decision.

### Agent Teams

PEN-AGENT's orchestrator (`/pen-agent-ctf`) uses [Claude Code agent
teams](https://code.claude.com/docs/en/agent-teams) — `TeamCreate`,
`Agent(team_name=...)`, persistent peer `SendMessage`. This is an experimental
CLI feature, enabled by the `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` env var
above, and it is **not available in every Claude Code surface** — hosted/cloud
sessions in particular may not expose `TeamCreate` or the `team_name`
parameter on `Agent` at all, regardless of settings. Run PEN-AGENT from a
local Claude Code CLI session (an isolated VM or dedicated pentesting
machine — see [Prerequisites](#prerequisites)). For split-pane teammate
visibility, start Claude Code inside a `tmux` session; without tmux, teammates
run in in-process mode instead (cycle through them with Shift+Down).

### Attackbox dependencies

The installer sets up PEN-AGENT itself, but skills also depend on standard pentesting tools installed on the attackbox (nmap, ffuf, sqlmap, hashcat, impacket, git-dumper, etc.). After installing, run the preflight check — and let it install what's missing:

```bash
bash preflight.sh                       # report what's missing
bash preflight.sh --install             # install missing REQUIRED tools, then re-check
bash preflight.sh --install --optional  # also install the optional tools
```

Preflight verifies that required tools are available and reports missing ones. With `--install` it installs them: system packages via `apt` (into `/usr/bin`), and everything else (Go, pipx, git-clone, and release binaries) under `/opt/PEN-AGENT/tools` — a single, clean tool directory added to `PATH` via `/etc/profile.d`. Override the location with `PEN_AGENT_TOOLS_DIR`, or preview without changes using `PEN_AGENT_INSTALL_DRYRUN=1`. A handful of AV-sensitive Windows binaries and build-from-source tools are flagged for manual install. `--install` needs sudo. See [dependencies](dependencies.md) for the full list organized by category.

### Symlink vs copy mode

```bash
./install.sh          # Default: symlinks (edits in repo reflect immediately)
./install.sh --copy   # Copies (snapshots skills and agents into ~/.claude/)
```

Symlink mode is recommended — changes to skills and agents in the repo take effect immediately without re-running the installer. Copy mode snapshots the files, so you need to re-run the installer to pick up changes.

Both modes require the repo directory to stay in place. MCP servers run from `tools/` and the skill-router reads skill files from `skills/` at runtime.

### Hardening with permission denies

PEN-AGENT is [designed so Claude never needs sudo](architecture.md#privilege-boundaries) — nmap and Responder run inside Docker containers, and system changes like `/etc/hosts` are hard stops that require operator action. You can enforce this by denying `sudo` in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Bash(sudo *)",
      "Bash(rm -rf *)",
      "Bash(rm -fr *)",
      "Bash(git push --force*)",
      "Bash(git reset --hard*)"
    ]
  }
}
```

The `Bash(sudo *)` rule makes Claude Code refuse any Bash command starting with `sudo`. The other rules block common destructive commands. See the [Trail of Bits Claude Code hardening guide](https://blog.trailofbits.com/2025/07/10/securing-claude-code/) for the full recommended configuration.

## Running

### Quick start (shell-server only)

```bash
cd PEN-AGENT
./run.sh
```

`run.sh` starts shell-server, launches Claude Code, and auto-triggers `/pen-agent-ctf`. The orchestrator asks config questions (scan type, proxy, etc.) on first run. Give it a target IP to begin.

### With C2 (Metasploit or custom)

If `metasploit-framework` is installed, `run.sh` already brings up Metasploit C2
automatically — no config step needed. To pin the backend explicitly or wire a
custom C2:

```bash
cd PEN-AGENT
bash config.sh             # config wizard — picks C2 backend, patches .mcp.json
./run.sh                   # starts shell-server + Metasploit RPC + MCP, launches Claude Code
```

`config.sh` is optional. Use it to pin `metasploit`, wire a `custom` C2 MCP, or
pre-answer the orchestrator's config questions via `engagement/config.yaml`.

### Flags

```bash
./run.sh --yolo         # skip permission prompts
```

If shell-server has active sessions from a previous run, `run.sh` prompts to keep, clear, or restart them.

## Uninstall

```bash
./uninstall.sh
```

This removes:

- Native skill from `~/.claude/skills/pen-agent-*/`
- ChromaDB index (`tools/skill-router/.chromadb/`)
- Python venvs (`tools/*/. venv/`)
- Docker images (`pen-agent-nmap:latest`, `pen-agent-shell:latest`)

It does **not** remove `.mcp.json` or `.claude/settings.json` (project config), and it does not touch the `engagement/` directory.

## Troubleshooting

### Docker not available

```
WARNING: Docker required for nmap MCP server but not available.
```

Install Docker and ensure the daemon is running. The nmap-server and shell-server privileged mode require Docker. The rest of the toolkit works without it.

### Broken symlinks

```
ERROR: Broken skill: ~/.claude/skills/pen-agent-ctf/SKILL.md -> unknown
```

The repo directory was moved or deleted after install. Either move it back or re-run `./install.sh`.

### Missing uv

```
ERROR: uv is required but not found.
```

See [uv install docs](https://docs.astral.sh/uv/getting-started/installation/).

### Embedding model download fails

The skill-router downloads `all-MiniLM-L6-v2` on first run. If your VM lacks internet access, download the model elsewhere and set `HF_HUB_OFFLINE=1` (already set in `.mcp.json` for runtime). For initial indexing, internet access is required.

### Chromium install fails

If `playwright install chromium` fails behind a proxy, download Chromium manually. See [Playwright docs](https://playwright.dev/python/docs/browsers#install-behind-a-firewall-or-a-proxy) for proxy configuration.

### MCP servers not starting

Verify `.mcp.json` exists in the repo root and `.claude/settings.json` has `enableAllProjectMcpServers: true`. Check server logs with:

```bash
uv run --directory tools/skill-router python server.py  # Should start without errors
```
