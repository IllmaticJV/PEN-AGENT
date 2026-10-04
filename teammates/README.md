# Teammate Spawn Templates

Markdown files the `/pen-agent-ctf` orchestrator reads at runtime and passes as
spawn prompts when creating agent team teammates. These are NOT Claude Code skills
or agent definitions — they're prompt templates.

## How they work

1. Orchestrator decides to spawn a teammate (e.g., web vuln found → need web-ops)
2. Orchestrator reads `teammates/web-ops.md` via the Read tool
3. Orchestrator spawns via `Agent(prompt=<template>, name="web-ops")` — with
   `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` set, a named `Agent` call spawns a
   persistent teammate, not a one-shot subagent. No separate team-creation
   call exists; the team forms implicitly and is torn down automatically
   when the lead's session ends.
4. Teammate inherits the lead's MCP servers, permissions, and CLAUDE.md
5. Teammate goes idle after activation — wakes on `SendMessage` from lead or peers

## Teammate types

**Infrastructure** — spawned at engagement start, persists entire engagement:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `state-mgr.md` | state-mgr | Centralized state writer, dedup, graph coherence | sonnet |
| `shell-mgr.md` + `shell-mgr-<backend>.md` | shell-mgr | Shell session lifecycle (listeners, processes, upgrades, handoff) | sonnet |

**Enumeration** — one per target surface, multiple instances from same template:

| File | Naming | Domain | Model |
|------|--------|--------|-------|
| `net-enum.md` | net-enum, net-enum-\<target\> | Network recon + service enumeration | sonnet |
| `web-enum.md` | web-enum-\<site\> | Web app discovery | sonnet |
| `ad-enum.md` | ad-enum | AD discovery (BloodHound, LDAP, ADCS) | sonnet |
| `lin-enum.md` | lin-enum-\<host\> | Linux host discovery | sonnet |
| `win-enum.md` | win-enum-\<host\> | Windows host discovery | sonnet |
| `ai-enum.md` | ai-enum-\<target\> | AI target recon + threat modeling | sonnet |

**Operations** — one per target surface when parallel paths exist:

| File | Naming | Domain | Model |
|------|--------|--------|-------|
| `web-ops.md` | web-ops, web-ops-\<target\> | Web technique execution | sonnet |
| `ad-ops.md` | ad-ops | AD technique execution | sonnet |
| `lin-ops.md` | lin-ops-\<host\> | Linux privesc techniques | sonnet |
| `win-ops.md` | win-ops-\<host\> | Windows privesc techniques | sonnet |
| `ai-ops.md` | ai-ops, ai-ops-\<target\> | AI exploitation (LLM/agent/RAG/MCP/infra) | sonnet |

**On-demand** — spawn for specific tasks, dismiss when done:

| File | Name | Domain | Model |
|------|------|--------|-------|
| `bypass.md` | bypass | AV/EDR bypass | sonnet |
| `spray.md` | spray | Password spraying | haiku |
| `recover.md` | recover | Offline hash recovery | haiku |
| `research.md` | research | Deep analysis | sonnet |

## Template conventions

- No YAML frontmatter — teammates inherit config from the lead
- Model is specified by the orchestrator in the spawn instruction, not in the template
- Sonnet teammates spawn as Sonnet 200k by default; for 1M context, set
  `ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-4-6[1m]` in `.claude/settings.json` env
- **Shared behavior lives in CLAUDE.md § Teammate Protocol** — task workflow,
  state writes, tool execution, operational rules, stall detection, and
  activation protocol. Templates contain only domain-specific content.
- Enum teammates discover and report — they don't action findings
- Ops teammates action assigned vulns — they don't discover new ones
- On-demand teammates handle one task and get dismissed

