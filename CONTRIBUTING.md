# Contributing to PEN-AGENT

Reference for **editing this repository** — skill/template authoring, docs, and
layout. Runtime behavior (engagement workflow, teammate protocol, state rules)
lives in `CLAUDE.md`; this file is the stuff you only need when changing the
code, kept out of `CLAUDE.md` so it doesn't ride in every agent turn's context.

## Token Budget

Every token costs money and latency. Consider token impact when making ANY
change — agent templates, skill text, MCP responses, orchestrator prompts.
Prefer designs that minimize per-invocation token usage without sacrificing
needed functionality. Put hints in tool responses (loaded only when called)
rather than agent templates (loaded every invocation).

**No inline file templates.** Never embed file contents (YAML, shell scripts,
JSON, config files) directly in skill files, agent templates, or orchestrator
prompts. Store templates in `operator/templates/` and reference them by path.

## Documentation Rules

| Component | Documentation | Rule |
|-----------|--------------|------|
| Repo root | `README.md` | Update on architecture/installation/behavior changes |
| Docs site | `docs/*.md` | Human-facing reference. `docs/dependencies.md` tracks tool deps. |
| MCP servers | `tools/*/README.md` | **Required.** Update when tools/params/behavior change |
| Skills | `skills/*/SKILL.md` | Self-contained |
| Teammates | `teammates/*.md` | Self-contained (shared behavior in `CLAUDE.md` § Teammate Protocol). When pointing at a local helper, use a bulleted section titled exactly `## Local helpers (prefer over LLM round-trips)` — the same wording as `CLAUDE.md § Local Helpers` — so greps across teammates stay stable. |
| Hooks | `tools/hooks/README.md` | Update when hook scripts change |
| Operator portal | Root `README.md` (Operator portal section) | No per-tool README — one README only. Update when behavior changes |

**Changelog is mandatory.** Every branch merged to main must update
`CHANGELOG.md` under a date heading (`## YYYY-MM-DD`).

### Teammate template authorship — keep the ride-every-turn text light

Teammate templates ride in context on EVERY turn of their session,
so dense technique-specific language (verbatim tool names,
offensive-sounding verbs, CVE identifiers piled together) in the
template can trip the Anthropic safety classifier at spawn time and
block the agent before it does any work.

Two rules that keep templates spawn-safe:

1. **Open with an authorization frame** — one short paragraph naming
   the engagement, pointing at `engagement/scope.md` /
   `scope.allow`, and noting the MCP-enforced scope. The classifier
   keys on authorization context; a stated frame lowers risk
   materially. Mirror the preamble used in `teammates/smb-ops.md`
   and `teammates/ad-ops.md`.
2. **Push dense technique language into the skills** — the template
   describes WHAT the teammate owns and WHEN to load each skill; the
   skill (loaded on-demand via `get_skill`) carries the HOW
   (commands, flags, tool names, filename patterns, CVE lists,
   executor comparison tables). Specific tool names, exploit names,
   and payload format matrices belong in the skill text, not in the
   template that runs every turn. The classifier evaluates each
   message independently, so an on-demand skill fetch is a different
   evaluation surface than the spawn template.
3. **Infrastructure teammates: use a contract doc for message
   protocols.** When a teammate's job is to receive structured
   messages and call one or two MCP tools in response, move the
   full message shape — field lists, HEREDOC examples,
   inbound/outbound forms, validation rules — into a reference doc
   next to the tool it drives. The template says "load this at
   activation and reference it"; the dense content loads once at
   spawn and stays in context, outside the ride-every-turn
   surface. Pattern already applied to:
   - `scribe` → `tools/shell-server/RECORDING.md`
   - `shell-mgr` → `tools/shell-server/SESSIONS.md`
   - `state-mgr` → `tools/state-server/WRITES.md`
   Scribe went from density 0.28 → 0.15 this way; state-mgr lost
   ~110 lines of ride-every-turn template.

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

## Directory Layout

```
PEN-AGENT/
  CLAUDE.md              # Runtime instructions (loaded every agent turn)
  CONTRIBUTING.md        # This file — repo-development reference
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

## Installation

```bash
./install.sh          # Symlinks — edits in repo reflect immediately
./install.sh --copy   # Copies — for machines without the repo
./uninstall.sh        # Remove everything
```

Requires [uv](https://docs.astral.sh/uv/), Docker (for nmap), and
Playwright (for browser automation — Chromium installed automatically).
