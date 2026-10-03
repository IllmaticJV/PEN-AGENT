# Metasploit Operator Console

Web dashboard that gives the human operator eyes on — and, if needed, hands
on — the same Metasploit instance the `metasploit-server` MCP is driving.

## Why this works

`metasploit-server` (the MCP teammates use) and this viewer both connect to
the **same running `msfrpcd` daemon** via `engagement/msfrpc.yaml`. Sessions,
jobs, and routes all belong to that daemon's single Framework instance, not
to whichever RPC client happened to create them. So:

- The session/job list here is exactly what the agent sees — live, no polling
  lag beyond the 2s refresh.
- The embedded console is a **real msfconsole**, created via the RPC
  `console.create`/`write`/`read` API (the same mechanism `console_exec` in
  `metasploit-server` uses for one-shot commands, except this console stays
  open). Typing `sessions -i 1` here interacts with session 1 directly —
  whether the agent opened it or you did.
- Killing a session, running a module, or starting a handler from this
  console is visible to the agent's next `list_sessions()`/`list_jobs()` call,
  and vice versa.

## Usage

```bash
bash operator/msf-console/start.sh      # http://127.0.0.1:8100
```

Requires `engagement/msfrpc.yaml` to exist — `./run.sh` writes this
automatically when it starts `msfrpcd`. Without it, the page loads but shows
a "not configured" banner (same graceful-degradation behavior as
`metasploit-server`).

For custom options:

```bash
uv run --directory operator/msf-console python server.py --port 9000
```

## Authentication

Shares the **same token file** as the state dashboard
(`~/.config/pen-agent/viewer-token`). If it exists, this server also binds to
`0.0.0.0` and requires the token (cookie login or `Authorization: Bearer`);
otherwise it binds `127.0.0.1` only, same rules as `operator/state-viewer`.

```bash
bash operator/state-viewer/generate-token.sh   # one token, gates both dashboards
```

This console is equivalent to local `msfconsole` access to the engagement's
C2 — treat the token with the same care as a credential to the attackbox,
and don't expose it beyond a trusted network.

## Features

- **Session list** — id, type (shell/meterpreter), platform, `via_exploit`,
  info. Click a session id to drop straight into `sessions -i <id>`.
- **Job list** — handlers and running aux/server jobs, with ids for
  `kill_job`-style cleanup from the console (`jobs -K`, `kill <id>`, etc.).
- **Interactive console** — full msfconsole: run any command, module, or
  `sessions -i` interaction. Command history (&uarr;/&darr;).
- **Reset console** — destroys and recreates the RPC console if it ever gets
  stuck (e.g. after `exit`-ing an interactive session the wrong way). Does
  **not** touch sessions/jobs — those live on the Framework, not the console.
- **Live updates** — SSE stream: console output pushed as it arrives,
  sessions/jobs refreshed every 2s.
- **Graceful degradation** — if `msfrpc.yaml` is missing or `msfrpcd` is
  unreachable, the status pill goes red and says why; no crash.

## Architecture

- Single-file HTTP server (`http.server` stdlib), inline HTML/CSS/JS — same
  shape as `operator/state-viewer`.
- One dependency: `pymetasploit3` (the RPC client), hence `uv run` instead of
  bare `python3`.
- One shared `MsfRpcClient` and one shared RPC console per server process,
  guarded by a lock — every browser tab sees and writes to the same console.
  This is intentional: it's a shared operator terminal, not a private one.
- `ThreadingHTTPServer` so the long-lived `/api/stream` connection doesn't
  block page loads or writes from another tab.

## Endpoints

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | HTML console page |
| `/login` | GET/POST | Login page / token submit (only when token configured) |
| `/api/status` | GET | `{configured, connected, error?}` |
| `/api/sessions` | GET | Live session list |
| `/api/jobs` | GET | Live job list |
| `/api/console/write` | POST | `{"command": "..."}` — write a line to the shared console |
| `/api/console/reset` | POST | Destroy and recreate the shared console |
| `/api/stream` | GET | SSE — console output as it arrives; sessions/jobs/status every 2s |
