# Metasploit MCP Server

MCP server wrapping the [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
RPC API (`msfrpcd`) via [pymetasploit3](https://github.com/DanMcInerney/pymetasploit3).
Metasploit is PEN-AGENT's C2 backend: initial shells are caught by shell-server,
then upgraded to Meterpreter sessions here for stable transport, file transfer,
post-exploitation, and pivoting.

## Prerequisites

- **metasploit-framework** installed (`msfconsole`, `msfvenom` on PATH)
- A running RPC instance and an engagement config at `engagement/msfrpc.yaml`.
  `run.sh`/`config.sh` start it via `tools/metasploit-server/c2-up.sh` and
  write this file automatically. `c2-up.sh` prefers an interactive
  `msfconsole` running the `msgrpc` plugin inside tmux (so the operator gets a
  full console via `tmux attach -t pen-msf`), and falls back to headless
  `msfrpcd` when tmux is absent. Either way pymetasploit3 connects to the same
  RPC. Manual equivalents:

  ```bash
  # interactive (recommended): console IS the RPC server
  msfconsole -q -x "load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=<password> SSL=true"
  # headless daemon (no operator console)
  msfrpcd -P <password> -U msf -a 127.0.0.1 -p 55553
  ```

  `engagement/msfrpc.yaml`:

  ```yaml
  host: 127.0.0.1
  port: 55553
  user: msf
  password: <password>
  ssl: true
  ```

## Transport

SSE on `127.0.0.1:8024` (configurable via `MSF_SSE_PORT`).

## Scope Guardrail

Tools that take a **remote target** validate it against `engagement/scope.allow`
and refuse out-of-scope targets:

- `run_module` — every `RHOSTS`/`RHOST` value is checked.
- `console_exec` — every `set RHOSTS`/`set RHOST` line is checked.

Session-directed tools (`execute`, `upload`, `download`, …) operate on
already-established access and are not target-gated. If `scope.allow` is absent,
enforcement is off (all targets allowed) and a warning is logged. See
`scope.py`.

## Tools

### Handlers & Payloads

| Tool | Description |
|------|-------------|
| `start_handler(payload, lhost, lport, exit_on_session)` | Start `exploit/multi/handler` to catch a callback |
| `generate_payload(payload, lhost, lport, format, name, extra_options)` | Build a payload with msfvenom into `engagement/evidence/` |
| `list_jobs()` | List active jobs (handlers, servers, aux) |
| `kill_job(job_id)` | Stop a job |

### Session Operations

| Tool | Description |
|------|-------------|
| `list_sessions()` | List active sessions with metadata |
| `execute(session_id, command, timeout)` | Run a command on a shell or Meterpreter session |
| `upgrade_to_meterpreter(session_id, lhost, lport)` | Upgrade a raw shell to Meterpreter |
| `upload(session_id, local_path, remote_path)` | Upload a file (Meterpreter) |
| `download(session_id, remote_path, local_path)` | Download a file (Meterpreter) |
| `ifconfig(session_id)` | List target network interfaces (pivot detection) |
| `kill_session(session_id)` | Terminate a session |
| `spawn_session(session_id, lhost, lport)` | Spawn a second session from a foothold for another agent to use (shell source → shell_to_meterpreter), so two agents never share one session's stream |
| `spawn_operator_session(session_id, lhost, lport)` | Same spawn, but reserves the new session for the operator (shell source → shell_to_meterpreter) |
| `reserve_operator_session(session_id, note)` | Reserve an existing session for the operator — agent session tools then refuse it |
| `release_operator_session(session_id)` | Return a reserved session to the agents |

Session-directed tools (`execute`, `upload`, `download`, `ifconfig`,
`upgrade_to_meterpreter`, `kill_session`, `start_socks_proxy`) **refuse any
session reserved for the operator** (returning `error: operator_reserved`), and
`list_sessions()` flags them `operator_reserved: true`. The reservation lives
in `engagement/operator-sessions.json` (also read by the operator console).
This lets the operator work a host in the tmux msfconsole with no contention.

### Modules & Pivoting

| Tool | Description |
|------|-------------|
| `run_module(module_type, module_name, options, payload, as_job)` | Run any exploit/auxiliary/post module. RHOSTS scope-checked |
| `console_exec(command, read_timeout)` | Run raw msfconsole commands. `set RHOSTS` scope-checked |
| `start_socks_proxy(session_id, srvport)` | autoroute + `auxiliary/server/socks_proxy` for internal pivoting |

## Graceful Degradation

If `engagement/msfrpc.yaml` is absent or msfrpcd is unreachable, all tools
return a clear error directing the operator to start it. The server still binds
its SSE port — it just can't reach Metasploit without a running daemon.

## Concurrency

All teammates connect to this one SSE service and share a single
`MsfRpcClient`. FastMCP runs the sync tool handlers in a threadpool, so
without protection two teammates calling msf tools at once would use that
client — and its single `requests.Session` and console objects — from two
threads simultaneously, which pymetasploit3 is not built for (it corrupts
the RPC stream and drops the connection). Every RPC-touching tool is
therefore wrapped with `@_serialized`, a single reentrant lock, so msf calls
run one at a time. `generate_payload` is intentionally excluded — it's a pure
`msfvenom` subprocess with no shared client, so a long build never blocks
live RPC. This is per-process: the operator portal and the tmux `msfconsole`
are separate processes with their own clients, and the RPC service handles
multiple distinct clients fine, so the operator and the agents can both drive
the same Framework instance concurrently.

## RPC error handling

`msfrpcd`'s `module.execute()` does not raise on a server-side failure (e.g.
bad option validation) — it returns an `{"error": true, "error_message":
...}` dict, or a result with a null `job_id`. The job-starting tools
(`start_handler`, `upgrade_to_meterpreter`, `start_socks_proxy`, and
`run_module`) check for both via `_execute_error()` and return an `ERROR:`
string instead of reporting success, so a handler/proxy that never actually
bound is never reported as "listening"/"started". `start_handler` and
`run_module` also set the Meterpreter payload option `AutoLoadExtensions`
explicitly, working around an msfrpcd bug where its RPC-exposed default comes
back non-scalar and fails option validation.

## Operator Visibility

Two complementary surfaces, both on the same Framework this server drives:

- **Full interactive console** — when tmux is present, `c2-up.sh` runs the C2
  as an `msfconsole`+`msgrpc` in tmux; `tmux attach -t pen-msf` is a real
  console (`sessions -i`, meterpreter interactive, all of it). Operator and
  agents share it live.
- **`operator/portal/` MSF Logs tab** (`bash operator/portal/start.sh` →
  `http://127.0.0.1:8099`) — read-only: the live session/listener list plus a
  **per-session command log**: every `execute()` this server runs is appended
  to `engagement/evidence/msf-sessions/<id>.jsonl` so the operator can watch
  what agents did on a session without attaching to (and stealing) its stream.

## HTTP Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /status` | Health check — returns connection status and session count |
