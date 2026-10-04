# Metasploit MCP Server

MCP server wrapping the [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
RPC API (`msfrpcd`) via [pymetasploit3](https://github.com/DanMcInerney/pymetasploit3).
Metasploit is PEN-AGENT's C2 backend: initial shells are caught by shell-server,
then upgraded to Meterpreter sessions here for stable transport, file transfer,
post-exploitation, and pivoting.

## Prerequisites

- **metasploit-framework** installed (`msfconsole`, `msfvenom`, `msfrpcd` on PATH)
- **msfrpcd** running and an engagement config at `engagement/msfrpc.yaml`.
  `run.sh` starts the daemon and writes this file automatically; `config.sh`
  wires it as the shell backend. Manual start:

  ```bash
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

`operator/msf-console/` connects to the same `msfrpcd` daemon (same
`engagement/msfrpc.yaml`) and gives the human operator a live session/job
list plus a real, interactive msfconsole on that shared Framework instance —
`sessions -i <id>` there reaches whatever the agent opened here, live, and
anything run from it is visible to this server's next `list_sessions()`/
`list_jobs()` call. `bash operator/msf-console/start.sh` →
`http://127.0.0.1:8100`.

## HTTP Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /status` | Health check — returns connection status and session count |
