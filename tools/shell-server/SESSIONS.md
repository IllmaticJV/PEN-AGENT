# Session lifecycle — message contract

This is the message contract between domain teammates and the
`shell-mgr` teammate for session lifecycle: setup, ownership
handoff, dropped-shell recovery, pivot setup, and preflight.

shell-mgr's spawn template is intentionally thin — the field lists
and example message shapes live here. shell-mgr loads this file on
demand at activation. The shell-server and metasploit-server MCP
tool docstrings are the normative source for individual field
semantics; this file is the message shape and workflow around them.

## Inbound — from domain teammates

```
[shell-established] session_id=<id> ip=<target> platform=<linux|windows>
  delivery="<working payload that produced this session>"
  label="<label>"
  Teammate caught a session. shell-mgr takes ownership — stabilize,
  upgrade if C2 is configured, notify the lead.

[setup-process] command="<cmd>" label="<label>" privileged=<bool> startup_delay=<N>
  Spawn a local interactive process (evil-winrm, ssh, psexec.py, etc.).
  Credential-based — no delivery payload involved.

[shell-dropped] session_id=<id>
  A teammate's session died. Re-establish by REPLAYING the recorded
  engagement/exploits/<host>-<label>.sh — load the shell-recovery
  skill. Notify the teammate with [session-restored] on success.

[setup-pivot] host=<ip> target_subnet=<cidr> via_access_id=<N>
  Set up a tunnel to reach target_subnet through host. shell-mgr
  picks the method based on backend, available sessions, and access
  type (per CLAUDE.md's "Pivoting: NEVER default to MSF SOCKS" rule).
  Respond with [pivot-ready] or [pivot-failed].

[close-session] session_id=<id> save_transcript=<bool>
  Close a session and optionally save transcript.

[list-sessions]
  Return all active sessions shell-mgr is tracking.

[preflight-payloads] lhost=<IP|iface>
  (Metasploit backend only) Pre-generate the common msfvenom payloads
  AND bring up a handler per entry so later techniques can grab a
  ready-made binary + hot handler without round-trips. One-time at
  engagement init. See the Preflight Payloads flow in
  teammates/shell-mgr.md and tools/preflight/README.md.
```

## Outbound — to the requesting teammate

```
[session-ready] session_id=<id> backend=<shell-server|metasploit> platform=<linux|windows>
  <MCP interaction instructions — backend-specific, see shell-mgr-<backend>.md>
  — Session is stabilized (or upgraded to C2). The teammate can now
    interact via the MCP tool named above.

[process-ready] session_id=<id> backend=shell-server platform=<linux|windows>
  — Interactive process is up. Use send_command for interaction.

[session-restored] session_id=<id> backend=<backend>
  — Dropped session re-established. Resume interaction with the new
    session_id.

[session-dead] session_id=<id> ip=<target>
  — Re-establishment failed after multiple attempts.

[session-closed] session_id=<id> transcript=<path>
  — Session closed. Transcript saved.

[pivot-ready] host=<ip> target_subnet=<cidr> tunnel_type=<type>
  endpoint=<socks5://127.0.0.1:port>
  transparent=<yes|no> proxychains_line="<socks5 127.0.0.1 port>"
  — Tunnel established. Include this context in all tasks targeting
    hosts behind the tunnel.

[pivot-failed] host=<ip> target_subnet=<cidr> reason="<why>"
  — Tunnel setup failed.
```

## Outbound — notifications to the lead

```
[backend-down] backend=<name> error="<details>"
  — Shell backend is unreachable. Lead escalates to operator.

[session-ready] session_id=<id> ip=<target> platform=<platform> for=<teammate>
  — Session stabilized/upgraded and ready for enum teammates.

[session-lost] session_id=<id> ip=<target>
  — A session dropped. Attempting re-establishment.

[session-restored] session_id=<id> ip=<target>
  — Dropped session re-established.

[session-dead] session_id=<id> ip=<target>
  — Re-establishment failed. Need alternative access path.

[pivot-ready] host=<ip> target_subnet=<cidr> tunnel_type=<type>
  endpoint=<endpoint> transparent=<yes|no> proxychains_line="<line>"
  — Tunnel to internal subnet established. Ready for recon.

[pivot-failed] host=<ip> target_subnet=<cidr> reason="<why>"
  — Pivot setup failed. May need alternative access or manual
    intervention.

[preflight-ready] payloads=<N> handlers=<N> xor=<yes|no>
  index=engagement/payloads/index.json
  — Preflight payload bake-off complete. HARD GATE lifted; the lead
    may now route exploitation tasks.

[preflight-failed] reason="<N payloads failed, see shell-mgr log>"
  — Preflight bake-off aborted (gen_payloads.sh exit 3). Do NOT
    retry blindly; lead decides.
```
