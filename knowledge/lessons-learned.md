# Lessons Learned

A persistent, cross-engagement knowledge base. The orchestrator **reads this at
the start of every engagement** and carries relevant lessons into teammate
briefs; the **retrospective appends new lessons at the end** of an engagement
(the lead may also append one mid-engagement when a teammate reports a reusable
gotcha). This is how PEN-AGENT gets better over time instead of relearning the
same things each run.

## What belongs here — and what must NEVER

Lessons must be **generalizable**: tooling flags and quirks, methodology
improvements, environment gotchas, skill gaps, detection/OPSEC notes, and
reusable attack patterns that apply to *future, different* targets.

**Never record target-specific solutions.** No credentials, no "box/app X is
solved by Y", no CTF/lab answers, no host-specific exploit chains, no flags.
Writing those here would (a) leak engagement data across clients and (b)
contaminate future runs — the harness would "succeed" by recall instead of by
method, which invalidates results. Keep per-engagement detail in that
engagement's `state.db` / `findings/`, not here. When in doubt, generalize the
lesson and drop the specifics.

## How to add a lesson

Append an entry under the matching category using this format. Before adding,
scan for an existing entry on the same point and refine it rather than
duplicating.

```
### <short, searchable title>
- **Context:** when this applies (a generalizable trigger, not a target name)
- **Lesson:** what to do / what was learned
- **Added:** YYYY-MM-DD
```

---

## Tooling

_Flags, versions, and quirks of tools on the attackbox._

### pymetasploit3 returns error-dicts on auth failure, doesn't raise

pymetasploit3's `MsfRpcClient.call()` does NOT raise on an auth failure. When
the stored token is stale (e.g. msfconsole restarted and the client cached the
old token), the call silently returns
`{"error": True, "error_message": "Invalid request parameters"}` as a normal
response dict. Any probe that only wraps `client.core.version` in a try/except
will think the stale client is healthy. **A liveness probe must inspect the
RESPONSE, not just exceptions**, and treat an auth-error dict as "re-login
required." PEN-AGENT's `tools/metasploit-server/server.py` handles this in
`_get_client` + a `_serialized` one-shot retry so an msfconsole restart is
transparent to the MCP (no server.py restart, no `/mcp` reconnect needed).

### pymetasploit3 has no RPC-level timeout — a wedged msgrpc can hang indefinitely

pymetasploit3's `post_request` uses `requests.post` with no `timeout=`, and is
decorated with `@retry(tries=3, backoff=2)` — so a single wedged msgrpc call
(classic: an orphaned `auxiliary/server/socks_proxy` relay pointing at a dead
session) blocks forever and, because our MCP serializes RPC calls behind one
lock, starves every other agent tool call behind it. Fix in PEN-AGENT: install
a bounded `(connect, read)` socket timeout on the client's `post_request` (via
`_install_rpc_timeout` in `metasploit-server/server.py`) so a wedge fails fast
and the lock releases.

## Methodology

_Routing, sequencing, and approach improvements._

### Lead must proactively probe silent teammates (teammates can't self-report wedges)

The teammate-side 5-round stall detection only fires when a teammate is still
executing tool calls. A teammate wedged mid-tool-call — hung bash command,
long-blocking RPC, or finished-but-forgot-to-signal — looks exactly like
"working" from the outside and self-reports nothing. The lead is the only
role with the context (`TaskGet` + message log + `poll_events`) to notice
silence, so it must do so proactively on every orchestrator loop iteration,
not just when a message or event wakes it. PEN-AGENT's orchestrator skill
runs a Stall Sweep each loop: probe at ~3 min silence (5 min for known
long-running skills — nmap `-p-`, spraying, cracking), escalate to the
operator at probe + 90 s with respawn / mark-failed options. State-mgr can't
own this — it has no `TaskList` visibility, no scheduling authority, and the
"one writer, no decisions" contract would blur if it did.

### Pivots: never un-scoped `autoroute` (`autoadd`) on a multi-homed host

Metasploit's `post/multi/manage/autoroute` with `CMD=autoadd` enumerates every
interface on the pivot host and adds a route per subnet — on a dual-NIC
jumphost, a dockerized target, or a host with VPN/bridge interfaces, that
routes agent traffic through management or internet subnets you did not
scope. On top of that it makes the pivot's route table flaky and hard to tear
down. Always add a **specific** route (`run autoroute -s <cidr>` or
`autoroute CMD=add` with explicit `SUBNET`+`NETMASK`), matched to the subnet
the lead's `[setup-pivot]` message supplies. PEN-AGENT's `start_socks_proxy`
MCP tool enforces this: it requires `target_subnet` unless the caller passes
`allow_autoadd=True` explicitly.

### Every reverse shell needs an END-TO-END executable re-trigger

The "how did we trigger this shell?" detail evaporates fast in a long
engagement, and re-triggering a dropped shell three hours later requires
not just the final payload but every prerequisite step — the login that
produced the session cookie, the CSRF token fetch, the intermediate upload
with that cookie. Capturing only the final payload gets you a `.sh` that
fails on re-run because the session cookie is dead and nothing in the
script knows how to get a new one.

The right shape is: a code gate on `send_command` that refuses un-logged
reverse shells, PLUS a `.sh` log that re-performs the FULL chain from
scratch (auth → CSRF → cookies → intermediate requests → payload), with
`${LHOST}` / `${LPORT}` / `${LABEL}` env-overridable, PLUS a `.md`
sidecar for context, PLUS an optional Python helper for steps that are
unreadable in bash+curl (session jars, structured JSON, binary protocols)
— invoked from the `.sh` with `python3 "${EXPLOITS_DIR}/python/<...>.py"`
and reading env vars for callback endpoint.

PEN-AGENT's `shell-server.record_exploit()` writes all three to
`engagement/exploits/`. Local processes (ssh/evil-winrm via
`start_process`) are exempt — their launching command is already the
recipe. The teammate that established the shell is the one that must call
`record_exploit()`; infrastructure teammates (shell-mgr) lack the context.

### MSF restart: handlers can be snapshotted + restored, sessions cannot

Metasploit sessions are stateful Ruby objects holding live TCP sockets; they
cannot be pickled and will not survive the Framework dying. But the HANDLERS
can be snapshotted (payload / LHOST / LPORT / ExitOnSession), re-registered
on a fresh console, and if the implants were built with transport retry
(default `SessionCommunicationTimeout=600`, `SessionExpirationTimeout=86400`)
they reconnect to the restored handlers automatically within the comm-timeout
window. msfrpcd's `list_jobs` doesn't expose a handler's payload/LHOST/LPORT —
that config has to come from somewhere else; PEN-AGENT reconstructs it from
the module-call log (`engagement/evidence/msf-modules/`) written by every
`start_handler` call. Shell-server sessions live in a separate process and
survive the MSF restart untouched — don't co-kill them on a C2-only restart.

### Pivot sessions: never kill_job an already-orphaned SOCKS proxy

When a pivot session dies (common on Jenkins/webshell footholds — the nested
`bash → python PTY → …` chain is reaped when the originating request thread
ends), the `auxiliary/server/socks_proxy` job running through it is left
pointing at a dead relay. Calling `kill_job` on that orphaned job hangs
msfrpcd's command dispatch indefinitely (shared Framework instance, serialized
dispatch) and every subsequent RPC call hangs the ~300s socket default behind
it — the only reliable recovery is killing the msfconsole process. **Order of
operations matters**: when a pivot session starts to look degraded, drop the
SOCKS job FIRST, then handle the session. Once a SOCKS job is already orphaned
(its session is confirmed dead), do NOT `kill_job` it — restart the console.

### Pivot footholds: daemonize properly, don't just background

A pivot foothold that stays parented under its originating process (JVM
script-console thread, PHP request handler, SSH session) gets reaped when that
parent dies. `nohup &` is not enough. The reliable pattern is **double-fork +
setsid + close/redirect all three fds** so the implant ends up orphaned under
PID 1, severed from the originating request/thread lineage. Kills the main
"pivot session mysteriously dies after a few minutes" class of failures at the
source — if the sessions don't die, the SOCKS jobs don't orphan, and the
cascade this lessons section describes doesn't start.

### sudoers command-arg `*` and `/`: don't use arg globs for anything with slashes

sudo's command-arg wildcard uses `fnmatch` and on many builds (default
`FNM_PATHNAME`) `*` does NOT match `/`. A sudoers rule like
`NOPASSWD: /usr/local/bin/foo *` silently fails to match arguments
containing `/` (CIDR notation `172.16.0.0/24`, file paths, URLs) and sudo
falls back to a password prompt — exactly the opposite of what you set up
`NOPASSWD` for. Portable fix: pass the slash-containing value via an env
var, tag the sudoers rule `NOPASSWD: SETENV:`, and scope
`Defaults!<path> env_keep += "FOO"`. No wildcarding needed. Self-check the
installer against the exact path the operator will exercise (not just the
no-arg case); the bug otherwise ships silent until someone actually tries
to re-trigger a real pivot.

### Ligolo-ng attackbox-root friction: use pinned-path sudoers helpers, not wildcard `ip`

Ligolo-ng is the most reliable pivot method in practice but needs root on the
attackbox for TUN setup + routes. The naive "whitelist `ip` in sudoers"
approach is a bad trade — any `ip` command becomes passwordless, and that's
far more than ligolo actually needs. Better pattern (PEN-AGENT's
`tools/ligolo/`): ship a handful of narrow helper scripts
(`pen-agent-ligolo-{up,down,route,unroute}`) that each do ONE thing with
their own argument validation, pin them to `/usr/local/bin`, and grant
NOPASSWD on just those absolute paths. The sudoers file contains no `ip`
wildcard, so the attack surface is exactly "what those scripts do" — easy to
audit. The route helpers validate IPv4 CIDRs themselves (reject IPv6,
`0.0.0.0/0`, `127.0.0.0/8`). Opt-in per attackbox, revocable with a
companion uninstaller. Same approach generalizes to any other
root-on-attackbox tool.

### Dropped shells: replay the recorded .sh FIRST, don't rebuild from snippets

PEN-AGENT's `record_exploit` writes an end-to-end `.sh` (full chain:
auth → CSRF → cookies → payload, dual-session) to
`engagement/exploits/<host>-<label>.sh` for every reverse shell. On a
drop, shell-mgr was ignoring it and rebuilding the callback from the
`delivery_payload` snippet it had stored in-memory — which drops the
auth/CSRF/cookie steps and fails against anything but a trivially
stateless RCE. Pattern: when the recovery artifact already exists on
disk, the first recovery attempt is to RUN it (`bash <path>`), not to
re-synthesize. Only fall back to the recording teammate when the `.sh`
itself fails for a cause they must fix (stale auth, broken injection,
target implant died). Codified as `skills/post-exploit/shell-recovery`.

### Methodology-only rules get skipped — code-gate the ones that matter

Session-handoff invariants ("every foothold gets one operator + one agent
session", "every reverse shell must have a recorded exploit", "pivot via
non-MSF tools first") were documented in skills and teammate templates and
STILL got skipped. The pattern that actually works: refuse the operation
in the MCP server by default, require an explicit `confirm_X=True` boolean
plus a ≥20-char `reason` string that gets logged to
`engagement/evidence/msf-modules/` for operator audit. Also gate every
BYPASS path, not just the obvious tool — e.g. for the dual-session
invariant, `execute` / `upload` / `ifconfig` all check it, AND
`run_module` refuses a `SESSION=<reserved>` option, AND `console_exec`
refuses `sessions -i <reserved>`. One un-gated path and the whole thing
leaks. Mirror the gate wherever the shadow surface exists (shell-server
mirrors msf's reserve on labels ending in `-operator`).

### Pivots: default to out-of-Framework tools (chisel / ligolo-ng / sshuttle / SSH)

Metasploit's in-Framework `auxiliary/server/socks_proxy` has proven unstable
across engagements as a general pivot method, not just for long-lived ones. A
dead relay wedges the shared RPC and forces a full msfconsole restart. A
separate-process tunnel on the pivot host decouples the tunnel from the MSF
RPC — when the tunnel dies the MSF console stays healthy, and recovery is a
fresh agent, not a Framework restart. PEN-AGENT now defaults to loading the
`pivoting-tunneling` skill (chisel / ligolo-ng / sshuttle / native SSH `-D`
or `-L`) for every pivot. `start_socks_proxy` is kept as a labeled FALLBACK
for the narrow cases where the alternatives aren't viable (no attackbox
inbound to pivot, can't drop a binary on target, or need every Metasploit
module to route transparently without proxychains).

## Environment

_Attackbox / lab / network gotchas that recur across engagements._

## AI / LLM targets

_Patterns and oracles for AI red teaming that generalize across AI systems._

## Skill gaps

_Missing coverage or weak spots observed, to drive new/updated skills._

## Detection & OPSEC

_What was noisy or got caught, and quieter alternatives._
