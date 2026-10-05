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

### Long-lived pivots: prefer out-of-Framework agents (ligolo-ng, chisel)

For multi-hour engagements, Metasploit's in-Framework `socks_proxy` is a
single point of failure: a dead relay wedges the shared RPC. A separate agent
on the pivot host (ligolo-ng, chisel) decouples the tunnel from the MSF RPC —
when the agent dies the MSF console stays healthy, and recovery is a fresh
agent, not a Framework restart. Costs an extra binary on target; worth it for
anything beyond a quick in-and-out.

## Environment

_Attackbox / lab / network gotchas that recur across engagements._

## AI / LLM targets

_Patterns and oracles for AI red teaming that generalize across AI systems._

## Skill gaps

_Missing coverage or weak spots observed, to drive new/updated skills._

## Detection & OPSEC

_What was noisy or got caught, and quieter alternatives._
