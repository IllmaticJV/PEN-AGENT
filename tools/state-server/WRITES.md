# State writes — message contract

This is the message contract between domain teammates and the
`state-mgr` teammate for engagement state writes. All writes to
`state.db` flow through state-mgr; teammates send structured
messages and state-mgr calls the matching MCP tool with dedup +
graph-coherence judgment.

state-mgr's spawn template is intentionally thin — the message
shapes, outbound replies, and tool-reference lists live here.
state-mgr loads this file on demand at activation. The MCP tool
docstrings in `tools/state-server/` are the normative source for
individual field semantics; this file is the message shape and
the validation rules around them.

Teammates do NOT read this file. CLAUDE.md § "State Writes via
state-mgr" carries the brief examples teammates need for their
Communication blocks. This file is for state-mgr itself.

## Inbound — from domain teammates

```
[add-vuln] ip=<ip> title="<title>" vuln_type=<type> severity=<sev>
  via_access_id=<N> via_credential_id=<M> details="<details>" discovered_by=<teammate>

[update-vuln] id=<N> status=<status> details="<additional details>"
  via_access_id=<M> via_credential_id=<M> via_vuln_id=<M>
  technique_id=<T> in_graph=<0|1> chain_order=<N>

[add-cred] username=<user> secret=<secret> secret_type=<type>
  domain=<domain> source="<source>" via_access_id=<N> via_vuln_id=<M>

[update-cred] id=<N> cracked=true secret=<plaintext>
  via_access_id=<M> via_vuln_id=<M> chain_order=<N>

[add-access] ip=<ip> method=<method> user=<user>
  level=<user|admin|root|system>
  via_credential_id=<N> via_access_id=<M> via_vuln_id=<V>

[update-access] id=<N> status=<active|lost> notes="<details>"
  via_credential_id=<M> via_access_id=<M> via_vuln_id=<V>
  technique_id=<T> in_graph=<0|1> chain_order=<N>

[add-port] ip=<ip> port=<N> proto=<tcp|udp> service=<svc> version="<ver>"

[add-target] ip=<ip> hostname=<host> os="<os>" role=<role>

[update-target] ip=<ip> hostname=<host> os="<os>" notes="<notes>"

[add-pivot] from_ip=<ip> to_subnet=<cidr> pivot_type="<type>"

[add-blocked] ip=<ip> technique="<name>" reason="<why>" retry=<no|later|with_context>

[add-tunnel] tunnel_type=<type> local_port=<N> remote_host=<ip>
  remote_network=<cidr> via_access_id=<N>

[update-tunnel] id=<N> status=<active|down|closed> notes="<details>"

[reorder] vuln id=<N> chain_order=<N>
[reorder] access id=<N> chain_order=<N>
[reorder] cred id=<N> chain_order=<N>
```

Teammates may batch multiple actions in a single message:
```
[add-port] ip=10.10.10.5 port=80 proto=tcp service=http
[add-port] ip=10.10.10.5 port=443 proto=tcp service=https
[add-port] ip=10.10.10.5 port=445 proto=tcp service=smb
```

## Batched dependent writes — local references

A provenance chain (vuln → cred → access) used to force one round-trip
per link: the teammate wrote the vuln, waited for its id, then wrote the
cred with `via_vuln_id=<that id>`, waited again, then the access. Through
the single writer that is pure serialization. **Local references collapse
the whole chain into one message.**

- `ref=<label>` on any `[add-*]` names the row being created. Labels are
  local to this one message (convention `v1`, `c1`, `a1`; any
  `[a-z0-9_]+` works).
- `@<label>` as the value of any id field (`via_vuln_id=@v1`,
  `via_credential_id=@c1`, `via_access_id=@a1`) refers to a row created
  **earlier in the same message**. List rows parent-first — `@label` is
  always a backward reference.

```
[add-vuln]   ref=v1 ip=10.1.1.5 title="Kerberoast svc_sql" vuln_type=kerberoast severity=high via_access_id=4 discovered_by=ad-ops
[add-cred]   ref=c1 username=svc_sql secret=<tgs-hash> secret_type=kerberos_tgs source=kerberoast via_vuln_id=@v1 discovered_by=ad-ops
[add-access] ip=10.1.1.5 method=winrm user=svc_sql level=admin via_credential_id=@c1 via_vuln_id=@v1 discovered_by=ad-ops
```

**How state-mgr resolves a batch (do this in one turn, no reply between
rows):**

1. Keep a `refs = {}` map for the message. Process rows top-to-bottom.
2. For each row, substitute every `@label` value from `refs`. If a
   `@label` is not yet in `refs` (forward reference or typo), do NOT
   write that row or any later row that depends on it — reply
   `[batch-error] unresolved ref @<label> on <action>` and write only
   the rows that resolved cleanly.
3. Strip the `ref=` field — it is a batch label, never a tool argument.
   Call the matching write tool with the resolved numeric ids and apply
   normal dedup. If the row merges into an existing record, bind
   `refs[label]` to the **surviving** id so later rows link to the real
   row, not a phantom.
4. Dedup, the technique-vuln gate, and graph coherence still run per row.
   A chain that supplies its own `via_vuln_id=@v1` satisfies the gate
   in-batch, so no `[cred-needs-vuln]` round-trip is needed. Still audit
   that the chain's **root** traces back to a target; emit `[chain-gap]`
   only for a missing link the batch did not supply.
5. Send ONE `[batch-written]` confirmation with the full label map (see
   Outbound), and notify the lead once per new finding. **If the batch
   produced new access, send `[new-access]` to the lead FIRST** — before the
   batch confirmation and the other notifications — because it is the lead's
   Execution Achieved trigger (the highest-priority signal); don't make a new
   foothold wait behind lower-priority rows.

## Agent attribution (critical)

Every write tool has an agent attribution field. state-mgr MUST pass
the originating teammate's name on every write call:

```
add_target(discovered_by=<sender>)
add_credential(discovered_by=<sender>)
add_access(discovered_by=<sender>)
add_vuln(discovered_by=<sender>)
add_pivot(discovered_by=<sender>)
add_blocked(blocked_by=<sender>)
add_tunnel(created_by=<sender>)
```

Determine the sender from the message context. If the message
includes `discovered_by=<name>`, use that value. Otherwise use the
teammate name from the SendMessage sender. When the lead messages
state-mgr, attribute to "lead" or to the teammate the lead names.

This populates the `agent` field on timeline events. Missing
attribution breaks the engagement timeline — never omit it.

## Outbound — confirmations to teammates

```
[batch-written] v1→vuln#12 c1→cred#7 access#3  — one line per batched message, label→id map
[vuln-written] id=<N> title="<title>" (new)
[vuln-merged] id=<N> ← your "<title>" merged into existing
[vuln-updated] id=<N> status=<status>
[cred-written] id=<N> username=<user> (new)
[cred-exists] id=<N> username=<user> (already recorded)
[cred-needs-vuln] source="<source>" — send [add-vuln] for the technique first, then resubmit with via_vuln_id
[cred-updated] id=<N>
[access-written] id=<N> <user>@<ip> via <method>
[access-updated] id=<N>
[port-written] ip=<ip> port=<N>
[target-written] ip=<ip>
[target-updated] ip=<ip>
[pivot-written] id=<N>
[blocked-written] id=<N>
[tunnel-written] id=<N>
[tunnel-updated] id=<N>
```

## Outbound — notifications to lead

```
[new-vuln] id=<N> "<title>" on <ip> severity=<sev> — discovered by <teammate>
[new-cred] id=<N> <user> (<secret_type>) — source: <source>
[new-access] id=<N> <user>@<ip> via <method> level=<level>
[vuln-review] wrote id=<N> but possible overlap with id=<M> — operator judgment needed
[chain-gap] access id=<N> has no via_credential_id — which cred was used?
```

## Write tools state-mgr calls

```
add_target(ip, hostname, os, role, notes, ports, discovered_by)
update_target(ip, hostname, os, role, notes)
add_port(ip, port, protocol, service, banner)
add_credential(username, secret, secret_type, domain, source, via_access_id, via_vuln_id, discovered_by)
update_credential(id, cracked, secret, notes, via_access_id, via_vuln_id, in_graph, chain_order)
add_access(ip, access_type, username, privilege, method, via_credential_id, via_access_id, via_vuln_id, discovered_by)
update_access(id, active, privilege, notes, via_credential_id, via_access_id, via_vuln_id, technique_id, in_graph, chain_order)
add_vuln(title, ip, vuln_type, severity, details, status, via_access_id, via_credential_id, discovered_by)
update_vuln(id, status, severity, details, in_graph, via_access_id, via_credential_id, via_vuln_id, technique_id, chain_order)
add_pivot(source, destination, method, status, discovered_by)
update_pivot(id, status, notes)
add_blocked(technique, reason, ip, retry, notes, blocked_by)
add_tunnel(tunnel_type, pivot_host, target_subnet, local_endpoint, remote_endpoint, requires_proxychains, created_by)
update_tunnel(id, status, notes)
```

## Validation rules (enforce before writing)

- `ip` is the target lookup key — must match an existing target for
  most writes
- `add_vuln(ip=)` — required
- `add_credential(secret=)` — required, no empty secrets
- `add_credential(secret_type=)` — valid: `password`, `ntlm_hash`,
  `net_ntlm`, `aes_key`, `kerberos_tgt`, `kerberos_tgs`, `dcc2`,
  `ssh_key`, `token`, `certificate`, `webapp_hash`, `dpapi`, `other`
- `add_vuln(status=)` — valid: `found`, `actioned`, `blocked`
- `add_vuln(severity=)` — valid: `info`, `low`, `medium`, `high`, `critical`
- `add_blocked(retry=)` — valid: `no`, `later`, `with_context`
- `add_blocked(ip=)` — must match an existing target if provided

## Read tools state-mgr calls (for dedup checks)

```
get_state_summary()
get_vulns(status, target)
get_credentials(untested_only, username, domain)   # pass username= for [add-cred] dedup — keeps the read flat as creds pile up
get_access(target, active_only)
get_targets(ip)
```
