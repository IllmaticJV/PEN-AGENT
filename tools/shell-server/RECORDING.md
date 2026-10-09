# Session re-trigger recording — message contract

This is the message contract between domain teammates and the `scribe`
teammate for recording how a session was established, so a later drop
can be recovered by re-running the recorded `.sh`.

Scribe's spawn template is intentionally thin — the HEREDOC-heavy
examples, field definitions, and edge cases live here. Scribe loads
this file on demand when it needs to resolve a message it hasn't
seen before. The `record_exploit` and `record_non_session_exploit`
tool docstrings in `tools/shell-server/server.py` are the normative
source for individual field semantics; this file is the message
shape and workflow around them.

## Inbound — session-producing (default)

Sent by the domain teammate as soon as `start_listener` catches a
callback, before any `send_command` (which is gated on the record).

```
[record-exploit] session_id=<id> target=<ip> label="<slug>"
  hostname="<optional short host name>"
  listener_port=<N>
  references="<CVE / state.db vuln_id / finding_id / URLs>"
  notes="<optional operator notes>"
  python_helper=<0|1>          # if 1, source arrives in a following message block
  delivery=<<<EOD
  <full bash body — EVERY prerequisite step from scratch:
   login → CSRF fetch → cookie carry → intermediate requests →
   payload. Reference ${LHOST} / ${LPORT} / ${LABEL}. Reference
   ${EXPLOITS_DIR}/python/<name>.py for helper calls. Do NOT assume
   external auth state.>
  EOD
  python_source=<<<EOP          # only if python_helper=1
  <python source — reads os.environ["LHOST"|"LPORT"|"LABEL"|"EXPLOITS_DIR"]>
  EOP
```

Required: `session_id`, `target` (must contain a valid IPv4 — the
tool enforces this), `label`, `delivery`. Everything else is optional.

## Inbound — non-session

For techniques that NEVER produced a `list_sessions` row: file-read
RCEs where the response is the proof, prompt-injection extractions,
DPAPI decrypts on the attackbox, API-only credential recovery, cert /
AD abuse that just mutates directory state. The `.sh` runs the body
end-to-end and prints the proof to stdout — no listener involved.

```
[record-exploit] mode=no-session target=<ip> label="<slug>"
  hostname="<optional short host name>"
  references="<CVE / state.db vuln_id / finding_id / URLs>"
  notes="<optional operator notes>"
  python_helper=<0|1>
  body=<<<EOD
  <standalone bash — every prerequisite + the technique, printing
   the proof artifact (extracted token, flag, cert fingerprint,
   status message) to stdout so re-runs are self-verifying.>
  EOD
```

Required: `mode=no-session`, `target`, `label`, `body`. On receipt
scribe calls `record_non_session_exploit` instead of `record_exploit`.
Filename contract is the same (`<ip>-[<hostname>-]<label>.sh`); the
sidecar `.md` is tagged `kind: non-session`.

## Inbound — lead nudges

```
[nudge-session] session_id=<id>
  Lead noticed a reverse-shell session with no record yet. Scribe
  finds the session in list_sessions, identifies the originating
  teammate from recent messages, and asks them with
  [request-exploit-context] session_id=<id>.

[nudge-vuln] vuln_id=<N> target=<ip> title="<title>" discovered_by=<teammate>
  Lead noticed an actioned vuln with no engagement/exploits/<ip>-*
  file. Scribe messages `discovered_by` with
  [request-exploit-context] vuln_id=<N> target=<ip>
  — asking whether the technique produced a session (default form)
  or not (`mode=no-session`), then records it.
```

## Outbound — to the originating teammate

```
[recorded] session_id=<id> sh=<path> md=<path> python=<path or none>
  Record written; send_command is now unlocked for this session.

[record-rejected] session_id=<id> reason="<why>"
  Something was missing or invalid (no IP in target, delivery blank,
  session not found). Caller must fix and resend.

[request-exploit-context] session_id=<id>
  Scribe knows a shell landed (lead nudged, or saw it in
  list_sessions) but no [record-exploit] arrived yet. Asking for it.
```

## Outbound — to the lead

```
[exploit-recorded] session_id=<id> target=<ip> label=<slug>
  sh=<path> via=<originating-teammate>
  — One line per record. Scribe sends this on every successful write.

[exploit-stale] session_id=<id> reason="no delivery context from <teammate>"
  — Scribe asked for context and no one answered. Lead intervenes.
```

## Filename contract

The tool enforces this; the caller doesn't format filenames:

- `.sh` / `.md`: `engagement/exploits/<ip>-[<hostname>-]<label>.{sh,md}`
- Python helper: `engagement/exploits/python/<ip>-[<hostname>-]<label>.py`

The IP leads so `ls engagement/exploits/` groups by host. No hostname
→ just `<ip>-<label>`. The tool refuses the call if `target` doesn't
contain a valid IPv4; scribe passes that error through to the caller
as `[record-rejected]`.
