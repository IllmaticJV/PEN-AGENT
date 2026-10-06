# tools/preflight

Per-engagement msfvenom payload bake-off + handler bring-up. Run **once at
engagement init** by shell-mgr in response to the orchestrator's mandatory
`[preflight-payloads] lhost=…` message, on the Metasploit backend only.

Not to be confused with the repo-root `preflight.sh`, which installs
attackbox pentest dependencies (nmap, ffuf, hashcat, impacket, …) at
install time. These three scripts run per-engagement; `preflight.sh`
runs per-attackbox.

## Scripts

| Script | Role |
|---|---|
| `gen_payloads.sh --lhost <IP\|iface>` | Generates ~13 standard payloads (windows/linux × shell/meterpreter × exe/elf/raw + OSEP-style AMSI/ETW-bypassed `ps1`) into `engagement/payloads/<name>.<ext>`, writes `index.json` with the matrix (`{name, path, size, payload, platform, arch, format, lport, callback, handler_module, sha256}`). `--lhost` accepts an interface name (resolved to its current IPv4). |
| `handler_calls.py [--json]` | Reads `engagement/payloads/index.json` and emits the exact `mcp__metasploit-server__start_handler(...)` calls shell-mgr iterates to bring up one hot handler per baked payload. `--json` for machine-readable form. |
| `pick.py --platform X --arch Y --format Z` | Teammate-side lookup: returns the path of a pre-baked payload matching the request, plus the live handler details and a delivery template. Replaces mid-exploit `msfvenom` round-trips. Prints `MISS:` when nothing matches so the caller falls through to custom generation. |

## Flow

```
orchestrator  →  [preflight-payloads] lhost=tun0  →  shell-mgr
shell-mgr     →  bash gen_payloads.sh --lhost tun0
shell-mgr     →  python3 handler_calls.py --json  →  iterate start_handler(...)
shell-mgr     →  [preflight-ready] payloads=N handlers=N   (HARD GATE)
teammate      →  python3 pick.py --platform windows --arch x64 --format exe
teammate      →  deliver <path>; callback lands on the already-live handler
```

## Rules

- Starter set only — no custom encoders/templates. For hardened AV, the
  teammate regenerates per-target with its own msfvenom invocation.
- LPORT ranges (one handler per entry): `44xx` = windows, `45xx` = linux,
  `46xx` = scripting.
- `--only-missing` on `gen_payloads.sh` is safe to re-run (skips payloads
  already on disk).

See the `index.json` schema in `gen_payloads.sh` for the full field list.
