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
| `gen_payloads.sh --lhost <IP\|iface> [--no-xor]` | Generates ~13 standard payloads (windows/linux × shell/meterpreter × exe/elf/raw + OSEP-style AMSI/ETW-bypassed `ps1`) into `engagement/payloads/<name>.<ext>`, writes `index.json` with the matrix (`{name, path, size, payload, platform, arch, format, lport, callback, handler_module, sha256, encoding}`). `--lhost` accepts an interface name (resolved to its current IPv4). Windows `.exe` rows are XOR-wrapped (OSEP-starter) when `mingw-w64` is installed on the attackbox — raw shellcode is XOR'd with a random 1-byte key and embedded in a C loader (VirtualAlloc → XOR-decode → CreateThread), then compiled with `x86_64-/i686-w64-mingw32-gcc`. Falls back to a plain msfvenom exe on any failure with a WARN. Pass `--no-xor` to skip. The script fail-fasts (exit 3) when ≥2 payloads fail. |
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

- Starter set only — no custom encoders/templates beyond the baseline
  XOR exe wrap. For hardened AV, the teammate regenerates per-target
  with its own msfvenom invocation + obfuscation.
- LPORT ranges (one handler per entry): `44xx` = windows, `45xx` = linux,
  `46xx` = scripting.
- `--only-missing` on `gen_payloads.sh` is safe to re-run (skips payloads
  already on disk).

## Trust rule — never Read the generated files

Files under `engagement/payloads/` are **trusted binary artifacts**:
raw msfvenom shellcode, XOR-encoded Windows loaders, OSEP-style
PowerShell with AMSI/ETW bypass strings. Agents MUST NOT call `Read`,
`cat`, `less`, `head`, `tail`, `strings`, or any content-inspection
tool against them, and MUST NOT paste their content into chat.

Why:
- Burns thousands of tokens per file for zero decision value.
- Trips the Claude Code safety classifier, which disables Bash for
  the rest of the session (see `knowledge/lessons-learned.md`).
- Nothing an agent would learn from the bytes is actionable —
  `index.json` and `pick.py` already surface everything useful
  (name, path, size, sha256, payload, callback, handler, encoding).

The agent interface, in order of use:
1. `python3 tools/preflight/pick.py --platform X --arch Y --format Z` —
   returns the match plus the `start_handler` call and delivery
   template.
2. `engagement/payloads/index.json` — the full structured matrix.
3. `sha256sum --check` against the index value — the ONLY correct
   way to verify a file's integrity if ever needed.

`gen_payloads.sh` fail-fasts (exit 3) when ≥2 payloads fail, so
a successful run (exit 0) is the trust signal. One missing exotic
payload is normal (missing on this msfvenom build); the summary
line says so.

See the `index.json` schema in `gen_payloads.sh` for the full field list.
