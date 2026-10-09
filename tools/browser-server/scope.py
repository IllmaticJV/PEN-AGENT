"""Engagement scope enforcement for PEN-AGENT MCP servers.

Reads ``engagement/scope.allow`` and decides whether a target is in scope.
The file lists one entry per line — an IP, a CIDR range, a hostname, or a
``*.wildcard`` — with ``#`` comments and blank lines ignored.

Policy (defense-in-depth):
  * scope.allow ABSENT  -> allow everything (enforcement off; warn on stderr).
  * scope.allow PRESENT -> only targets matching an allow entry pass; every
    other target is refused (fail-closed).

This makes "stay in scope" a rule enforced in code at the tool layer, not
merely an instruction the model is trusted to follow. The orchestrator writes
scope.allow at engagement start from the operator-defined scope.

Keep this module dependency-free (stdlib only) and identical across servers.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path

_WARNED = False


class ScopeError(Exception):
    """Raised when a target is outside the engagement scope."""


def _scope_file(project_root: Path | str) -> Path:
    override = os.environ.get("PEN_AGENT_SCOPE_FILE")
    if override:
        return Path(override)
    return Path(project_root) / "engagement" / "scope.allow"


def load_scope(project_root: Path | str):
    """Parse scope.allow.

    Returns ``(networks, hostnames, wildcards)`` or ``None`` when no scope
    file exists (enforcement disabled).
    """
    path = _scope_file(project_root)
    if not path.exists():
        return None

    networks: list = []
    hostnames: set[str] = set()
    wildcards: list[str] = []

    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if line.startswith("*."):
            wildcards.append(line[1:])  # ".example.com"
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
            continue
        except ValueError:
            pass
        hostnames.add(line.rstrip("."))

    return networks, hostnames, wildcards


def _host_allowed(host: str, hostnames: set[str], wildcards: list[str]) -> bool:
    host = host.lower().rstrip(".")
    if host in hostnames:
        return True
    return any(host.endswith(suffix) for suffix in wildcards)


def _deny(target: str) -> str:
    return (
        f"OUT OF SCOPE: {target!r} is not covered by engagement/scope.allow. "
        "Refusing to act on it. If this target is authorized, add it to "
        "engagement/scope.allow (operator decision) and retry."
    )


def check_scope(target: str, project_root: Path | str) -> None:
    """Raise ScopeError if ``target`` is out of scope. No-op if no scope file.

    ``target`` may be an IP, CIDR, or hostname. A CIDR target must be fully
    contained within an allowed network (you cannot scan a /16 when only a
    /24 is authorized).
    """
    global _WARNED
    scope = load_scope(project_root)
    if scope is None:
        if not _WARNED:
            print(
                "[scope] engagement/scope.allow not found — scope enforcement "
                "OFF (all targets allowed).",
                file=sys.stderr,
            )
            _WARNED = True
        return

    networks, hostnames, wildcards = scope
    t = target.strip().lower()

    # IP / CIDR target
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        net = None

    if net is not None:
        for allowed in networks:
            if net.version == allowed.version and net.subnet_of(allowed):
                return
        raise ScopeError(_deny(target))

    # Hostname target
    if _host_allowed(t, hostnames, wildcards):
        return

    raise ScopeError(_deny(target))
