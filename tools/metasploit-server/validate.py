"""Input validation for the Metasploit MCP server.

Defense-in-depth against prompt injection. Module names, payloads, and option
values are validated before they reach the Metasploit RPC API. Remote-target
scope enforcement lives in scope.py and is applied to RHOST/RHOSTS.
"""

from __future__ import annotations

import re

# Module paths: exploit/windows/smb/ms17_010_eternalblue, payload names,
# auxiliary/..., post/... — bare module paths only, no shell metacharacters.
_MODULE_RE = re.compile(r"^[a-z0-9][a-z0-9/_-]{1,200}$")

_MODULE_TYPES = frozenset(
    {"exploit", "auxiliary", "post", "payload", "encoder", "nop", "evasion"}
)

# Option values that reach msfvenom argv or console lines must be free of
# shell metacharacters. API-set options (via pymetasploit3) are passed as a
# dict and never hit a shell, but we validate anyway as belt-and-braces.
_SHELL_METACHAR = re.compile(r"[;|&`$(){}\[\]<>\n\r]")


class ValidationError(Exception):
    """Raised when input validation fails."""


def validate_module_type(module_type: str) -> str:
    if module_type not in _MODULE_TYPES:
        raise ValidationError(
            f"Invalid module type: {module_type!r} — must be one of "
            f"{sorted(_MODULE_TYPES)}"
        )
    return module_type


def validate_module_name(name: str) -> str:
    if not name or not _MODULE_RE.match(name):
        raise ValidationError(
            f"Invalid module/payload name: {name!r} — bare module paths only"
        )
    return name


def validate_option_value(value: str) -> str:
    if _SHELL_METACHAR.search(str(value)):
        raise ValidationError(
            f"Blocked option value: {value!r} — contains shell metacharacters"
        )
    return value
