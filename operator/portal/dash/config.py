"""Paths and constants shared across the portal package.

Resolved relative to this file: dash/ → portal/ → operator/ → repo root.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve()
PORTAL_DIR = _HERE.parents[1]          # operator/portal
PROJECT_ROOT = _HERE.parents[3]        # repo root
TEMPLATE_DIR = PORTAL_DIR / "templates"

_ENG = PROJECT_ROOT / "engagement"
EVIDENCE_DIR = _ENG / "evidence"

DEFAULT_DB = _ENG / "state.db"
MSF_CFG = _ENG / "msfrpc.yaml"
SCOPE_MD = _ENG / "scope.md"
SCOPE_ALLOW = _ENG / "scope.allow"
SESSION_LOG_DIR = EVIDENCE_DIR / "msf-sessions"
MODULE_LOG_DIR = EVIDENCE_DIR / "msf-modules"
CONSOLE_SPOOL = EVIDENCE_DIR / "msf-console.log"
SHELL_LOG_DIR = EVIDENCE_DIR
SHELL_CMD_LOG = EVIDENCE_DIR / "shell-commands.log"
TEAMMATE_LOG_DIR = EVIDENCE_DIR / "logs"
OPERATOR_SESSIONS = _ENG / "operator-sessions.json"
OBJECTIVES_JSON = _ENG / "objectives.json"
FINDINGS_DIR = _ENG / "findings"

TOKEN_FILE = Path.home() / ".config" / "pen-agent" / "viewer-token"
SESSION_MAX_AGE = 86400  # 24h

NOT_CONFIGURED = (
    "Metasploit RPC not configured for this engagement (engagement/msfrpc.yaml "
    "missing). Start it with ./run.sh."
)
NOT_CONNECTED = (
    "Failed to connect to msfrpcd. Ensure the C2 is running (tmux attach -t "
    "pen-msf, or pgrep -f msfrpcd) and engagement/msfrpc.yaml is correct."
)
