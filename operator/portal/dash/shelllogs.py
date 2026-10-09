"""Shell-server read-side (operator visibility into non-MSF sessions).

Shell-server writes a per-session live log at
engagement/evidence/shell-<session_id>-<label>.log and appends every
send_command to engagement/evidence/shell-commands.log. The portal reads
those files directly — shell-server itself doesn't expose HTTP.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from dash.config import SHELL_CMD_LOG, SHELL_LOG_DIR

_SHELL_LOG_RE = re.compile(r"^shell-([^-]+)-(.+)\.log$")


def list_sessions() -> dict:
    """Scan engagement/evidence for shell-<sid>-<label>.log files.

    Returns newest-first by mtime so the active session floats to the top.
    """
    if not SHELL_LOG_DIR.exists():
        return {"sessions": []}
    out = []
    try:
        for p in SHELL_LOG_DIR.glob("shell-*.log"):
            m = _SHELL_LOG_RE.match(p.name)
            if not m:
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            out.append({
                "session_id": m.group(1),
                "label": m.group(2),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "mtime_iso": datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat(timespec="seconds"),
                "file": p.name,
            })
    except OSError:
        return {"sessions": []}
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return {"sessions": out}


def session_log(file_name: str, max_bytes: int = 128 * 1024) -> dict:
    """Return the tail of a single shell-session live log.

    `file_name` is validated against the shell-*.log pattern so a crafted
    `../` can't walk out of the evidence dir. Falls back to the whole file
    when it's smaller than max_bytes.
    """
    if not _SHELL_LOG_RE.match(file_name):
        return {"data": "", "error": "invalid file name"}
    p = SHELL_LOG_DIR / file_name
    try:
        p = p.resolve()
    except OSError:
        return {"data": "", "error": "resolve failed"}
    try:
        if not str(p).startswith(str(SHELL_LOG_DIR.resolve())):
            return {"data": "", "error": "out of scope"}
    except OSError:
        return {"data": "", "error": "resolve failed"}
    if not p.exists():
        return {"data": "", "error": "not found"}
    try:
        with p.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return {"data": f.read().decode(errors="replace"), "size": size}
    except OSError as e:
        return {"data": "", "error": str(e)}


def command_log(max_bytes: int = 64 * 1024) -> dict:
    """Return the tail of the shared shell-commands.log — a one-liner-per-
    command log across all shell-server sessions. Useful as a global
    activity feed above the per-session views."""
    if not SHELL_CMD_LOG.exists():
        return {"data": ""}
    try:
        with SHELL_CMD_LOG.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            return {"data": f.read().decode(errors="replace"), "size": size}
    except OSError as e:
        return {"data": "", "error": str(e)}
