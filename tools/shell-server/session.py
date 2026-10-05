"""Session primitives: Listener/Session dataclasses, prompt detection.

The long-lived connection objects the server tracks, their I/O (socket or
PTY), transcript/live-log plumbing, the command log, and shell-prompt
probing. No MCP or server-wiring concerns live here.
"""

from __future__ import annotations

import os
import re
import select
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Defaults
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_TIMEOUT = 300  # 5 minutes
DEFAULT_CMD_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 2.0
RECV_SIZE = 4096
PROBE_COMMAND = "echo __SHELL_PROBE__"
PROBE_MARKER = "__SHELL_PROBE__"
MARKER_START = "__CMD_START_7f3a__"
MARKER_END = "__CMD_END_7f3a__"

_CMD_LOG = _PROJECT_ROOT / "engagement" / "evidence" / "shell-commands.log"


def _log_command(session: "Session", command: str) -> None:
    """Append a timestamped command entry to the command log."""
    try:
        if _CMD_LOG.parent.exists():
            ts = datetime.now().strftime("%H:%M:%S")
            label = session.label or session.session_id[:8]
            _CMD_LOG.open("a").write(f"[{ts}] [{label}] {command}\n")
    except Exception:
        pass  # Never break send_command over logging


@dataclass
class Listener:
    listener_id: str
    port: int
    host: str
    sock: socket.socket
    thread: threading.Thread
    timeout: int
    label: str
    status: str  # "listening" | "connected" | "timed_out" | "error"
    started_at: datetime
    session_id: str | None = None
    error_msg: str = ""


@dataclass
class Session:
    session_id: str
    conn: socket.socket | None
    remote_addr: tuple[str, int]
    port: int
    label: str
    session_type: str = "remote"  # "remote" | "local"
    master_fd: int | None = None  # PTY master fd (local only)
    process: subprocess.Popen | None = None  # subprocess handle (local only)
    command: str = ""  # original command (local only)
    privileged: bool = False  # running inside Docker container
    container_name: str | None = None  # Docker container name (privileged only)
    pty: bool = False
    prompt_pattern: str = ""
    platform: str = ""  # "windows" | "linux" | "" (auto-detected or caller-set)
    shell_type: str = ""  # "cmd" | "powershell" | "sh" | "" (auto-detected)
    status: str = "connected"  # "connected" | "stabilized" | "closed"
    connected_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    transcript: list[tuple[str, str, str]] = field(default_factory=list)
    live_log: Path | None = None
    # Enforcement flag for the exploit-recording rule. Set True only after a
    # successful record_exploit() call that wrote engagement/exploits/<id>-*.md
    # for this session, OR when the session legitimately needs no exploit log
    # (local credential-based processes — the creds themselves are already in
    # state.db). send_command refuses to run on a remote session with this
    # flag False, so a reverse shell can't be driven until the operator or the
    # orchestrating teammate has captured how it was triggered.
    exploit_recorded: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, direction: str, data: str) -> None:
        ts = datetime.now(tz=timezone.utc).isoformat()
        self.transcript.append((ts, direction, data))
        if self.live_log:
            prefix = ">>>" if direction == "send" else "<<<"
            try:
                with open(self.live_log, "a") as f:
                    f.write(f"[{ts}] {prefix}\n{data}\n\n")
            except OSError:
                pass

    def send(self, data: str) -> None:
        if self.session_type == "local":
            os.write(self.master_fd, data.encode())
        else:
            self.conn.sendall(data.encode())
        self.log("send", data)

    def recv(self, timeout: float = DEFAULT_READ_TIMEOUT) -> str:
        """Read available data from socket or PTY with timeout."""
        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        fd = self.master_fd if self.session_type == "local" else self.conn
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if not ready:
                if chunks:
                    break
                continue
            try:
                if self.session_type == "local":
                    chunk = os.read(self.master_fd, RECV_SIZE)
                else:
                    chunk = self.conn.recv(RECV_SIZE)
            except (ConnectionError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk.decode(errors="replace"))
            # Brief pause to let more data arrive before next select
            time.sleep(0.05)
        result = "".join(chunks)
        if result:
            self.log("recv", result)
        return result

    def drain(self, timeout: float = 0.5) -> str:
        """Drain any pending output from the socket or PTY."""
        return self.recv(timeout=timeout)


def _detect_prompt(session: Session) -> str:
    """Probe the shell to detect its prompt pattern.

    Also auto-detects platform (windows/linux) from the probe output
    and sets session.platform if not already set.
    """
    session.drain(timeout=1.0)
    session.send(f"{PROBE_COMMAND}\n")
    time.sleep(1.0)
    output = session.recv(timeout=3.0)

    # Auto-detect platform and shell type from probe output
    if not session.platform:
        out_lower = output.lower()
        if any(sig in out_lower for sig in ["c:\\", "ps ", "windows", ">echo "]):
            session.platform = "windows"
        elif any(sig in out_lower for sig in ["$", "/home/", "/root/", "/bin/"]):
            session.platform = "linux"
    if not session.shell_type:
        if "PS " in output:
            session.shell_type = "powershell"
        elif session.platform == "windows":
            session.shell_type = "cmd"
        elif session.platform == "linux":
            session.shell_type = "sh"

    # Look for the line after the probe marker — that's the prompt
    lines = output.split("\n")
    for i, line in enumerate(lines):
        if PROBE_MARKER in line and i + 1 < len(lines):
            prompt_line = lines[i + 1].strip()
            if prompt_line:
                # Escape regex special chars and create a pattern
                escaped = re.escape(prompt_line)
                # Allow the last char to vary (e.g., $ or #)
                if len(escaped) > 1:
                    return escaped[:-1] + "."
                return escaped

    # Fallback: common prompt patterns
    return r"[\$#>]\s*$"
