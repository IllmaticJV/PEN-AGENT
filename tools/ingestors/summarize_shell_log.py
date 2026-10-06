#!/usr/bin/env python3
"""Local shell/MSF transcript summarizer — strips the noise before the LLM reads it.

Why: a 5-minute shell session with MOTD + banners + repeated prompts +
`ls` output on a big directory is thousands of tokens of mostly
boilerplate. When a teammate (or the lead) wants to catch up on what
happened on a session, the signal is: WHICH commands ran, and the
non-trivial output. This script keeps that and drops the rest.

Usage:
  python3 tools/ingestors/summarize_shell_log.py <path> [--last-n 50] [--max-recv-lines 30]

Input: a `shell-<sid>-<label>.log` from shell-server, OR a Metasploit
module JSONL from `engagement/evidence/msf-modules/*.jsonl`, OR any
transcript shaped as `[ts] send: cmd` / `[ts] recv: out` lines.

Output: one `[hh:mm:ss] $ cmd` per command, with recv blocks:
  - Trimmed to --max-recv-lines (default 30) with `[... K more lines
    elided ...]` footer
  - Blanks + MOTD/banner lines collapsed
  - Identical consecutive recv blocks collapsed to `[same as above]`
  - Prompt lines (`ubuntu@host:~$`) removed from recv blocks since the
    shell-server frame already delimits them

Use before pasting a session log into the lead's turn, or in the
`[task-summary]` for a long-running recon pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


_LINE_RE = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+(?P<kind>send|recv)[:]\s*(?P<body>.*)$")
_PROMPT_RE = re.compile(
    r"^(?:[\w.-]+@[\w.-]+:[^\s]*[\$#]\s*|PS\s+[A-Z]:\\[^>]*>\s*|[A-Z]:\\[^>]*>\s*|>\s*|\$\s*|#\s*)$"
)
# Common MOTD / banner noise worth dropping unconditionally.
_NOISE_PATTERNS = [
    re.compile(r"^Welcome to Ubuntu"),
    re.compile(r"^\s*\* Documentation:"),
    re.compile(r"^\s*\* Management:"),
    re.compile(r"^\s*\* Support:"),
    re.compile(r"^Last login:"),
    re.compile(r"^The programs included"),
    re.compile(r"^Ubuntu comes with ABSOLUTELY"),
    re.compile(r"^To run a command"),
    re.compile(r"^See \"man sudo_root\""),
]


def _is_noise(line: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if _PROMPT_RE.match(s):
        return True
    for pat in _NOISE_PATTERNS:
        if pat.search(s):
            return True
    return False


def _parse(text: str) -> list[tuple[str, str, list[str]]]:
    """Walk the transcript, pairing each `send:` line with the following
    `recv:` lines (which may span multiple lines of output).

    Returns [(timestamp, command, [recv_line, ...]), ...].
    """
    events: list[tuple[str, str, list[str]]] = []
    current: list | None = None
    for raw in text.splitlines():
        m = _LINE_RE.match(raw)
        if not m:
            # Continuation of the previous recv block (nmap outputs
            # multiline results that fall through here).
            if current is not None:
                current[2].append(raw.rstrip())
            continue
        kind = m.group("kind")
        body = m.group("body").rstrip()
        if kind == "send":
            if current is not None:
                events.append((current[0], current[1], current[2]))
            current = [m.group("ts"), body, []]
        else:  # recv
            if current is None:
                # Pre-command recv (banner) — attach to a synthetic cmd.
                current = [m.group("ts"), "(session banner)", []]
            current[2].append(body)
    if current is not None:
        events.append((current[0], current[1], current[2]))
    return events


def _trim_recv(lines: list[str], max_lines: int) -> list[str]:
    """Drop prompt/noise + cap at max_lines, with elided-count footer."""
    cleaned = [l for l in lines if not _is_noise(l)]
    if len(cleaned) <= max_lines:
        return cleaned
    kept = cleaned[: max_lines - 1]
    kept.append(f"[... {len(cleaned) - len(kept)} more lines elided (--max-recv-lines)]")
    return kept


def _format(events: list[tuple[str, str, list[str]]],
            max_recv: int, last_n: int) -> tuple[str, dict]:
    if last_n:
        events = events[-last_n:]
    out = []
    stats = {"commands": 0, "recv_lines_in": 0, "recv_lines_out": 0}
    prev_recv_text = None
    for ts, cmd, recv in events:
        stats["commands"] += 1
        stats["recv_lines_in"] += len(recv)
        trimmed = _trim_recv(recv, max_recv)
        stats["recv_lines_out"] += len(trimmed)
        if cmd == "(session banner)" and not trimmed:
            continue
        out.append(f"[{ts}] $ {cmd}")
        if trimmed:
            joined = "\n".join(trimmed)
            if joined == prev_recv_text:
                out.append("    [same output as previous command]")
            else:
                for line in trimmed:
                    out.append("    " + line)
                prev_recv_text = joined
        else:
            prev_recv_text = ""
        out.append("")
    return "\n".join(out).rstrip() + "\n", stats


def _try_msf_jsonl(path: Path) -> str | None:
    """If this looks like an msf-modules JSONL, emit a one-liner summary
    per record (ts, module, options.SESSION, result.status) and return
    the formatted text; else return None so the shell parser runs."""
    try:
        lines = [l for l in path.read_text(errors="replace").splitlines() if l.strip()]
    except OSError:
        return None
    if not lines or not lines[0].lstrip().startswith("{"):
        return None
    out = []
    for raw in lines:
        try:
            r = json.loads(raw)
        except json.JSONDecodeError:
            continue
        ts = r.get("ts") or r.get("event") or ""
        tool = r.get("tool", "")
        module = r.get("module", "")
        job = r.get("job_id")
        opts = r.get("options", {}) or {}
        key_opts = {k: v for k, v in opts.items()
                    if k in ("SESSION", "RHOSTS", "RHOST", "LHOST", "LPORT",
                             "PAYLOAD", "URI", "TARGETURI")}
        head = f"[{ts}] {tool} {module}" + (f" → job {job}" if job else "")
        out.append(head)
        if key_opts:
            out.append("    " + " ".join(f"{k}={v}" for k, v in key_opts.items()))
        err = (r.get("result") or {}).get("error") if isinstance(r.get("result"), dict) else None
        if err:
            out.append(f"    ERROR: {err}")
    return "\n".join(out) + "\n" if out else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="shell-<sid>-<label>.log OR msf JSONL")
    ap.add_argument("--last-n", type=int, default=0,
                    help="only summarize the last N commands (0 = all)")
    ap.add_argument("--max-recv-lines", type=int, default=30,
                    help="trim each recv block to this many lines (default 30)")
    ap.add_argument("--stats", action="store_true",
                    help="print a token-savings line to stderr")
    args = ap.parse_args()

    p = Path(args.path)
    if not p.exists():
        print(f"ERROR: {p} not found", file=sys.stderr)
        return 2

    # MSF JSONL branch first (format is unambiguous).
    msf = _try_msf_jsonl(p)
    if msf is not None:
        print(msf, end="")
        return 0

    text = p.read_text(errors="replace")
    events = _parse(text)
    if not events:
        # Not shaped like a transcript — show the raw tail as a fallback.
        print(text, end="")
        return 0
    out, stats = _format(events, args.max_recv_lines, args.last_n)
    print(out, end="")
    if args.stats:
        orig = len(text)
        new = len(out)
        pct = (100 * new / orig) if orig else 0
        print(
            f"[summarize_shell_log] commands={stats['commands']} "
            f"recv_lines {stats['recv_lines_in']}→{stats['recv_lines_out']} "
            f"bytes {orig}→{new} ({pct:.0f}%)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
