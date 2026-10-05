"""Parse OBJECTIVES: section from engagement/scope.md.

Shared parser used by the state-server (to initialize objectives.json at
engagement start) and the operator portal (to re-sync the text if the
operator edits scope.md). Returns a list of {id, text} dicts, numbered
from 1 in document order.

Grammar (loose, forgiving):
- Section header matches `^\s*#* *OBJECTIVES?[: ]` case-insensitive, OR
  the explicit text block `OBJECTIVES:` on its own line. First one wins.
- Items match `^\s*(\d+)[.)]\s+(.*)$` for ordered-list style, OR
  `^\s*[-*]\s+(.*)$` for bullet style (auto-numbered 1..N in order).
- Section ends at the next header line (`^#`), blank-then-non-list, or EOF.
- Multi-line continuations: a non-empty, non-list line immediately after
  an item is appended to that item's text (space-joined).

Example input:

    OBJECTIVES:
    1. Find a way to coerce the utility on DEVHUB...
    2. An SSH key you recovered grants a foothold...

Example output:

    [{"id": 1, "text": "Find a way to coerce..."},
     {"id": 2, "text": "An SSH key you recovered..."}]
"""

from __future__ import annotations

import re
from pathlib import Path


_HEADER_RE = re.compile(r"^\s*#*\s*OBJECTIVES?\b[: ]?", re.IGNORECASE)
_NUMBERED_RE = re.compile(r"^\s*(\d+)[.)]\s+(.*\S)\s*$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(.*\S)\s*$")
_HEADER_LINE_RE = re.compile(r"^\s*#")


def parse(text: str) -> list[dict]:
    """Parse objectives from scope.md text. Returns list of {id, text}."""
    if not text:
        return []
    lines = text.splitlines()
    # Find section start
    start = None
    for i, line in enumerate(lines):
        if _HEADER_RE.match(line):
            start = i + 1
            break
    if start is None:
        return []

    items: list[list[str]] = []  # list of lines per item (first line is item body)
    counter = 0
    i = start
    saw_item = False
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        # Section terminator: another markdown header
        if saw_item and _HEADER_LINE_RE.match(line) and not _HEADER_RE.match(line):
            break
        # Section terminator: a known labelled block like "IPS:" / "SCOPE:"
        if saw_item and re.match(r"^\s*[A-Z][A-Z _]+:\s*$", line):
            break
        m = _NUMBERED_RE.match(line)
        if m:
            items.append([m.group(2)])
            saw_item = True
            i += 1
            continue
        b = _BULLET_RE.match(line)
        if b:
            items.append([b.group(1)])
            saw_item = True
            i += 1
            continue
        # Continuation of previous item: indented, non-blank, non-list line.
        if saw_item and line.strip():
            if items and re.match(r"^\s+", raw):
                items[-1].append(line.strip())
                i += 1
                continue
        # Blank line between items is fine; just skip.
        i += 1

    out: list[dict] = []
    for idx, parts in enumerate(items, start=1):
        text_joined = " ".join(p for p in parts if p).strip()
        if text_joined:
            out.append({"id": idx, "text": text_joined})
    return out


def parse_file(path: Path) -> list[dict]:
    try:
        return parse(path.read_text(errors="replace"))
    except OSError:
        return []


if __name__ == "__main__":
    import json, sys
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("engagement/scope.md")
    print(json.dumps(parse_file(p), indent=2))
