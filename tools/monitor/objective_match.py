#!/usr/bin/env python3
"""Propose objective → vuln / access matches for operator confirmation.

Why: the operator has to notice "oh, that vuln just actioned covers
objective 3" and tell the lead to flip the tracker. Scoring the
overlap between objective text and the vuln/access rows that landed
is deterministic — compute it locally and PROPOSE updates. Never
auto-apply (keyword overlap has false positives); the operator (or
the lead) decides.

Signals used per objective:
  - Keyword overlap between objective text and (vuln.title + details,
    access.ip + method + username, target.hostname) weighted by IDF.
  - Target hostname / IP mentioned verbatim in the objective text
    (strong signal).
  - CVE id mentioned in both (strong signal).
  - vuln.status == 'actioned' → candidate is "done"; otherwise
    "in_progress".

Output: markdown table of proposed updates with a confidence score
(0.0 – 1.0). The lead cross-checks and sends
`update_objective(id=N, status=…, note=…)` for each one they accept.

Usage:
  python3 tools/monitor/objective_match.py [--threshold 0.35] [--limit 10]
                                           [--include-done]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_STATE_DB = _PROJECT_ROOT / "engagement" / "state.db"
_OBJECTIVES = _PROJECT_ROOT / "engagement" / "objectives.json"


# Words that are too generic to carry meaning when matching objectives.
_STOP = frozenset("""
a an and or but if then the to of in on at by for with without into onto
is are be been being was were do does did have has had will would should
could may might must shall from this that these those it its as not no
not use uses used using find found locate recover obtain access execute
run get give proof file service system account user credential token key
command commands code shell shell's host your their his her it them we
you them i me only also one two three four five six seven eight nine
ten first second next then finally server host target identify known
pivot access authenticate credentials via over through using run executed
execution gain gaining obtain obtaining prove proving show showing
authenticated unauthenticated privilege escalate escalation lateral
movement internal external new a-new another other some all each every
any such this these those what who where when which how why valid
""".split())


_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_CVE_RE = re.compile(r"CVE[-]?\d{4}[-]\d{4,7}", re.I)


def _tokens(text: str) -> list[str]:
    if not text:
        return []
    out = []
    for m in _WORD_RE.findall(text):
        s = m.lower()
        if len(s) < 3 or s in _STOP:
            continue
        out.append(s)
    return out


def _load_db():
    if not _STATE_DB.exists():
        return [], [], {}
    conn = sqlite3.connect(f"file:{_STATE_DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    vulns = [dict(r) for r in conn.execute(
        """SELECT v.id, v.title, v.vuln_type, v.status, v.severity, v.details,
                  t.ip AS target_ip, t.hostname AS target_hostname
           FROM vulns v LEFT JOIN targets t ON t.id = v.target_id""").fetchall()]
    access = [dict(r) for r in conn.execute(
        """SELECT a.id, a.username, a.access_type, a.privilege, a.active,
                  t.ip AS target_ip, t.hostname AS target_hostname
           FROM access a LEFT JOIN targets t ON t.id = a.target_id""").fetchall()]
    targets = {r["ip"]: r["hostname"] for r in conn.execute(
        "SELECT ip, hostname FROM targets").fetchall()}
    conn.close()
    return vulns, access, targets


def _load_objectives():
    if not _OBJECTIVES.exists():
        return []
    try:
        return (json.loads(_OBJECTIVES.read_text()).get("objectives") or [])
    except (OSError, json.JSONDecodeError):
        return []


def _idf(docs: list[list[str]]) -> dict[str, float]:
    """IDF over the universe of signals so common words don't swamp."""
    n = len(docs) or 1
    df: Counter = Counter()
    for d in docs:
        for w in set(d):
            df[w] += 1
    return {w: math.log(1 + n / df_w) for w, df_w in df.items()}


def _score(obj_tokens: list[str], cand_tokens: list[str],
           idf: dict[str, float]) -> float:
    if not obj_tokens or not cand_tokens:
        return 0.0
    obj_set = set(obj_tokens)
    cand_set = set(cand_tokens)
    overlap = obj_set & cand_set
    if not overlap:
        return 0.0
    hit_weight = sum(idf.get(w, 1.0) for w in overlap)
    obj_weight = sum(idf.get(w, 1.0) for w in obj_set) or 1.0
    return min(1.0, hit_weight / obj_weight)


def _candidate_text(c: dict, kind: str) -> str:
    if kind == "vuln":
        return " ".join(str(c.get(k) or "") for k in
                        ("title", "vuln_type", "details", "target_ip",
                         "target_hostname"))
    return " ".join(str(c.get(k) or "") for k in
                    ("username", "access_type", "target_ip",
                     "target_hostname"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--threshold", type=float, default=0.35,
                    help="min overlap score to propose (0.0-1.0, default 0.35)")
    ap.add_argument("--limit", type=int, default=10,
                    help="max proposals per objective (default 10)")
    ap.add_argument("--include-done", action="store_true",
                    help="also propose updates for already-done objectives")
    args = ap.parse_args()

    objectives = _load_objectives()
    if not objectives:
        print("No engagement/objectives.json found. Run init_objectives first.",
              file=sys.stderr)
        return 2
    vulns, access, targets = _load_db()
    if not vulns and not access:
        print("state.db is empty — nothing to match against.", file=sys.stderr)
        return 2

    # Build IDF from all candidate texts.
    docs = [_tokens(_candidate_text(v, "vuln")) for v in vulns] + \
           [_tokens(_candidate_text(a, "access")) for a in access]
    idf = _idf(docs)

    proposals = []
    for obj in objectives:
        if obj.get("status") == "done" and not args.include_done:
            continue
        text = obj.get("text") or ""
        obj_tokens = _tokens(text)
        # Verbatim-IP / verbatim-hostname / verbatim-CVE boost
        obj_ips = set(_IP_RE.findall(text))
        obj_cves = {c.upper().replace("CVE", "CVE-").replace("--", "-")
                    for c in _CVE_RE.findall(text)}
        obj_hostnames = {h.lower() for h in targets.values() if h and h.lower() in text.lower()}

        for kind, items in (("vuln", vulns), ("access", access)):
            for c in items:
                score = _score(obj_tokens, _tokens(_candidate_text(c, kind)), idf)
                ctext_lower = _candidate_text(c, kind).lower()
                if c.get("target_ip") in obj_ips:
                    score = max(score, 0.9)
                for cve in obj_cves:
                    if cve.lower() in ctext_lower:
                        score = max(score, 0.9)
                for hn in obj_hostnames:
                    if hn in ctext_lower:
                        score = max(score, max(score, 0.6))
                if score < args.threshold:
                    continue
                proposals.append({
                    "obj_id": obj["id"],
                    "obj_text": text,
                    "obj_status_current": obj.get("status", "pending"),
                    "kind": kind, "cand_id": c["id"],
                    "cand_summary": (c.get("title") if kind == "vuln"
                                     else f"{c.get('username')}@{c.get('target_ip')} ({c.get('access_type')})"),
                    "cand_target": c.get("target_ip") or "",
                    "cand_status": c.get("status") if kind == "vuln" else ("active" if c.get("active") else "lost"),
                    "proposed_status": "done" if (kind == "vuln" and c.get("status") == "actioned")
                                       or (kind == "access" and c.get("active"))
                                       else "in_progress",
                    "score": round(score, 2),
                })

    if not proposals:
        print("No proposals above threshold. Try --threshold 0.25.")
        return 0

    # Keep best N per objective; sort by score desc.
    by_obj: dict = {}
    for p in proposals:
        by_obj.setdefault(p["obj_id"], []).append(p)
    for lst in by_obj.values():
        lst.sort(key=lambda x: x["score"], reverse=True)

    print("# Proposed objective updates (operator / lead must confirm)")
    print("")
    print("| Obj | Current | Proposed | Score | Evidence")
    print("|-----|---------|----------|-------|---------")
    for obj_id in sorted(by_obj):
        for p in by_obj[obj_id][: args.limit]:
            evidence = f"{p['kind']}#{p['cand_id']}  {p['cand_summary'][:60]}"
            if p["cand_target"]:
                evidence += f"  [{p['cand_target']}]"
            print(f"| #{p['obj_id']} | {p['obj_status_current']} | "
                  f"**{p['proposed_status']}** | {p['score']:.2f} | {evidence}")
    print("")
    print("For each row you accept, send scribe/state-mgr:")
    print("  mcp__state__update_objective objective_id=<N> "
          "status=<proposed> note=\"<vuln #id / access #id>\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
