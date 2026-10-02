#!/usr/bin/env python3
"""Assemble PEN-AGENT findings into an importable OffSec-style report.

Reads per-finding JSON files written by the engagement agents
(engagement/findings/*.json), validates them against finding.schema.json,
cross-links them to state.db, and emits:

  - engagement/findings.json   (importable, schema-conformant report)
  - engagement/report.md       (human-readable OffSec-style report)

Every finding must carry a complete, ordered, command-by-command
`steps_to_reproduce` path and a verification oracle — this exporter LINTS for
that and fails (in --strict) when a finding is not independently reproducible.

Usage:
  python export_report.py [--engagement PATH] [--strict]
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "finding.schema.json"
SCHEMA_VERSION = "1.0"


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def _validator(schema: dict):
    """Return a callable(report_dict) -> list[str] of error messages.

    Uses jsonschema if available; otherwise a minimal structural fallback so
    the exporter still runs on a bare attackbox.
    """
    try:
        from jsonschema import Draft202012Validator

        v = Draft202012Validator(schema)

        def validate(doc):
            return [
                f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
                for e in sorted(v.iter_errors(doc), key=lambda e: list(e.path))
            ]

        return validate, True
    except Exception:
        finding_req = schema["$defs"]["finding"]["required"]

        def validate(doc):
            errs = []
            for i, f in enumerate(doc.get("findings", [])):
                fid = f.get("id", f"#{i}")
                for k in finding_req:
                    if k not in f:
                        errs.append(f"findings/{fid}: missing required '{k}'")
                steps = f.get("steps_to_reproduce", [])
                if not steps:
                    errs.append(f"findings/{fid}: steps_to_reproduce is empty")
            return errs

        return validate, False


def _lint(finding: dict) -> list[str]:
    """Reproducibility / trust lints beyond schema validity (warnings)."""
    w = []
    fid = finding.get("id", "?")
    steps = finding.get("steps_to_reproduce", [])
    concrete = [s for s in steps if s.get("command") or s.get("payload")]
    if not concrete:
        w.append(
            f"{fid}: no step has a 'command' or 'payload' — the exploit path is "
            f"not independently runnable."
        )
    without_expected = [s for s in steps if not s.get("expected_result")]
    if without_expected:
        w.append(f"{fid}: {len(without_expected)} step(s) lack 'expected_result'.")
    ver = finding.get("verification", {})
    if ver.get("status") == "confirmed" and ver.get("oracle_type") == "model-judgement":
        w.append(f"{fid}: 'confirmed' with oracle_type 'model-judgement' — not an objective proof.")
    if not finding.get("evidence"):
        w.append(f"{fid}: no evidence items attached.")
    steps_no_ev = [s for s in steps if not s.get("evidence_ref")]
    if steps_no_ev:
        w.append(f"{fid}: {len(steps_no_ev)} step(s) have no evidence_ref (cannot cross-check against raw logs).")
    return w


def _load_findings(findings_dir: Path) -> list[dict]:
    findings = []
    for p in sorted(findings_dir.glob("*.json")):
        if p.name == "findings.json":
            continue
        try:
            doc = json.loads(p.read_text())
        except json.JSONDecodeError as e:
            print(f"  ! {p.name}: invalid JSON ({e})", file=sys.stderr)
            continue
        # Accept either a bare finding or {"finding": {...}}.
        findings.append(doc.get("finding", doc))
    return findings


def _enrich_from_state(findings: list[dict], db: Path) -> list[str]:
    """Best-effort cross-link to state.db; return mismatch notes."""
    notes = []
    if not db.exists():
        return notes
    try:
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        for f in findings:
            vid = f.get("state_vuln_id")
            if not vid:
                continue
            row = conn.execute(
                "SELECT title, severity, status, evidence_path FROM vulns WHERE id=?",
                (vid,),
            ).fetchone()
            if row is None:
                notes.append(f"{f.get('id')}: state_vuln_id {vid} not found in state.db")
                continue
            if row["severity"] != f.get("severity"):
                notes.append(
                    f"{f.get('id')}: severity '{f.get('severity')}' differs from "
                    f"state.db vuln {vid} '{row['severity']}'"
                )
            f.setdefault("_state", {"status": row["status"], "evidence_path": row["evidence_path"]})
        conn.close()
    except sqlite3.Error as e:
        notes.append(f"state.db read error: {e}")
    return notes


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_report(engagement_name: str, scope: list[str], findings: list[dict]) -> dict:
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "info"), 9))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    return {
        "report": {
            "engagement": engagement_name,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tool": "pen-agent",
            "schema_version": SCHEMA_VERSION,
            "scope": scope,
        },
        "summary": {"total": len(findings), "counts_by_severity": counts},
        "findings": findings,
    }


def _md(report: dict) -> str:
    r, out = report["report"], []
    out.append(f"# Engagement Report — {r['engagement']}\n")
    out.append(f"_Generated {r['generated_at']} by {r['tool']}._\n")
    s = report.get("summary", {})
    if s:
        counts = ", ".join(f"{k}: {v}" for k, v in s.get("counts_by_severity", {}).items())
        out.append(f"**Findings:** {s.get('total', 0)} ({counts})\n")
    if r.get("scope"):
        out.append("**Scope:** " + ", ".join(r["scope"]) + "\n")
    out.append("\n---\n")
    for f in report["findings"]:
        out.append(f"\n## [{f.get('severity','?').upper()}] {f.get('id','?')} — {f.get('title','')}\n")
        cls = f.get("classification", {})
        tags = []
        if cls.get("owasp_llm"): tags += cls["owasp_llm"]
        if cls.get("mitre_atlas"): tags += cls["mitre_atlas"]
        if cls.get("cwe"): tags += cls["cwe"]
        if cls.get("ai300_module"): tags.append(f"AI-300 M{cls['ai300_module']}")
        if tags:
            out.append("**Classification:** " + " · ".join(tags) + "\n")
        cvss = f.get("cvss", {})
        if cvss.get("score") is not None:
            out.append(f"**CVSS {cvss.get('version','')}:** {cvss.get('score')} `{cvss.get('vector','')}`\n")
        ver = f.get("verification", {})
        out.append(f"**Confidence:** {f.get('confidence','?')} · "
                   f"**Verification:** {ver.get('status','?')} via {ver.get('oracle_type','?')}\n")
        if ver.get("oracle"):
            out.append(f"> Oracle: {ver['oracle']}\n")
        # Affected
        tl = []
        for t in f.get("affected", {}).get("targets", []):
            parts = [t.get("host"), (f":{t['port']}" if t.get("port") else None),
                     t.get("url"), t.get("component")]
            tl.append(" ".join(p for p in parts if p))
        if tl:
            out.append("**Affected:** " + "; ".join(tl) + "\n")
        out.append(f"\n**Summary.** {f.get('summary','')}\n")
        out.append(f"\n**Impact.** {f.get('impact','')}\n")
        if f.get("prerequisites"):
            out.append(f"\n**Prerequisites.** {f['prerequisites']}\n")
        if f.get("placeholders"):
            out.append("\n**Placeholders.** " +
                       ", ".join(f"`{k}` = {v}" for k, v in f["placeholders"].items()) + "\n")
        # Steps
        out.append("\n### Steps to Reproduce\n")
        for st in f.get("steps_to_reproduce", []):
            out.append(f"\n**{st.get('step','?')}. {st.get('instruction','')}**")
            if st.get("target"):
                out.append(f"  _(target: {st['target']}, via {st.get('tool','')})_")
            out.append("")
            if st.get("command"):
                out.append("```bash\n" + st["command"] + "\n```")
            if st.get("payload"):
                out.append("Payload:\n```\n" + st["payload"] + "\n```")
            if st.get("expected_result"):
                out.append(f"_Expected:_ {st['expected_result']}")
            if st.get("actual_result"):
                out.append(f"_Observed:_ {st['actual_result']}")
            if st.get("evidence_ref"):
                out.append(f"_Evidence:_ `{st['evidence_ref']}`")
        # Evidence
        if f.get("evidence"):
            out.append("\n### Evidence\n")
            for ev in f["evidence"]:
                out.append(f"- [{ev.get('type','file')}] `{ev.get('path','')}` — {ev.get('description','')}")
        out.append(f"\n### Remediation\n\n{f.get('remediation','')}\n")
        if f.get("references"):
            out.append("### References\n")
            for ref in f["references"]:
                out.append(f"- {ref}")
        out.append("\n---\n")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Export PEN-AGENT findings to OffSec-style report.")
    ap.add_argument("--engagement", default="engagement", help="Engagement directory (default: ./engagement).")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero if any finding is invalid or not reproducible.")
    args = ap.parse_args()

    eng = Path(args.engagement)
    findings_dir = eng / "findings"
    if not findings_dir.is_dir():
        print(f"No findings directory at {findings_dir}. Agents write one JSON per finding there.", file=sys.stderr)
        return 2

    name = eng.name
    scope_file = eng / "scope.allow"
    scope = []
    if scope_file.exists():
        scope = [l.split("#", 1)[0].strip() for l in scope_file.read_text().splitlines()
                 if l.split("#", 1)[0].strip()]

    findings = _load_findings(findings_dir)
    if not findings:
        print("No findings found.", file=sys.stderr)
        return 2

    state_notes = _enrich_from_state(findings, eng / "state.db")
    report = _build_report(name, scope, findings)

    schema = _load_schema()
    validate, used_jsonschema = _validator(schema)
    errors = validate(report)

    warnings = []
    for f in findings:
        warnings += _lint(f)

    # Write outputs (strip internal _state before serializing the public JSON).
    public = json.loads(json.dumps(report))
    for f in public["findings"]:
        f.pop("_state", None)
    (eng / "findings.json").write_text(json.dumps(public, indent=2) + "\n")
    (eng / "report.md").write_text(_md(public))

    print(f"Wrote {eng/'findings.json'} and {eng/'report.md'} ({len(findings)} findings).")
    print(f"Schema validation: {'jsonschema' if used_jsonschema else 'structural-fallback'}")
    for n in state_notes:
        print(f"  state: {n}")
    if errors:
        print(f"\nSCHEMA ERRORS ({len(errors)}):", file=sys.stderr)
        for e in errors:
            print(f"  ✗ {e}", file=sys.stderr)
    if warnings:
        print(f"\nREPRODUCIBILITY WARNINGS ({len(warnings)}):", file=sys.stderr)
        for wmsg in warnings:
            print(f"  ! {wmsg}", file=sys.stderr)
    if not errors and not warnings:
        print("All findings valid and independently reproducible.")

    if args.strict and (errors or warnings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
