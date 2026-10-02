# reporter — OffSec-style findings

Turns PEN-AGENT findings into an **importable, OffSec-style report** where every
finding carries a complete, ordered, **command-by-command reproduction path**
and a **verification oracle**, so a human can independently reproduce and trust
each result.

This is the "Finding contract" layer. The live attack graph stays in `state.db`;
findings are the reviewable, exportable product on top of it.

## How findings are produced

During an engagement, whenever a vulnerability is confirmed (marked `actioned`),
the responsible agent writes **one JSON file per finding** to
`engagement/findings/<id>.json`, conforming to [`finding.schema.json`](finding.schema.json).
See [`examples/finding-prompt-injection.json`](examples/finding-prompt-injection.json)
for a complete, worked example to copy.

The finding MUST include:

- **`steps_to_reproduce`** — the full exploit path, in order. Every command the
  agent actually ran (copy-pasteable), each with `expected_result`,
  `actual_result`, and an `evidence_ref` pointing at the saved raw output. UI /
  chat actions give the literal `payload` instead of a shell command.
- **`verification`** — how success was *proven* independent of the model's
  opinion (an out-of-band callback, an exfiltrated canary, code execution, a
  concrete state change). `status: confirmed` may not use `oracle_type:
  model-judgement`.
- **`placeholders`** — operator-specific values used in commands (e.g.
  `ATTACKBOX` → `10.10.14.5`) so the steps are fully reproducible.
- Severity, impact, affected target(s), remediation, and taxonomy
  (CWE / OWASP LLM Top 10 / MITRE ATLAS / AI-300 module).

## Export

```bash
uv run --directory tools/reporter python export_report.py --engagement engagement
# strict mode fails if any finding is invalid or not independently reproducible:
uv run --directory tools/reporter python export_report.py --strict
```

Outputs:

- `engagement/findings.json` — consolidated, schema-conformant, **importable**.
- `engagement/report.md` — human-readable OffSec-style report.

The exporter validates every finding against the schema, **lints** for
reproducibility (warns when a step has no command/payload, no `expected_result`,
or no `evidence_ref`, or when a "confirmed" verdict rests only on model
judgement), and cross-links each finding to its `state.db` vuln (flagging
severity mismatches). In `--strict` mode any error or warning is a non-zero
exit — use it in CI / pre-report gates so incomplete, non-reproducible findings
never ship.

## Schema

[`finding.schema.json`](finding.schema.json) is JSON Schema (draft 2020-12). The
top-level document is `{ report, summary, findings[] }`; each finding follows
`$defs/finding`. Import `findings.json` into any tool that accepts JSON, or
validate third-party findings against the schema directly.
