# Lessons Learned

A persistent, cross-engagement knowledge base. The orchestrator **reads this at
the start of every engagement** and carries relevant lessons into teammate
briefs; the **retrospective appends new lessons at the end** of an engagement
(the lead may also append one mid-engagement when a teammate reports a reusable
gotcha). This is how PEN-AGENT gets better over time instead of relearning the
same things each run.

## What belongs here — and what must NEVER

Lessons must be **generalizable**: tooling flags and quirks, methodology
improvements, environment gotchas, skill gaps, detection/OPSEC notes, and
reusable attack patterns that apply to *future, different* targets.

**Never record target-specific solutions.** No credentials, no "box/app X is
solved by Y", no CTF/lab answers, no host-specific exploit chains, no flags.
Writing those here would (a) leak engagement data across clients and (b)
contaminate future runs — the harness would "succeed" by recall instead of by
method, which invalidates results. Keep per-engagement detail in that
engagement's `state.db` / `findings/`, not here. When in doubt, generalize the
lesson and drop the specifics.

## How to add a lesson

Append an entry under the matching category using this format. Before adding,
scan for an existing entry on the same point and refine it rather than
duplicating.

```
### <short, searchable title>
- **Context:** when this applies (a generalizable trigger, not a target name)
- **Lesson:** what to do / what was learned
- **Added:** YYYY-MM-DD
```

---

## Tooling

_Flags, versions, and quirks of tools on the attackbox._

## Methodology

_Routing, sequencing, and approach improvements._

## Environment

_Attackbox / lab / network gotchas that recur across engagements._

## AI / LLM targets

_Patterns and oracles for AI red teaming that generalize across AI systems._

## Skill gaps

_Missing coverage or weak spots observed, to drive new/updated skills._

## Detection & OPSEC

_What was noisy or got caught, and quieter alternatives._
