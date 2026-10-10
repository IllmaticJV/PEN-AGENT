"""Lead-parked indicator — is actionable output sitting unacted?

Read-only, derived entirely from state.db. The portal can't observe the
lead's `AskUserQuestion` directly, but it can see the *symptom* the operator
cares about: actionable findings exist in state yet the engagement has gone
quiet. That is exactly what happens when the lead is parked on a per-task
approval gate (the `manual`/`guided` autonomy tiers) with the operator away,
or otherwise stalled.

"Actionable backlog" mirrors the orchestrator's Decision Logic and the
`tools/monitor/state_audit.py` sweep:
  - un-actioned vulns          (vulns.status = 'found')
  - untested credentials       (no credential_access row)
  - unactioned pivots          (pivot_map.status = 'identified')
  - retryable blocked items    (blocked.retry IN ('later','with_context'))

"Quiet" = seconds since the newest state_events row (the engagement's
heartbeat; state-mgr writes one on every state change).

status:
  working  activity within the quiet threshold — the engagement is moving
  waiting  backlog exists and its oldest item has aged past the threshold,
           but activity is still recent (lead is progressing on another path)
  parked   backlog exists AND the engagement has been quiet past the
           threshold — actionable output is sitting unacted (the alarm case)
  idle     no backlog and quiet — nothing to act on, legitimately waiting

Only `parked` and `waiting` raise the banner; `parked` is the red one.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dash import state

# Matches the orchestrator Stall Sweep's teammate-silence threshold (3 min):
# a backlog that has sat untouched this long is worth surfacing.
QUIET_THRESHOLD_S = 180


def _age_seconds(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (datetime.now(tz=timezone.utc) - dt).total_seconds()


def _category(conn, sql: str) -> tuple[int, float | None, list[str]]:
    """Return (count, oldest_age_seconds, up to 3 sample labels) for a query
    that selects (label, created_at) rows, oldest first."""
    try:
        rows = state.rows(conn, sql)
    except Exception:
        return 0, None, []
    if not rows:
        return 0, None, []
    oldest_age = _age_seconds(rows[0].get("created_at"))
    samples = [str(r.get("label") or "?") for r in rows[:3]]
    return len(rows), oldest_age, samples


def build(db_path: Path) -> dict:
    conn = state.get_db(db_path)
    if conn is None:
        return {"available": False, "reason": "state.db not found yet."}
    try:
        eng = state.rows(conn, "SELECT status FROM engagement LIMIT 1")
        if not eng:
            return {"available": False, "reason": "No engagement initialized yet."}

        cats = []
        n, age, s = _category(conn, """
            SELECT COALESCE(t.ip,'?') || ' — ' || v.title AS label, v.created_at
            FROM vulns v LEFT JOIN targets t ON t.id = v.target_id
            WHERE v.status = 'found' ORDER BY v.created_at""")
        if n:
            cats.append({"kind": "vuln", "label": "un-actioned vulns",
                         "count": n, "oldest_age_s": age, "samples": s})

        n, age, s = _category(conn, """
            SELECT c.username AS label, c.created_at FROM credentials c
            WHERE NOT EXISTS (SELECT 1 FROM credential_access ca
                              WHERE ca.credential_id = c.id)
            ORDER BY c.created_at""")
        if n:
            cats.append({"kind": "credential", "label": "untested credentials",
                         "count": n, "oldest_age_s": age, "samples": s})

        n, age, s = _category(conn, """
            SELECT COALESCE(source,'?') || ' → ' || COALESCE(destination,'?') AS label,
                   created_at FROM pivot_map
            WHERE status = 'identified' ORDER BY created_at""")
        if n:
            cats.append({"kind": "pivot", "label": "unactioned pivots",
                         "count": n, "oldest_age_s": age, "samples": s})

        n, age, s = _category(conn, """
            SELECT technique AS label, created_at FROM blocked
            WHERE retry IN ('later','with_context') ORDER BY created_at""")
        if n:
            cats.append({"kind": "blocked", "label": "retryable blocks",
                         "count": n, "oldest_age_s": age, "samples": s})

        last = state.rows(conn, "SELECT summary, event_type, agent, created_at "
                                "FROM state_events ORDER BY id DESC LIMIT 1")
        last_event = last[0] if last else None
    except Exception:
        return {"available": False, "reason": "state.db not readable."}
    finally:
        conn.close()

    total = sum(c["count"] for c in cats)
    quiet_s = _age_seconds(last_event["created_at"]) if last_event else None
    ages = [c["oldest_age_s"] for c in cats if c["oldest_age_s"] is not None]
    oldest_backlog_age_s = max(ages) if ages else None

    quiet = quiet_s is None or quiet_s >= QUIET_THRESHOLD_S
    aged = oldest_backlog_age_s is not None and oldest_backlog_age_s >= QUIET_THRESHOLD_S

    if total == 0:
        status = "idle" if quiet else "working"
    elif quiet:
        status = "parked"
    elif aged:
        status = "waiting"
    else:
        status = "working"

    return {
        "available": True,
        "status": status,
        "alert": status in ("parked", "waiting"),
        "backlog_total": total,
        "backlog": cats,
        "oldest_backlog_age_s": oldest_backlog_age_s,
        "quiet_seconds": quiet_s,
        "threshold_seconds": QUIET_THRESHOLD_S,
        "last_event": last_event,
    }
