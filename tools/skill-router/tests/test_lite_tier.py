"""Tests for the classifier-risk tiered loading in get_skill.

tier="lite" returns the structural scaffolding of a SKILL.md — role,
scope, state, prerequisites, verification oracle, routing — but drops
the attack-variant bodies where classifier-trigger density
concentrates. Teammates load lite first on `classifier_risk: high`
skills and escalate to default (core) or `tier="full"` only when they
actually need to run the technique.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import _is_lite_keeper, _split_sections


class TestIsLiteKeeper:
    def test_keep_scope_boundary(self):
        assert _is_lite_keeper("Scope Boundary")
        assert _is_lite_keeper("Scope Boundaries")

    def test_keep_verification(self):
        assert _is_lite_keeper("Verification Oracle")
        assert _is_lite_keeper("Verification")

    def test_keep_state_mgmt(self):
        assert _is_lite_keeper("State Management")

    def test_keep_prereqs(self):
        assert _is_lite_keeper("Prerequisites")

    def test_keep_engagement_logging(self):
        assert _is_lite_keeper("Engagement Logging")

    def test_keep_post_exit(self):
        assert _is_lite_keeper("Post-Exploitation Exit")
        assert _is_lite_keeper("Post-Attack Exit")

    def test_drop_attack_variants(self):
        assert not _is_lite_keeper("Attack Variants")
        assert not _is_lite_keeper("Variant A — Hydra SSH")

    def test_drop_steps(self):
        assert not _is_lite_keeper("Step 1: Assess")
        assert not _is_lite_keeper("Step 3: Exploit")

    def test_drop_troubleshooting(self):
        assert not _is_lite_keeper("Troubleshooting")

    def test_drop_exploitation(self):
        assert not _is_lite_keeper("Exploitation")

    def test_default_keep_unknown(self):
        # Unknown headings default to keep (safer — authors label the
        # dense ones explicitly via drop patterns).
        assert _is_lite_keeper("Communication")
        assert _is_lite_keeper("AV/EDR Detection")


class TestLiteTierShape:
    """End-to-end on a real high-risk skill — auth-coercion-relay."""

    def test_auth_coercion_relay_lite_shape(self):
        skill = (
            Path(__file__).resolve().parent.parent.parent.parent
            / "skills" / "ad" / "auth-coercion-relay" / "SKILL.md"
        )
        content = skill.read_text()
        _, sections = _split_sections(content)
        kept = [h for h, _ in sections if _is_lite_keeper(h)]
        dropped = [h for h, _ in sections if not _is_lite_keeper(h)]
        # Preamble (always kept) carries the role + hard stops
        assert any("Prerequisites" in h for h in kept)
        assert any("State Management" in h for h in kept)
        # The dense step-by-step bodies should drop
        assert any("Step" in h for h in dropped)
        assert any("Troubleshooting" in h for h in dropped)
