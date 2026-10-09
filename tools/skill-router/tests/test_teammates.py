"""Lint tests for teammate spawn templates.

Validates required sections, state-mgr message protocol awareness,
via_vuln_id coverage, and scope boundaries. No network or MCP server
required — reads teammate files directly.

Note on compression: CLAUDE.md § State Writes carries the brief
`[add-port]` / `[add-target]` / `[add-vuln]` / `[add-cred]` /
`[add-access]` examples once (every teammate turn gets it), and the
full write contract lives at `tools/state-server/WRITES.md`. These
tests therefore check for PROTOCOL AWARENESS in each teammate (route
through state-mgr, use the structured `[action]` protocol), not
template-level duplication of each `[add-*]` literal.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# --- Paths ---

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
TEAMMATES_DIR = REPO_ROOT / "teammates"

# state-mgr is the protocol receiver, not sender — skip protocol sender checks
STATE_MGR = "state-mgr"

# Infrastructure teammates — don't send target-facing protocol messages;
# they have their own workflow / role.
INFRA = {"shell-mgr", "shell-mgr-metasploit", "shell-mgr-shell-server", "scribe"}

# On-demand teammates have specialized roles — not all protocol actions apply
ON_DEMAND = {"pivot", "bypass", "spray", "recover", "research"}

# Backend appendices inherit scope + context from their parent shell-mgr
APPENDICES = {"shell-mgr-metasploit", "shell-mgr-shell-server"}

# Enum + ops teammates are the core senders of all protocol actions
CORE_TEAMMATES = None  # computed at test time: everything except STATE_MGR, INFRA, and ON_DEMAND


# --- Helpers ---


def _get_teammate_files() -> list[Path]:
    """Return all .md files in teammates/ except README.md."""
    if not TEAMMATES_DIR.exists():
        return []
    return sorted(
        p for p in TEAMMATES_DIR.glob("*.md") if p.name != "README.md"
    )


def _teammate_id(path: Path) -> str:
    return path.stem


# --- Fixtures ---


@pytest.fixture(params=_get_teammate_files(), ids=lambda p: _teammate_id(p))
def teammate_file(request: pytest.FixtureRequest) -> Path:
    return request.param


@pytest.fixture
def teammate_text(teammate_file: Path) -> str:
    return teammate_file.read_text()


# --- Required sections ---


class TestRequiredSections:
    def test_has_workflow_section(self, teammate_file: Path, teammate_text: str):
        """Every teammate needs some workflow section — either its own
        (infrastructure teammates have custom shapes: 'How Messages Work',
        'How It Works', 'Workflow') or the shared one in CLAUDE.md §
        Teammate Protocol (domain teammates). Appendices inherit."""
        if teammate_file.stem in APPENDICES:
            pytest.skip(f"{teammate_file.stem} is a backend appendix (inherits from parent)")
        if teammate_file.stem in INFRA or teammate_file.stem == STATE_MGR:
            # Infrastructure teammates have their own workflow section
            has_section = any(
                h in teammate_text
                for h in (
                    "## How Tasks Work",
                    "## How Messages Work",
                    "## How It Works",
                    "## Workflow",
                )
            )
            assert has_section, (
                f"{teammate_file.stem}: infrastructure teammate missing a "
                f"workflow section (How Tasks Work / How Messages Work / "
                f"How It Works / Workflow)"
            )
            return
        # Domain teammates: workflow is in CLAUDE.md § Teammate Protocol,
        # but the template must point there.
        has_pointer = (
            "CLAUDE.md" in teammate_text
            and "Teammate Protocol" in teammate_text
        )
        assert has_pointer, (
            f"{teammate_file.stem}: domain teammate missing a pointer to "
            f"'CLAUDE.md § Teammate Protocol' (shared workflow lives there)"
        )

    def test_has_communication(self, teammate_file: Path, teammate_text: str):
        if teammate_file.stem in APPENDICES:
            pytest.skip(f"{teammate_file.stem} is a backend appendix")
        if teammate_file.stem == "scribe":
            pytest.skip("scribe's outbound protocol lives in RECORDING.md")
        assert "## Communication" in teammate_text, (
            f"{teammate_file.stem}: missing '## Communication' section"
        )

    def test_has_scope_boundaries(self, teammate_file: Path, teammate_text: str):
        """Accept 'Scope Boundary' or 'Scope Boundaries' (case-insensitive).
        Appendices inherit from parent shell-mgr."""
        if teammate_file.stem in APPENDICES:
            pytest.skip(f"{teammate_file.stem} inherits scope from parent")
        pattern = re.compile(r"^##\s+Scope Boundar(y|ies)\s*$",
                             re.MULTILINE | re.IGNORECASE)
        assert pattern.search(teammate_text), (
            f"{teammate_file.stem}: missing '## Scope Boundary/Boundaries' section"
        )

    def test_has_authorization_preamble(
        self, teammate_file: Path, teammate_text: str
    ):
        """Every spawn template (except appendices + the directory README)
        opens with the 'Engagement context:' authorization preamble —
        lowers classifier-trigger risk at spawn (see knowledge/
        lessons-learned.md)."""
        if teammate_file.stem in APPENDICES:
            pytest.skip(f"{teammate_file.stem} inherits context from parent")
        assert "Engagement context:" in teammate_text, (
            f"{teammate_file.stem}: missing 'Engagement context:' "
            f"authorization preamble (see CONTRIBUTING.md § Teammate "
            f"template authorship)"
        )


# --- State message protocol ---


class TestStateProtocol:
    """Core teammates (enum + ops) must be AWARE of the state-mgr write
    protocol — route all writes through state-mgr via the structured
    `[action]` protocol. The brief `[add-*]` examples themselves live in
    CLAUDE.md § State Writes (loaded into every teammate's turn context);
    the full contract is `tools/state-server/WRITES.md`. These tests
    check awareness, not template-level duplication of each `[add-*]`
    literal.
    """

    def _skip_non_core(self, teammate_file: Path):
        if teammate_file.stem == STATE_MGR:
            pytest.skip("state-mgr defines the protocol, not sends it")
        if teammate_file.stem in INFRA:
            pytest.skip(f"{teammate_file.stem} is infrastructure — custom protocol")
        if teammate_file.stem in ON_DEMAND:
            pytest.skip(f"{teammate_file.stem} is on-demand — protocol subset expected")

    def test_routes_writes_through_state_mgr(
        self, teammate_file: Path, teammate_text: str
    ):
        """Core teammates must message state-mgr for writes (not call
        state tools directly). Check the Communication block mentions
        state-mgr."""
        self._skip_non_core(teammate_file)
        assert "state-mgr" in teammate_text, (
            f"{teammate_file.stem}: no reference to 'state-mgr' — "
            f"writes must route through the dedicated state teammate"
        )
        # Must reference the structured [action] protocol (not raw tool calls)
        has_protocol_pointer = (
            "[action]" in teammate_text
            or "[add-" in teammate_text
            or "[update-" in teammate_text
        )
        assert has_protocol_pointer, (
            f"{teammate_file.stem}: no reference to the structured [action] "
            f"protocol (see CLAUDE.md § State Writes for the brief examples)"
        )


# --- via_vuln_id coverage ---


class TestViaVulnId:
    """When a teammate carries a literal `[add-access]` example in its
    body, that example must include `via_vuln_id` so the engagement
    timeline links access back to the technique that produced it.
    (The canonical example in CLAUDE.md already carries this; this
    test is for any teammate that duplicates it for emphasis.)"""

    def test_add_access_has_via_vuln_id(self, teammate_file: Path, teammate_text: str):
        if teammate_file.stem == STATE_MGR:
            pytest.skip("state-mgr defines the protocol, not sends it")
        # Find all [add-access] lines in the teammate's body and check
        # at least one carries via_vuln_id. Only lint duplicates — if
        # none, the canonical in CLAUDE.md covers it.
        access_lines = [
            line for line in teammate_text.splitlines()
            if "[add-access]" in line and "ip=" in line
        ]
        if not access_lines:
            pytest.skip(
                f"{teammate_file.stem}: no literal [add-access] in body "
                f"— canonical example lives in CLAUDE.md § State Writes"
            )
        has_via_vuln = any("via_vuln_id" in line for line in access_lines)
        assert has_via_vuln, (
            f"{teammate_file.stem}: literal [add-access] example missing "
            f"via_vuln_id (should match the canonical in CLAUDE.md)"
        )


# --- Skill discovery restrictions ---


class TestNoSkillDiscovery:
    """Templates should not call search_skills() or list_skills() except in negative context."""

    def test_no_search_skills_call(self, teammate_file: Path, teammate_text: str):
        lines = teammate_text.splitlines()
        for i, line in enumerate(lines, 1):
            if "search_skills" in line and "search_skills()" not in line:
                continue  # Just a mention, not a call
            if "search_skills()" in line:
                lower = line.lower()
                neg = ("do not", "don't", "never", "not call", "only",
                       "no `search_skills", "no search_skills")
                if not any(n in lower for n in neg):
                    pytest.fail(
                        f"{teammate_file.stem}:{i}: references search_skills() "
                        f"outside negative/restrictive context"
                    )

    def test_no_list_skills_call(self, teammate_file: Path, teammate_text: str):
        lines = teammate_text.splitlines()
        for i, line in enumerate(lines, 1):
            if "list_skills" in line and "list_skills()" not in line:
                continue
            if "list_skills()" in line:
                lower = line.lower()
                neg = ("do not", "don't", "never", "not call", "only",
                       "no `list_skills", "no list_skills")
                if not any(n in lower for n in neg):
                    pytest.fail(
                        f"{teammate_file.stem}:{i}: references list_skills() "
                        f"outside negative/restrictive context"
                    )


# --- state-mgr isolation ---


class TestStateMgrIsolation:
    """state-mgr must not reference target-interaction tools."""

    @pytest.fixture
    def state_mgr_text(self) -> str:
        path = TEAMMATES_DIR / "state-mgr.md"
        if not path.exists():
            pytest.skip("state-mgr.md not found")
        return path.read_text()

    def test_no_shell_server_tool_calls(self, state_mgr_text: str):
        """state-mgr should not contain tool call patterns for target interaction."""
        # These are actual tool invocation patterns, not negative scope mentions
        tool_calls = [
            "send_command(",
            "start_listener(",
            "start_process(",
            "nmap_scan(",
        ]
        for pattern in tool_calls:
            assert pattern not in state_mgr_text, (
                f"state-mgr.md contains tool call '{pattern}' — "
                f"state-mgr must not interact with targets"
            )
