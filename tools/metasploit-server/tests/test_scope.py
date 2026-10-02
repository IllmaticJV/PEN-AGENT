"""Tests for the engagement scope guardrail (scope.py)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scope import ScopeError, check_scope  # noqa: E402


def _engagement(tmp_path: Path, allow: str | None) -> Path:
    """Create a project root with (or without) engagement/scope.allow."""
    (tmp_path / "engagement").mkdir()
    if allow is not None:
        (tmp_path / "engagement" / "scope.allow").write_text(allow)
    return tmp_path


def test_no_scope_file_allows_everything(tmp_path):
    root = _engagement(tmp_path, None)
    # No scope.allow -> enforcement off, nothing raises.
    check_scope("10.10.10.5", root)
    check_scope("8.8.8.8", root)
    check_scope("evil.example.com", root)


def test_ip_in_and_out_of_cidr(tmp_path):
    root = _engagement(tmp_path, "10.10.10.0/24\n")
    check_scope("10.10.10.5", root)  # in range
    with pytest.raises(ScopeError):
        check_scope("10.10.11.5", root)  # outside range
    with pytest.raises(ScopeError):
        check_scope("8.8.8.8", root)


def test_single_ip_entry(tmp_path):
    root = _engagement(tmp_path, "10.10.10.5\n192.168.1.0/24\n")
    check_scope("10.10.10.5", root)
    check_scope("192.168.1.77", root)
    with pytest.raises(ScopeError):
        check_scope("10.10.10.6", root)


def test_cidr_target_must_be_subnet(tmp_path):
    root = _engagement(tmp_path, "10.10.10.0/24\n")
    check_scope("10.10.10.0/25", root)  # subnet of allowed /24
    with pytest.raises(ScopeError):
        check_scope("10.10.0.0/16", root)  # broader than allowed


def test_hostname_and_wildcard(tmp_path):
    root = _engagement(tmp_path, "target.htb\n*.corp.local\n")
    check_scope("target.htb", root)
    check_scope("TARGET.HTB", root)  # case-insensitive
    check_scope("dc01.corp.local", root)  # wildcard match
    with pytest.raises(ScopeError):
        check_scope("other.htb", root)
    with pytest.raises(ScopeError):
        check_scope("corp.evil.com", root)


def test_comments_and_blanks_ignored(tmp_path):
    root = _engagement(tmp_path, "# in-scope hosts\n\n10.10.10.5  # the DC\n")
    check_scope("10.10.10.5", root)
    with pytest.raises(ScopeError):
        check_scope("10.10.10.6", root)
