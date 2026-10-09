"""Tests for the start_process target-host extraction + scope check.

shell-server pattern-matches common CLI shapes (ssh / scp / impacket /
evil-winrm / nxc) and runs each extracted host through check_scope so
a rogue `[setup-process]` can't quietly connect to an out-of-scope
target. Unparseable commands fall through to operator approval — this
is defense in depth, not a replacement for the permission prompt.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scope import ScopeError, check_scope  # noqa: E402
from server import _extract_targets  # noqa: E402


class TestExtractTargets:
    def test_ssh_user_at_host(self):
        assert _extract_targets("ssh user@10.1.1.5") == ["10.1.1.5"]

    def test_ssh_with_flags(self):
        cmd = "ssh -i /tmp/key -o StrictHostKeyChecking=no admin@10.1.1.5 bash -i"
        assert _extract_targets(cmd) == ["10.1.1.5"]

    def test_scp_user_at_host(self):
        assert _extract_targets("scp local.txt user@target.htb:/tmp/") == ["target.htb"]

    def test_impacket_psexec(self):
        cmd = "impacket-psexec Administrator:Password123@10.10.10.5"
        assert _extract_targets(cmd) == ["10.10.10.5"]

    def test_impacket_wmiexec_with_hash(self):
        cmd = "impacket-wmiexec DOMAIN/user@dc01.lab.local -hashes :NTHASH"
        assert _extract_targets(cmd) == ["dc01.lab.local"]

    def test_evil_winrm_dash_i(self):
        cmd = "evil-winrm -i 10.10.10.5 -u admin -p 'P@ss'"
        assert _extract_targets(cmd) == ["10.10.10.5"]

    def test_nxc_smb(self):
        cmd = "nxc smb 10.10.10.5 -u admin -p pass"
        assert _extract_targets(cmd) == ["10.10.10.5"]

    def test_localhost_filtered(self):
        assert _extract_targets("ssh user@127.0.0.1") == []
        assert _extract_targets("ssh user@localhost") == []

    def test_unparseable_command(self):
        # msfconsole with no target — nothing to extract, operator-
        # approval remains the gate.
        assert _extract_targets("msfconsole -q") == []

    def test_distinct_hosts(self):
        # Deduplication within a single command
        cmd = "ssh user@10.1.1.5 'ssh user@10.1.1.5 bash'"
        assert _extract_targets(cmd) == ["10.1.1.5"]


class TestScopeIntegration:
    """End-to-end: extract from a command, check scope.allow."""

    def _engagement(self, tmp_path: Path, allow: str) -> Path:
        (tmp_path / "engagement").mkdir()
        (tmp_path / "engagement" / "scope.allow").write_text(allow)
        return tmp_path

    def test_in_scope_passes(self, tmp_path):
        root = self._engagement(tmp_path, "10.10.10.0/24\n")
        for host in _extract_targets("ssh user@10.10.10.5"):
            check_scope(host, root)  # no raise

    def test_out_of_scope_raises(self, tmp_path):
        root = self._engagement(tmp_path, "10.10.10.0/24\n")
        with pytest.raises(ScopeError):
            for host in _extract_targets("evil-winrm -i 192.168.1.99 -u a -p b"):
                check_scope(host, root)

    def test_hostname_wildcard(self, tmp_path):
        root = self._engagement(tmp_path, "*.lab.local\n")
        for host in _extract_targets("impacket-wmiexec DOMAIN/u@dc01.lab.local"):
            check_scope(host, root)  # no raise
        with pytest.raises(ScopeError):
            for host in _extract_targets("impacket-wmiexec DOMAIN/u@dc01.evil.com"):
                check_scope(host, root)
