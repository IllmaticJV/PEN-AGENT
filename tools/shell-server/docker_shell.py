"""Privileged-Docker shell mode: image config and container lifecycle.

Checks Docker/image availability and reaps orphaned pen-agent-* containers
left by crashed or restarted server processes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

SHELL_DOCKER_IMAGE = os.environ.get("SHELL_DOCKER_IMAGE", "pen-agent-shell:latest")
DOCKER_STAGE_DIR = os.environ.get(
    "SHELL_STAGE_DIR",
    str(_PROJECT_ROOT / "engagement" / "stage"),
)  # Host↔container shared staging


def _check_docker_shell() -> str | None:
    """Check if Docker and the shell image are available. Returns error message or None."""
    docker_path = shutil.which("docker")
    if not docker_path:
        return "docker not found. Install Docker to use privileged mode."

    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return (
                "Docker daemon not running. Start Docker first.\n"
                f"stderr: {result.stderr.strip()}"
            )
    except subprocess.TimeoutExpired:
        return "docker info timed out — Docker daemon may be unresponsive."

    try:
        result = subprocess.run(
            ["docker", "image", "inspect", SHELL_DOCKER_IMAGE],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return (
                f"Docker image '{SHELL_DOCKER_IMAGE}' not found. "
                f"Build it with: docker build -t {SHELL_DOCKER_IMAGE} tools/shell-server/"
            )
    except subprocess.TimeoutExpired:
        return "docker image inspect timed out."

    return None


def _find_orphan_containers() -> list[str]:
    """Find running pen-agent-* Docker containers not tracked by this process."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=pen-agent-", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []
        return [
            name.strip() for name in result.stdout.strip().split("\n") if name.strip()
        ]
    except Exception:
        return []


def _kill_orphan_containers() -> list[str]:
    """Kill orphaned pen-agent-* containers from previous MCP sessions.

    Returns list of container names that were killed.
    """
    orphans = _find_orphan_containers()
    killed = []
    for name in orphans:
        try:
            subprocess.run(
                ["docker", "kill", name],
                capture_output=True,
                timeout=10,
            )
            killed.append(name)
        except Exception:
            pass
    return killed
