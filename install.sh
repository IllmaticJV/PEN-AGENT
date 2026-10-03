#!/usr/bin/env bash
set -euo pipefail

# install.sh — Install PEN-AGENT skill library
#
# Installs the orchestrator as a native Claude Code skill, custom subagents,
# and sets up MCP servers (skill-router, nmap-server, shell-server,
# state-server) for on-demand skill loading, privileged scanning, reverse
# shell management, and SQLite engagement state.
#
# Default: creates symlinks (edits in repo reflect immediately)
# --copy:  copies files (for machines without persistent repo access)
#
# MCP servers always read from the repo, so the repo must stay in place.
#
# Requires: uv (https://docs.astral.sh/uv/)

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

# Progress display for long-running commands
# Spinner — shows elapsed time and rotating indicator
run_with_spin() {
    local label=$1 msg=$2
    shift 2
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0 elapsed=0

    # Disable line wrapping so resizing the terminal doesn't leave ghost text
    tput rmam 2>/dev/null || true
    trap 'tput smam 2>/dev/null || true' RETURN

    "$@" &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  [%s] %s %s (%ds)" "$label" "${chars:i%${#chars}:1}" "$msg" "$elapsed"
        sleep 0.5
        i=$((i + 1))
        elapsed=$((i / 2))
    done
    wait "$pid"
    local rc=$?
    printf "\r  [%s] %s (%ds)\n" "$label" "$msg" "$elapsed"
    return $rc
}

# Run uv sync with native output — just a label header, then let uv talk
run_uv_sync() {
    local label=$1 uv_dir=$2
    echo "  [${label}] Installing dependencies..."
    uv sync --directory "$uv_dir"
}

# Check if Docker image needs rebuild by comparing Dockerfile hash
docker_needs_rebuild() {
    local image=$1 dockerfile=$2
    [[ "$REBUILD_DOCKER" == true ]] && return 0
    ! docker image inspect "$image" &>/dev/null && return 0
    local current_hash stored_hash
    current_hash=$(sha256sum "$dockerfile" | cut -d' ' -f1)
    stored_hash=$(docker inspect --format='{{index .Config.Labels "pen-agent.dockerfile-hash"}}' "$image" 2>/dev/null || echo "")
    [[ "$current_hash" != "$stored_hash" ]]
}

SKILLS_SRC="${REPO_DIR}/skills"
SKILLS_DST="${HOME}/.claude/skills"
PREFIX="pen-agent"
MCP_SKILL_ROUTER="${REPO_DIR}/tools/skill-router"
MCP_NMAP_SERVER="${REPO_DIR}/tools/nmap-server"
MCP_SHELL_SERVER="${REPO_DIR}/tools/shell-server"
MCP_STATE_SERVER="${REPO_DIR}/tools/state-server"
MCP_BROWSER_SERVER="${REPO_DIR}/tools/browser-server"
MCP_RDP_SERVER="${REPO_DIR}/tools/rdp-server"
MCP_METASPLOIT_SERVER="${REPO_DIR}/tools/metasploit-server"
REPORTER_DIR="${REPO_DIR}/tools/reporter"
MSF_CONSOLE_DIR="${REPO_DIR}/operator/msf-console"

# Only the orchestrator is installed as a native Claude Code skill.
# Everything else is served on-demand via the MCP skill-router.
NATIVE_SKILLS=("ctf")

MODE="symlink"
REBUILD_DOCKER=false
for arg in "$@"; do
    case "$arg" in
        --copy) MODE="copy" ;;
        --rebuild) REBUILD_DOCKER=true ;;
    esac
done

mkdir -p "${SKILLS_DST}"

echo ""
echo "This may take 5 minutes or more, depending on your connection speed."
echo ""

# --- Step 1: Install native skills ---
echo "Installing native skills..."
native_count=0
for skill_name in "${NATIVE_SKILLS[@]}"; do
    skill_file="$(find "${SKILLS_SRC}" -path "*/${skill_name}/SKILL.md" -print -quit)"
    if [[ -z "$skill_file" ]]; then
        echo "ERROR: Cannot find SKILL.md for native skill '${skill_name}'" >&2
        exit 1
    fi

    installed_name="${PREFIX}-${skill_name}"
    dest_dir="${SKILLS_DST}/${installed_name}"
    skill_src_dir="$(dirname "$skill_file")"

    mkdir -p "${dest_dir}"

    rm -f "${dest_dir}/SKILL.md"
    if [[ "$MODE" == "symlink" ]]; then
        ln -s "$skill_file" "${dest_dir}/SKILL.md"
    else
        cp "$skill_file" "${dest_dir}/SKILL.md"
    fi

    # Install subdirectories (scripts/, references/, assets/) if they exist
    for subdir in scripts references assets; do
        if [[ -d "${skill_src_dir}/${subdir}" ]]; then
            rm -rf "${dest_dir:?}/${subdir}"
            if [[ "$MODE" == "symlink" ]]; then
                ln -s "${skill_src_dir}/${subdir}" "${dest_dir}/${subdir}"
            else
                cp -r "${skill_src_dir}/${subdir}" "${dest_dir}/${subdir}"
            fi
        fi
    done

    echo "  ${installed_name} -> ${skill_file}"
    native_count=$((native_count + 1))
done

# --- Step 2: Validate native installs ---
for skill_name in "${NATIVE_SKILLS[@]}"; do
    installed="${SKILLS_DST}/${PREFIX}-${skill_name}/SKILL.md"
    if [[ ! -r "$installed" ]]; then
        target="$(readlink -f "$installed" 2>/dev/null || echo "unknown")"
        echo "ERROR: Broken skill: ${installed} -> ${target}" >&2
        exit 1
    fi
done

# --- Step 3: Remove any legacy subagents from a previous install ---
# The subagent orchestrator has been removed; clean up its installed agents.
rm -f "${HOME}/.claude/agents"/*-agent.md 2>/dev/null

# --- Step 4: Set up MCP servers ---
echo ""
echo "Setting up MCP servers..."

if ! command -v uv &>/dev/null; then
    echo "ERROR: uv is required but not found." >&2
    echo "  Install: https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi

# Skill-router (ChromaDB + embeddings)
run_uv_sync "skill-router" "${MCP_SKILL_ROUTER}"

run_with_spin "skill-router" "Indexing skills into ChromaDB..." \
    uv run --directory "${MCP_SKILL_ROUTER}" python indexer.py 2>/dev/null

# nmap-server
run_uv_sync "nmap-server" "${MCP_NMAP_SERVER}"

# Build Docker image for nmap
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    if docker_needs_rebuild pen-agent-nmap:latest "${MCP_NMAP_SERVER}/Dockerfile"; then
        hash=$(sha256sum "${MCP_NMAP_SERVER}/Dockerfile" | cut -d' ' -f1)
        run_with_spin "nmap-server" "Building Docker image..." \
            docker build -t pen-agent-nmap:latest --label "pen-agent.dockerfile-hash=${hash}" "${MCP_NMAP_SERVER}" --quiet
    else
        echo "  [nmap-server] Docker image: up to date"
    fi
else
    echo ""
    echo "  WARNING: Docker required for nmap MCP server but not available."
    echo "  Install Docker and ensure the daemon is running, then re-run install.sh."
    echo ""
fi

# shell-server (TCP listener + reverse shell manager)
run_uv_sync "shell-server" "${MCP_SHELL_SERVER}"

# Build Docker image for shell-server (privileged mode)
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    if docker_needs_rebuild pen-agent-shell:latest "${MCP_SHELL_SERVER}/Dockerfile"; then
        hash=$(sha256sum "${MCP_SHELL_SERVER}/Dockerfile" | cut -d' ' -f1)
        run_with_spin "shell-server" "Building Docker image..." \
            docker build -t pen-agent-shell:latest --label "pen-agent.dockerfile-hash=${hash}" "${MCP_SHELL_SERVER}" --quiet
    else
        echo "  [shell-server] Docker image: up to date"
    fi
else
    echo ""
    echo "  NOTE: Docker image for shell-server (privileged mode) not built."
    echo "  Privileged mode (Responder, mitm6, etc.) requires Docker."
    echo "  Build manually: docker build -t pen-agent-shell:latest tools/shell-server/"
    echo ""
fi

# state-server (SQLite engagement state)
run_uv_sync "state-server" "${MCP_STATE_SERVER}"

# browser-server (headless browser automation)
run_uv_sync "browser-server" "${MCP_BROWSER_SERVER}"
echo "  [browser-server] Installing Chromium..."
uv run --directory "${MCP_BROWSER_SERVER}" playwright install chromium

# rdp-server (headless RDP automation via aardwolf — pure Python, no system deps)
run_uv_sync "rdp-server" "${MCP_RDP_SERVER}"

# metasploit-server (Metasploit RPC wrapper — C2 backend)
if run_uv_sync "metasploit-server" "${MCP_METASPLOIT_SERVER}" 2>/dev/null; then
    echo "  metasploit-server MCP dependencies installed"
    if ! command -v msfrpcd &>/dev/null; then
        echo "  NOTE: metasploit-framework not found — install it for C2 support"
        echo "        (msfconsole, msfvenom, msfrpcd). See docs/installation.md."
    fi
else
    echo "  metasploit-server MCP dependency install failed (check uv/network)"
fi

# reporter (OffSec-style finding schema + exporter — not an MCP server)
if run_uv_sync "reporter" "${REPORTER_DIR}" 2>/dev/null; then
    echo "  reporter dependencies installed (jsonschema)"
else
    echo "  reporter dependency install failed (check uv/network)"
fi

# msf-console (operator web console for the shared msfrpcd — not an MCP server)
if run_uv_sync "msf-console" "${MSF_CONSOLE_DIR}" 2>/dev/null; then
    echo "  msf-console operator dependencies installed"
else
    echo "  msf-console operator dependency install failed (check uv/network)"
fi

# --- Step 5: Verify project config ---
config_warnings=0
if [[ ! -f "${REPO_DIR}/.mcp.json" ]]; then
    echo ""
    echo "WARNING: .mcp.json not found — MCP servers won't auto-start."
    config_warnings=$((config_warnings + 1))
fi

settings_file="${REPO_DIR}/.claude/settings.json"
if [[ -f "$settings_file" ]]; then
    if ! grep -q '"enableAllProjectMcpServers"' "$settings_file"; then
        echo ""
        echo "WARNING: enableAllProjectMcpServers not set in .claude/settings.json"
        config_warnings=$((config_warnings + 1))
    fi
fi

# --- Summary ---
echo ""
echo "Installed ${native_count} native skill(s) to ${SKILLS_DST}/ (${MODE} mode)"
echo "84 technique/discovery skills served via MCP skill-router"
echo "nmap MCP server ready (Dockerized nmap)"
echo "shell MCP server ready (SSE on 127.0.0.1:8022 — shared sessions)"
echo "state MCP server ready (SQLite engagement state)"
echo "browser MCP server ready (headless Chromium)"
echo "rdp MCP server ready (headless RDP via aardwolf)"
if [[ "$config_warnings" -eq 0 ]]; then
    echo ""
    # Restart any running SSE MCP servers to pick up new code
    echo "Restarting SSE MCP servers..."
    if pkill -f "tools/shell-server/.*server.py" 2>/dev/null; then echo "  shell-server: stopped"; fi
    if pkill -f "tools/metasploit-server/.*server.py" 2>/dev/null; then echo "  metasploit-server: stopped"; fi
    sleep 1
    bash "${REPO_DIR}/tools/shell-server/start.sh"
    if ss -tln 2>/dev/null | grep -q ":8022 "; then
        echo "  shell-server: listening"
    else
        echo "  WARNING: shell-server failed to start — run manually:"
        echo "    bash tools/shell-server/start.sh"
    fi
    # Restart metasploit-server if a Metasploit RPC config exists
    if ss -tln 2>/dev/null | grep -q ":${MSF_SSE_PORT:-8024} " || [[ -f "${REPO_DIR}/engagement/msfrpc.yaml" ]]; then
        if bash "${REPO_DIR}/tools/metasploit-server/start.sh" 2>/dev/null; then
            echo "  metasploit-server: listening"
        fi
    fi
    echo ""
    echo "Done! Next steps:"
    echo ""
    echo "  ./config.sh             # optional — configure C2 backend (Metasploit, custom)"
    echo "  ./run.sh                # starts shell-server (+ Metasploit if installed) + Claude Code"
    echo ""
    echo "  config.sh is only needed to pin a C2 backend. Without it, run.sh"
    echo "  auto-starts Metasploit RPC when metasploit-framework is installed,"
    echo "  otherwise PEN-AGENT uses shell-server (raw TCP reverse shells)."
    echo ""
    echo "  Tip: tmux recommended — agent teams spawn multiple long-running"
    echo "  teammates that benefit from persistent terminal sessions."
fi
