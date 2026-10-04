#!/usr/bin/env bash
set -euo pipefail

# uninstall.sh — Remove PEN-AGENT skills, agents, and MCP server data
#
# Removes:
# - All PEN-AGENT native skills from ~/.claude/skills/
# - Custom subagents from ~/.claude/agents/
# - ChromaDB index (tools/skill-router/.chromadb/)
# - Python venvs for all MCP servers
# - Docker images (pen-agent-nmap, pen-agent-shell)
# - Playwright browsers
# - Viewer auth token (~/.config/pen-agent/)
#
# Does NOT remove .mcp.json or .claude/settings.json (project config).

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DST="${HOME}/.claude/skills"
AGENTS_DST="${HOME}/.claude/agents"
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

# --- Step 1: Remove native skills ---
echo "Removing native skills..."
count=0
for dir in "${SKILLS_DST}/${PREFIX}-"*/; do
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        echo "  Removed: $(basename "$dir")"
        count=$((count + 1))
    fi
done
echo "  ${count} skill(s) removed"

# --- Step 2: Remove legacy subagents (the subagent orchestrator was removed) ---
echo ""
echo "Removing legacy subagents (if any)..."
agent_count=0
for dest_file in "${AGENTS_DST}"/*-agent.md; do
    [[ -f "$dest_file" || -L "$dest_file" ]] || continue
    rm -f "$dest_file"
    echo "  Removed: $(basename "$dest_file")"
    agent_count=$((agent_count + 1))
done
echo "  ${agent_count} legacy agent(s) removed"

# --- Step 3: Clean up MCP servers ---
echo ""
echo "Cleaning up MCP servers..."
mcp_cleaned=0

# Skill-router
if [[ -d "${MCP_SKILL_ROUTER}/.chromadb" ]]; then
    rm -rf "${MCP_SKILL_ROUTER}/.chromadb"
    echo "  Removed ChromaDB index"
    mcp_cleaned=$((mcp_cleaned + 1))
fi
# skill-router runs as a shared SSE daemon — stop it before removing its venv.
pkill -f "tools/skill-router/.*server.py" 2>/dev/null && echo "  Stopped skill-router MCP" || true
if [[ -d "${MCP_SKILL_ROUTER}/.venv" ]]; then
    rm -rf "${MCP_SKILL_ROUTER}/.venv"
    echo "  Removed skill-router venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# nmap-server
if [[ -d "${MCP_NMAP_SERVER}/.venv" ]]; then
    rm -rf "${MCP_NMAP_SERVER}/.venv"
    echo "  Removed nmap-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# Docker images
for img in pen-agent-nmap:latest pen-agent-shell:latest; do
    if command -v docker &>/dev/null && docker image inspect "$img" &>/dev/null 2>&1; then
        docker rmi "$img" &>/dev/null
        echo "  Removed Docker image: ${img}"
        mcp_cleaned=$((mcp_cleaned + 1))
    fi
done

# shell-server
if [[ -d "${MCP_SHELL_SERVER}/.venv" ]]; then
    rm -rf "${MCP_SHELL_SERVER}/.venv"
    echo "  Removed shell-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# state-server
if [[ -d "${MCP_STATE_SERVER}/.venv" ]]; then
    rm -rf "${MCP_STATE_SERVER}/.venv"
    echo "  Removed state-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# browser-server
if [[ -d "${MCP_BROWSER_SERVER}/.venv" ]]; then
    rm -rf "${MCP_BROWSER_SERVER}/.venv"
    echo "  Removed browser-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# rdp-server
if [[ -d "${MCP_RDP_SERVER}/.venv" ]]; then
    rm -rf "${MCP_RDP_SERVER}/.venv"
    echo "  Removed rdp-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# metasploit-server (stop msfrpcd + MCP, remove venv)
pkill -f "tools/metasploit-server/.*server.py" 2>/dev/null && echo "  Stopped metasploit-server MCP" || true
pkill -f "msfrpcd" 2>/dev/null && echo "  Stopped msfrpcd" || true
if [[ -d "${MCP_METASPLOIT_SERVER}/.venv" ]]; then
    rm -rf "${MCP_METASPLOIT_SERVER}/.venv"
    echo "  Removed metasploit-server venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# reporter
if [[ -d "${REPORTER_DIR}/.venv" ]]; then
    rm -rf "${REPORTER_DIR}/.venv"
    echo "  Removed reporter venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# msf-console (operator web console)
pkill -f "operator/msf-console/.*server.py" 2>/dev/null && echo "  Stopped msf-console" || true
if [[ -d "${MSF_CONSOLE_DIR}/.venv" ]]; then
    rm -rf "${MSF_CONSOLE_DIR}/.venv"
    echo "  Removed msf-console venv"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

# Playwright browsers
if command -v playwright &>/dev/null; then
    playwright uninstall chromium &>/dev/null 2>&1 && echo "  Removed Playwright Chromium" && mcp_cleaned=$((mcp_cleaned + 1))
fi

# Viewer auth token
if [[ -d "${HOME}/.config/pen-agent" ]]; then
    rm -rf "${HOME}/.config/pen-agent"
    echo "  Removed viewer config (~/.config/pen-agent/)"
    mcp_cleaned=$((mcp_cleaned + 1))
fi

if [[ "$mcp_cleaned" -eq 0 ]]; then
    echo "  Nothing to clean up"
fi

echo ""
echo "Uninstall complete."
