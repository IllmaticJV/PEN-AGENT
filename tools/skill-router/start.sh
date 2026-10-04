#!/usr/bin/env bash
# Start skill-router as a persistent SSE service.
# Idempotent — exits once the server is listening.
#
# skill-router loads a sentence-transformer embedding model + ChromaDB on
# startup, so the SSE port only binds after that load completes (tens of
# seconds on first use). The readiness wait below is therefore much longer
# than shell-server's. Running it once as a shared daemon is the whole point:
# every agent-team teammate connects to this one warm instance instead of
# standing up its own copy and re-paying the model-load cost.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${SKILL_ROUTER_SSE_PORT:-8023}"

# Already listening — nothing to do
if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
    exit 0
fi

# The index must exist (built by install.sh via indexer.py). Without it the
# server exits immediately, so fail fast with a clear message rather than
# waiting out the full timeout.
if [[ ! -d "$REPO_DIR/tools/skill-router/.chromadb" ]]; then
    echo "skill-router: ChromaDB index missing — run: uv run --directory tools/skill-router python indexer.py" >&2
    exit 1
fi

# Start server in background. HF_HUB_OFFLINE=1 preserves the old stdio
# .mcp.json behavior (use the locally-cached embedding model, don't phone
# home at runtime); install.sh's indexer step populates that cache.
HF_HUB_OFFLINE=1 uv run --directory "$REPO_DIR/tools/skill-router" python server.py &>/dev/null &

# Wait until it's actually listening. Model load can take a while on a cold
# cache, so allow up to 90s (180 × 0.5s).
for i in $(seq 1 180); do
    if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
        exit 0
    fi
    sleep 0.5
done

echo "skill-router failed to start on port ${PORT} within 90s" >&2
exit 1
