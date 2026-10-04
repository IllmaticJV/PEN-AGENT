#!/usr/bin/env bash
# Start the PEN-AGENT operator portal (objective/scope + live status + MSF logs,
# one tabbed page on http://127.0.0.1:8099).
#
# Usage:
#   bash operator/portal/start.sh
#
# For custom options, run the server directly:
#   uv run --directory operator/portal python server.py --port 9000

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v uv &>/dev/null; then
    echo "ERROR: uv is required but not found." >&2
    echo "  Install: https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi

exec uv run --directory "$REPO_DIR/operator/portal" python server.py "$@"
