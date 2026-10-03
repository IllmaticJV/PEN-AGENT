#!/usr/bin/env bash
# Start the Metasploit operator console (live session list + interactive
# msfconsole on the engagement's shared msfrpcd).
#
# Usage:
#   bash operator/msf-console/start.sh
#
# For custom options, run the server directly:
#   uv run --directory operator/msf-console python server.py --port 9000

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v uv &>/dev/null; then
    echo "ERROR: uv is required but not found." >&2
    echo "  Install: https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi

exec uv run --directory "$REPO_DIR/operator/msf-console" python server.py "$@"
