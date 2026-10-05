#!/usr/bin/env bash
# tools/shell-server/mcp-call.sh — thin shim for calling a shell-server MCP
# tool from a shell script and getting its JSON/text result on stdout.
#
# Used by the generated per-exploit re-trigger scripts in
# engagement/exploits/*.sh so they stay short + readable. Also usable for
# ad-hoc operator-side invocations ("just start a listener on 9001 real quick").
#
# Usage:
#   bash tools/shell-server/mcp-call.sh <tool_name> <json_args>
#   e.g. bash tools/shell-server/mcp-call.sh start_listener '{"port":4444,"label":"web01-sqli"}'
#
# Exit codes:
#   0  tool returned successfully (stdout = text of each content block)
#   1  MCP unreachable or RPC error (stderr says why)
#   2  bad args / uv missing
#
# Env: SHELL_SSE_PORT (default 8022; must match the shell-server start.sh)

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <tool_name> <json_args>" >&2
    exit 2
fi
TOOL="$1"
ARGS_JSON="$2"
PORT="${SHELL_SSE_PORT:-8022}"

if ! command -v uv >/dev/null 2>&1; then
    echo "mcp-call: uv not on PATH — can't talk to the MCP from here" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

TOOL="$TOOL" ARGS_JSON="$ARGS_JSON" MCP_PORT="$PORT" \
    uv run --directory "$HERE" --quiet python - <<'PY' || exit 1
import anyio, json, os, sys
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

async def _call():
    tool = os.environ["TOOL"]
    args = json.loads(os.environ.get("ARGS_JSON") or "{}")
    port = int(os.environ.get("MCP_PORT", "8022"))
    url = f"http://127.0.0.1:{port}/sse"
    async with sse_client(url) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args)
            for c in res.content:
                if hasattr(c, "text"):
                    print(c.text)
try:
    anyio.run(_call)
except Exception as e:
    print(f"mcp-call: {e}", file=sys.stderr)
    sys.exit(1)
PY
