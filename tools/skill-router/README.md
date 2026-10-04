# skill-router MCP Server

MCP server providing semantic skill discovery and retrieval for PEN-AGENT
agents. Skills are indexed from structured YAML frontmatter into ChromaDB
with sentence-transformer embeddings, enabling natural language search across
the entire skill library.

## Prerequisites

### Install Python dependencies

```bash
uv sync --directory tools/skill-router
```

This pulls in ChromaDB, sentence-transformers (`all-MiniLM-L6-v2`), and the
MCP SDK. First run will download the embedding model (~80MB).

## Usage

### Index skills

Before the server can serve queries, skills must be indexed:

```bash
uv run --directory tools/skill-router python indexer.py
```

The indexer reads every `skills/<category>/<skill-name>/SKILL.md`, extracts
YAML frontmatter (name, description, keywords, tools, opsec), and upserts into
a ChromaDB collection at `tools/skill-router/.chromadb/`. Stale entries (deleted
skills) are automatically cleaned up.

Re-run the indexer after adding, removing, or modifying skills.

### Start the server

skill-router runs as a **persistent SSE daemon** (not a per-session stdio
server), because it loads a sentence-transformer embedding model + ChromaDB
on startup — too slow to re-pay in every spawned agent-team teammate. One
shared instance means the model loads once and the lead plus every teammate
connect to the same warm server by URL (`http://127.0.0.1:8023/sse`,
configurable via `SKILL_ROUTER_SSE_PORT`).

`run.sh` and `install.sh` start it for you via `start.sh` (idempotent — exits
if already listening). To start/test manually:

```bash
bash tools/skill-router/start.sh          # background daemon + readiness wait
# or, foreground for debugging:
uv run --directory tools/skill-router python server.py
```

## Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| `search_skills` | `query` (required), `n` (default 5), `category` (optional), `min_similarity` (default 0.4) | Semantic search across all indexed skills |
| `get_skill` | `name` (required), `section` (optional) | Load a skill by name. Default returns the **core** (methodology + steps + payloads) with the Troubleshooting section omitted to save tokens; `section="troubleshooting"` fetches that on demand (any heading substring works), `section="full"` returns the whole file. Deferred sections are tunable via `SKILL_DEFER_SECTIONS` (comma-separated heading substrings; empty disables deferral). |
| `list_skills` | `category` (optional) | List all available skills, optionally filtered by category |

## How indexing works

The indexer builds one embedding document per skill from structured frontmatter
fields:

- **description**: Provides semantic context for natural language queries
- **keywords**: Exact search terms (technique names, CVE IDs, tool names)
- **tools**: Enables tool-name lookups (e.g., "sqlmap" finds SQL injection skills)
- **opsec**: Included in search results so agents can assess detection risk
- **section headers**: Technique-specific headers added as bonus context

Documents are embedded with `all-MiniLM-L6-v2` (256-token limit). The indexer
caps headers at 15 to stay within the limit.

## Configuration

| CLI Flag | Default | Description |
|----------|---------|-------------|
| `--skills-dir` | `../../skills` (relative to script) | Path to skills directory |
| `--db-dir` | `.chromadb/` (next to script) | Path to ChromaDB data directory |

## Data

ChromaDB data lives at `tools/skill-router/.chromadb/` (gitignored). Delete it
and re-run the indexer to rebuild from scratch.
