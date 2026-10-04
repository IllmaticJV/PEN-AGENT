"""MCP server for semantic skill discovery and retrieval in PEN-AGENT.

Provides three tools:
- search_skills: Semantic search across all indexed skills
- get_skill: Load a skill's full SKILL.md content by name
- list_skills: Browse skill inventory by category

Usage:
    uv run python server.py [--skills-dir PATH] [--db-dir PATH]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Suppress HF Hub warnings and telemetry (no need to phone home for local embeddings)
import os
import warnings

logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
warnings.filterwarnings("ignore", message=".*unauthenticated.*")
warnings.filterwarnings("ignore", message=".*UNEXPECTED.*")

import chromadb  # noqa: E402 — must follow warnings.filterwarnings
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "pen-agent-skills"

# Resolve defaults relative to this script
_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_SKILLS_DIR = _SCRIPT_DIR.parent.parent / "skills"
_DEFAULT_DB_DIR = _SCRIPT_DIR / ".chromadb"


# Sections get_skill defers from the default load (fetch on demand with
# section=...). Troubleshooting is only needed when a step actually fails, so
# it's deferred by default to cut per-task tokens. Tune with the env var
# SKILL_DEFER_SECTIONS (comma-separated heading substrings, case-insensitive);
# set it to "" to disable deferral and always return the full skill.
_DEFER_DEFAULT = "troubleshooting"


def _deferred_section_matchers() -> list[str]:
    raw = os.environ.get("SKILL_DEFER_SECTIONS", _DEFER_DEFAULT)
    return [s.strip().lower() for s in raw.split(",") if s.strip()]


def _split_sections(content: str) -> tuple[str, list[tuple[str, str]]]:
    """Split a SKILL.md body into (preamble, [(heading_text, section_text), …]).

    A section runs from a level-2 `## ` heading to the next level-2 heading, so
    `###` subsections stay with their parent. Preamble is everything before the
    first `## `. Pure text slicing — nothing is reflowed.
    """
    lines = content.splitlines(keepends=True)
    starts = [i for i, ln in enumerate(lines) if ln.startswith("## ")]
    if not starts:
        return content, []
    preamble = "".join(lines[: starts[0]])
    sections: list[tuple[str, str]] = []
    for idx, s in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        heading = lines[s][3:].strip()
        sections.append((heading, "".join(lines[s:end])))
    return preamble, sections


def _get_collection(db_dir: Path) -> chromadb.Collection:
    """Get the ChromaDB collection with pinned embedding function."""
    embedding_fn = SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)
    client = chromadb.PersistentClient(path=str(db_dir))
    return client.get_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
    )


def create_server(skills_dir: Path, db_dir: Path) -> FastMCP:
    """Create and configure the MCP server with skill routing tools."""
    sse_port = int(os.environ.get("SKILL_ROUTER_SSE_PORT", "8023"))
    mcp = FastMCP(
        "pen-agent-skill-router",
        host="127.0.0.1",
        port=sse_port,
        instructions=(
            "Provides pentesting skill discovery and retrieval for PEN-AGENT. "
            "Use search_skills to find relevant skills by describing a scenario. "
            "Use get_skill to load a skill's full methodology. "
            "Use list_skills to browse the inventory."
        ),
    )
    collection = _get_collection(db_dir)

    @mcp.tool()
    def search_skills(
        query: str,
        n: int = 5,
        category: str | None = None,
        min_similarity: float = 0.4,
    ) -> str:
        """Search for pentesting skills by describing a scenario or technique.

        Args:
            query: Natural language description of what you need
                   (e.g., "blind SQL injection in a login form",
                   "escalate privileges on Linux with SUID binaries",
                   "Kerberos ticket forging for domain persistence").
            n: Maximum number of results to return (default 5).
            category: Optional filter by category (web, ad, privesc, network).
            min_similarity: Minimum cosine similarity threshold (0.0-1.0).
                           Results below this are excluded. Default 0.4.
        """
        where = {"category": category} if category else None
        results = collection.query(
            query_texts=[query],
            n_results=min(n, 20),
            where=where,
            include=["metadatas", "distances"],
        )

        if not results["ids"][0]:
            return "No matching skills found."

        lines = []
        for id_, metadata, distance in zip(
            results["ids"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            similarity = 1 - distance  # cosine distance → similarity
            if similarity < min_similarity:
                continue
            opsec = metadata.get("opsec", "unknown")
            lines.append(
                f"**{id_}** ({metadata['category']}, opsec: {opsec}) "
                f"[similarity: {similarity:.2f}]\n"
                f"  {metadata['description'][:200]}"
            )

        if not lines:
            return f"No skills found above similarity threshold ({min_similarity})."
        return "\n\n".join(lines)

    @mcp.tool()
    def get_skill(name: str, section: str = "") -> str:
        """Load a pentesting skill's SKILL.md by name.

        By default returns the skill's CORE — full methodology, steps and
        payloads — with long-tail sections (Troubleshooting) omitted to save
        tokens; the response lists what was omitted. If a step fails, fetch the
        rest with section="troubleshooting" (or section="full" for everything).

        Args:
            name: Skill name (e.g., "sql-injection-union", "kerberos-roasting",
                  "linux-sudo-suid-capabilities"). Use search_skills to discover
                  available names.
            section: "" (default) = core; "full" = the entire SKILL.md;
                  otherwise a heading substring (e.g. "troubleshooting") to fetch
                  just that section on demand.
        """
        # Look up the skill path from ChromaDB metadata
        results = collection.get(ids=[name], include=["metadatas"])
        if not results["ids"]:
            # Fuzzy fallback: search by name
            search = collection.query(
                query_texts=[name], n_results=3, include=["metadatas"]
            )
            if search["ids"][0]:
                suggestions = ", ".join(search["ids"][0])
                return (
                    f"Skill '{name}' not found. Did you mean: {suggestions}?\n"
                    f'Use search_skills("{name}") for semantic search.'
                )
            return (
                f"Skill '{name}' not found. Use list_skills() to see available skills."
            )

        metadata = results["metadatas"][0]
        skill_path = Path(metadata["path"])

        if not skill_path.exists():
            # Path from index is stale — try to find it by convention
            skill_path = skills_dir / metadata["category"] / name / "SKILL.md"
            if not skill_path.exists():
                return (
                    f"Skill '{name}' is indexed but SKILL.md not found at "
                    f"{skill_path}. Re-run the indexer."
                )

        content = skill_path.read_text()
        header = (
            f"# SKILL: {name}\n"
            f"**Category**: {metadata['category']}\n"
            f"**Source**: {skill_path}\n\n"
            f"---\n\n"
        )

        want = section.strip().lower()
        if want == "full":
            return header + content

        preamble, sections = _split_sections(content)

        # Specific section requested → return just the matching section(s).
        if want:
            hits = [text for heading, text in sections if want in heading.lower()]
            if hits:
                return header + "".join(hits)
            avail = ", ".join(h for h, _ in sections) or "(none)"
            return (
                f"{header}No section matching '{section}' in skill '{name}'.\n"
                f"Available sections: {avail}\n"
                f'Use get_skill("{name}", section="full") for the whole skill.'
            )

        # Default → core (everything except the deferred sections), plus a note.
        matchers = _deferred_section_matchers()
        core_parts = [preamble]
        deferred: list[str] = []
        for heading, text in sections:
            if matchers and any(m in heading.lower() for m in matchers):
                deferred.append(heading)
            else:
                core_parts.append(text)
        core = "".join(core_parts)
        if deferred:
            names = ", ".join(deferred)
            core += (
                f"\n\n---\n_Omitted to save tokens: **{names}**. "
                f'If a step fails, fetch it with get_skill("{name}", '
                f'section="{deferred[0].lower()}") — or section="full" for everything._\n'
            )
        return header + core

    @mcp.tool()
    def list_skills(category: str | None = None) -> str:
        """List all available pentesting skills, optionally filtered by category.

        Args:
            category: Filter by category (web, ad, privesc, network).
                      Omit to list all skills.
        """
        where = {"category": category} if category else None
        results = collection.get(where=where, include=["metadatas"])

        if not results["ids"]:
            if category:
                return f"No skills found in category '{category}'."
            return "No skills indexed. Run the indexer first."

        # Group by category
        by_category: dict[str, list[dict]] = {}
        for id_, metadata in zip(results["ids"], results["metadatas"]):
            cat = metadata["category"]
            by_category.setdefault(cat, []).append(
                {"name": id_, "description": metadata["description"][:150]}
            )

        lines = []
        for cat in sorted(by_category):
            lines.append(f"## {cat} ({len(by_category[cat])} skills)")
            for skill in sorted(by_category[cat], key=lambda s: s["name"]):
                lines.append(f"- **{skill['name']}**: {skill['description']}")
            lines.append("")

        total = sum(len(v) for v in by_category.values())
        lines.insert(0, f"**{total} skills available**\n")
        return "\n".join(lines)

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="PEN-AGENT skill router MCP server")
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=_DEFAULT_SKILLS_DIR,
        help="Path to skills/ directory",
    )
    parser.add_argument(
        "--db-dir",
        type=Path,
        default=_DEFAULT_DB_DIR,
        help="Path to ChromaDB data directory",
    )
    args = parser.parse_args()

    if not args.db_dir.exists():
        print(
            f"Error: ChromaDB directory not found: {args.db_dir}\n"
            f"Run the indexer first: uv run python indexer.py",
            file=sys.stderr,
        )
        sys.exit(1)

    server = create_server(args.skills_dir, args.db_dir)
    # SSE, not stdio: skill-router loads a sentence-transformer embedding model
    # + ChromaDB (tens of seconds). As a stdio server every spawned agent-team
    # teammate would stand up its OWN copy and re-pay that cost, which is why
    # teammates couldn't resolve its tools in time. Run it once as a shared SSE
    # daemon (like shell-server/metasploit-server) so the lead and every
    # teammate connect to the same warm instance.
    server.run(transport="sse")


if __name__ == "__main__":
    main()
