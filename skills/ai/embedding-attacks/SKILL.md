---
name: embedding-attacks
description: >
  Attack embeddings and vector databases: embedding inversion to reconstruct
  source text, membership/attribute inference, similarity-based information
  extraction, and direct exploitation of exposed vector stores (Weaviate,
  Qdrant, Milvus, Chroma, pgvector, Pinecone). Use when the target exposes
  embeddings, an embeddings API, similarity search, or a reachable vector DB.
  For poisoning a RAG corpus via documents use rag-exploitation.
keywords:
  - embedding inversion
  - embedding attack
  - vector database attack
  - vec2text
  - membership inference
  - similarity search abuse
  - Weaviate Qdrant Milvus Chroma pgvector Pinecone
  - recover text from embeddings
  - information extraction embeddings
  - vector store exfiltration
  - OSAI AI-300
tools:
  - curl
  - python3
opsec: medium
---

# Attacking Embeddings

You are helping a penetration tester attack the embedding layer of an ML system.
Embeddings are dense vectors that encode text/images and are often treated as
"safe" to store or expose — but they leak their source content. Goals:
reconstruct source text from vectors (inversion), infer membership/attributes,
extract data via similarity search, and loot exposed vector databases. All
testing is under explicit written authorization.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[embedding-attacks] Activated → <target>` to the screen on activation.
- **Evidence** → save recovered text, dumps, and scripts to
  `engagement/evidence/` (e.g., `embedding-inversion-recovered.txt`,
  `vectordb-dump.json`).

## Scope Boundary

This skill covers embeddings and vector stores. If an exposed vector DB also
exposes host/network services, **STOP** and route to ai-infra-exploitation.
If the goal is corpus poisoning via documents, use rag-exploitation. Only act on
in-scope targets (`engagement/scope.allow`).

## State Management

Call `get_state_summary()` to read current engagement state. Report back:
- Embedding surface (API, model, dimensionality; vector DB type/endpoint/auth)
- Source text/data recovered (inversion, extraction)
- Inference results (membership/attributes of known records)
- Vector store access (read/write, collections, exfiltrated content)
- Blocked items (what failed, whether retryable)

## Prerequisites

- An embedding surface (from ai-recon): an embeddings endpoint, similarity
  search that returns vectors/scores, or a reachable vector DB port.
- The embedding model name/family if you can get it (inversion is far easier
  with a matching or known encoder).

## Step 1: Characterize the Embedding Surface

```bash
# OpenAI-compatible embeddings endpoint
curl -s https://TARGET/v1/embeddings -H 'Content-Type: application/json' \
  -d '{"model":"text-embedding-3-small","input":"hello world"}'
```
Record: vector dimensionality, model name, whether identical input is
deterministic (it usually is), and whether the app ever returns raw vectors.

## Step 2: Embedding Inversion (Recover Source Text)

If you can obtain embeddings of unknown source text (returned by the API, stored
in a reachable DB, or in a leaked file), reconstruct the text.

- **Known/black-box encoder → `vec2text`**: train/apply a corrector model that
  iteratively edits a guess to match the target vector. Works best when the
  victim embeddings come from an encoder you can query (query it to build the
  inversion dataset).
- **Nearest-text search**: embed a large candidate corpus with the same model
  and return the texts whose vectors are closest to the target — recovers exact
  or near-exact matches for in-distribution content (PII templates, boilerplate,
  known phrases).

```python
# Nearest-text recovery sketch (same encoder for candidates + targets)
import numpy as np
def cos(a, b): return a @ b / (np.linalg.norm(a) * np.linalg.norm(b))
# targets = victim vectors; cand_vecs/cand_txt = your corpus embedded identically
for t in targets:
    best = max(range(len(cand_vecs)), key=lambda i: cos(t, cand_vecs[i]))
    print(cand_txt[best])
```
Tooling (`vec2text`) requires install — if absent, stop and report the command;
the nearest-text method above needs only numpy + the embeddings API.

## Step 3: Membership & Attribute Inference

- **Membership**: embed a candidate record and check if an (near-)identical
  vector exists in the store (very high similarity ⇒ the record is in the
  corpus). Confirms whether a specific person/document was used.
- **Attribute inference**: compare a target vector's similarity to labeled
  anchor texts ("diagnosis: X", "salary band Y") to infer sensitive attributes
  of the source.

## Step 4: Similarity-Search Information Extraction

If the app exposes similarity search over a private corpus, use it as an oracle:
- Query with sensitive seed phrases and read back the nearest stored items (or
  their scores/snippets/IDs) to enumerate content without ever seeing raw text.
- Binary-search phrasing to extract specific values when only scores are
  returned.

## Step 5: Exposed Vector Database

If ai-recon found a reachable vector DB, hit its API directly (scope-enforced):

```bash
# Weaviate — schema + objects, often unauthenticated
curl -s http://HOST:8080/v1/schema
curl -s "http://HOST:8080/v1/objects?limit=100"
# Qdrant — collections + scroll all points (payloads often hold raw text!)
curl -s http://HOST:6333/collections
curl -s -X POST http://HOST:6333/collections/COLL/points/scroll \
  -H 'Content-Type: application/json' -d '{"limit":100,"with_payload":true}'
# Chroma
curl -s http://HOST:8000/api/v1/collections
```
Vector-DB **payloads frequently store the original text** alongside the vector —
dump them directly. Write access = corpus poisoning (route to rag-exploitation).

## Step N: Exit

STOP and return with: embedding surface details, recovered source text,
inference results, and any vector-DB access (read/write, dumped content).

## Troubleshooting

### Inversion output is garbled
Encoder mismatch. Identify the exact embedding model (Step 1) and use the same
one for candidates; `vec2text` needs the correct base encoder to converge.

### API never returns raw vectors
Pivot to the similarity-search oracle (Step 4) and membership inference, which
need only scores/rankings, or to a directly reachable vector DB (Step 5).

### Vector DB requires an API key
Record the endpoint and return — the lead routes credential discovery, then
re-queues this skill.
