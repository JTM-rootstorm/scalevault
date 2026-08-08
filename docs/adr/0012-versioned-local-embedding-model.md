# ADR 0012: Versioned local embedding model

- Status: Accepted
- Date: 2026-08-08
- Supersedes: None
- Extends: ADR 0002, ADR 0007, ADR 0008, ADR 0009, and ADR 0011

## Context

ADR 0008 deliberately deferred a physical embedding table until a model,
dimension, normalization, and artifact contract were selected. Milestone 4 now
needs asynchronous semantic candidates without making vectors canonical,
coupling model replacement to event replay, downloading executable artifacts at
runtime, or weakening hard-forget behavior.

The model is an English sentence and short-paragraph encoder. Semantic
similarity is one retrieval signal and must not be interpreted as truth,
authority, scope eligibility, or permission.

## Decision

### Initial model contract

Embedding contract `memory-statement-embedding-v1` uses:

| Property | Frozen value |
|---|---|
| Upstream model | `sentence-transformers/all-MiniLM-L6-v2` |
| Upstream revision | `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` |
| License | Apache-2.0 |
| Dimension | 384 |
| Maximum sequence length | 256 wordpieces using the pinned tokenizer configuration |
| Pooling | Mean of token embeddings weighted by the attention mask |
| Normalization | L2 normalization after pooling |
| Distance | Cosine |
| Runtime | Locally pinned ONNX Runtime with an explicitly configured execution provider |
| Physical table | `memory_embeddings_v1` with PostgreSQL `vector(384)` |

The upstream model card documents the 384-dimensional sentence representation,
attention-mask-aware mean pooling, L2 normalization, 256-wordpiece truncation,
and Apache-2.0 license. The pinned revision, rather than a moving model name, is
the upstream source identity.

### Immutable local bundle

Deployment prepares an immutable local bundle containing the ONNX graph,
tokenizer files, model configuration, license, upstream revision, export-tool
versions, ONNX Runtime version, execution-provider configuration, and a manifest
of every file's SHA-256. The SHA-256 of the canonical bundle manifest is stored
as `embedding_models.artifact_sha256`; the remaining identity and runtime values
are recorded in that registry row.

The worker verifies the bundle manifest and every listed file before creating
an inference session. It fails closed on a missing network-share mount, hash
mismatch, unrecorded file, incompatible graph input/output shape, tokenizer
drift, or runtime mismatch. It never downloads, updates, or resolves model
artifacts at runtime. A failed semantic worker leaves lexical and trigram reads
available and reports semantic retrieval as unavailable.

ONNX Runtime's official Python API defines `InferenceSession` as the model-load
and execution boundary and allows execution providers to be selected
explicitly. ScaleVault supplies the verified local graph path and a reviewed
provider list; provider fallback is not allowed to select an unrecorded runtime
path silently.

### Embedding input

The model-facing text is exactly the canonical current memory `statement`. It
does not include reason to remember, evidence, interpretation limits, metadata,
subject labels, retrieval cues, negative cues, raw transcripts, or hidden
reasoning.

Input identity is domain-separated without changing the text sent to the
tokenizer. The SHA-256 input material is:

```text
UTF-8("scalevault.memory.statement.embedding.v1")
0x00
UTF-8(statement)
```

The domain separator and input SHA-256 are stored with the vector. Any future
change to model-facing text or framing requires a new embedding-input version,
backfill, and evaluation; it cannot reinterpret existing rows.

The tokenizer truncates according to the pinned 256-wordpiece configuration.
The worker records a stable truncation flag for diagnostics and evaluation but
does not store discarded text.

### Physical table and eligibility

`memory_embeddings_v1` is tenant-owned and forced through the same row-level
security boundary as other tenant data. Each row binds at least:

- tenant, lineage, branch, memory ID, and source memory revision;
- embedding-model registry ID and input-contract version;
- domain-separated input SHA-256;
- the 384-dimensional normalized vector;
- truncation state and creation timestamp.

Composite foreign keys prevent cross-tenant, cross-lineage, or cross-branch
references. The primary or unique key permits exactly one current derived row
per `(tenant_id, memory_id, embedding_model_id)`. A worker conditionally
replaces that row only when it embeds a newer current source revision and input
hash. The same revision and hash is an idempotent replay, an older revision
cannot overwrite a newer row, and the same revision with a different hash fails
as an integrity error. Historical revision vectors are not retained. The table
stores no statement or evidence text.

A vector is eligible only when its tenant, lineage, exact branch, memory ID,
current revision, active model ID, and recomputed input SHA-256 all match the
eligible current projection. Stale or malformed rows are ignored and queued for
idempotent regeneration. Hard scope, visibility, sensitivity, lifecycle, and
authorization filters execute before vector distance can affect results.

The HNSW operator class and query operator use cosine distance. Index parameters
and search breadth are checked-in retrieval-profile settings and are reported
in evaluation evidence; they do not change vector meaning.

### Asynchronous generation and rebuild

Canonical mutations enqueue IDs-only `embed_memory` work in the transactional
outbox. The worker reloads the authorized current projection, embeds only the
current eligible statement, and conditionally writes the result for that exact
revision. A concurrent revision makes the result stale and schedules or leaves
work for the new revision; it never attaches an old vector to new content.

Embeddings are derived state. Projection replay does not recreate them or call
the model. Backfill and disaster recovery rebuild them asynchronously from the
current projection and the verified local bundle. The canonical event log and
archive contain no vectors.

### Activation and replacement

The registry lifecycle remains `registered`, `evaluating`, `approved`,
`retired`, or `rejected`, with at most one approved, non-retired model per
tenant.

For a replacement:

1. Add a new ADR and physical versioned table when dimension or vector meaning
   changes.
2. Register and verify the immutable bundle.
3. Dual-write new revisions and backfill the candidate table while its model is
   `evaluating`.
4. Run retrieval, scope-leakage, conflict, truncation, latency, and rollback
   evaluations against the active model.
5. In one transaction, retire the old active registry row and approve the new
   row.
6. Route new semantic reads only to the approved model.
7. Retain the old table and bundle for a bounded documented rollback window,
   then remove them through a reviewed cleanup.

Activation never mixes vectors from two models in one result. Rollback is an
explicit registry transition after bundle verification and health checks, not
an automatic fallback. Changing only checked-in retrieval weights follows ADR
0011's profile revision rule; changing model, tokenizer, pooling,
normalization, dimension, or input text requires an embedding contract change.

### Privacy and erasure

Vectors remain sensitive derived data on the controlled network-share mount.
They are not returned directly by MCP tools, exported to Git, sent to a hosted
embedding service, or cached by the relay.

Logical forget makes a vector immediately ineligible. Hard forget and payload
purge remove every vector and queued embedding job for the memory from all
active, evaluating, retained, and rollback tables. Backup and snapshot handling
continues to rely on ADR 0007's cryptographic-erasure boundary.

### Primary references

- [Pinned Sentence Transformers model tree](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/tree/1110a243fdf4706b3f48f1d95db1a4f5529b4d41)
- [Pinned Sentence Transformers model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/README.md)
- [ONNX Runtime Python API](https://onnxruntime.ai/docs/api/python/api_summary)

## Consequences

- Semantic retrieval is reproducible from a pinned, locally verified artifact.
- Model or vector drift cannot silently reinterpret canonical events.
- Exact-revision eligibility prevents stale embeddings from surfacing revised
  or forgotten content.
- English and 256-wordpiece limits remain visible model limitations; lexical
  and trigram channels remain necessary.
- Model replacement costs a versioned table, backfill, evaluation, and explicit
  activation in return for rollback safety and deterministic provenance.
