# ADR 0032: Offline public-artifact leakage scanner

- Status: Accepted
- Date: 2026-08-12
- Supersedes: None
- Extends: ADR 0005 and ADR 0017

## Context

Milestone 10 needs a reusable negative gate that detects planted private
canaries and structurally forbidden material in a prospective artifact. Public
selection, redaction, transformation, signing, and publication remain
Milestone 11 work. A scanner that crawls arbitrary paths, accepts unknown
formats, logs matches, or performs publication would cross that boundary and
could itself disclose the content it finds.

## Decision

### Pure bounded interface

The policy core is a pure offline function over an already-materialized map of
normalized relative POSIX path strings to immutable bytes and an explicit
protected canary set. It performs no filesystem access, network access,
environment discovery, database query, MCP operation, signing, mutation, or
publication. It never returns or logs matched bytes, paths, canaries, offsets,
field values, decoded material, or regex excerpts.

The accepted file types are strict UTF-8 `.json`, `.jsonl`, `.md`, and `.txt`.
JSON has no duplicate object keys or non-standard numeric values; JSONL has one
complete JSON value per non-empty line. Paths must already be normalized,
unique, relative POSIX paths with no empty, `.` or `..` component, control
character, backslash, absolute prefix, or normalization collision.

The hard limits are 1,024 files, 8 MiB per file, 64 MiB aggregate bytes, 16 path
components, and 240 UTF-8 bytes per path. Unknown extensions, malformed UTF-8,
malformed structured data, duplicate or colliding paths, and any exceeded limit
reject the complete artifact.

A filesystem adapter, when used, is a separate no-follow materializer. It must
bind one exact root, reject mounts or entries outside it, and reject symlinks,
hard-linked regular files, sockets, devices, FIFOs, directories in the final
map, races, and metadata changes during bounded reading. It never silently
skips an unsupported entry. Canary input is read separately from an explicit
root-owned mode-`0600`, single-link, bounded regular file and is never included
in the candidate artifact.

### Detection contract

For every explicit synthetic/private canary, the scanner checks the exact
UTF-8 form and its Unicode NFC and NFKC normalizations. For the resulting byte
forms it also checks standard and URL-safe Base64 with and without padding,
lowercase and uppercase hexadecimal, and lowercase and uppercase SHA-256
digest text. Empty canaries and canary sets that exceed their own fixed limits
are invalid inputs and fail closed.

The scanner recursively rejects forbidden structured keys, including any
schema spelling or normalized alias representing:

- sealed ciphertext, authentication tag, nonce, AAD or AAD hash;
- content-key identifier, provider name, provider key reference, or destruction
  receipt;
- statement, reason-to-remember, rationale, interpretation limits, evidence
  text, or content-bearing metadata;
- private source, transcript, archive source path, private manifest linkage, or
  canonical event linkage; and
- tenant, actor, client, credential, ingress, deployment, host, repository, or
  other private installation identifier.

It also rejects fixed credential and authorization grammar: authorization
headers and bearer/basic values, private-key PEM blocks, ScaleVault bearer
tokens and verifier strings, common provider/token prefixes, credential-bearing
URLs and database URLs, and high-confidence secret assignment forms. Grammar
matches report only their fixed class.

Textual scanning and structured-key scanning both apply to JSON/JSONL string
values; serialization does not hide a canary. An internal decoding,
normalization, hashing, parser, traversal, memory, or invariant error becomes a
fixed scanner-error rejection. There is no best-effort or warning-only mode.

### Result and reason vocabulary

The result contains only:

- a boolean pass/fail value;
- the deterministic SHA-256 digest of the bounded whole candidate artifact;
  and
- counts keyed by a closed reason-code vocabulary.

Reason classes distinguish invalid input, path/type/size/encoding/structure
rejection, raw/normalized/Base64/hex/digest canary detection, forbidden field,
credential grammar, and internal scanner failure. Counts are bounded and do not
identify which file or value matched. The artifact digest is computed from an
unambiguous length-delimited ordering of normalized path bytes and file bytes;
it is an identity for the scanned candidate, not a disclosure-safe substitute
for authorization or a public signature. When file/tree limits, unsafe
filesystem provenance, or an internal/input failure prevents complete bounded
materialization, the result instead carries one fixed domain-separated
incomplete-artifact sentinel digest. It never returns a digest of a partial
prefix and never omits the digest field.

Positive tests plant synthetic canaries in every representation and forbidden
field class, including intentionally colliding private/public synthetic
records. Negative tests cover every malformed or unsupported input and injected
internal failure. A bounded clean synthetic candidate must pass. Test failures
and reports retain only reason counts and artifact digests; protected canary
fixtures do not enter logs or generated reports.

The scanner exposes no MCP tool and performs no signing or publication.
Milestone 11 must define selection and transformation, then invoke this exact
gate over the exact final bytes it proposes to sign or publish. Passing the M10
synthetic scanner is not public-export acceptance.

## Consequences

- The scanner is deterministic, content-safe, and usable before any public
  publication machinery exists.
- Unknown formats and operational errors sacrifice availability rather than
  risk an incomplete scan.
- Directory safety belongs to a narrow materializer; the core cannot be tricked
  into traversing the host filesystem.
- Future public artifact types, digest forms, or transformation rules require a
  reviewed extension and matching positive controls before use.
