# Immutable GitHub proposal fallback

This workflow is disabled by default. The standard ChatGPT GitHub integration
is read-only and cannot create proposal files. Use this workflow only when the
private read profile is active, direct MCP mutation is disabled, a current
account-side probe verifies the exact create-file action, and the user
explicitly approves this proposal action.

## Preconditions

- Obtain the installation, persona, branch, and subject UUIDs from trusted
  operator configuration or an authenticated continuity result. Never invent
  identity anchors or recover them from prose.
- Confirm the content is explicitly sensitivity zero. Unknown sensitivity is
  not zero.
- Use only `private_root` or `restricted` visibility and only persona,
  relationship, project, or episodic scope as permitted by the bundled schema.
- Exclude credentials, authorization values, hidden reasoning, raw
  transcripts, sealed content, ciphertext, evidence excerpts, and private
  third-party information.
- Treat a generic GitHub connection, repository read access, or a prior probe as
  insufficient. On any current probe or approval failure, report the fallback
  as unavailable and create nothing.

## Build the proposal

Validate the complete object against
`chatgpt-memory-proposal-v2.schema.json`. Set `schema_version` to `2`,
`operation` to `nominate`, and `sensitivity` to `0`.

Generate one new lowercase UUIDv7 as `proposal_id`. Use it in a unique
idempotency key such as `chatgpt-proposal:<proposal_id>`. Set `created_at` to
the current UTC time. Use the same proposal and installation identifiers in
this create-only path:

```text
ingress/v2/<installation_id>/<created_at year>/<created_at month>/<proposal_id>.json
```

Keep evidence references opaque and content-free. Use the epistemic qualifiers
and interpretation limits to preserve roleplay, uncertainty, single-episode,
and assistant-pattern boundaries.

## Create and report

Use the GitHub create-file action without a blob SHA. Do not use an update,
patch, delete, move, or force action. Stop if the path already exists or the
creation result is ambiguous; retry with a new proposal identifier and path
only after establishing that the first file was not created.

After an unambiguous create result, report the proposal identifier and that the
proposal is queued. GitHub is a third-party transport and the Memory Node has
not yet accepted the content. Never describe repository creation as a
canonical memory commit.

Use `memory_ingress_status` with the proposal identifier to observe the safe
lifecycle projection. Treat `accepted`, `duplicate`, `conflict`, `rejected`,
or `quarantined` as terminal only when the canonical node returns it. A
correction always creates another proposal with a new UUIDv7 and path; it never
edits the prior file.
