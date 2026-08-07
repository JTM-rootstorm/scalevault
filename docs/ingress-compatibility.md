# GitHub ingress compatibility

## 2026-08-07 contract snapshot

The private `JTM-rootstorm/scalevault-memory-ingress` repository has changed
substantially since the original ingress capability probe. At commit
`b69f06d339ff`, its current authoring contract is Genesis checkpoint v2 under:

```text
ingress/checkpoints/v2/genesis/<yyyy>/<mm>/<checkpoint-id>.json
```

The repository now separates autobiographical owner, perspective, subjects,
participants, relationship namespaces, shared interactions, and staged
visibility. It also preserves two immutable legacy formats:

```text
ingress/v1/<installation-id>/<yyyy>/<mm>/<proposal-id>.json
ingress/checkpoints/v1/genesis/<yyyy>/<mm>/<checkpoint-id>.json
```

ScaleVault must not assume that the original proposal-v1 importer is sufficient
for the current repository. Before GitHub ingress implementation or deployment
resumes, re-audit the repository's current default-branch commit, README,
`docs/GENESIS_CHECKPOINT_V2.md`, both legacy compatibility documents, and all
applicable JSON Schemas. Pin the reviewed commit in the importer release
evidence.

The importer must preserve original bytes and Git commit provenance, validate
each file against its own versioned contract, and keep every checkpoint staged
and untrusted until an authorized review outcome exists. In particular, it must
not infer participants or relationship identity from `triggered_by`, merge
separate autobiographical owners, expand visibility, or treat Genesis history
as a Continuant runtime's firsthand experience.

This snapshot records a compatibility boundary only. Milestone 2 does not read,
copy, validate, or import the repository's private checkpoint payload files.
