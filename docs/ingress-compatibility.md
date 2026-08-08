# GitHub ingress compatibility

## Reviewed contract snapshots

The private `JTM-rootstorm/scalevault-memory-ingress` repository has changed
substantially since the original ingress capability probe. At commit
`b69f06d339ff5ee9052c08f40d6968cf55ee4572`, its authoring contract was
reviewed for compatibility with Genesis checkpoint v2 under:

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
for the current repository.

The first real Genesis import is pinned to the exact immutable source snapshot:

```text
7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9
```

The later authorization checkpoint is:

```text
f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d
```

That later commit is authorization evidence only. It is not part of the first
import source set and must never be enumerated by the first-import adapter.
Import planning and release evidence must retain all three identities: the
historical compatibility snapshot, the exact first-import source snapshot, and
the excluded post-freeze authorization checkpoint.

The importer must preserve original bytes and Git commit provenance, validate
each file against its own versioned contract, and keep every checkpoint staged
and untrusted until an authorized review outcome exists. In particular, it must
not infer participants or relationship identity from `triggered_by`, merge
separate autobiographical owners, expand visibility, or treat Genesis history
as a Continuant runtime's firsthand experience.

The historical `b69f06d...` snapshot records a compatibility boundary only.
The first-import implementation reads and validates only Git objects reachable
from `7dc1cae...`; it must not fetch a mutable default branch as its data source.
