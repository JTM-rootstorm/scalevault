# GitHub proposal bridge

The optional bridge creates one immutable, size-bounded JSON proposal per path
in a dedicated private GitHub repository. GitHub is a third-party transport,
not the semantic archive. Proposals are untrusted and remain queued until the
canonical node reports acceptance, duplication, conflict, rejection, or
quarantine.

The dedicated transport repository is the private
`JTM-rootstorm/scalevault-memory-ingress` repository. Clients must create unique
paths without supplying a blob `sha`, accept only GitHub's `201 Created`
response, and never update or delete proposal files. The connected GitHub app
must be explicitly granted access to this private repository. See the
[dated capability probe](capability-probe-2026-08-03.md) for the verified API,
connected-app creation, and pinned worker-fetch evidence.

The repository's contract has since expanded beyond the original proposal-v1
layout. Genesis checkpoint v2 and immutable checkpoint-v1 compatibility require
a version-aware importer. The first real Genesis import is frozen at exact
commit `7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9`; the later authorization commit
`f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d` is not source input. See
[GitHub ingress compatibility](ingress-compatibility.md). The existing probe and
proposal client do not constitute an implementation of those newer formats.

The fallback pins numeric repository ID `1322346959`. Its provider adapter must
resolve the numeric `/repositories/1322346959` endpoint immediately before
every create or duplicate read and require the exact ID,
`JTM-rootstorm/scalevault-memory-ingress` full name, and `main` default branch.
This prevents a same-name replacement, rename, or transfer from inheriting the
pin. Identity mismatch fails before a create-file `PUT`; no request supplies an
update `sha`.

The separately versioned repository was re-audited at exact commit
`84233835924ade0e3cf26bb995717c880c75ff5c`. It contains no proposal-creator
code and no proposal-v2 schema; ScaleVault's checked-in v2 schema remains the
live contract. This commit is the immutable Git-history bootstrap root for any
later approved worker activation, not authorization to enable the bridge.

ScaleVault's local fallback adapter derives one deterministic path from the
validated proposal bytes and never supplies an update `sha`. HTTP `409` and
`422` are ambiguous create outcomes: the adapter reads that exact path and
accepts only an exact byte match. A provider exception or timeout returns the
payload-free `github_create_ambiguous` code. A caller may retry only the same
proposal bytes, preserving the ingress ID, path, and request body; it must not
mint a replacement proposal identity.

The disabled non-secret deployment contract and remaining activation gates are
documented in [`deploy/github/`](../deploy/github/README.md).
