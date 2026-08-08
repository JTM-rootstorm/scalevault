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
