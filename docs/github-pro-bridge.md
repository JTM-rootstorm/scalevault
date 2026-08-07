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
layout. Genesis checkpoint v2 and immutable checkpoint-v1 compatibility now
require a version-aware importer and a fresh review of the default branch. See
[GitHub ingress compatibility](ingress-compatibility.md). The existing probe and
proposal client do not constitute acceptance of those newer formats.
