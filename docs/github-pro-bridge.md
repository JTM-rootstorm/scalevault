# GitHub proposal bridge

The optional bridge creates one immutable, size-bounded JSON proposal per path
in a dedicated private GitHub repository. GitHub is a third-party transport,
not the semantic archive. Proposals are untrusted and remain queued until the
canonical node reports acceptance, duplication, conflict, rejection, or
quarantine.

The dedicated private ingress repository has not been selected yet. Clients
must create unique paths without supplying a blob `sha`, accept only GitHub's
`201 Created` response, and never update or delete proposal files. See the
[dated capability probe](capability-probe-2026-08-03.md) for the verified API
contract and pending repository decision.
