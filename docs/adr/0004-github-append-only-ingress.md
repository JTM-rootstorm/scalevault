# ADR 0004: GitHub append-only ingress

- Status: Accepted
- Date: 2026-08-03

## Context

Some clients may need to submit memory proposals through GitHub.com when direct
mutation is unavailable. GitHub is outside the private canonical system and
must not become a mutable copy of memory state or be confused with the Forgejo
archive.

## Decision

GitHub.com ingress is transport-only and append-only. A submission creates a
new immutable proposal object. The canonical Memory Node evaluates that
proposal through the same policy and domain command path used by other
transports.

GitHub.com ingress is neither the semantic source of truth nor the recovery
archive.

## Consequences

- Existing proposal objects are not edited to represent revisions, status, or
  canonical state.
- Ingress processing must tolerate replay without committing a proposal more
  than once.
- Accepting, rejecting, revising, or conflicting a proposal occurs only in the
  canonical Memory Node.
- Proposal content crosses the GitHub.com privacy boundary and must be treated
  as untrusted input.
- The GitHub ingress repository and private Forgejo archive remain separate in
  purpose and credentials.
