# ADR 0003: Forgejo single-writer archive

- Status: Accepted
- Date: 2026-08-03

## Context

ScaleVault exports deterministic recovery material to a private Forgejo
repository. Multiple writers could race, reorder exported ranges, or produce
conflicting archive histories.

## Decision

The Forgejo archive exporter is the only logical writer to the archive
repository. Other services and transports must not create, edit, commit, or
push archive records directly.

Forgejo is an archive and recovery target. It is not the live semantic source of
truth.

## Consequences

- Archive writes must pass through the exporter and its writer-election
  mechanism.
- Direct clients, the Memory Node API, workers other than the exporter, the
  relay, and ingress processing receive no archive write authority.
- Archive output can lag PostgreSQL without becoming a competing current state.
- Recovery procedures must validate archive ordering and integrity before
  replaying records.
