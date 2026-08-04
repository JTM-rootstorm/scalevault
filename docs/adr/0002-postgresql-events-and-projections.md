# ADR 0002: PostgreSQL events and projections

- Status: Accepted
- Date: 2026-08-03

## Context

Durable memory operations require transactional ordering, concurrency control,
auditability, and a reproducible current view. Introducing another semantic
store would divide authority and complicate recovery.

## Decision

PostgreSQL is the semantic source of truth. Durable mutations are represented
in an append-only event log, with current state materialized as projections that
can be rebuilt from those events.

ScaleVault v1 does not use Redis. Queues, coordination state, and projections
that affect semantic behavior remain within the PostgreSQL-backed transaction
model.

## Consequences

- A projection is derived state and must not contain the only copy of a durable
  semantic fact.
- Projection rebuilds must be deterministic from the accepted event sequence.
- Mutations that change events and projections must preserve their transactional
  consistency.
- PostgreSQL availability and recovery are prerequisites for authoritative
  memory operations.
- A future Redis dependency requires a superseding ADR and cannot become a
  semantic authority.
