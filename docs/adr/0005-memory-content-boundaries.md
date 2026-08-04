# ADR 0005: Memory content boundaries

- Status: Accepted
- Date: 2026-08-03

## Context

Continuity depends on selected durable records, not indiscriminate capture.
Complete conversation transcripts create unnecessary privacy, retention, and
retrieval risk. Hidden model reasoning is not an appropriate persistence
surface and must not be requested or represented as durable memory.

## Decision

ScaleVault does not store raw transcripts by default. Durable records contain
only the selected statements, evidence, provenance, and interpretation context
permitted by memory policy.

ScaleVault never stores hidden reasoning. Inputs represented as private chain of
thought, hidden model reasoning, or equivalent internal reasoning are rejected
rather than converted into memory records.

## Consequences

- Transcript ingestion requires an explicit future policy decision and cannot
  be enabled as a default capture mode.
- Clients and ingress paths must not solicit hidden reasoning for persistence.
- Visible user-supplied rationale or a concise visible summary may be stored
  only when it independently satisfies memory policy.
- Logs, archives, exports, and projections inherit the same content boundary;
  another storage tier is not an exception.
