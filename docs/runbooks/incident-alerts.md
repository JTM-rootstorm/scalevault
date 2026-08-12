# Incident and alert response

## Triage

1. Acknowledge the alert without copying annotations into an unprotected
   channel. Record the fixed alert name, severity, state, first-seen time, and
   installation class.
2. Validate it with a second bounded signal: operator report, fixed metric,
   service result, backup sidecar, or sanitized configuration checker.
3. Classify impact: availability, recovery-chain integrity, archive trust,
   credential compromise, public exposure, privacy leakage, destruction-state
   conflict, or resource pressure.
4. Choose the narrowest containment that preserves evidence. Public exposure,
   authorization ambiguity, or payload leakage requires stopping affected
   listeners immediately. Archive faults require stopping the exporter.
   Database durability risk may require the full shutdown sequence.

## Investigation boundary

Query bounded time windows and fixed fields. Never enable HTTP raw/debug logs,
request or response bodies, SQL statement logging, environment dumps, shell
tracing around credentials, core dumps, or support bundles containing private
data. If an existing artifact contains a payload or credential canary, restrict
access, stop further collection, and treat the artifact itself as sensitive.

## Recovery and closure

Apply the relevant runbook, then prove the fault no longer reproduces and the
expected alert resolves. Verify no secondary failure was masked, writers did
not overlap, and recovery/credential/destruction posture remains valid.
Record cleanup, retained evidence location class, notification decisions,
remaining risk, and a follow-up issue reference. Alert clearance alone is not
proof of backup recoverability or restored correctness.
