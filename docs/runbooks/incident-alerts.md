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

The checked-in default thresholds are part of the reviewed contract: WAL age
warns at 10 minutes and is critical at 15; verified-base absence is critical at
26 hours; offsite-head verification at one hour; archive/runnable-job age at
15 minutes/one hour; storage free at 20/10 percent; pool use at 80/90 percent
for five minutes; tunnel disconnect at 5/15 minutes; direct credential expiry
at 30/7 days; PITR/full-drill overdue at 35/100 days; and enabled GitHub polling
at two/four times its configured interval. Missing required telemetry and
scrape failures alert separately. Do not weaken a threshold to clear an alert.

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
