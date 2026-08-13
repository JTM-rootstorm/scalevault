# ADR 0031: Private observability and operator audit

- Status: Accepted
- Date: 2026-08-12
- Supersedes: None
- Extends: ADR 0005, ADR 0018, ADR 0023, and ADR 0024
- Amended by: ADR 0033

## Context

ScaleVault needs backup, WAL, archive, queue, ingress, credential, recovery, and
hard-forget visibility. Raw identities or payload-bearing labels would turn
Prometheus and alert history into a second private data store. Exposing an
operator route through the Codex ingress would also broaden an intentionally
MCP-only boundary.

Aggregate collectors still need enough database access to describe work, while
identity-specific diagnosis belongs in a more protected local interface.

## Decision

### Topology and registry ownership

Prometheus exposition is available only on the canonical loopback API or on a
dedicated private monitoring listener restricted by host firewall to an exact
operator-controlled scraper. It is never added to the Codex ingress, Secure MCP
Tunnel, NPM ScaleVault virtual host, or a public route. Alertmanager and its
history use the same loopback/private monitoring boundary.

The application owns one explicit ScaleVault `CollectorRegistry`. Libraries
must not register ScaleVault collectors implicitly in the process-global
registry. Every metric name, type, help string, histogram bucket, label name,
and label value is declared in one reviewed contract and tested for duplicate
registration.

Labels have closed allowlists and fixed low-cardinality values. Raw or hashed
tenant, actor, client, credential, memory, subject, ingress, request,
repository, hostname, IP address, path, error text, provider value, or other
user-controlled data is forbidden as a label. Each family permits at most 256
label combinations and the complete ScaleVault registry at most 4,096 active
label combinations. Histogram buckets are fixed and reviewed; their generated
series are included in a separate 16,384-series process ceiling. Exceeding or
attempting an undeclared value fails instrumentation closed rather than
creating a time series.

Required aggregate families cover MCP profile/tool outcomes and duration,
authentication and ingress rejection categories, write/retry outcomes,
retrieval, database pool state, bounded queue state and oldest age, archive
lag/verification, optional GitHub ingress, credential expiry buckets, base
backup/WAL/offsite-copy state, recovery drills, service exits, projection
consistency, public-exposure probes, hard-forget work, and bounded storage
classes. They contain no statements, envelopes, evidence, proposal bodies,
authorization values, key references, database URLs, or private coordinates.

### Payload-blind collection and protected reports

Database-backed Prometheus collection uses a dedicated `NOLOGIN`, `NOINHERIT`
role with no table or sequence privileges. It receives `EXECUTE` only on
reviewed fixed-shape `SECURITY DEFINER` aggregate functions. Those functions
set an exact safe `search_path`, accept no arbitrary SQL, return only bounded
enumerations and numbers, and select explicit non-payload columns. `PUBLIC`
execute is revoked. Tests prove the role cannot select memory statements,
sealed envelopes, evidence, proposal or outbox bodies, credential verifiers,
content-key references, or arbitrary tenant rows.

Adding that role and those functions follows normal migration, RLS, downgrade,
and security review. ScaleVault does not add an observability database or copy
operational rows into a telemetry store.

Identity-specific audit is available only through a root-local CLI over an
explicit tenant scope. It uses a separate operator authorization boundary,
selects an allowlist of metadata columns, enforces row and output limits, and
does not display bodies, evidence, envelopes, verifiers, keys, or provider
responses. Reports may cover actor/client counts over time, conflicts,
high-sensitivity metadata, public-seed candidacy without promotion, lifecycle
state, branch divergence metadata, credential expiry, queues, backup/recovery,
and consistency. There is no `/admin/status` or remote report API. Report files
are root-owned, mode restricted, and created only at an explicit root-local
destination.

### Logs, failures, and retention

Production logs use a closed event-name and bounded error-code vocabulary.
Unexpected tracebacks, SQL diagnostics, Git stderr, provider response bodies,
access authorization, and request/response bodies are replaced at the logging
boundary by a fixed code and a random content-free recovery identifier. Debug
mode does not weaken production units. Secret-bearing services disable core
dumps. Log forwarding is a separate disclosure decision and is off by default.

ScaleVault service journals, PostgreSQL logs, tunnel JSON journals, NPM error
and container logs, and monitoring/alert history have a maximum 30-day
retention. Each also requires an operator-selected byte quota at activation;
the earlier age or capacity bound wins. Content-free backup verification,
restore, recovery-drill, and acceptance reports may be retained for 400 days,
also under an explicit byte quota and root-only access. Holds are explicit and
time bounded. No retention class permits payload or credential logging.

### Alerts and external detection

Checked-in rules and behavioral tests use these default thresholds:

- any backup/verification failure, archive signature or divergence failure,
  projection inconsistency, hard-forget terminal failure, or unauthorized
  public-exposure/backend observation alerts immediately;
- unarchived WAL age warns at 10 minutes and is critical at 15 minutes;
- absence of a verified daily base backup is critical at 26 hours;
- a changed accepted archive head without a verified encrypted secondary copy
  warns at one hour;
- archive or runnable-job oldest age warns at 15 minutes and is critical at one
  hour, with hard-forget terminal jobs critical immediately;
- PostgreSQL pool saturation sustained above 80 percent warns and above 90
  percent is critical; storage below 20 percent free warns and below 10 percent
  is critical;
- a required tunnel disconnected for five minutes warns and for 15 minutes is
  critical;
- direct credentials at 30 days to expiry warn and at seven days are critical;
- a monthly PITR drill is overdue at 35 days and a quarterly full recovery
  drill at 100 days; and
- when GitHub ingress is enabled, successful-poll age warns at twice and is
  critical at four times its configured interval, while authentication failure
  alerts immediately.

Authorization-failure and quarantine-spike rules require bounded count/window
values selected during activation from synthetic baseline tests; they may not
label or include the triggering identity. Alert delivery failures are locally
visible and do not stop the Memory Node. The alert receiver and its data-
handling policy are required operator activation inputs, not repository
defaults.

Public-exposure detection runs from an operator-selected vantage point outside
the approved LAN/VPN source policy and correlates fixed edge results with a
content-free backend connection observer. The vantage, receiver, private
addresses, and access credentials are required activation inputs. A repository
or same-LAN probe cannot substitute for that external proof.

## Consequences

- Prometheus and alerting remain operational summaries rather than a shadow
  memory or identity database.
- Aggregate collection requires a reviewed migration and narrowly privileged
  functions; until then, collectors requiring database state remain disabled.
- Detailed identity diagnosis requires local root authority and leaves a
  bounded protected artifact.
- Monitoring can detect public exposure only with an independently placed live
  probe; installed configuration and unit tests remain necessary but
  insufficient evidence.
