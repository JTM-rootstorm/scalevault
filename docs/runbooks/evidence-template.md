# Content-free operations evidence template

Copy this template to a protected operator evidence store, not into Git. Omit a
field rather than substituting private coordinates, unbounded identifiers, raw
logs, or sensitive values.

```text
record_kind: <backup|recovery|incident|upgrade|verification>
started_at_utc: <RFC3339>
completed_at_utc: <RFC3339-or-pending>
status: <pending|pass|fail|aborted>
operator_reviewed: <yes|no>

source_release: <commit-or-release>
migration_revision: <revision>
installation_class: <canonical|isolated-recovery|validation>
write_boundary: <disabled-and-confirmed|not-applicable|failed>

source_object_id: <bounded-safe-id-or-not-applicable>
source_head_digest: <digest-or-not-applicable>
manifest_digest: <digest-or-not-applicable>
ciphertext_digest: <digest-or-not-applicable>
target_kind: <time|lsn|name|head|not-applicable>
target_value_digest_or_safe_value: <bounded-value>

result_codes: <fixed comma-separated codes>
event_count: <integer-or-not-applicable>
projection_count: <integer-or-not-applicable>
aggregate_digest: <digest-or-not-applicable>
canary_result: <pass|fail|not-run|not-applicable>
credential_posture: <reviewed|reissue-required|not-applicable>
destruction_posture: <reconciled|blocked|not-applicable>
elapsed_seconds: <integer>

cleanup_status: <complete|pending|failed>
remaining_risks: <fixed issue references only>
reviewer: <local operator role, not a private identity>
```

Never include memory statements, evidence, proposal bodies, request or actor
identifiers, authorization values, database URLs, private hostnames or network
coordinates, raw exceptions, decrypted backup content, key bytes, credential
material, or command lines containing them.
