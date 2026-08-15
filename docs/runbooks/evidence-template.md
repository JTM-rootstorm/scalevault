# Content-free operations evidence template

Copy this template to a protected operator evidence store, not into Git. Omit a
field rather than substituting private coordinates, unbounded identifiers, raw
logs, or sensitive values. Repeat `no_prune_inventory_class`,
`credential_class`, `monitoring_fault_family`, and `retention_class` blocks once
for every applicable class; never combine classes into one result.

```text
record_kind: <backup|recovery|incident|upgrade|verification>
started_at_utc: <RFC3339>
completed_at_utc: <RFC3339-or-pending>
status: <pending|pass|fail|aborted>
operator_reviewed: <yes|no>

frozen_release: <commit-or-release>
frozen_release_archive_sha256: <sha256>
evidence_revision: <commit-or-pending>
evidence_revision_scope: <evidence-only|pending>
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
destruction_posture: <reconciled|blocked|not-applicable>
elapsed_seconds: <integer>
rpo_seconds: <integer-or-not-applicable>

forgejo_provider_recovery: excluded-not-evaluated
archive_continuation: excluded-not-evaluated
remote_archive_promotion: excluded-not-evaluated
normal_exporter_append: excluded-not-evaluated
backblaze_provider_evidence: non-blocking-not-evaluated
external_notification_delivery: non-blocking-not-evaluated

bundle_materialization_result: <pass|fail|pending>
bundle_clean_database_restore_result: <pass|fail|pending>
bundle_same_anchor_result: <pass|fail|pending>
bundle_negative_cases_result: <pass|fail|pending>
bundle_cleanup_result: <pass|fail|pending>

no_prune_expected_result: no_prune_dependency_watermark_absent
no_prune_actual_result: <no_prune_dependency_watermark_absent|pending|fail>
no_prune_deletion_attempt_count: <integer-or-pending>
no_prune_restore_points_and_holds_unchanged: <pass|fail|pending>
no_prune_capacity_result: <pass|fail|pending>
no_prune_inventory_class:
  class_name: <base|wal-history|restore-point|hold|verification-marker|index-manifest|status-artifact>
  before_count: <integer-or-pending>
  before_inventory_digest: <digest-or-pending>
  after_count: <integer-or-pending>
  after_inventory_digest: <digest-or-pending>
  equality_result: <pass|fail|pending>

credential_class:
  class_name: <bounded-public-class-name>
  lifecycle_kind: <rotatable|custody-recovery>
  consumer_units_result: <pass|fail|pending|not-applicable>
  issued_at_utc: <RFC3339-or-pending-or-not-applicable>
  replaced_at_utc: <RFC3339-or-pending-or-not-applicable>
  revoked_at_utc: <RFC3339-or-pending-or-not-applicable>
  intended_operation_result: <pass|fail|pending|not-applicable>
  old_credential_next_use_result: <rejected|accepted|pending|not-applicable>
  old_session_termination_result: <pass|fail|pending|not-applicable>
  provider_revocation_result: <pass|fail|pending|not-applicable>
  rollback_posture: <available|not-available|not-applicable|pending>
  canary_result: <pass|fail|pending>
  cleanup_result: <pass|fail|pending>

For `custody-recovery` classes whose old material must remain usable for
retained objects, record `not-applicable` for unsafe replacement, revocation,
old-next-use, old-session, provider-revocation, and rollback fields. Still
record the consumer/custody result, intended recovery operation, canary result,
and cleanup result.

hard_forget_drill:
  synthetic_envelope_scope_result: <pass|fail|pending>
  claim_scope: <postgresql-local-key-provider-ledger-installed-pitr>
  old_anchor_rejection_result: <pass|fail|pending>
  current_anchor_acknowledgement_result: <pass|fail|pending>
  provider_backup_excludes_ledger_and_anchor_result: <pass|fail|pending>
  protected_drill_manifest_sha256: <sha256-or-pending>
  provider_backup_active_control_count: <integer-or-pending>
  provider_backup_material_count: <integer-or-pending>
  provider_backup_byte_count: <integer-or-pending>
  provider_backup_inventory_sha256: <sha256-or-pending>
  phase_2_binding_result: <pass|fail|pending>
  base_backup_sha256: <sha256-or-pending>
  wal_window_sha256: <sha256-or-pending>
  recovery_target_sha256: <sha256-or-pending>
  synthetic_correlation_sha256: <sha256-or-pending>
  restore_reconcile_result: <pass|fail|pending>
  stale_active_control_absence_result: <pass|fail|pending>
  stale_material_absence_result: <pass|fail|pending>
  tombstone_result: <pass|fail|pending>
  canonical_cryptographic_erasure_result: <pass|fail|pending>
  pitr_correlation_result: <pass|fail|pending>
  pitr_unreadability_result: <pass|fail|pending>
  drill_cleanup_result: <pass|fail|pending>
  drill_second_check_result: <pass|fail|pending>

monitoring_scrape_result: <pass|fail|pending>
monitoring_rule_health_result: <pass|fail|pending>
monitoring_evaluation_error_count: <integer-or-pending>
monitoring_missing_series_result: <pass|fail|pending>
monitoring_scrape_down_result: <pass|fail|pending>
operator_report_result: <pass|fail|pending>
operator_report_stdout_absence_result: <pass|fail|pending>
monitoring_fault_family:
  family_name: <bounded-public-family-name>
  pending_result: <pass|fail|pending|not-applicable>
  firing_result: <pass|fail|pending|not-applicable>
  recovery_result: <pass|fail|pending|not-applicable>

retention_class:
  class_name: <journal|postgresql-log|tunnel-json|npm-container-log|prometheus-history|local-alert-state|protected-report>
  age_limit_days: <integer-or-not-applicable>
  byte_cap: <integer-or-not-applicable>
  age_limit_result: <pass|fail|pending|not-applicable>
  byte_cap_result: <pass|fail|pending|not-applicable>

offline_scanner_ok: <true|false|pending>
offline_scanner_artifact_sha256: <sha256-or-pending>
offline_scanner_counts: <fixed-bounded-counts-or-pending>
offline_scanner_negative_cases_result: <pass|fail|pending>
cross_process_canary_result: <pass|fail|pending>
cross_process_zero_match_count: <integer-or-pending>
scanner_cleanup_result: <pass|fail|pending>

npm_identity_result: <pass|fail|pending>
npm_static_check_result: <pass|fail|pending>
npm_server_location_real_ip_proxy_method_listener_counts: <fixed-bounded-counts-or-pending>
npm_unapproved_baseline_result: <rejected|accepted|pending>
npm_forwarded_spoof_result: <rejected|accepted|pending>
npm_x_forwarded_for_spoof_result: <rejected|accepted|pending>
npm_x_real_ip_spoof_result: <rejected|accepted|pending>
npm_rejected_probe_backend_contact_count: <integer-or-pending>
npm_approved_exact_mcp_result: <uniform-unauthenticated|unexpected|pending>
npm_invalid_request_matrix_result: <pass|fail|pending>
npm_direct_public_backend_absence_result: <pass|fail|pending>
npm_canary_scan_result: <pass|fail|pending>
npm_cleanup_result: <pass|fail|pending>

cleanup_inventory_result: <pass|fail|pending>
cleanup_result: <complete|pending|failed>
cleanup_second_check_result: <pass|fail|pending>
production_state_result: <expected-authorized-changes-only|unexpected-change|pending>
synthetic_canary_residue_count: <integer-or-pending>
remaining_risks: <fixed issue or decision references only>
reviewer: <local operator role, not a private identity>
```

`frozen_release` identifies the immutable installed and tested runtime source.
`evidence_revision` identifies the later commit containing only bounded evidence
and acceptance text. If that later revision changes executable behavior,
configuration, schema, migrations, generated artifacts, or dependencies, it is
not evidence-only and a new release freeze and applicable reruns are required.

The four excluded archive/provider fields are fixed M10 scope declarations, not
successful test results. The bundle result cannot pass until materialized local
history restores into a clean disposable database with exact same-anchor
binding. The no-prune expected code is not evidence by itself: record the actual
result, per-class before/after inventory equality, zero deletion attempts,
unchanged restore points and holds, and capacity result.

Never include memory statements, evidence, proposal bodies, request, actor,
client, installation, or subject identifiers; authorization values; database
URLs; private hostnames or network coordinates; raw exceptions; decrypted
backup content; key bytes; credential material; raw provider responses;
complete generated configuration; unbounded metric or journal output; or
command lines containing sensitive values.
