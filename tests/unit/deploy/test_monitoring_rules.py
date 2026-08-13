from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[3]
MONITORING = REPOSITORY_ROOT / "deploy" / "memory-node" / "monitoring"

EXPECTED_ALERTS = {
    "ScaleVaultArchiveLagCritical",
    "ScaleVaultArchiveLagWarning",
    "ScaleVaultArchiveVerificationFailure",
    "ScaleVaultAuthorizationFailureSpike",
    "ScaleVaultBackupFailure",
    "ScaleVaultBackupRPOCritical",
    "ScaleVaultBackupVerificationFailure",
    "ScaleVaultDatabasePoolSaturationCritical",
    "ScaleVaultDatabasePoolSaturationWarning",
    "ScaleVaultDirectCredentialExpiryCritical",
    "ScaleVaultDirectCredentialExpiryWarning",
    "ScaleVaultFullRecoveryDrillOverdue",
    "ScaleVaultGitHubAuthFailure",
    "ScaleVaultGitHubPollStalledCritical",
    "ScaleVaultGitHubPollStalledWarning",
    "ScaleVaultGitHubQuarantineSpike",
    "ScaleVaultGitHubTelemetryMissing",
    "ScaleVaultHardForgetPurgeFailure",
    "ScaleVaultHardForgetTerminalJob",
    "ScaleVaultMemoryNodeScrapeUnavailable",
    "ScaleVaultOffsiteHeadUnverified",
    "ScaleVaultOffsiteVerificationFailure",
    "ScaleVaultOperationalTelemetryMissing",
    "ScaleVaultPITRDrillOverdue",
    "ScaleVaultPostgreSQLUnavailable",
    "ScaleVaultProjectionInconsistency",
    "ScaleVaultPublicExposure",
    "ScaleVaultRunnableJobAgeCritical",
    "ScaleVaultRunnableJobAgeWarning",
    "ScaleVaultStorageFreeCritical",
    "ScaleVaultStorageFreeWarning",
    "ScaleVaultTunnelDisconnectedCritical",
    "ScaleVaultTunnelDisconnectedWarning",
    "ScaleVaultTunnelTelemetryMissing",
    "ScaleVaultWALArchiveFailure",
    "ScaleVaultWALAgeCritical",
    "ScaleVaultWALAgeWarning",
}


def test_monitoring_example_is_loopback_only_and_rules_are_complete() -> None:
    config = (MONITORING / "prometheus.yml.example").read_text()
    rules = (MONITORING / "scalevault.rules.yml").read_text()
    assert "127.0.0.1:8080" in config
    assert "0.0.0.0" not in config
    assert set(re.findall(r"^\s+- alert: (\w+)$", rules, re.MULTILINE)) == EXPECTED_ALERTS
    for forbidden in (
        "actor_id",
        "client_id",
        "credential_id",
        "hostname",
        "memory_id",
        "repository",
        "request_id",
        "subject_id",
        "tenant_id",
    ):
        assert forbidden not in rules


def test_alert_thresholds_match_accepted_adr_0031() -> None:
    rules = (MONITORING / "scalevault.rules.yml").read_text()
    required_fragments = (
        'kivra_memory_backup_age_seconds{kind="base"} > 93600',
        "kivra_memory_wal_oldest_age_seconds > 600",
        "kivra_memory_wal_oldest_age_seconds > 900",
        "kivra_memory_storage_free_ratio < 0.20",
        "kivra_memory_storage_free_ratio < 0.10",
        "kivra_memory_offsite_unverified_head_age_seconds > 3600",
        'kivra_memory_archive_lag_seconds{stage=~"export|push"} > 900',
        'kivra_memory_archive_lag_seconds{stage=~"export|push"} > 3600',
        "kivra_memory_queue_oldest_age_seconds > 900",
        "kivra_memory_queue_oldest_age_seconds > 3600",
        "kivra_memory_database_pool_saturation_ratio > 0.80",
        "kivra_memory_database_pool_saturation_ratio > 0.90",
        'expiry=~"expired|le_1d|le_7d|le_30d"',
        'expiry=~"expired|le_1d|le_7d"',
        "kivra_memory_github_poll_age_seconds > 2 * scalar(",
        "kivra_memory_github_poll_age_seconds > 4 * scalar(",
        'kivra_memory_recovery_drill_age_seconds{kind="pitr"} > 3024000',
        'kivra_memory_recovery_drill_age_seconds{kind="full"} > 8640000',
    )
    assert all(fragment in rules for fragment in required_fragments)
    assert rules.count("for: 5m") >= 5
    assert "for: 15m" in rules


def test_promtool_cases_cover_boundaries_durations_recovery_and_missing_series() -> None:
    tests = (MONITORING / "scalevault.rules.test.yml").read_text()
    for case in (
        "adr-0031-age-and-ratio-boundaries-fire-and-recover",
        "adr-0031-pool-and-tunnel-sustained-durations-and-recovery",
        "adr-0031-credential-and-github-relative-boundaries",
        "scrape-down-and-absent-series-fail-visible-then-recover",
        "entirely-absent-required-scrapes-still-alert",
        "optional-github-partial-telemetry-is-visible",
    ):
        assert f"name: {case}" in tests
    assert "_ _ _" in tests
    assert tests.count("exp_alerts: []") >= 15


def test_prometheus_rule_syntax_and_behavior_when_promtool_is_available() -> None:
    promtool = shutil.which("promtool")
    if promtool is None:
        pytest.skip("promtool is not installed")
    subprocess.run(
        [promtool, "check", "rules", "scalevault.rules.yml"],
        cwd=MONITORING,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [promtool, "test", "rules", "scalevault.rules.test.yml"],
        cwd=MONITORING,
        check=True,
        capture_output=True,
        text=True,
    )
