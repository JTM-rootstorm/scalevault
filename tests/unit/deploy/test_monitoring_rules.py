from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[3]
MONITORING = REPOSITORY_ROOT / "deploy" / "memory-node" / "monitoring"

EXPECTED_ALERTS = {
    "ScaleVaultArchiveLag",
    "ScaleVaultArchiveVerificationFailure",
    "ScaleVaultAuthorizationFailureSpike",
    "ScaleVaultBackupFailure",
    "ScaleVaultBackupRPOBreach",
    "ScaleVaultBackupVerificationFailure",
    "ScaleVaultDatabasePoolSaturation",
    "ScaleVaultDirectCredentialExpiry",
    "ScaleVaultGitHubAuthFailure",
    "ScaleVaultGitHubPollStalled",
    "ScaleVaultGitHubQuarantineSpike",
    "ScaleVaultHardForgetPurgeBacklog",
    "ScaleVaultHardForgetPurgeFailure",
    "ScaleVaultOffsiteCopyStale",
    "ScaleVaultOffsiteVerificationFailure",
    "ScaleVaultPostgreSQLUnavailable",
    "ScaleVaultProjectionInconsistency",
    "ScaleVaultPublicExposure",
    "ScaleVaultQueueOldestJob",
    "ScaleVaultRecoveryDrillOverdue",
    "ScaleVaultStoragePressure",
    "ScaleVaultTunnelDisconnected",
    "ScaleVaultWALArchiveFailure",
    "ScaleVaultWALBacklog",
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
