"""Static safety checks for the secure-tunnel rotation runbook."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNBOOK = ROOT / "deploy/memory-node/tunnel/ROTATION.md"


def test_rotation_uses_unique_protected_staging_and_atomic_fixed_path_cutover() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert "staging_dir=/etc/kivra-memory/tunnel-rotation" in runbook
    assert 'new_artifact="$staging_dir/new-$rotation_id.authorization"' in runbook
    assert 'test ! -e "$new_artifact"' in runbook
    assert "kivra-memory-credential-admin rotate-secure-tunnel" in runbook
    assert '--credential-id "$old_credential_id"' in runbook
    assert '--secret-output "$new_artifact"' in runbook
    assert 'mv -T -- "$new_artifact" "$fixed_authorization"' in runbook
    assert "sync -f /etc/kivra-memory" in runbook
    assert "--secret-stdout" in runbook
    assert "Never print" in runbook


def test_rotation_proves_new_succeeds_and_old_fails_after_restart() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")
    restart = runbook.index("systemctl restart kivra-memory-tunnel.service")
    after_restart = runbook[restart:]

    assert '"$fixed_authorization"' in after_restart
    assert '"$old_proof"' in after_restart
    assert "revoked credential was accepted after restart" in after_restart
    assert "http://127.0.0.1:8081/healthz" in after_restart
    assert "http://127.0.0.1:8081/readyz" in after_restart


def test_rotation_documents_each_forward_only_crash_boundary() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")

    headings = (
        "### Before database rotation",
        "### After database commit, before fixed-path install",
        "### After fixed-path install, before restart",
        "### Failed restart",
    )
    assert all(heading in runbook for heading in headings)
    assert "rerun the exact" in runbook
    assert "same old credential UUID and the same\nartifact path" in runbook
    assert "second forward rotation" in runbook
    assert "Do not move\n`old_proof` back" in runbook
    assert "Never silently re-enable the revoked old credential" in runbook
    assert "edit a credential row by hand" in runbook


def test_rotation_requires_live_collision_and_payload_log_canary_gates() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert "through the actual OpenAI\ntunnel" in runbook
    assert "Authorization collision" in runbook
    assert "connector-forwarded headers last" in runbook
    assert "successful read in the collision case is a release blocker" in runbook
    assert "Journal canary" in runbook
    assert "tunnel-log-canary-<UUIDv7>" in runbook
    assert 'grep -E -q "$canary|Bearer svb1\\.|Authorization:"' in runbook
    assert 'scan_status=("${PIPESTATUS[@]}")' in runbook
    assert "journal canary scan was unavailable" in runbook
    assert "never either Authorization value" in runbook


def test_rotation_never_restores_old_artifact_or_uses_reissue_as_rotation() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert 'mv -T -- "$old_proof" "$fixed_authorization"' not in runbook
    assert 'install -o root -g root -m 0600 "$old_proof" "$fixed_authorization"' not in runbook
    assert "Do not use `reissue-secure-tunnel`" in runbook
    assert 'rm -f -- "$old_proof"' in runbook
