"""Milestone 6 runtime configuration and trusted-seam tests."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import pytest
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import NominationCommandLike
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import AuthorityClass, MemoryCategory
from kivra_memory.ingress.poller import GitHubSnapshotPollResult
from kivra_memory.policy import (
    EvidenceKind,
    EvidenceTrust,
    NominationEvidenceReference,
    SelectionBasis,
)
from kivra_memory.storage.github_heads import (
    GITHUB_INGRESS_BOOTSTRAP_COMMIT,
    GITHUB_INGRESS_BOOTSTRAP_TREE,
    GitHubProviderHeadState,
    GitHubProviderIdentity,
)
from kivra_memory.storage.github_revocation import (
    GitHubInstallationEpoch,
    GitHubInstallationRevoked,
)
from kivra_memory.workers.github_ingress import GitHubIngressIdentity
from kivra_memory.workers.github_ingress_main import (
    GitHubIngressPollLoop,
    GitHubIngressSettings,
    PinnedGitHubNominationResolver,
    PinnedPromotionPrincipalProvider,
    _provider_backoff_seconds,
    _provider_failure_alert,
    run_ingress,
)


def _uuid(value: int) -> UUID:
    return UUID(f"019c0000-0000-7000-8000-{value:012d}")


def _settings() -> GitHubIngressSettings:
    return GitHubIngressSettings(
        ingress_database_url="postgresql+psycopg://ingress@127.0.0.1/memory",
        command_database_url="postgresql+psycopg://api@127.0.0.1/memory",
        identity=GitHubIngressIdentity(
            tenant_id=_uuid(1),
            transport_binding_id=_uuid(2),
            installation_id=_uuid(3),
            actor_id=_uuid(4),
            client_id=_uuid(5),
            repository_id=1234,
            branch_name="main",
        ),
        repository_owner="owner",
        repository_name="memory-ingress",
        ingress_prefix="ingress/v2",
        token="not-a-real-token",
        allowed_selection_basis=SelectionBasis.ASSISTANT_OBSERVATION,
        authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
        evidence_kind=EvidenceKind.ASSISTANT_OBSERVATION,
        evidence_trust=EvidenceTrust.TRUSTED,
        bootstrap_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
        bootstrap_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
        promotion_actor_id=_uuid(6),
        promotion_client_id=_uuid(7),
        promotion_transport_binding_id=_uuid(8),
    )


def _principal(settings: GitHubIngressSettings) -> CommandPrincipal:
    identity = settings.identity
    return CommandPrincipal(
        tenant_id=identity.tenant_id,
        actor_id=identity.actor_id,
        client_id=identity.client_id,
        transport_binding_id=identity.transport_binding_id,
        scopes=frozenset({"memory:propose"}),
        ingress_id=_uuid(9),
    )


async def test_poll_rechecks_epoch_after_provider_io_before_processing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    identity = settings.identity
    epoch = GitHubInstallationEpoch(
        tenant_id=identity.tenant_id,
        installation_id=identity.installation_id,
        enrolled_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    checkpoint = GitHubProviderHeadState(
        identity=GitHubProviderIdentity(
            tenant_id=identity.tenant_id,
            installation_id=identity.installation_id,
            transport_binding_id=identity.transport_binding_id,
            repository_id=identity.repository_id,
            branch_name=identity.branch_name,
        ),
        bootstrap_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
        bootstrap_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
        last_verified_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
        last_verified_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
        etag=None,
        verified_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    provider_started = asyncio.Event()
    provider_release = asyncio.Event()

    class BlockingPoller:
        def poll(self, *_args: object, **_kwargs: object) -> GitHubSnapshotPollResult:
            raise AssertionError("provider call must run through the offload seam")

    class ForbiddenWorker:
        async def process_batch(self, _items: object) -> object:
            raise AssertionError("revoked provider result reached processing")

    loop = object.__new__(GitHubIngressPollLoop)
    loop._settings = settings
    loop._poller = cast(Any, BlockingPoller())
    loop._worker = cast(Any, ForbiddenWorker())

    async def capture() -> GitHubInstallationEpoch:
        return epoch

    async def provider_head(observed: GitHubInstallationEpoch) -> GitHubProviderHeadState:
        assert observed == epoch
        return checkpoint

    async def known_objects(observed: GitHubInstallationEpoch) -> dict[str, str]:
        assert observed == epoch
        return {}

    async def revoked_after_provider(observed: GitHubInstallationEpoch) -> None:
        assert observed == epoch
        raise GitHubInstallationRevoked("github_installation_revoked")

    async def provider_io(
        function: object, *_args: object, **_kwargs: object
    ) -> GitHubSnapshotPollResult:
        assert function == loop._poller.poll
        provider_started.set()
        await provider_release.wait()
        return GitHubSnapshotPollResult(
            next_etag=None,
            unchanged=True,
            commit_id=None,
            tree_id=None,
            proposals=(),
        )

    monkeypatch.setattr(loop, "_installation_epoch", capture)
    monkeypatch.setattr(loop, "_provider_head", provider_head)
    monkeypatch.setattr(loop, "_known_objects", known_objects)
    monkeypatch.setattr(loop, "_check_installation_epoch", revoked_after_provider)
    monkeypatch.setattr("kivra_memory.workers.github_ingress_main.asyncio.to_thread", provider_io)

    poll_task = asyncio.create_task(loop.poll_once())
    await provider_started.wait()
    provider_release.set()
    with pytest.raises(GitHubInstallationRevoked, match="github_installation_revoked"):
        await poll_task


async def test_revoked_installation_stops_loop_cleanly_and_closes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    polls = 0
    closed = False

    class RevokedPollLoop:
        def __init__(self, _settings: GitHubIngressSettings) -> None:
            return None

        async def poll_once(self) -> int:
            nonlocal polls
            polls += 1
            raise GitHubInstallationRevoked("must-not-be-rendered")

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(
        "kivra_memory.workers.github_ingress_main.GitHubIngressPollLoop",
        RevokedPollLoop,
    )
    monkeypatch.setattr(asyncio.get_running_loop(), "add_signal_handler", lambda *_args: None)

    await run_ingress(_settings())

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "ScaleVault GitHub ingress installation is revoked\n"
    assert "must-not-be-rendered" not in captured.err
    assert polls == 1
    assert closed is True


def _server_evidence_key(settings: GitHubIngressSettings) -> str:
    identity = settings.identity
    material = {
        "tenant_id": identity.tenant_id,
        "actor_id": identity.actor_id,
        "client_id": identity.client_id,
        "transport_binding_id": identity.transport_binding_id,
        "repository_id": identity.repository_id,
    }
    return f"github-proposal-source-v1:{hashlib.sha256(canonical_json_bytes(material)).hexdigest()}"


def _command(
    basis: SelectionBasis,
    *,
    category: MemoryCategory = MemoryCategory.EMERGENT_TENDENCY,
    with_evidence: bool = True,
    evidence_key: str = "reviewed-project-source",
    opaque_reference: str = "project-source:reviewed",
) -> NominationCommandLike:
    proposal = SimpleNamespace(
        selection_basis=basis,
        category=category,
        evidence_references=(
            (
                NominationEvidenceReference(
                    evidence_key=evidence_key,
                    opaque_reference=opaque_reference,
                ),
            )
            if with_evidence
            else ()
        ),
    )
    return cast(NominationCommandLike, SimpleNamespace(proposal=proposal))


async def test_trusted_resolver_uses_operator_profile_not_payload_claims() -> None:
    settings = _settings()
    resolved = await PinnedGitHubNominationResolver(settings).resolve(
        _principal(settings),
        _command(SelectionBasis.ASSISTANT_OBSERVATION),
    )

    assert resolved.source_kind == "github_proposal"
    assert resolved.effective_authority_class is AuthorityClass.ASSISTANT_OBSERVATION
    assert resolved.evidence[0].kind is EvidenceKind.ASSISTANT_OBSERVATION
    assert resolved.evidence[0].trust is EvidenceTrust.TRUSTED
    assert resolved.evidence[0].evidence_key == _server_evidence_key(settings)
    assert resolved.evidence[0].evidence_key != "reviewed-project-source"

    with pytest.raises(RuntimeError, match="trust_profile_mismatch"):
        await PinnedGitHubNominationResolver(settings).resolve(
            _principal(settings),
            _command(SelectionBasis.VERIFIED_PROJECT_DECISION),
        )


async def test_promotion_provider_returns_only_pinned_internal_identity() -> None:
    settings = _settings()
    principal = await PinnedPromotionPrincipalProvider(settings).resolve(
        _principal(settings),
        _command(SelectionBasis.VERIFIED_PROJECT_DECISION),
        _uuid(10),
    )

    assert principal.actor_id == settings.promotion_actor_id
    assert principal.client_id == settings.promotion_client_id
    assert principal.transport_binding_id == settings.promotion_transport_binding_id
    assert principal.scopes == frozenset({"memory.lifecycle.promote"})


async def test_trusted_resolver_allows_schema_valid_proposal_without_evidence() -> None:
    settings = _settings()
    resolved = await PinnedGitHubNominationResolver(settings).resolve(
        _principal(settings),
        _command(SelectionBasis.ASSISTANT_OBSERVATION, with_evidence=False),
    )

    assert resolved.source_kind == "github_proposal"
    assert len(resolved.evidence) == 1
    assert resolved.evidence[0].evidence_key == _server_evidence_key(settings)


async def test_trusted_resolver_key_is_stable_across_hostile_payload_references() -> None:
    settings = _settings()
    resolver = PinnedGitHubNominationResolver(settings)
    first = await resolver.resolve(
        _principal(settings),
        _command(SelectionBasis.ASSISTANT_OBSERVATION),
    )
    second_command = _command(
        SelectionBasis.ASSISTANT_OBSERVATION,
        evidence_key="hostile-independent-source",
        opaque_reference="hostile:must-not-persist",
    )
    second = await resolver.resolve(_principal(settings), second_command)

    assert first.evidence == second.evidence
    assert second.evidence[0].evidence_key == _server_evidence_key(settings)


async def test_resolver_rejects_non_candidate_category() -> None:
    settings = _settings()
    with pytest.raises(RuntimeError, match="trust_profile_mismatch"):
        await PinnedGitHubNominationResolver(settings).resolve(
            _principal(settings),
            _command(
                SelectionBasis.ASSISTANT_OBSERVATION,
                category=MemoryCategory.PROJECT_DECISION,
            ),
        )


def test_settings_reject_verified_project_trust_profile() -> None:
    settings = _settings()

    with pytest.raises(ValueError, match="candidate-only"):
        replace(
            settings,
            allowed_selection_basis=SelectionBasis.VERIFIED_PROJECT_DECISION,
            authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
            evidence_kind=EvidenceKind.PROJECT_SOURCE,
        )


def test_ingress_settings_fail_closed_without_systemd_credential_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(RuntimeError, match="invalid_github_ingress_configuration"):
        GitHubIngressSettings.from_environment()


def test_provider_failures_use_bounded_backoff_and_fixed_alerts() -> None:
    assert [_provider_backoff_seconds(30, failure) for failure in range(1, 8)] == [
        30,
        60,
        120,
        240,
        480,
        900,
        900,
    ]
    assert _provider_failure_alert("auth_failure") == (
        "ScaleVault GitHub ingress provider authentication failed"
    )
    assert "response" not in _provider_failure_alert("rate_limited")
    with pytest.raises(ValueError):
        _provider_backoff_seconds(30, 0)
