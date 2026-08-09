"""Milestone 6 runtime configuration and trusted-seam tests."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import NominationCommandLike
from kivra_memory.domain.enums import AuthorityClass
from kivra_memory.policy import (
    EvidenceKind,
    EvidenceTrust,
    NominationEvidenceReference,
    SelectionBasis,
)
from kivra_memory.workers.github_ingress import GitHubIngressIdentity
from kivra_memory.workers.github_ingress_main import (
    GitHubIngressSettings,
    PinnedGitHubNominationResolver,
    PinnedPromotionPrincipalProvider,
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
        allowed_selection_basis=SelectionBasis.VERIFIED_PROJECT_DECISION,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        evidence_kind=EvidenceKind.PROJECT_SOURCE,
        evidence_trust=EvidenceTrust.TRUSTED,
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


def _command(basis: SelectionBasis, *, with_evidence: bool = True) -> NominationCommandLike:
    proposal = SimpleNamespace(
        selection_basis=basis,
        evidence_references=(
            (
                NominationEvidenceReference(
                    evidence_key="reviewed-project-source",
                    opaque_reference="project-source:reviewed",
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
        _command(SelectionBasis.VERIFIED_PROJECT_DECISION),
    )

    assert resolved.source_kind == "github_proposal"
    assert resolved.effective_authority_class is AuthorityClass.VERIFIED_PROJECT_SOURCE
    assert resolved.evidence[0].kind is EvidenceKind.PROJECT_SOURCE
    assert resolved.evidence[0].trust is EvidenceTrust.TRUSTED

    with pytest.raises(RuntimeError, match="trust_profile_mismatch"):
        await PinnedGitHubNominationResolver(settings).resolve(
            _principal(settings),
            _command(SelectionBasis.EXPLICIT_USER_REQUEST),
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
        _command(SelectionBasis.VERIFIED_PROJECT_DECISION, with_evidence=False),
    )

    assert resolved.source_kind == "github_proposal"
    assert resolved.evidence == ()


def test_ingress_settings_fail_closed_without_systemd_credential_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(RuntimeError, match="invalid_github_ingress_configuration"):
        GitHubIngressSettings.from_environment()
