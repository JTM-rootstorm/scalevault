"""Dedicated immutable GitHub proposal polling process."""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote
from uuid import UUID

from pydantic import PostgresDsn, TypeAdapter, ValidationError
from sqlalchemy import select

from kivra_memory.application.github_ingress import GitHubIngressOrchestrator
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
    SelectionEngine,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import AuthorityClass
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.ingress.github_client import GitHubProposalClient
from kivra_memory.ingress.poller import GitHubSnapshotPoller
from kivra_memory.policy import EvidenceKind, EvidenceSummary, EvidenceTrust, SelectionBasis
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import IngressItem
from kivra_memory.workers.github_ingress import (
    GitHubIngressIdentity,
    GitHubIngressWorker,
    work_item_from_proposal,
)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or any(character in value for character in "\r\n\x00"):
        raise RuntimeError("invalid_github_ingress_configuration")
    return value


def _uuid7(name: str) -> UUID:
    try:
        value = UUID(_required(name))
        require_uuid7(value, field_name=name.lower())
    except ValueError:
        raise RuntimeError("invalid_github_ingress_configuration") from None
    return value


def _database_url(name: str) -> str:
    try:
        value = TypeAdapter(PostgresDsn).validate_python(_required(name))
        if value.scheme not in {"postgres", "postgresql", "postgresql+psycopg"}:
            raise ValueError
        if {key for key, _item in value.query_params()} & {
            "host",
            "hostaddr",
            "service",
            "servicefile",
        }:
            raise ValueError
        allowed = {"localhost", "127.0.0.1", "::1", "/run/postgresql", "/var/run/postgresql"}
        if any(
            host["host"] is None
            or unquote(str(host["host"])).removeprefix("[").removesuffix("]") not in allowed
            for host in value.hosts()
        ):
            raise ValueError
    except (ValidationError, ValueError):
        raise RuntimeError("invalid_github_ingress_configuration") from None
    return str(value)


def _bounded_integer(name: str, default: str, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        raise RuntimeError("invalid_github_ingress_configuration") from None
    if not minimum <= value <= maximum:
        raise RuntimeError("invalid_github_ingress_configuration")
    return value


def _read_credential(directory: Path, name: str) -> str:
    path = directory / name
    try:
        data = path.read_bytes()
        value = data.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise RuntimeError("github_ingress_credential_unavailable") from None
    if (
        not 1 <= len(data) <= 4096
        or value != value.strip()
        or any(character in value for character in "\r\n\x00")
    ):
        raise RuntimeError("github_ingress_credential_invalid")
    return value


@dataclass(frozen=True, slots=True)
class GitHubIngressSettings:
    ingress_database_url: str = field(repr=False)
    command_database_url: str = field(repr=False)
    identity: GitHubIngressIdentity
    repository_owner: str
    repository_name: str
    ingress_prefix: str
    token: str = field(repr=False)
    allowed_selection_basis: SelectionBasis
    authority_class: AuthorityClass
    evidence_kind: EvidenceKind
    evidence_trust: EvidenceTrust
    promotion_actor_id: UUID
    promotion_client_id: UUID
    promotion_transport_binding_id: UUID
    poll_interval_seconds: int = 30
    concurrency: int = 8

    @classmethod
    def from_environment(cls) -> GitHubIngressSettings:
        credentials = Path(_required("CREDENTIALS_DIRECTORY"))
        if not credentials.is_absolute():
            raise RuntimeError("invalid_github_ingress_configuration")
        try:
            repository_id = int(_required("KIVRA_MEMORY_GITHUB_REPOSITORY_ID"))
            basis = SelectionBasis(_required("KIVRA_MEMORY_GITHUB_ALLOWED_SELECTION_BASIS"))
            authority = AuthorityClass(_required("KIVRA_MEMORY_GITHUB_AUTHORITY_CLASS"))
            evidence_kind = EvidenceKind(_required("KIVRA_MEMORY_GITHUB_EVIDENCE_KIND"))
            evidence_trust = EvidenceTrust(_required("KIVRA_MEMORY_GITHUB_EVIDENCE_TRUST"))
        except ValueError:
            raise RuntimeError("invalid_github_ingress_configuration") from None
        identity = GitHubIngressIdentity(
            tenant_id=_uuid7("KIVRA_MEMORY_GITHUB_TENANT_ID"),
            transport_binding_id=_uuid7("KIVRA_MEMORY_GITHUB_TRANSPORT_BINDING_ID"),
            installation_id=_uuid7("KIVRA_MEMORY_GITHUB_INSTALLATION_ID"),
            actor_id=_uuid7("KIVRA_MEMORY_GITHUB_ACTOR_ID"),
            client_id=_uuid7("KIVRA_MEMORY_GITHUB_CLIENT_ID"),
            repository_id=repository_id,
            branch_name=_required("KIVRA_MEMORY_GITHUB_BRANCH"),
        )
        return cls(
            ingress_database_url=_database_url("KIVRA_MEMORY_GITHUB_INGRESS_DATABASE_URL"),
            command_database_url=_database_url("KIVRA_MEMORY_GITHUB_COMMAND_DATABASE_URL"),
            identity=identity,
            repository_owner=_required("KIVRA_MEMORY_GITHUB_REPOSITORY_OWNER"),
            repository_name=_required("KIVRA_MEMORY_GITHUB_REPOSITORY_NAME"),
            ingress_prefix=_required("KIVRA_MEMORY_GITHUB_INGRESS_PREFIX"),
            token=_read_credential(credentials, "github-token"),
            allowed_selection_basis=basis,
            authority_class=authority,
            evidence_kind=evidence_kind,
            evidence_trust=evidence_trust,
            promotion_actor_id=_uuid7("KIVRA_MEMORY_GITHUB_PROMOTION_ACTOR_ID"),
            promotion_client_id=_uuid7("KIVRA_MEMORY_GITHUB_PROMOTION_CLIENT_ID"),
            promotion_transport_binding_id=_uuid7(
                "KIVRA_MEMORY_GITHUB_PROMOTION_TRANSPORT_BINDING_ID"
            ),
            poll_interval_seconds=_bounded_integer(
                "KIVRA_MEMORY_GITHUB_POLL_INTERVAL_SECONDS", "30", minimum=5, maximum=3600
            ),
            concurrency=_bounded_integer(
                "KIVRA_MEMORY_GITHUB_CONCURRENCY", "8", minimum=1, maximum=50
            ),
        )


class PinnedGitHubNominationResolver:
    """Resolve only the operator-pinned trust profile for one ingress identity.

    Proposal evidence references are untrusted payload fields and are ignored.
    The one trusted evidence key identifies the authenticated, operator-pinned
    GitHub source.  It deliberately excludes proposal/object identifiers so
    repeated submissions from one source cannot manufacture corroboration.
    """

    def __init__(self, settings: GitHubIngressSettings) -> None:
        self._settings = settings

    async def resolve(
        self, principal: CommandPrincipal, command: NominationCommandLike, /
    ) -> ResolvedNominationContext:
        identity = self._settings.identity
        if (
            principal.tenant_id != identity.tenant_id
            or principal.transport_binding_id != identity.transport_binding_id
            or principal.actor_id != identity.actor_id
            or principal.client_id != identity.client_id
            or principal.ingress_id is None
            or command.proposal.selection_basis is not self._settings.allowed_selection_basis
        ):
            raise RuntimeError("github_ingress_trust_profile_mismatch")
        return ResolvedNominationContext(
            source_kind="github_proposal",
            effective_authority_class=self._settings.authority_class,
            evidence=(
                EvidenceSummary(
                    evidence_key=_github_proposal_evidence_key(identity),
                    kind=self._settings.evidence_kind,
                    trust=self._settings.evidence_trust,
                ),
            ),
        )


def _github_proposal_evidence_key(identity: GitHubIngressIdentity) -> str:
    material = {
        "tenant_id": identity.tenant_id,
        "actor_id": identity.actor_id,
        "client_id": identity.client_id,
        "transport_binding_id": identity.transport_binding_id,
        "repository_id": identity.repository_id,
    }
    digest = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    return f"github-proposal-source-v1:{digest}"


class PinnedPromotionPrincipalProvider:
    """Supply one configured internal-service identity for candidate promotion."""

    def __init__(self, settings: GitHubIngressSettings) -> None:
        self._settings = settings

    async def resolve(
        self,
        nominator: CommandPrincipal,
        command: NominationCommandLike,
        memory_id: UUID,
        /,
    ) -> CommandPrincipal:
        del command, memory_id
        if nominator.tenant_id != self._settings.identity.tenant_id:
            raise RuntimeError("github_ingress_promotion_identity_mismatch")
        return CommandPrincipal(
            tenant_id=nominator.tenant_id,
            actor_id=self._settings.promotion_actor_id,
            client_id=self._settings.promotion_client_id,
            transport_binding_id=self._settings.promotion_transport_binding_id,
            scopes=frozenset({"memory.lifecycle.promote"}),
        )


class GitHubIngressPollLoop:
    """Compose immutable transport polling with canonical policy orchestration."""

    def __init__(self, settings: GitHubIngressSettings) -> None:
        self._settings = settings
        self._ingress_database = Database(settings.ingress_database_url)
        self._command_database = Database(settings.command_database_url)
        client = GitHubProposalClient(
            repository_id=settings.identity.repository_id,
            repository_owner=settings.repository_owner,
            repository_name=settings.repository_name,
            default_branch=settings.identity.branch_name,
            ingress_prefix=settings.ingress_prefix,
            installation_id=settings.identity.installation_id,
            token=settings.token,
        )
        self._poller = GitHubSnapshotPoller(client)
        selection = SelectionEngine(
            self._command_database.session_factory,
            PinnedGitHubNominationResolver(settings),
            PinnedPromotionPrincipalProvider(settings),
        )
        orchestrator = GitHubIngressOrchestrator(
            self._ingress_database.session_factory,
            selection,
        )
        self._worker = GitHubIngressWorker(orchestrator, concurrency=settings.concurrency)
        self._etag: str | None = None

    async def _known_objects(self) -> dict[str, str]:
        identity = self._settings.identity
        async with self._ingress_database.tenant_session(identity.tenant_id) as session:
            rows = await session.execute(
                select(IngressItem.immutable_path, IngressItem.blob_id).where(
                    IngressItem.tenant_id == identity.tenant_id,
                    IngressItem.provider == "github",
                    IngressItem.repository_external_id == str(identity.repository_id),
                )
            )
        known: dict[str, str] = {}
        for path, blob_id in rows:
            if path in known and known[path] != blob_id:
                raise RuntimeError("github_ingress_provenance_conflict")
            known[path] = blob_id
        return known

    async def poll_once(self) -> int:
        known = await self._known_objects()
        snapshot = await asyncio.to_thread(
            self._poller.poll,
            self._etag,
            known_objects=known,
        )
        if snapshot.unchanged:
            return 0
        discovered_at = datetime.now(UTC)
        items = tuple(
            work_item_from_proposal(
                proposal,
                identity=self._settings.identity,
                discovered_at=discovered_at,
            )
            for proposal in snapshot.proposals
        )
        results = await self._worker.process_batch(items)
        if not any(result.disposition == "retry" for result in results):
            self._etag = snapshot.next_etag
        return len(results)

    async def close(self) -> None:
        await self._ingress_database.dispose()
        await self._command_database.dispose()


async def run_ingress(settings: GitHubIngressSettings) -> None:
    worker = GitHubIngressPollLoop(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected_signal, stop.set)
    try:
        while not stop.is_set():
            await worker.poll_once()
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=settings.poll_interval_seconds)
    finally:
        await worker.close()


def main() -> None:
    """Run without logging proposal content, credentials, or remote responses."""

    try:
        settings = GitHubIngressSettings.from_environment()
        asyncio.run(run_ingress(settings))
    except Exception:
        print("ScaleVault GitHub ingress failed safely", file=sys.stderr)
        raise SystemExit(2) from None


__all__ = [
    "GitHubIngressPollLoop",
    "GitHubIngressSettings",
    "PinnedGitHubNominationResolver",
    "PinnedPromotionPrincipalProvider",
    "main",
    "run_ingress",
]
