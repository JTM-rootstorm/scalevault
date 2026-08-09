"""Tenant-scoped bearer credential lookup, audit, and operator persistence."""

from __future__ import annotations

import hmac
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from sqlalchemy import Row, Select, Table, func, insert, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.admin.credentials import (
    ALLOWED_CLIENT_SCOPES,
    BearerCredentialReplacement,
    CodexInstallationIssuance,
    CredentialAdminError,
    CredentialMetadata,
)
from kivra_memory.application.authentication import CredentialIdentity, CredentialLookup
from kivra_memory.auth import ClientCapabilityProfile
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import TransportKind
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.storage.models import (
    Actor,
    Client,
    ClientCredential,
    Tenant,
    TransportBinding,
)
from kivra_memory.storage.transactions import run_serializable_transaction

_VERIFIER_PATTERN = re.compile(r"hmac-sha256-v1:[A-Za-z0-9_-]{43}\Z")
_KEY_ID_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\Z")


class CredentialStorageError(RuntimeError):
    """One content-free request credential persistence failure."""

    def __init__(self) -> None:
        super().__init__("authentication failed")


class CredentialRepositoryProtocol(Protocol):
    """Request-time persistence boundary used by bearer authentication."""

    async def lookup(
        self,
        tenant_hint: UUID,
        credential_id: UUID,
        /,
    ) -> CredentialLookup | None: ...

    async def record_successful_use(
        self,
        lookup: CredentialLookup,
        /,
        *,
        transport_kind: TransportKind,
        installation_id: UUID | None,
        used_at: datetime,
    ) -> CredentialIdentity: ...


@dataclass(frozen=True, slots=True)
class _CredentialState:
    credential: ClientCredential
    tenant: Tenant
    actor: Actor
    client: Client
    binding: TransportBinding


@dataclass(frozen=True, slots=True)
class _AdminCredentialState:
    credential_id: UUID
    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID
    public_hint: str | None
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    client_scopes: tuple[str, ...]
    capability_profile: dict[str, object]
    actor_metadata: dict[str, object]


type _AdminCredentialRow = tuple[
    UUID,
    UUID,
    UUID,
    UUID,
    UUID,
    str | None,
    datetime,
    datetime | None,
    datetime | None,
    datetime | None,
    list[str],
    dict[str, object],
    dict[str, object],
]


class CredentialRepository:
    """Resolve one bearer credential inside ordinary tenant RLS transactions."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def lookup(
        self,
        tenant_hint: UUID,
        credential_id: UUID,
        /,
    ) -> CredentialLookup | None:
        try:
            require_uuid7(tenant_hint, field_name="tenant_hint")
            require_uuid7(credential_id, field_name="credential_id")
        except (TypeError, ValueError):
            return None

        async def operation(session: AsyncSession) -> CredentialLookup | None:
            row = (
                await session.execute(_credential_lookup_statement(tenant_hint, credential_id))
            ).one_or_none()
            if row is None:
                return None
            resolved_tenant_id, resolved_credential_id, verifier, hash_key_id = row
            if (
                verifier is None
                or hash_key_id is None
                or _VERIFIER_PATTERN.fullmatch(verifier) is None
                or _KEY_ID_PATTERN.fullmatch(hash_key_id) is None
            ):
                return None
            return CredentialLookup(
                tenant_id=resolved_tenant_id,
                credential_id=resolved_credential_id,
                secret_verifier=verifier,
                hash_key_id=hash_key_id,
            )

        try:
            return await run_serializable_transaction(
                self._session_factory,
                tenant_hint,
                operation,
            )
        except SQLAlchemyError:
            raise CredentialStorageError from None

    async def record_successful_use(
        self,
        lookup: CredentialLookup,
        /,
        *,
        transport_kind: TransportKind,
        installation_id: UUID | None,
        used_at: datetime,
    ) -> CredentialIdentity:
        try:
            require_uuid7(lookup.tenant_id, field_name="tenant_hint")
            require_uuid7(lookup.credential_id, field_name="credential_id")
            if installation_id is not None:
                require_uuid7(installation_id, field_name="installation_id")
            _require_utc(used_at)
            requested_transport = TransportKind(transport_kind)
            if (
                _VERIFIER_PATTERN.fullmatch(lookup.secret_verifier) is None
                or _KEY_ID_PATTERN.fullmatch(lookup.hash_key_id) is None
            ):
                raise ValueError("credential lookup is invalid")
        except (TypeError, ValueError):
            raise CredentialStorageError from None

        async def operation(session: AsyncSession) -> CredentialIdentity:
            database_now = _require_utc(
                cast(datetime, await session.scalar(select(func.current_timestamp())))
            )
            state = await _load_state(
                session,
                tenant_id=lookup.tenant_id,
                credential_id=lookup.credential_id,
                for_update=True,
            )
            if (
                state is None
                or state.credential.secret_hash is None
                or state.credential.secret_hash_key_id is None
                or not hmac.compare_digest(
                    state.credential.secret_hash,
                    lookup.secret_verifier,
                )
                or not hmac.compare_digest(
                    state.credential.secret_hash_key_id,
                    lookup.hash_key_id,
                )
                or not _state_is_active(
                    state,
                    transport_kind=requested_transport,
                    installation_id=installation_id,
                    used_at=database_now,
                )
            ):
                raise CredentialStorageError
            identity = _identity_from_state(state)
            credential = state.credential
            audit_at = _monotonic_audit_timestamp(
                credential.last_used_at,
                database_now,
            )
            if credential.last_used_at != audit_at:
                credential.last_used_at = audit_at
                await session.flush()
            return identity

        try:
            return await run_serializable_transaction(
                self._session_factory,
                lookup.tenant_id,
                operation,
            )
        except CredentialStorageError:
            raise
        except SQLAlchemyError:
            raise CredentialStorageError from None


class CredentialAdminStorageRepository:
    """Operator-only atomic storage for Codex installation credential lifecycle."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create_codex_installation(
        self,
        issuance: CodexInstallationIssuance,
    ) -> CredentialMetadata:
        _validate_issuance(issuance)

        async def operation(session: AsyncSession) -> CredentialMetadata:
            tenant_id = await session.scalar(
                select(Tenant.tenant_id).where(
                    Tenant.tenant_id == issuance.tenant_id,
                    Tenant.state == "active",
                )
            )
            if tenant_id is None:
                raise CredentialAdminError("credential_identity_unavailable")
            await session.execute(
                insert(cast(Table, Actor.__table__)).values(
                    actor_id=issuance.actor_id,
                    tenant_id=issuance.tenant_id,
                    handle=issuance.actor_handle,
                    display_name=issuance.actor_display_name,
                    kind="agent",
                    metadata=issuance.actor_metadata,
                    created_at=issuance.created_at,
                )
            )
            await session.execute(
                insert(cast(Table, Client.__table__)).values(
                    client_id=issuance.client_id,
                    tenant_id=issuance.tenant_id,
                    public_id=issuance.client_public_id,
                    display_name=issuance.client_display_name,
                    kind="interactive",
                    transport_kind=TransportKind.DIRECT_PRIVATE.value,
                    scopes=list(issuance.client_scopes),
                    capability_profile=issuance.client_capability_profile.model_dump(mode="json"),
                    created_at=issuance.created_at,
                )
            )
            await session.execute(
                insert(cast(Table, TransportBinding.__table__)).values(
                    transport_binding_id=issuance.transport_binding_id,
                    tenant_id=issuance.tenant_id,
                    actor_id=issuance.actor_id,
                    client_id=issuance.client_id,
                    transport_kind=TransportKind.DIRECT_PRIVATE.value,
                    disclosure_boundary="private_node",
                    installation_id=None,
                    authorized_operations={"operations": list(issuance.authorized_operations)},
                    created_at=issuance.created_at,
                    valid_until=None,
                )
            )
            await session.execute(
                insert(cast(Table, ClientCredential.__table__)).values(
                    credential_id=issuance.credential_id,
                    tenant_id=issuance.tenant_id,
                    actor_id=issuance.actor_id,
                    client_id=issuance.client_id,
                    transport_binding_id=issuance.transport_binding_id,
                    kind="bearer_token",
                    public_hint=issuance.public_hint,
                    secret_hash=issuance.secret_hash,
                    secret_hash_key_id=issuance.secret_hash_key_id,
                    created_at=issuance.created_at,
                    expires_at=issuance.expires_at,
                )
            )
            return _metadata_from_issuance(issuance)

        return await self._admin_transaction(issuance.tenant_id, operation)

    async def list_bearer_credentials(
        self,
        *,
        tenant_id: UUID,
        client_id: UUID | None,
    ) -> Sequence[CredentialMetadata]:
        _require_identifier(tenant_id, "tenant_id")
        if client_id is not None:
            _require_identifier(client_id, "client_id")

        async def operation(session: AsyncSession) -> tuple[CredentialMetadata, ...]:
            statement = _admin_credential_statement().where(
                ClientCredential.tenant_id == tenant_id,
                ClientCredential.kind == "bearer_token",
            )
            if client_id is not None:
                statement = statement.where(ClientCredential.client_id == client_id)
            statement = statement.order_by(
                ClientCredential.created_at,
                ClientCredential.credential_id,
            )
            rows = (await session.execute(statement)).all()
            return tuple(_metadata_from_state(_admin_state(row)) for row in rows)

        return await self._admin_transaction(tenant_id, operation)

    async def revoke_bearer_credential(
        self,
        *,
        tenant_id: UUID,
        credential_id: UUID,
        revoked_at: datetime,
    ) -> CredentialMetadata:
        _require_identifier(tenant_id, "tenant_id")
        _require_identifier(credential_id, "credential_id")
        timestamp = _require_admin_timestamp(revoked_at)

        async def operation(session: AsyncSession) -> CredentialMetadata:
            row = await _load_admin_credential(
                session,
                tenant_id=tenant_id,
                credential_id=credential_id,
            )
            if row is None:
                raise CredentialAdminError("credential_not_found")
            if row.revoked_at is None:
                await session.execute(
                    update(ClientCredential)
                    .where(
                        ClientCredential.tenant_id == tenant_id,
                        ClientCredential.credential_id == credential_id,
                    )
                    .values(revoked_at=timestamp)
                )
                row = replace(row, revoked_at=timestamp)
            return _metadata_from_state(row)

        return await self._admin_transaction(tenant_id, operation)

    async def rotate_bearer_credential(
        self,
        *,
        tenant_id: UUID,
        credential_id: UUID,
        replacement: BearerCredentialReplacement,
        rotated_at: datetime,
    ) -> CredentialMetadata:
        _require_identifier(tenant_id, "tenant_id")
        _require_identifier(credential_id, "credential_id")
        _validate_replacement(replacement, tenant_id=tenant_id)
        timestamp = _require_admin_timestamp(rotated_at)
        if timestamp != replacement.created_at:
            raise CredentialAdminError("credential_request_invalid")

        async def operation(session: AsyncSession) -> CredentialMetadata:
            row = await _load_admin_credential(
                session,
                tenant_id=tenant_id,
                credential_id=credential_id,
            )
            if row is None:
                raise CredentialAdminError("credential_not_found")
            if row.revoked_at is not None:
                raise CredentialAdminError("credential_not_active")
            await session.execute(
                update(ClientCredential)
                .where(
                    ClientCredential.tenant_id == tenant_id,
                    ClientCredential.credential_id == credential_id,
                )
                .values(revoked_at=timestamp)
            )
            await session.execute(
                insert(cast(Table, ClientCredential.__table__)).values(
                    credential_id=replacement.credential_id,
                    tenant_id=row.tenant_id,
                    actor_id=row.actor_id,
                    client_id=row.client_id,
                    transport_binding_id=row.transport_binding_id,
                    kind="bearer_token",
                    public_hint=row.public_hint,
                    secret_hash=replacement.secret_hash,
                    secret_hash_key_id=replacement.secret_hash_key_id,
                    created_at=replacement.created_at,
                    expires_at=replacement.expires_at,
                )
            )
            return _metadata_from_state(
                replace(
                    row,
                    credential_id=replacement.credential_id,
                    created_at=replacement.created_at,
                    expires_at=replacement.expires_at,
                    last_used_at=None,
                    revoked_at=None,
                )
            )

        return await self._admin_transaction(tenant_id, operation)

    async def _admin_transaction[T](
        self,
        tenant_id: UUID,
        operation: Callable[[AsyncSession], Awaitable[T]],
    ) -> T:
        try:
            return await run_serializable_transaction(
                self._session_factory,
                tenant_id,
                operation,
            )
        except CredentialAdminError:
            raise
        except SQLAlchemyError:
            raise CredentialAdminError("credential_repository_unavailable") from None


async def _load_state(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    credential_id: UUID,
    for_update: bool,
) -> _CredentialState | None:
    statement = (
        select(ClientCredential, Tenant, Actor, Client, TransportBinding)
        .join(Tenant, Tenant.tenant_id == ClientCredential.tenant_id)
        .join(
            Actor,
            (Actor.tenant_id == ClientCredential.tenant_id)
            & (Actor.actor_id == ClientCredential.actor_id),
        )
        .join(
            Client,
            (Client.tenant_id == ClientCredential.tenant_id)
            & (Client.client_id == ClientCredential.client_id),
        )
        .join(
            TransportBinding,
            (TransportBinding.tenant_id == ClientCredential.tenant_id)
            & (TransportBinding.transport_binding_id == ClientCredential.transport_binding_id)
            & (TransportBinding.actor_id == ClientCredential.actor_id)
            & (TransportBinding.client_id == ClientCredential.client_id),
        )
        .where(
            ClientCredential.tenant_id == tenant_id,
            ClientCredential.credential_id == credential_id,
        )
    )
    if for_update:
        statement = statement.with_for_update(of=ClientCredential)
    row = (await session.execute(statement)).one_or_none()
    if row is None:
        return None
    credential, tenant, actor, client, binding = row
    return _CredentialState(
        credential=credential,
        tenant=tenant,
        actor=actor,
        client=client,
        binding=binding,
    )


def _state_is_active(
    state: _CredentialState,
    *,
    transport_kind: TransportKind,
    installation_id: UUID | None,
    used_at: datetime,
) -> bool:
    credential = state.credential
    binding = state.binding
    client = state.client
    return bool(
        credential.kind == "bearer_token"
        and credential.secret_hash is not None
        and credential.secret_hash_key_id is not None
        and credential.revoked_at is None
        and (credential.expires_at is None or credential.expires_at > used_at)
        and credential.created_at <= used_at
        and state.tenant.state == "active"
        and state.actor.kind == "agent"
        and state.actor.metadata_.get("provisioning_contract") == "scalevault-codex-installation-v1"
        and state.actor.revoked_at is None
        and client.kind == "interactive"
        and client.revoked_at is None
        and transport_kind is TransportKind.DIRECT_PRIVATE
        and installation_id is None
        and client.transport_kind == transport_kind.value
        and binding.transport_kind == transport_kind.value
        and binding.disclosure_boundary == "private_node"
        and binding.installation_id is None
        and (binding.valid_until is None or binding.valid_until > used_at)
    )


def _credential_lookup_statement(
    tenant_hint: UUID,
    credential_id: UUID,
) -> Select[tuple[UUID, UUID, str | None, str | None]]:
    """Select only the verifier tuple before bearer HMAC authentication."""

    return select(
        ClientCredential.tenant_id,
        ClientCredential.credential_id,
        ClientCredential.secret_hash,
        ClientCredential.secret_hash_key_id,
    ).where(
        ClientCredential.tenant_id == tenant_hint,
        ClientCredential.credential_id == credential_id,
        ClientCredential.kind == "bearer_token",
        ClientCredential.revoked_at.is_(None),
        ClientCredential.created_at <= func.current_timestamp(),
        (
            ClientCredential.expires_at.is_(None)
            | (ClientCredential.expires_at > func.current_timestamp())
        ),
        ClientCredential.secret_hash.is_not(None),
        ClientCredential.secret_hash_key_id.is_not(None),
    )


def _monotonic_audit_timestamp(
    current: datetime | None,
    database_now: datetime,
) -> datetime:
    """Preserve monotonic audit state if the database wall clock rolls backward."""

    return database_now if current is None or current < database_now else current


def _identity_from_state(state: _CredentialState) -> CredentialIdentity:
    scopes = tuple(state.client.scopes)
    if not scopes or len(scopes) != len(set(scopes)) or not set(scopes) <= ALLOWED_CLIENT_SCOPES:
        raise CredentialStorageError
    try:
        capability = _capability_profile_from_jsonb(state.client.capability_profile)
    except (TypeError, ValueError):
        raise CredentialStorageError from None
    operations = state.binding.authorized_operations
    if set(operations) != {"operations"} or not isinstance(operations["operations"], list):
        raise CredentialStorageError
    raw_operations = operations["operations"]
    if any(not isinstance(value, str) for value in raw_operations):
        raise CredentialStorageError
    authorized = frozenset(cast(list[str], raw_operations))
    if len(authorized) != len(raw_operations):
        raise CredentialStorageError
    return CredentialIdentity(
        tenant_id=state.tenant.tenant_id,
        actor_id=state.actor.actor_id,
        client_id=state.client.client_id,
        credential_id=state.credential.credential_id,
        transport_binding_id=state.binding.transport_binding_id,
        transport_kind=TransportKind(state.binding.transport_kind).value,
        disclosure_boundary=state.binding.disclosure_boundary,
        installation_id=state.binding.installation_id,
        client_scopes=tuple(scopes),
        capability_profile=capability.model_dump(mode="json"),
        authorized_operations=tuple(sorted(authorized)),
    )


async def _load_admin_credential(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    credential_id: UUID,
) -> _AdminCredentialState | None:
    row = (
        await session.execute(
            _admin_credential_statement()
            .where(
                ClientCredential.tenant_id == tenant_id,
                ClientCredential.credential_id == credential_id,
                ClientCredential.kind == "bearer_token",
            )
            .with_for_update(of=ClientCredential)
        )
    ).one_or_none()
    if row is None:
        return None
    return _admin_state(row)


def _admin_credential_statement() -> Select[_AdminCredentialRow]:
    return (
        select(
            ClientCredential.credential_id,
            ClientCredential.tenant_id,
            ClientCredential.actor_id,
            ClientCredential.client_id,
            ClientCredential.transport_binding_id,
            ClientCredential.public_hint,
            ClientCredential.created_at,
            ClientCredential.expires_at,
            ClientCredential.last_used_at,
            ClientCredential.revoked_at,
            Client.scopes,
            Client.capability_profile,
            Actor.metadata_,
        )
        .join(
            Client,
            (Client.tenant_id == ClientCredential.tenant_id)
            & (Client.client_id == ClientCredential.client_id),
        )
        .join(
            Actor,
            (Actor.tenant_id == ClientCredential.tenant_id)
            & (Actor.actor_id == ClientCredential.actor_id),
        )
    )


def _admin_state(row: Row[_AdminCredentialRow]) -> _AdminCredentialState:
    values = row._tuple()
    return _AdminCredentialState(
        credential_id=values[0],
        tenant_id=values[1],
        actor_id=values[2],
        client_id=values[3],
        transport_binding_id=values[4],
        public_hint=values[5],
        created_at=values[6],
        expires_at=values[7],
        last_used_at=values[8],
        revoked_at=values[9],
        client_scopes=tuple(values[10]),
        capability_profile=values[11],
        actor_metadata=values[12],
    )


def _metadata_from_issuance(issuance: CodexInstallationIssuance) -> CredentialMetadata:
    return CredentialMetadata(
        credential_id=issuance.credential_id,
        tenant_id=issuance.tenant_id,
        actor_id=issuance.actor_id,
        client_id=issuance.client_id,
        transport_binding_id=issuance.transport_binding_id,
        host_label=issuance.host_label,
        environment_label=issuance.environment_label,
        public_hint=issuance.public_hint,
        scopes=issuance.client_scopes,
        capability_profile=issuance.client_capability_profile,
        created_at=issuance.created_at,
        expires_at=issuance.expires_at,
        last_used_at=None,
        revoked_at=None,
    )


def _metadata_from_state(state: _AdminCredentialState) -> CredentialMetadata:
    host, environment = _actor_labels(state.actor_metadata)
    try:
        profile = _capability_profile_from_jsonb(state.capability_profile)
    except (TypeError, ValueError):
        raise CredentialAdminError("credential_metadata_invalid") from None
    return CredentialMetadata(
        credential_id=state.credential_id,
        tenant_id=state.tenant_id,
        actor_id=state.actor_id,
        client_id=state.client_id,
        transport_binding_id=state.transport_binding_id,
        host_label=host,
        environment_label=environment,
        public_hint=state.public_hint or "",
        scopes=state.client_scopes,
        capability_profile=profile,
        created_at=state.created_at,
        expires_at=state.expires_at,
        last_used_at=state.last_used_at,
        revoked_at=state.revoked_at,
    )


def _capability_profile_from_jsonb(value: dict[str, object]) -> ClientCapabilityProfile:
    """Hydrate strict capability types through their canonical JSON representation."""

    if not isinstance(value, dict) or set(value) != {"contract_version", "read"}:
        raise ValueError("capability profile JSON shape is invalid")
    read = value["read"]
    if read is not None:
        if not isinstance(read, dict) or set(read) != {
            "allowed_memory_scopes",
            "allowed_visibilities",
            "max_sensitivity",
            "allow_candidates",
        }:
            raise ValueError("read capability JSON shape is invalid")
        for field_name in ("allowed_memory_scopes", "allowed_visibilities"):
            values = read[field_name]
            if (
                not isinstance(values, list)
                or not values
                or any(not isinstance(item, str) for item in values)
                or len(values) != len(set(values))
            ):
                raise ValueError("read capability collection is invalid")
    return ClientCapabilityProfile.model_validate_json(
        canonical_json_bytes(value),
        strict=True,
    )


def _actor_labels(metadata: dict[str, object]) -> tuple[str, str]:
    host = metadata.get("host_label")
    environment = metadata.get("environment_label")
    if (
        not isinstance(host, str)
        or _LABEL_PATTERN.fullmatch(host) is None
        or not isinstance(environment, str)
        or _LABEL_PATTERN.fullmatch(environment) is None
    ):
        raise CredentialAdminError("credential_metadata_invalid")
    return host, environment


def _validate_issuance(issuance: CodexInstallationIssuance) -> None:
    for name in (
        "tenant_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "credential_id",
    ):
        _require_identifier(cast(UUID, getattr(issuance, name)), name)
    if (
        _VERIFIER_PATTERN.fullmatch(issuance.secret_hash) is None
        or _KEY_ID_PATTERN.fullmatch(issuance.secret_hash_key_id) is None
        or not issuance.client_scopes
        or len(issuance.client_scopes) != len(set(issuance.client_scopes))
        or not set(issuance.client_scopes) <= ALLOWED_CLIENT_SCOPES
        or issuance.client_scopes != tuple(sorted(issuance.client_scopes))
        or _LABEL_PATTERN.fullmatch(issuance.host_label) is None
        or _LABEL_PATTERN.fullmatch(issuance.environment_label) is None
    ):
        raise CredentialAdminError("credential_request_invalid")
    created = _require_admin_timestamp(issuance.created_at)
    if issuance.expires_at is not None and _require_admin_timestamp(issuance.expires_at) <= created:
        raise CredentialAdminError("credential_request_invalid")


def _validate_replacement(
    replacement: BearerCredentialReplacement,
    *,
    tenant_id: UUID,
) -> None:
    _require_identifier(replacement.credential_id, "credential_id")
    _require_identifier(replacement.tenant_id, "tenant_id")
    if (
        replacement.tenant_id != tenant_id
        or _VERIFIER_PATTERN.fullmatch(replacement.secret_hash) is None
        or _KEY_ID_PATTERN.fullmatch(replacement.secret_hash_key_id) is None
    ):
        raise CredentialAdminError("credential_request_invalid")
    created = _require_admin_timestamp(replacement.created_at)
    if (
        replacement.expires_at is not None
        and _require_admin_timestamp(replacement.expires_at) <= created
    ):
        raise CredentialAdminError("credential_request_invalid")


def _require_identifier(value: UUID, field_name: str) -> None:
    try:
        require_uuid7(value, field_name=field_name)
    except (TypeError, ValueError):
        raise CredentialAdminError("credential_request_invalid") from None


def _require_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _require_admin_timestamp(value: datetime) -> datetime:
    try:
        return _require_utc(value)
    except (TypeError, ValueError):
        raise CredentialAdminError("credential_request_invalid") from None


__all__ = [
    "CredentialAdminStorageRepository",
    "CredentialIdentity",
    "CredentialLookup",
    "CredentialRepository",
    "CredentialRepositoryProtocol",
    "CredentialStorageError",
]
