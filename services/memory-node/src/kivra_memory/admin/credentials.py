"""Secret-safe provisioning of direct-private Codex installation identities."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Protocol
from uuid import UUID

from kivra_memory.auth import (
    BearerTokenCodec,
    BearerTokenHasher,
    ClientCapabilityProfile,
)
from kivra_memory.domain.identifiers import new_uuid7, require_uuid7

TOKEN_PEPPER_MINIMUM_BYTES: Final = 32
TOKEN_PEPPER_MAXIMUM_BYTES: Final = 128
_LABEL_PATTERN: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\Z")
ALLOWED_CLIENT_SCOPES: Final = frozenset(
    {
        "memory.read.conflicts",
        "memory.read.context",
        "memory.read.get",
        "memory.read.lineage",
        "memory.read.search",
        "memory.read.selection_history",
        "memory.read.timeline",
        "memory.status.ingress",
        "memory.status.transport",
        "memory.write.conflict.open",
        "memory.write.conflict.resolve",
        "memory.write.nominate",
        "memory.write.link",
        "memory.write.retire",
        "memory.write.forget",
    }
)
_WRITE_SCOPE_OPERATIONS: Final = {
    "memory.write.conflict.open": ("conflict_opened",),
    "memory.write.conflict.resolve": ("conflict_resolved",),
    "memory.write.nominate": ("observed", "remembered"),
    "memory.write.forget": ("tombstoned",),
    "memory.write.link": ("linked",),
    "memory.write.retire": ("retired",),
}


class CredentialAdminError(RuntimeError):
    """Content-free administration failure safe for a CLI boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class CodexInstallationIssuance:
    """Atomic persistence input containing a verifier but never a bearer secret."""

    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID
    credential_id: UUID
    host_label: str
    environment_label: str
    actor_handle: str
    actor_display_name: str
    actor_metadata: dict[str, object]
    client_public_id: str
    client_display_name: str
    client_scopes: tuple[str, ...]
    client_capability_profile: ClientCapabilityProfile
    authorized_operations: tuple[str, ...]
    public_hint: str
    secret_hash: str = field(repr=False)
    secret_hash_key_id: str
    created_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class BearerCredentialReplacement:
    """Atomic rotation input whose installation identity comes from the locked old row."""

    credential_id: UUID
    tenant_id: UUID
    secret_hash: str = field(repr=False)
    secret_hash_key_id: str
    created_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class CredentialMetadata:
    """Non-secret credential information suitable for operator listings."""

    credential_id: UUID
    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID
    host_label: str
    environment_label: str
    public_hint: str
    scopes: tuple[str, ...]
    capability_profile: ClientCapabilityProfile
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class IssuedBearerCredential:
    """One-time bearer secret paired with its safe persisted metadata."""

    metadata: CredentialMetadata
    token: str = field(repr=False)


class CredentialAdminRepository(Protocol):
    """Atomic persistence boundary for operator credential lifecycle actions."""

    async def create_codex_installation(
        self,
        issuance: CodexInstallationIssuance,
    ) -> CredentialMetadata:
        """Atomically create the actor, client, binding, and bearer credential."""
        ...

    async def list_bearer_credentials(
        self,
        *,
        tenant_id: UUID,
        client_id: UUID | None,
    ) -> Sequence[CredentialMetadata]:
        """Return metadata only, in deterministic order."""
        ...

    async def revoke_bearer_credential(
        self,
        *,
        tenant_id: UUID,
        credential_id: UUID,
        revoked_at: datetime,
    ) -> CredentialMetadata:
        """Idempotently revoke one tenant credential without returning its verifier."""
        ...

    async def rotate_bearer_credential(
        self,
        *,
        tenant_id: UUID,
        credential_id: UUID,
        replacement: BearerCredentialReplacement,
        rotated_at: datetime,
    ) -> CredentialMetadata:
        """Atomically revoke the old credential and persist its replacement."""
        ...


class CredentialAdminService:
    """Generate secrets in memory and pass only deterministic verifiers to persistence."""

    def __init__(
        self,
        repository: CredentialAdminRepository,
        *,
        token_pepper: bytes,
        secret_hash_key_id: str,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(token_pepper, bytes) or not (
            TOKEN_PEPPER_MINIMUM_BYTES <= len(token_pepper) <= TOKEN_PEPPER_MAXIMUM_BYTES
        ):
            raise CredentialAdminError("credential_admin_configuration_invalid")
        if re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", secret_hash_key_id) is None:
            raise CredentialAdminError("credential_admin_configuration_invalid")
        self._repository = repository
        try:
            self._hasher = BearerTokenHasher(token_pepper)
        except ValueError:
            raise CredentialAdminError("credential_admin_configuration_invalid") from None
        self._secret_hash_key_id = secret_hash_key_id
        self._now = now or (lambda: datetime.now(UTC))

    async def create(
        self,
        *,
        tenant_id: UUID,
        host_label: str,
        environment_label: str,
        scopes: Sequence[str],
        capability_profile: ClientCapabilityProfile,
        expires_at: datetime | None = None,
    ) -> IssuedBearerCredential:
        """Create one distinguishable direct-private Codex installation and secret."""

        require_uuid7(tenant_id, field_name="tenant_id")
        host = _require_label(host_label)
        environment = _require_label(environment_label)
        selected_scopes = _require_scopes(scopes, capability_profile)
        created_at = _require_utc(self._now())
        expiry = _require_expiry(expires_at, after=created_at)
        actor_id = new_uuid7()
        client_id = new_uuid7()
        binding_id = new_uuid7()
        credential_id = new_uuid7()
        issued = BearerTokenCodec.issue(tenant_id, credential_id, self._hasher)
        safe_name = f"Codex {host} ({environment})"
        public_hint = f"codex:{environment}:{host}"
        issuance = CodexInstallationIssuance(
            tenant_id=tenant_id,
            actor_id=actor_id,
            client_id=client_id,
            transport_binding_id=binding_id,
            credential_id=credential_id,
            host_label=host,
            environment_label=environment,
            actor_handle=f"codex-{environment}-{host}",
            actor_display_name=safe_name,
            actor_metadata={
                "environment_label": environment,
                "host_label": host,
                "provisioning_contract": "scalevault-codex-installation-v1",
            },
            client_public_id=f"codex-{environment}-{host}-{tenant_id}",
            client_display_name=safe_name,
            client_scopes=selected_scopes,
            client_capability_profile=capability_profile,
            authorized_operations=_authorized_operations(selected_scopes),
            public_hint=public_hint,
            secret_hash=issued.secret_hash,
            secret_hash_key_id=self._secret_hash_key_id,
            created_at=created_at,
            expires_at=expiry,
        )
        metadata = await self._repository.create_codex_installation(issuance)
        _require_matching_installation(metadata, issuance)
        return IssuedBearerCredential(metadata=metadata, token=issued.token)

    async def list_metadata(
        self,
        *,
        tenant_id: UUID,
        client_id: UUID | None = None,
    ) -> tuple[CredentialMetadata, ...]:
        """List only safe metadata; verifier and token bytes are not representable."""

        require_uuid7(tenant_id, field_name="tenant_id")
        if client_id is not None:
            require_uuid7(client_id, field_name="client_id")
        records = tuple(
            await self._repository.list_bearer_credentials(
                tenant_id=tenant_id,
                client_id=client_id,
            )
        )
        if any(record.tenant_id != tenant_id for record in records):
            raise CredentialAdminError("credential_repository_invalid")
        return records

    async def revoke(
        self,
        *,
        tenant_id: UUID,
        credential_id: UUID,
    ) -> CredentialMetadata:
        """Idempotently revoke one credential by its public UUID."""

        require_uuid7(tenant_id, field_name="tenant_id")
        require_uuid7(credential_id, field_name="credential_id")
        metadata = await self._repository.revoke_bearer_credential(
            tenant_id=tenant_id,
            credential_id=credential_id,
            revoked_at=_require_utc(self._now()),
        )
        if metadata.tenant_id != tenant_id or metadata.credential_id != credential_id:
            raise CredentialAdminError("credential_repository_invalid")
        return metadata

    async def rotate(
        self,
        *,
        tenant_id: UUID,
        credential_id: UUID,
        expires_at: datetime | None = None,
    ) -> IssuedBearerCredential:
        """Atomically replace one credential and return only the new secret."""

        require_uuid7(tenant_id, field_name="tenant_id")
        require_uuid7(credential_id, field_name="credential_id")
        rotated_at = _require_utc(self._now())
        expiry = _require_expiry(expires_at, after=rotated_at)
        replacement_id = new_uuid7()
        issued = BearerTokenCodec.issue(tenant_id, replacement_id, self._hasher)
        replacement = BearerCredentialReplacement(
            credential_id=replacement_id,
            tenant_id=tenant_id,
            secret_hash=issued.secret_hash,
            secret_hash_key_id=self._secret_hash_key_id,
            created_at=rotated_at,
            expires_at=expiry,
        )
        metadata = await self._repository.rotate_bearer_credential(
            tenant_id=tenant_id,
            credential_id=credential_id,
            replacement=replacement,
            rotated_at=rotated_at,
        )
        if metadata.tenant_id != tenant_id or metadata.credential_id != replacement_id:
            raise CredentialAdminError("credential_repository_invalid")
        return IssuedBearerCredential(metadata=metadata, token=issued.token)


def _require_matching_installation(
    metadata: CredentialMetadata,
    issuance: CodexInstallationIssuance,
) -> None:
    if (
        metadata.credential_id != issuance.credential_id
        or metadata.tenant_id != issuance.tenant_id
        or metadata.actor_id != issuance.actor_id
        or metadata.client_id != issuance.client_id
        or metadata.transport_binding_id != issuance.transport_binding_id
        or metadata.public_hint != issuance.public_hint
        or metadata.host_label != issuance.host_label
        or metadata.environment_label != issuance.environment_label
        or metadata.scopes != issuance.client_scopes
        or metadata.capability_profile != issuance.client_capability_profile
    ):
        raise CredentialAdminError("credential_repository_invalid")


def _require_label(value: str) -> str:
    if not isinstance(value, str) or _LABEL_PATTERN.fullmatch(value) is None:
        raise CredentialAdminError("credential_request_invalid")
    return value


def _require_scopes(
    values: Sequence[str], capability_profile: ClientCapabilityProfile
) -> tuple[str, ...]:
    scopes = tuple(sorted(set(values)))
    if not scopes or len(scopes) != len(values) or not set(scopes) <= ALLOWED_CLIENT_SCOPES:
        raise CredentialAdminError("credential_request_invalid")
    has_read_scope = any(scope.startswith("memory.read.") for scope in scopes)
    if has_read_scope != (capability_profile.read is not None):
        raise CredentialAdminError("credential_request_invalid")
    return scopes


def _authorized_operations(scopes: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {operation for scope in scopes for operation in _WRITE_SCOPE_OPERATIONS.get(scope, ())}
        )
    )


def _require_expiry(value: datetime | None, *, after: datetime) -> datetime | None:
    if value is None:
        return None
    expiry = _require_utc(value)
    if expiry <= after:
        raise CredentialAdminError("credential_request_invalid")
    return expiry


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CredentialAdminError("credential_request_invalid")
    return value.astimezone(UTC)


__all__ = [
    "ALLOWED_CLIENT_SCOPES",
    "TOKEN_PEPPER_MAXIMUM_BYTES",
    "TOKEN_PEPPER_MINIMUM_BYTES",
    "BearerCredentialReplacement",
    "CodexInstallationIssuance",
    "CredentialAdminError",
    "CredentialAdminRepository",
    "CredentialAdminService",
    "CredentialMetadata",
    "IssuedBearerCredential",
]
