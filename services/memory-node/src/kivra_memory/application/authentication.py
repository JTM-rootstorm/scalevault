"""Request-scoped bearer authentication and principal derivation."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from pydantic import ValidationError

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.auth.contracts import (
    AuthenticatedRequestIdentity,
    BearerAuthenticationError,
    BearerTokenCodec,
    BearerTokenHasher,
    ClientCapabilityProfile,
    RequestTransportIdentity,
    StatusIdentity,
)
from kivra_memory.domain.enums import EventOperation, MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.retrieval.contracts import QueryPrincipal

_SUPPORTED_SCOPES = frozenset(
    {
        "memory.read.context",
        "memory.read.search",
        "memory.read.get",
        "memory.read.timeline",
        "memory.read.conflicts",
        "memory.read.lineage",
        "memory.read.selection_history",
        "memory.status.ingress",
        "memory.status.transport",
        "memory.write.nominate",
        "memory.write.link",
        "memory.write.conflict.open",
        "memory.write.conflict.resolve",
        "memory.write.retire",
        "memory.write.forget",
    }
)
_READ_SCOPES = frozenset(scope for scope in _SUPPORTED_SCOPES if scope.startswith("memory.read."))
_QUERY_SCOPES = _READ_SCOPES | {"memory.status.ingress", "memory.status.transport"}
_WRITE_SCOPE_OPERATIONS: Mapping[str, frozenset[EventOperation]] = {
    "memory.write.nominate": frozenset({EventOperation.OBSERVED, EventOperation.REMEMBERED}),
    "memory.write.link": frozenset({EventOperation.LINKED}),
    "memory.write.conflict.open": frozenset({EventOperation.CONFLICT_OPENED}),
    "memory.write.conflict.resolve": frozenset({EventOperation.CONFLICT_RESOLVED}),
    "memory.write.retire": frozenset({EventOperation.RETIRED}),
    "memory.write.forget": frozenset({EventOperation.TOMBSTONED}),
}


@dataclass(frozen=True, slots=True)
class CredentialLookup:
    """First-phase tenant-scoped verifier lookup with secret-safe repr."""

    tenant_id: UUID
    credential_id: UUID
    hash_key_id: str
    secret_verifier: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class CredentialIdentity:
    """Identity returned only after persistence locks and rechecks active state."""

    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    credential_id: UUID
    transport_binding_id: UUID
    transport_kind: str
    disclosure_boundary: str
    installation_id: UUID | None
    client_scopes: tuple[str, ...]
    capability_profile: Mapping[str, object]
    authorized_operations: tuple[str, ...]


class CredentialRepository(Protocol):
    """Two-phase persistence boundary preserving tenant RLS and revocation races."""

    async def lookup(
        self,
        tenant_hint: UUID,
        credential_id: UUID,
        /,
    ) -> CredentialLookup | None:
        """Return only verifier metadata through ordinary tenant RLS."""
        ...

    async def record_successful_use(
        self,
        lookup: CredentialLookup,
        /,
        *,
        transport_kind: TransportKind,
        installation_id: UUID | None,
        used_at: datetime,
    ) -> CredentialIdentity | None:
        """Lock/recheck verifier, active joins, and trusted transport, then record use."""
        ...


class BearerAuthenticator:
    """Authenticate one direct-private request without caching authority."""

    def __init__(
        self,
        repository: CredentialRepository,
        *,
        hashers: Mapping[str, BearerTokenHasher],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not hashers or any(
            not key or not isinstance(value, BearerTokenHasher) for key, value in hashers.items()
        ):
            raise ValueError("bearer authenticator configuration is invalid")
        self._repository = repository
        self._hashers = dict(hashers)
        self._dummy_hasher = next(iter(self._hashers.values()))
        self._clock = clock or (lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return "BearerAuthenticator(<redacted>)"

    async def authenticate(
        self,
        authorization_header: str | None,
        expected_transport: RequestTransportIdentity,
        /,
    ) -> AuthenticatedRequestIdentity:
        """Resolve one header to immutable application principals or fail identically."""

        hmac_performed = False
        try:
            credential = BearerTokenCodec.parse_authorization(authorization_header)
            if (
                expected_transport.transport_kind is not TransportKind.DIRECT_PRIVATE
                or expected_transport.installation_id is not None
            ):
                self._dummy_hasher.verify(credential, "")
                hmac_performed = True
                raise BearerAuthenticationError
            lookup = await self._repository.lookup(
                credential.tenant_id,
                credential.credential_id,
            )
            if lookup is None:
                self._dummy_hasher.verify(credential, "")
                hmac_performed = True
                raise BearerAuthenticationError
            if (
                lookup.tenant_id != credential.tenant_id
                or lookup.credential_id != credential.credential_id
            ):
                self._dummy_hasher.verify(credential, lookup.secret_verifier)
                hmac_performed = True
                raise BearerAuthenticationError
            hasher = self._hashers.get(lookup.hash_key_id)
            if hasher is None:
                self._dummy_hasher.verify(credential, lookup.secret_verifier)
                hmac_performed = True
                raise BearerAuthenticationError
            verified = hasher.verify(credential, lookup.secret_verifier)
            hmac_performed = True
            if not verified:
                raise BearerAuthenticationError
            used_at = self._clock()
            if used_at.tzinfo is None or used_at.utcoffset() is None:
                raise BearerAuthenticationError
            identity = await self._repository.record_successful_use(
                lookup,
                transport_kind=expected_transport.transport_kind,
                installation_id=expected_transport.installation_id,
                used_at=used_at.astimezone(UTC),
            )
            if identity is None:
                raise BearerAuthenticationError
            if (
                identity.tenant_id != lookup.tenant_id
                or identity.credential_id != lookup.credential_id
            ):
                raise BearerAuthenticationError
            return _principals(identity, expected_transport)
        except BearerAuthenticationError:
            if not hmac_performed:
                self._perform_dummy_verification()
            raise
        except Exception:
            if not hmac_performed:
                self._perform_dummy_verification()
            raise BearerAuthenticationError from None

    def _perform_dummy_verification(self) -> None:
        dummy = BearerTokenCodec.parse_authorization(
            "Bearer svb1.00000000-0000-7000-8000-000000000000."
            "00000000-0000-7000-8000-000000000001.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        self._dummy_hasher.verify(dummy, "")


def _principals(
    identity: CredentialIdentity,
    expected_transport: RequestTransportIdentity,
) -> AuthenticatedRequestIdentity:
    if (
        identity.transport_kind != TransportKind.DIRECT_PRIVATE.value
        or identity.disclosure_boundary != "private_node"
        or identity.installation_id is not None
        or expected_transport.transport_kind is not TransportKind.DIRECT_PRIVATE
        or expected_transport.installation_id is not None
    ):
        raise BearerAuthenticationError

    scopes = _validated_scopes(identity.client_scopes)
    operations = _validated_operations(identity.authorized_operations)
    required_operations = frozenset(
        operation
        for scope, scope_operations in _WRITE_SCOPE_OPERATIONS.items()
        if scope in scopes
        for operation in scope_operations
    )
    if operations != required_operations:
        raise BearerAuthenticationError
    profile = _validated_capability_profile(identity.capability_profile)
    read_scopes = scopes & _READ_SCOPES
    if read_scopes and profile.read is None:
        raise BearerAuthenticationError
    read = profile.read
    command_scopes = scopes & frozenset(_WRITE_SCOPE_OPERATIONS)
    query_scopes = scopes & _QUERY_SCOPES
    command_principal = CommandPrincipal(
        tenant_id=identity.tenant_id,
        actor_id=identity.actor_id,
        client_id=identity.client_id,
        transport_binding_id=identity.transport_binding_id,
        scopes=frozenset(command_scopes),
        ingress_id=None,
    )
    query_principal = QueryPrincipal(
        tenant_id=identity.tenant_id,
        actor_id=identity.actor_id,
        client_id=identity.client_id,
        transport_binding_id=identity.transport_binding_id,
        scopes=frozenset(query_scopes),
        allowed_memory_scopes=(
            frozenset(read.allowed_memory_scopes) if read is not None else frozenset()
        ),
        allowed_visibilities=(
            frozenset(read.allowed_visibilities) if read is not None else frozenset()
        ),
        max_sensitivity=read.max_sensitivity if read is not None else 0,
        allow_candidates=read.allow_candidates if read is not None else False,
        ingress_id=None,
    )
    status_identity = StatusIdentity(
        tenant_id=identity.tenant_id,
        actor_id=identity.actor_id,
        client_id=identity.client_id,
        credential_id=identity.credential_id,
        transport_binding_id=identity.transport_binding_id,
        transport_kind=TransportKind(identity.transport_kind),
        disclosure_boundary="private_node",
        installation_id=None,
    )
    try:
        return AuthenticatedRequestIdentity(
            command_principal=command_principal,
            query_principal=query_principal,
            status_identity=status_identity,
        )
    except ValidationError:
        raise BearerAuthenticationError from None


def _validated_scopes(values: tuple[str, ...]) -> frozenset[str]:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) > 64
        or len(values) != len(set(values))
        or any(not isinstance(value, str) or value not in _SUPPORTED_SCOPES for value in values)
    ):
        raise BearerAuthenticationError
    return frozenset(values)


def _validated_operations(values: tuple[str, ...]) -> frozenset[EventOperation]:
    if (
        not isinstance(values, tuple)
        or len(values) > len(EventOperation)
        or len(values) != len(set(values))
    ):
        raise BearerAuthenticationError
    try:
        return frozenset(EventOperation(value) for value in values)
    except (TypeError, ValueError):
        raise BearerAuthenticationError from None


def _validated_capability_profile(value: Mapping[str, object]) -> ClientCapabilityProfile:
    if not isinstance(value, dict):
        raise BearerAuthenticationError
    document = dict(value)
    read = document.get("read")
    if read is not None:
        if not isinstance(read, dict):
            raise BearerAuthenticationError
        read_document = dict(read)
        for field_name, enum_type in (
            ("allowed_memory_scopes", MemoryScope),
            ("allowed_visibilities", MemoryVisibility),
        ):
            raw_values = read_document.get(field_name)
            if (
                not isinstance(raw_values, list)
                or not raw_values
                or len(raw_values) != len(set(raw_values))
                or any(not isinstance(item, str) for item in raw_values)
            ):
                raise BearerAuthenticationError
            try:
                read_document[field_name] = frozenset(enum_type(item) for item in raw_values)
            except ValueError:
                raise BearerAuthenticationError from None
        document["read"] = read_document
    try:
        return ClientCapabilityProfile.model_validate(document)
    except ValidationError:
        raise BearerAuthenticationError from None


__all__ = [
    "BearerAuthenticator",
    "CredentialIdentity",
    "CredentialLookup",
    "CredentialRepository",
]
