"""Versioned bearer credentials and authenticated request identity contracts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.retrieval.contracts import QueryPrincipal

BEARER_TOKEN_VERSION = "svb1"
BEARER_VERIFIER_VERSION = "hmac-sha256-v1"
CLIENT_CAPABILITY_VERSION = "scalevault-client-capability-v1"
_SECRET_BYTES = 32
_B64URL_BYTES_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_UUID7_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_TOKEN_PATTERN = re.compile(
    rf"^svb1\.({_UUID7_PATTERN})\.({_UUID7_PATTERN})\.([A-Za-z0-9_-]{{43}})$"
)
_VERIFIER_PATTERN = re.compile(r"^hmac-sha256-v1:([A-Za-z0-9_-]{43})$")
_HASH_DOMAIN = b"scalevault-client-bearer-token-v1\x00"


class BearerAuthenticationError(Exception):
    """One deliberately indistinguishable, content-free authentication failure."""

    def __init__(self) -> None:
        super().__init__("authentication failed")


@dataclass(frozen=True, repr=False)
class BearerCredential:
    """Parsed secret-bearing credential; repr deliberately reveals no fields."""

    tenant_id: UUID
    credential_id: UUID
    secret: bytes

    def __repr__(self) -> str:
        return "BearerCredential(<redacted>)"


@dataclass(frozen=True, repr=False)
class IssuedBearerCredential:
    """One-time issuance result whose repr never exposes token or verifier."""

    token: str
    secret_hash: str

    def __repr__(self) -> str:
        return "IssuedBearerCredential(<redacted>)"


class BearerTokenHasher:
    """Create and verify purpose-separated HMAC bearer verifiers."""

    def __init__(self, pepper: bytes) -> None:
        if not isinstance(pepper, bytes) or len(pepper) < 32:
            raise ValueError("bearer token pepper must contain at least 32 bytes")
        self._pepper = pepper

    def __repr__(self) -> str:
        return "BearerTokenHasher(<redacted>)"

    @staticmethod
    def _canonical_token(credential: BearerCredential) -> str:
        return (
            f"{BEARER_TOKEN_VERSION}.{credential.tenant_id}.{credential.credential_id}."
            f"{_encode_b64url(credential.secret)}"
        )

    def hash(self, credential: BearerCredential) -> str:
        canonical_token = self._canonical_token(credential)
        digest = hmac.new(
            self._pepper,
            _HASH_DOMAIN + canonical_token.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return f"{BEARER_VERIFIER_VERSION}:{_encode_b64url(digest)}"

    def verify(self, credential: BearerCredential, verifier: str) -> bool:
        if not isinstance(verifier, str) or _VERIFIER_PATTERN.fullmatch(verifier) is None:
            expected = f"{BEARER_VERIFIER_VERSION}:{'A' * 43}"
        else:
            expected = verifier
        actual = self.hash(credential)
        return hmac.compare_digest(actual.encode("ascii"), expected.encode("ascii"))


class BearerTokenCodec:
    """Issue and strictly parse the accepted version-one bearer wire format."""

    @staticmethod
    def issue(
        tenant_id: UUID,
        credential_id: UUID,
        hasher: BearerTokenHasher,
        *,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> IssuedBearerCredential:
        require_uuid7(tenant_id, field_name="tenant_id")
        require_uuid7(credential_id, field_name="credential_id")
        secret = random_bytes(_SECRET_BYTES)
        if not isinstance(secret, bytes) or len(secret) != _SECRET_BYTES:
            raise ValueError("bearer secret source returned invalid material")
        credential = BearerCredential(
            tenant_id=tenant_id,
            credential_id=credential_id,
            secret=secret,
        )
        token = BearerTokenHasher._canonical_token(credential)
        return IssuedBearerCredential(token=token, secret_hash=hasher.hash(credential))

    @staticmethod
    def parse_authorization(authorization_header: str | None) -> BearerCredential:
        if not isinstance(authorization_header, str) or len(authorization_header) > 256:
            raise BearerAuthenticationError
        if len(authorization_header) < 8 or authorization_header[6] != " ":
            raise BearerAuthenticationError
        if authorization_header[:6].lower() != "bearer":
            raise BearerAuthenticationError
        token = authorization_header[7:]
        match = _TOKEN_PATTERN.fullmatch(token)
        if match is None:
            raise BearerAuthenticationError
        try:
            tenant_id = UUID(match.group(1))
            credential_id = UUID(match.group(2))
            require_uuid7(tenant_id, field_name="tenant_id")
            require_uuid7(credential_id, field_name="credential_id")
            secret = _decode_b64url(match.group(3))
        except (ValueError, TypeError, binascii.Error):
            raise BearerAuthenticationError from None
        if len(secret) != _SECRET_BYTES:
            raise BearerAuthenticationError
        return BearerCredential(
            tenant_id=tenant_id,
            credential_id=credential_id,
            secret=secret,
        )


def _encode_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if _B64URL_BYTES_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid base64url value")
    decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    if _encode_b64url(decoded) != value:
        raise ValueError("non-canonical base64url value")
    return decoded


class _AuthenticationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ReadCapability(_AuthenticationModel):
    """Server-controlled authorization ceilings for semantic reads."""

    allowed_memory_scopes: Annotated[frozenset[MemoryScope], Field(min_length=1)]
    allowed_visibilities: Annotated[frozenset[MemoryVisibility], Field(min_length=1)]
    max_sensitivity: Annotated[int, Field(ge=0, le=4)]
    allow_candidates: bool = False


class ClientCapabilityProfile(_AuthenticationModel):
    """Strict versioned shape stored on a bearer-authenticated client."""

    contract_version: Literal["scalevault-client-capability-v1"]
    read: ReadCapability | None = None


class RequestTransportIdentity(_AuthenticationModel):
    """Transport facts supplied by a trusted listener, never by MCP tool input."""

    transport_kind: TransportKind
    installation_id: UUID | None = None

    @field_validator("installation_id")
    @classmethod
    def validate_installation_id(cls, value: UUID | None) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name="installation_id")
        return value


class StatusIdentity(_AuthenticationModel):
    """Content-free authenticated identity for status and audit adapters."""

    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    credential_id: UUID
    transport_binding_id: UUID
    transport_kind: TransportKind
    disclosure_boundary: Literal["private_node"]
    installation_id: UUID | None = None

    @field_validator(
        "tenant_id",
        "actor_id",
        "client_id",
        "credential_id",
        "transport_binding_id",
        "installation_id",
    )
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))
        return value

    @model_validator(mode="after")
    def validate_transport_boundary(self) -> StatusIdentity:
        expected = {TransportKind.DIRECT_PRIVATE: "private_node"}.get(self.transport_kind)
        if expected is None or self.disclosure_boundary != expected:
            raise ValueError("unsupported bearer transport identity")
        return self


class AuthenticatedRequestIdentity(_AuthenticationModel):
    """Request-scoped principals derived entirely from authenticated storage state."""

    command_principal: CommandPrincipal
    query_principal: QueryPrincipal
    status_identity: StatusIdentity

    @model_validator(mode="after")
    def validate_principal_identity(self) -> AuthenticatedRequestIdentity:
        status = self.status_identity
        expected = (
            status.tenant_id,
            status.actor_id,
            status.client_id,
            status.transport_binding_id,
        )
        command = self.command_principal
        query = self.query_principal
        if (
            command.tenant_id,
            command.actor_id,
            command.client_id,
            command.transport_binding_id,
        ) != expected or (
            query.tenant_id,
            query.actor_id,
            query.client_id,
            query.transport_binding_id,
        ) != expected:
            raise ValueError("authenticated principal identities do not match")
        if command.ingress_id is not None or query.ingress_id is not None:
            raise ValueError("bearer identities cannot carry ingress provenance")
        return self


__all__ = [
    "BEARER_TOKEN_VERSION",
    "BEARER_VERIFIER_VERSION",
    "CLIENT_CAPABILITY_VERSION",
    "AuthenticatedRequestIdentity",
    "BearerAuthenticationError",
    "BearerCredential",
    "BearerTokenCodec",
    "BearerTokenHasher",
    "ClientCapabilityProfile",
    "IssuedBearerCredential",
    "ReadCapability",
    "RequestTransportIdentity",
    "StatusIdentity",
]
