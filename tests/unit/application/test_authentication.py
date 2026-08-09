from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock

import pytest
from kivra_memory.application.authentication import (
    BearerAuthenticator,
    CredentialIdentity,
    CredentialLookup,
    CredentialRepository,
)
from kivra_memory.auth import (
    BearerAuthenticationError,
    BearerTokenCodec,
    BearerTokenHasher,
    RequestTransportIdentity,
)
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.domain.identifiers import new_uuid7

NOW = datetime(2026, 8, 9, 18, tzinfo=UTC)
PEPPER = b"p" * 32
TENANT_ID = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=1)
ACTOR_ID = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=2)
CLIENT_ID = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=3)
CREDENTIAL_ID = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=4)
BINDING_ID = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=5)


class _CountingHasher(BearerTokenHasher):
    def __init__(self, pepper: bytes) -> None:
        super().__init__(pepper)
        self.verify_calls = 0

    def verify(self, credential: object, verifier: str) -> bool:
        self.verify_calls += 1
        return super().verify(credential, verifier)  # type: ignore[arg-type]


def _material() -> tuple[str, str]:
    issued = BearerTokenCodec.issue(
        TENANT_ID,
        CREDENTIAL_ID,
        BearerTokenHasher(PEPPER),
        random_bytes=lambda size: b"s" * size,
    )
    return f"Bearer {issued.token}", issued.secret_hash


def _profile() -> dict[str, object]:
    return {
        "contract_version": "scalevault-client-capability-v1",
        "read": {
            "allowed_memory_scopes": ["persona", "project"],
            "allowed_visibilities": ["private_root", "restricted"],
            "max_sensitivity": 4,
            "allow_candidates": False,
        },
    }


def _identity(**updates: object) -> CredentialIdentity:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "actor_id": ACTOR_ID,
        "client_id": CLIENT_ID,
        "credential_id": CREDENTIAL_ID,
        "transport_binding_id": BINDING_ID,
        "transport_kind": "direct_private",
        "disclosure_boundary": "private_node",
        "installation_id": None,
        "client_scopes": (
            "memory.read.context",
            "memory.status.transport",
            "memory.write.nominate",
        ),
        "capability_profile": _profile(),
        "authorized_operations": ("observed", "remembered"),
    }
    values.update(updates)
    return CredentialIdentity(**values)  # type: ignore[arg-type]


def _authenticator(
    identity: CredentialIdentity | None = None,
    *,
    verifier: str | None = None,
    hash_key_id: str = "pilot-v1",
    hasher: BearerTokenHasher | None = None,
) -> tuple[BearerAuthenticator, AsyncMock, AsyncMock]:
    _, expected_verifier = _material()
    lookup = CredentialLookup(
        tenant_id=TENANT_ID,
        credential_id=CREDENTIAL_ID,
        hash_key_id=hash_key_id,
        secret_verifier=verifier if verifier is not None else expected_verifier,
    )
    lookup_call = AsyncMock(return_value=lookup)
    successful_use = AsyncMock(return_value=identity or _identity())
    repository = AsyncMock(spec=CredentialRepository)
    repository.lookup = lookup_call
    repository.record_successful_use = successful_use
    authenticator = BearerAuthenticator(
        cast(CredentialRepository, repository),
        hashers={"pilot-v1": hasher or BearerTokenHasher(PEPPER)},
        clock=lambda: NOW,
    )
    return authenticator, lookup_call, successful_use


def _transport(kind: TransportKind = TransportKind.DIRECT_PRIVATE) -> RequestTransportIdentity:
    return RequestTransportIdentity(transport_kind=kind)


async def test_authentication_maps_storage_authority_to_all_typed_identities() -> None:
    header, _ = _material()
    authenticator, lookup, successful_use = _authenticator()

    result = await authenticator.authenticate(header, _transport())

    lookup.assert_awaited_once_with(TENANT_ID, CREDENTIAL_ID)
    successful_use.assert_awaited_once()
    assert successful_use.await_args.kwargs == {
        "transport_kind": TransportKind.DIRECT_PRIVATE,
        "installation_id": None,
        "used_at": NOW,
    }
    assert result.command_principal.model_dump() == {
        "tenant_id": TENANT_ID,
        "actor_id": ACTOR_ID,
        "client_id": CLIENT_ID,
        "transport_binding_id": BINDING_ID,
        "scopes": frozenset({"memory.write.nominate"}),
        "ingress_id": None,
    }
    assert result.query_principal.scopes == frozenset(
        {"memory.read.context", "memory.status.transport"}
    )
    assert result.query_principal.allowed_memory_scopes == frozenset(
        {MemoryScope.PERSONA, MemoryScope.PROJECT}
    )
    assert result.query_principal.allowed_visibilities == frozenset(
        {MemoryVisibility.PRIVATE_ROOT, MemoryVisibility.RESTRICTED}
    )
    assert result.query_principal.max_sensitivity == 4
    assert result.query_principal.ingress_id is None
    assert result.status_identity.credential_id == CREDENTIAL_ID
    assert result.status_identity.transport_kind is TransportKind.DIRECT_PRIVATE
    assert result.status_identity.installation_id is None


@pytest.mark.parametrize(
    ("identity", "transport"),
    [
        (_identity(client_scopes=("memory:read",)), _transport()),
        (_identity(client_scopes=("memory.write.legacy_v1",)), _transport()),
        (_identity(client_scopes=("memory.write.observe",)), _transport()),
        (_identity(client_scopes=("memory.write.revise",)), _transport()),
        (_identity(authorized_operations=("observed",)), _transport()),
        (
            _identity(authorized_operations=("observed", "remembered", "revised")),
            _transport(),
        ),
        (_identity(transport_kind="relay", disclosure_boundary="public_relay"), _transport()),
        (_identity(), _transport(TransportKind.RELAY)),
        (_identity(capability_profile={"contract_version": "unknown"}), _transport()),
        (
            _identity(
                capability_profile={
                    **_profile(),
                    "read": {**cast(dict[str, object], _profile()["read"]), "extra": True},
                }
            ),
            _transport(),
        ),
    ],
)
async def test_scope_binding_transport_and_capability_mismatches_fail_identically(
    identity: CredentialIdentity,
    transport: RequestTransportIdentity,
) -> None:
    header, _ = _material()
    authenticator, _, _ = _authenticator(identity)

    with pytest.raises(BearerAuthenticationError) as caught:
        await authenticator.authenticate(header, transport)

    assert str(caught.value) == "authentication failed"
    assert header not in str(caught.value)


async def test_verifier_mismatch_never_advances_successful_use() -> None:
    header, _ = _material()
    authenticator, _, successful_use = _authenticator(verifier="hmac-sha256-v1:" + "A" * 43)

    with pytest.raises(BearerAuthenticationError, match="authentication failed"):
        await authenticator.authenticate(header, _transport())

    successful_use.assert_not_awaited()


async def test_unknown_hash_key_missing_lookup_and_revocation_race_are_indistinguishable() -> None:
    header, _ = _material()
    unknown_key, _, successful_use = _authenticator(hash_key_id="retired-key")
    with pytest.raises(BearerAuthenticationError, match="authentication failed"):
        await unknown_key.authenticate(header, _transport())
    successful_use.assert_not_awaited()

    missing, missing_lookup, missing_use = _authenticator()
    missing_lookup.return_value = None
    with pytest.raises(BearerAuthenticationError, match="authentication failed"):
        await missing.authenticate(header, _transport())
    missing_use.assert_not_awaited()

    raced, _, raced_use = _authenticator()
    raced_use.return_value = None
    with pytest.raises(BearerAuthenticationError, match="authentication failed"):
        await raced.authenticate(header, _transport())


@pytest.mark.parametrize(
    "failure",
    ["missing_header", "malformed_header", "unknown", "wrong_secret", "wrong_tenant", "revoked"],
)
async def test_every_failure_path_performs_exactly_one_hmac(failure: str) -> None:
    header, _ = _material()
    hasher = _CountingHasher(PEPPER)
    verifier = "hmac-sha256-v1:" + "A" * 43 if failure == "wrong_secret" else None
    authenticator, lookup, successful_use = _authenticator(verifier=verifier, hasher=hasher)
    if failure == "missing_header":
        header = None  # type: ignore[assignment]
    elif failure == "malformed_header":
        header = "Bearer malformed"
    elif failure == "unknown":
        lookup.return_value = None
    elif failure == "wrong_tenant":
        lookup.return_value = replace(
            lookup.return_value,
            tenant_id=new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=20),
        )
    elif failure == "revoked":
        successful_use.return_value = None

    with pytest.raises(BearerAuthenticationError, match="authentication failed"):
        await authenticator.authenticate(header, _transport())

    assert hasher.verify_calls == 1


async def test_locked_identity_must_match_verified_lookup() -> None:
    header, _ = _material()
    authenticator, _, _ = _authenticator(replace(_identity(), credential_id=new_uuid7()))

    with pytest.raises(BearerAuthenticationError, match="authentication failed"):
        await authenticator.authenticate(header, _transport())


async def test_write_only_identity_receives_no_read_ceiling() -> None:
    header, _ = _material()
    identity = _identity(
        client_scopes=("memory.write.forget",),
        capability_profile={
            "contract_version": "scalevault-client-capability-v1",
            "read": None,
        },
        authorized_operations=("tombstoned",),
    )
    authenticator, _, _ = _authenticator(identity)

    result = await authenticator.authenticate(header, _transport())

    assert result.command_principal.scopes == frozenset({"memory.write.forget"})
    assert result.query_principal.scopes == frozenset()
    assert result.query_principal.allowed_memory_scopes == frozenset()
    assert result.query_principal.allowed_visibilities == frozenset()
    assert result.query_principal.max_sensitivity == 0
