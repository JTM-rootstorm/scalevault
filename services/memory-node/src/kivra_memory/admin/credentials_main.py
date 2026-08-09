"""Operator CLI for direct-private Codex bearer credential lifecycle actions."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Never, cast
from uuid import UUID

from kivra_memory.admin.credential_io import (
    DEFAULT_ADMIN_CONFIG_PATH,
    CredentialAdminSettings,
    load_or_create_authorization,
    write_one_time_secret,
)
from kivra_memory.admin.credentials import (
    ALLOWED_CLIENT_SCOPES,
    SECURE_TUNNEL_CLIENT_SCOPES,
    CredentialAdminError,
    CredentialAdminService,
    CredentialMetadata,
)
from kivra_memory.auth import ClientCapabilityProfile, ReadCapability
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility
from kivra_memory.storage.credentials import CredentialAdminStorageRepository
from kivra_memory.storage.database import Database

_DEFAULT_SCOPES = (
    "memory.read.conflicts",
    "memory.read.context",
    "memory.read.get",
    "memory.read.lineage",
    "memory.read.search",
    "memory.read.selection_history",
    "memory.read.timeline",
    "memory.status.transport",
    "memory.write.nominate",
)
_DEFAULT_MEMORY_SCOPES = (
    MemoryScope.GLOBAL,
    MemoryScope.PERSONA,
    MemoryScope.RELATIONSHIP,
    MemoryScope.PROJECT,
    MemoryScope.EPISODIC,
)
_DEFAULT_SECURE_TUNNEL_SCOPES = tuple(sorted(SECURE_TUNNEL_CLIENT_SCOPES))
_DEFAULT_VISIBILITIES = (
    MemoryVisibility.PRIVATE_ROOT,
    MemoryVisibility.RESTRICTED,
    MemoryVisibility.SHAREABLE,
    MemoryVisibility.PUBLIC_SEED,
)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        self.print_usage(sys.stderr)
        raise SystemExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="kivra-memory-credential-admin",
        description="Provision and rotate direct-private Codex bearer credentials.",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_ADMIN_CONFIG_PATH)
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create")
    create.add_argument("--tenant-id", type=UUID, required=True)
    create.add_argument("--host-label", required=True)
    create.add_argument("--environment-label", required=True)
    create.add_argument("--scope", action="append", choices=sorted(ALLOWED_CLIENT_SCOPES))
    create.add_argument(
        "--read-memory-scope",
        action="append",
        choices=[value.value for value in MemoryScope],
    )
    create.add_argument(
        "--read-visibility",
        action="append",
        choices=[value.value for value in MemoryVisibility],
    )
    create.add_argument("--max-sensitivity", type=int, choices=range(5), default=3)
    create.add_argument("--allow-candidates", action="store_true")
    create.add_argument("--expires-at", type=_parse_timestamp)
    _secret_output_arguments(create)

    secure_tunnel = commands.add_parser("create-secure-tunnel")
    secure_tunnel.add_argument("--tenant-id", type=UUID, required=True)
    secure_tunnel.add_argument("--actor-id", type=UUID, required=True)
    secure_tunnel.add_argument("--installation-id", type=UUID, required=True)
    secure_tunnel.add_argument("--tunnel-label", required=True)
    secure_tunnel.add_argument(
        "--scope",
        action="append",
        choices=sorted(SECURE_TUNNEL_CLIENT_SCOPES),
    )
    secure_tunnel.add_argument(
        "--read-memory-scope",
        action="append",
        choices=[value.value for value in MemoryScope],
    )
    secure_tunnel.add_argument(
        "--read-visibility",
        action="append",
        choices=[value.value for value in MemoryVisibility],
    )
    secure_tunnel.add_argument("--max-sensitivity", type=int, choices=range(5), default=3)
    secure_tunnel.add_argument("--allow-candidates", action="store_true")
    secure_tunnel.add_argument("--expires-at", type=_parse_timestamp)
    secure_tunnel.add_argument("--secret-output", type=Path, required=True)

    listing = commands.add_parser("list-metadata")
    listing.add_argument("--tenant-id", type=UUID, required=True)
    listing.add_argument("--client-id", type=UUID)

    revoke = commands.add_parser("revoke")
    revoke.add_argument("--tenant-id", type=UUID, required=True)
    revoke.add_argument("--credential-id", type=UUID, required=True)

    rotate = commands.add_parser("rotate")
    rotate.add_argument("--tenant-id", type=UUID, required=True)
    rotate.add_argument("--credential-id", type=UUID, required=True)
    rotate.add_argument("--expires-at", type=_parse_timestamp)
    _secret_output_arguments(rotate)

    secure_rotate = commands.add_parser("rotate-secure-tunnel")
    secure_rotate.add_argument("--tenant-id", type=UUID, required=True)
    secure_rotate.add_argument("--credential-id", type=UUID, required=True)
    secure_rotate.add_argument("--expires-at", type=_parse_timestamp)
    secure_rotate.add_argument("--secret-output", type=Path, required=True)
    return parser


def _secret_output_arguments(parser: argparse.ArgumentParser) -> None:
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--secret-output", type=Path)
    output.add_argument("--secret-stdout", action="store_true")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError("invalid timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("invalid timestamp")
    return parsed.astimezone(UTC)


async def _run(arguments: argparse.Namespace, settings: CredentialAdminSettings) -> None:
    database = Database(settings.database_url)
    repository = CredentialAdminStorageRepository(database.session_factory)
    service = CredentialAdminService(
        repository,
        token_pepper=settings.token_pepper,
        secret_hash_key_id=settings.secret_hash_key_id,
    )
    try:
        if arguments.command == "create":
            scopes = tuple(arguments.scope) if arguments.scope is not None else _DEFAULT_SCOPES
            capability = _capability_from_arguments(arguments, scopes=scopes)
            issued = await service.create(
                tenant_id=arguments.tenant_id,
                host_label=arguments.host_label,
                environment_label=arguments.environment_label,
                scopes=scopes,
                capability_profile=capability,
                expires_at=arguments.expires_at,
            )
            _emit_secret(arguments, issued.token)
            return
        if arguments.command == "create-secure-tunnel":
            secure_scopes = (
                tuple(arguments.scope)
                if arguments.scope is not None
                else _DEFAULT_SECURE_TUNNEL_SCOPES
            )
            secure_capability = _capability_from_arguments(
                arguments,
                scopes=secure_scopes,
            )
            record = await service.create_or_load_secure_tunnel(
                tenant_id=arguments.tenant_id,
                actor_id=arguments.actor_id,
                installation_id=arguments.installation_id,
                tunnel_label=arguments.tunnel_label,
                scopes=secure_scopes,
                capability_profile=secure_capability,
                authorization_artifact=lambda proposed: load_or_create_authorization(
                    cast(Path, arguments.secret_output),
                    proposed,
                ),
                expires_at=arguments.expires_at,
            )
            _emit_metadata((record,))
            return
        if arguments.command == "list-metadata":
            records = await service.list_metadata(
                tenant_id=arguments.tenant_id,
                client_id=arguments.client_id,
            )
            _emit_metadata(records)
            return
        if arguments.command == "revoke":
            record = await service.revoke(
                tenant_id=arguments.tenant_id,
                credential_id=arguments.credential_id,
            )
            _emit_metadata((record,))
            return
        if arguments.command == "rotate":
            issued = await service.rotate(
                tenant_id=arguments.tenant_id,
                credential_id=arguments.credential_id,
                expires_at=arguments.expires_at,
            )
            _emit_secret(arguments, issued.token)
            return
        if arguments.command == "rotate-secure-tunnel":
            rotated = await service.rotate_secure_tunnel(
                tenant_id=arguments.tenant_id,
                credential_id=arguments.credential_id,
                authorization_artifact=lambda proposed: load_or_create_authorization(
                    cast(Path, arguments.secret_output),
                    proposed,
                ),
                expires_at=arguments.expires_at,
            )
            _emit_metadata((rotated,))
            return
        raise CredentialAdminError("credential_request_invalid")
    finally:
        await database.dispose()


def _capability_from_arguments(
    arguments: argparse.Namespace,
    *,
    scopes: Sequence[str],
) -> ClientCapabilityProfile:
    has_read_scope = any(scope.startswith("memory.read.") for scope in scopes)
    explicit_capability = bool(
        arguments.read_memory_scope or arguments.read_visibility or arguments.allow_candidates
    )
    if not has_read_scope:
        if explicit_capability:
            raise CredentialAdminError("credential_request_invalid")
        return ClientCapabilityProfile(
            contract_version="scalevault-client-capability-v1",
            read=None,
        )
    selected_memory_scopes = (
        tuple(MemoryScope(value) for value in arguments.read_memory_scope)
        if arguments.read_memory_scope
        else _DEFAULT_MEMORY_SCOPES
    )
    selected_visibilities = (
        tuple(MemoryVisibility(value) for value in arguments.read_visibility)
        if arguments.read_visibility
        else _DEFAULT_VISIBILITIES
    )
    return ClientCapabilityProfile(
        contract_version="scalevault-client-capability-v1",
        read=ReadCapability(
            allowed_memory_scopes=frozenset(selected_memory_scopes),
            allowed_visibilities=frozenset(selected_visibilities),
            max_sensitivity=arguments.max_sensitivity,
            allow_candidates=arguments.allow_candidates,
        ),
    )


def _emit_secret(arguments: argparse.Namespace, token: str) -> None:
    output = cast(Path | None, arguments.secret_output)
    if output is not None:
        write_one_time_secret(output, token)
        return
    if arguments.secret_stdout is not True:
        raise CredentialAdminError("credential_secret_output_failed")
    sys.stdout.write(token + "\n")
    sys.stdout.flush()


def _emit_metadata(records: Sequence[CredentialMetadata]) -> None:
    safe = [
        {
            "actor_id": str(record.actor_id),
            "capability_profile": _capability_json(record.capability_profile),
            "client_id": str(record.client_id),
            "created_at": _timestamp(record.created_at),
            "credential_id": str(record.credential_id),
            "environment_label": record.environment_label,
            "expires_at": _timestamp(record.expires_at),
            "host_label": record.host_label,
            "last_used_at": _timestamp(record.last_used_at),
            "public_hint": record.public_hint,
            "revoked_at": _timestamp(record.revoked_at),
            "scopes": list(record.scopes),
            "tenant_id": str(record.tenant_id),
            "transport_binding_id": str(record.transport_binding_id),
        }
        for record in records
    ]
    sys.stdout.buffer.write(canonical_json_bytes(safe) + b"\n")
    sys.stdout.buffer.flush()


def _capability_json(profile: ClientCapabilityProfile) -> dict[str, object]:
    read = profile.read
    return {
        "contract_version": profile.contract_version,
        "read": (
            None
            if read is None
            else {
                "allowed_memory_scopes": sorted(item.value for item in read.allowed_memory_scopes),
                "allowed_visibilities": sorted(item.value for item in read.allowed_visibilities),
                "max_sensitivity": read.max_sensitivity,
                "allow_candidates": read.allow_candidates,
            }
        ),
    }


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def main() -> None:
    try:
        arguments = _parser().parse_args()
        settings = CredentialAdminSettings.from_file(arguments.config)
        asyncio.run(_run(arguments, settings))
    except SystemExit:
        raise
    except CredentialAdminError as error:
        print("ScaleVault credential administration failed", file=sys.stderr)
        if error.code == "credential_repository_rejected_after_secret_output":
            print(
                "Protected authorization artifact may require operator recovery",
                file=sys.stderr,
            )
        raise SystemExit(2) from None
    except Exception:
        print("ScaleVault credential administration failed", file=sys.stderr)
        raise SystemExit(2) from None


__all__ = ["main"]
