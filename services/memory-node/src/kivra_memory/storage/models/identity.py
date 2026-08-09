"""Tenant identity, authentication, installation, and transport provenance models."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    ARRAY,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kivra_memory.storage.base import TENANT_OWNED_INFO_KEY, Base
from kivra_memory.storage.models._shared import (
    ACTOR_KINDS,
    CLIENT_KINDS,
    DISCLOSURE_BOUNDARIES,
    TENANT_TABLE_ARGS,
    TRANSPORT_KINDS,
    json_object_check,
    uuid_v7_check,
    values_check,
)


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("length(btrim(slug::text)) BETWEEN 1 AND 128", name="slug_length"),
        CheckConstraint(
            "length(btrim(display_name)) BETWEEN 1 AND 128", name="display_name_length"
        ),
        values_check("state", ("active", "suspended", "retired"), name="state_values"),
        uuid_v7_check("tenant_id", name="tenant_id_uuid_v7"),
        TENANT_TABLE_ARGS,
    )

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(CITEXT(), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'active'"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class Actor(Base):
    __tablename__ = "actors"
    __table_args__ = (
        UniqueConstraint("tenant_id", "actor_id", name="actors_tenant_actor"),
        UniqueConstraint("tenant_id", "handle", name="tenant_handle"),
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        values_check("kind", ACTOR_KINDS, name="kind_values"),
        json_object_check("metadata", name="metadata_object"),
        CheckConstraint("revoked_at IS NULL OR revoked_at >= created_at", name="revocation_order"),
        uuid_v7_check("actor_id", name="actor_id_uuid_v7"),
        TENANT_TABLE_ARGS,
    )

    actor_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    handle: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    metadata_: Mapped[dict[str, object]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Client(Base):
    __tablename__ = "clients"
    __table_args__ = (
        UniqueConstraint("tenant_id", "client_id", name="tenant_client"),
        UniqueConstraint(
            "tenant_id", "client_id", "transport_kind", name="tenant_client_transport"
        ),
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        values_check("kind", CLIENT_KINDS, name="kind_values"),
        values_check("transport_kind", TRANSPORT_KINDS, name="transport_kind_values"),
        CheckConstraint("cardinality(scopes) BETWEEN 1 AND 64", name="scopes_count"),
        CheckConstraint("array_position(scopes, NULL) IS NULL", name="scopes_no_nulls"),
        json_object_check("capability_profile", name="capability_profile_object"),
        CheckConstraint("revoked_at IS NULL OR revoked_at >= created_at", name="revocation_order"),
        uuid_v7_check("client_id", name="client_id_uuid_v7"),
        TENANT_TABLE_ARGS,
    )

    client_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    public_id: Mapped[str] = mapped_column(CITEXT(), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    transport_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text()), nullable=False)
    capability_profile: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ClientCredential(Base):
    __tablename__ = "client_credentials"
    __table_args__ = (
        UniqueConstraint("tenant_id", "credential_id", name="tenant_credential"),
        ForeignKeyConstraint(
            ["tenant_id", "client_id"],
            ["clients.tenant_id", "clients.client_id"],
            name="client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
            [
                "transport_bindings.tenant_id",
                "transport_bindings.transport_binding_id",
                "transport_bindings.actor_id",
                "transport_bindings.client_id",
            ],
            name="transport_binding",
            ondelete="RESTRICT",
        ),
        values_check("kind", ("bearer_token", "client_certificate"), name="kind_values"),
        CheckConstraint(
            "(kind = 'bearer_token' AND secret_hash IS NOT NULL "
            "AND secret_hash_key_id IS NOT NULL AND certificate_sha256 IS NULL) OR "
            "(kind = 'client_certificate' AND secret_hash IS NULL "
            "AND secret_hash_key_id IS NULL AND certificate_sha256 IS NOT NULL)",
            name="material_matches_kind",
        ),
        CheckConstraint(
            "secret_hash IS NULL OR secret_hash ~ '^hmac-sha256-v1:[A-Za-z0-9_-]{43}$'",
            name="secret_hash_format",
        ),
        CheckConstraint(
            "secret_hash_key_id IS NULL OR secret_hash_key_id ~ '^[a-z][a-z0-9_.-]{0,63}$'",
            name="secret_hash_key_id_format",
        ),
        CheckConstraint(
            "certificate_sha256 IS NULL OR octet_length(certificate_sha256) = 32",
            name="certificate_hash_length",
        ),
        CheckConstraint("expires_at IS NULL OR expires_at > created_at", name="expiry_order"),
        CheckConstraint("revoked_at IS NULL OR revoked_at >= created_at", name="revocation_order"),
        CheckConstraint(
            "last_used_at IS NULL OR (last_used_at >= created_at "
            "AND (revoked_at IS NULL OR last_used_at <= revoked_at))",
            name="last_used_order",
        ),
        uuid_v7_check("credential_id", name="credential_id_uuid_v7"),
        Index(
            "uq_client_credentials_active_public_hint",
            "tenant_id",
            "kind",
            "public_hint",
            unique=True,
            postgresql_where=text("revoked_at IS NULL AND public_hint IS NOT NULL"),
        ),
        Index(
            "uq_client_credentials_active_binding",
            "tenant_id",
            "client_id",
            "transport_binding_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL AND kind = 'bearer_token'"),
        ),
        {
            "info": {
                TENANT_OWNED_INFO_KEY: True,
                "scalevault_immutable_fields": (
                    "credential_id",
                    "tenant_id",
                    "actor_id",
                    "client_id",
                    "transport_binding_id",
                    "kind",
                    "public_hint",
                    "secret_hash",
                    "secret_hash_key_id",
                    "certificate_sha256",
                    "created_at",
                    "expires_at",
                ),
                "scalevault_delete_forbidden": True,
                "scalevault_contains_no_plaintext_secret": True,
            }
        },
    )

    credential_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    client_id: Mapped[UUID] = mapped_column(nullable=False)
    transport_binding_id: Mapped[UUID] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    public_hint: Mapped[str | None] = mapped_column(String(128))
    secret_hash: Mapped[str | None] = mapped_column(Text())
    secret_hash_key_id: Mapped[str | None] = mapped_column(String(64))
    certificate_sha256: Mapped[bytes | None] = mapped_column(LargeBinary())
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TransportInstallation(Base):
    __tablename__ = "transport_installations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "installation_id", name="tenant_installation"),
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        values_check(
            "health_state",
            ("unknown", "healthy", "degraded", "offline"),
            name="health_state_values",
        ),
        CheckConstraint(
            "node_certificate_sha256 IS NULL OR octet_length(node_certificate_sha256) = 32",
            name="certificate_hash_length",
        ),
        json_object_check("capability_profile", name="capability_profile_object"),
        CheckConstraint("revoked_at IS NULL OR revoked_at >= enrolled_at", name="revocation_order"),
        uuid_v7_check("installation_id", name="installation_id_uuid_v7"),
        TENANT_TABLE_ARGS,
    )

    installation_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    route_key: Mapped[str] = mapped_column(CITEXT(), nullable=False, unique=True)
    relay_hostname: Mapped[str | None] = mapped_column(CITEXT())
    node_certificate_sha256: Mapped[bytes | None] = mapped_column(LargeBinary())
    capability_profile: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    health_state: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'unknown'")
    )


class TransportBinding(Base):
    __tablename__ = "transport_bindings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "transport_binding_id", name="tenant_binding"),
        UniqueConstraint(
            "tenant_id",
            "transport_binding_id",
            "actor_id",
            "client_id",
            name="tenant_binding_actor_client",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "actor_id"],
            ["actors.tenant_id", "actors.actor_id"],
            name="actor",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "client_id", "transport_kind"],
            ["clients.tenant_id", "clients.client_id", "clients.transport_kind"],
            name="client_transport",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "installation_id"],
            ["transport_installations.tenant_id", "transport_installations.installation_id"],
            name="installation",
            ondelete="RESTRICT",
        ),
        values_check("transport_kind", TRANSPORT_KINDS, name="transport_kind_values"),
        values_check(
            "disclosure_boundary", DISCLOSURE_BOUNDARIES, name="disclosure_boundary_values"
        ),
        CheckConstraint(
            "(transport_kind = 'direct_private' AND disclosure_boundary = 'private_node') OR "
            "(transport_kind = 'secure_tunnel' AND "
            "disclosure_boundary = 'openai_secure_tunnel') OR "
            "(transport_kind = 'relay' AND disclosure_boundary = 'public_relay') OR "
            "(transport_kind = 'github_ingress' AND disclosure_boundary = 'github_com') OR "
            "(transport_kind = 'internal_service' AND disclosure_boundary = 'internal') OR "
            "(transport_kind = 'archive_restore' AND disclosure_boundary = 'archive')",
            name="transport_disclosure_pair",
        ),
        CheckConstraint(
            "transport_kind <> 'relay' OR installation_id IS NOT NULL",
            name="relay_has_installation",
        ),
        CheckConstraint("valid_until IS NULL OR valid_until > created_at", name="validity_order"),
        json_object_check("authorized_operations", name="authorized_operations_object"),
        uuid_v7_check("transport_binding_id", name="binding_id_uuid_v7"),
        {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_immutable": True}},
    )

    transport_binding_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    client_id: Mapped[UUID] = mapped_column(nullable=False)
    transport_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    disclosure_boundary: Mapped[str] = mapped_column(String(32), nullable=False)
    installation_id: Mapped[UUID | None] = mapped_column()
    authorized_operations: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AlembicCompatibility(Base):
    __tablename__ = "alembic_compatibility"
    __table_args__ = (
        CheckConstraint("length(component) BETWEEN 1 AND 64", name="component_length"),
        CheckConstraint("contract_version >= 1", name="contract_version_positive"),
    )

    component: Mapped[str] = mapped_column(String(64), primary_key=True)
    contract_version: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    minimum_reader_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    minimum_writer_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
