"""Complete declarative model registry for Alembic and storage repositories."""

from kivra_memory.storage.base import Base, metadata, tenant_table_names
from kivra_memory.storage.models.events import (
    CommandReceipt,
    IngressItem,
    MemoryEvent,
    MemoryEventCounter,
)
from kivra_memory.storage.models.identity import (
    Actor,
    AlembicCompatibility,
    Client,
    ClientCredential,
    Tenant,
    TransportBinding,
    TransportInstallation,
)
from kivra_memory.storage.models.lineage import (
    Branch,
    Lineage,
    LogicalSession,
    Persona,
    Subject,
    SubjectAlias,
)
from kivra_memory.storage.models.operations import (
    ArchiveExportCheckpoint,
    ArchiveTarget,
    EmbeddingModel,
    OutboxJob,
)
from kivra_memory.storage.models.projections import (
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryContentKey,
    MemoryEvidence,
    MemoryLink,
)

TENANT_TABLE_NAMES = tenant_table_names()

__all__ = [
    "TENANT_TABLE_NAMES",
    "Actor",
    "AlembicCompatibility",
    "ArchiveExportCheckpoint",
    "ArchiveTarget",
    "Base",
    "Branch",
    "Client",
    "ClientCredential",
    "CommandReceipt",
    "EmbeddingModel",
    "IngressItem",
    "Lineage",
    "LogicalSession",
    "Memory",
    "MemoryConflict",
    "MemoryConflictMember",
    "MemoryContentKey",
    "MemoryEvent",
    "MemoryEventCounter",
    "MemoryEvidence",
    "MemoryLink",
    "OutboxJob",
    "Persona",
    "Subject",
    "SubjectAlias",
    "Tenant",
    "TransportBinding",
    "TransportInstallation",
    "metadata",
]
