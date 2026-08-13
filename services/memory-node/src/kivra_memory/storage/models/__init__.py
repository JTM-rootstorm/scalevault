"""Complete declarative model registry for Alembic and storage repositories."""

from kivra_memory.storage.base import Base, metadata, tenant_table_names
from kivra_memory.storage.models.events import (
    CommandReceipt,
    IngressItem,
    IngressProviderHead,
    IngressProviderViolation,
    MemoryEvent,
    MemoryEventCounter,
    SelectionDecision,
    SelectionDecisionCounter,
)
from kivra_memory.storage.models.genesis_import import (
    GenesisImportExclusion,
    GenesisImportRecord,
    GenesisImportRun,
    GenesisImportRunResult,
    GenesisImportSource,
    GenesisImportSupersession,
)
from kivra_memory.storage.models.identity import (
    Actor,
    AlembicCompatibility,
    Client,
    ClientCredential,
    ObservabilityTenantBinding,
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
    MemoryEmbeddingV1,
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
    "GenesisImportExclusion",
    "GenesisImportRecord",
    "GenesisImportRun",
    "GenesisImportRunResult",
    "GenesisImportSource",
    "GenesisImportSupersession",
    "IngressItem",
    "IngressProviderHead",
    "IngressProviderViolation",
    "Lineage",
    "LogicalSession",
    "Memory",
    "MemoryConflict",
    "MemoryConflictMember",
    "MemoryContentKey",
    "MemoryEmbeddingV1",
    "MemoryEvent",
    "MemoryEventCounter",
    "MemoryEvidence",
    "MemoryLink",
    "ObservabilityTenantBinding",
    "OutboxJob",
    "Persona",
    "SelectionDecision",
    "SelectionDecisionCounter",
    "Subject",
    "SubjectAlias",
    "Tenant",
    "TransportBinding",
    "TransportInstallation",
    "metadata",
]
