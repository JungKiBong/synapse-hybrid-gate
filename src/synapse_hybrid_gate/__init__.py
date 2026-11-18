"""Public package interface for synapse-hybrid-gate (Apache-2.0 Open-Source Release Candidate)."""
from .adapters import (
    CallableExternalAdapter,
    CallableMoriesAdapter,
    CircuitBreakingAdapter,
    DEFAULT_MAX_FILE_BYTES,
    EvidenceSnapshot,
    ExternalMemoryItem,
    ExternalMemoryPort,
    LocalFileEvidenceAdapter,
    MoriesEvidenceAdapter,
    MoriesItemState,
    OfflineExternalAdapter,
    OfflineMoriesAdapter,
    validate_provider,
)
from .context_cache import CachedStepOutcome, KVPinnedContextPlan, WorkLease
from .core_hook import NormativeGatePort, NormativeVerdict, SynapseCoreGateAdapter
from .exceptions import (
    EvidenceConflictError,
    PathSecurityError,
    ReadOnlyGateError,
    SchemaVersionError,
    StaleWorkConflictError,
    SynapseGateError,
    ValidationError,
)
from .plugins import make_mem0_adapter, make_mories_adapter, make_zep_adapter
from .store import (
    GENESIS_CHAIN_HASH,
    GateCheckResult,
    HybridEvidenceGate,
    LEGACY_SCHEMA_V1,
    LEGACY_SCHEMA_V2,
    SCHEMA_VERSION,
    migrate_database,
)

__version__ = "0.3.1"

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "LEGACY_SCHEMA_V1",
    "LEGACY_SCHEMA_V2",
    "GENESIS_CHAIN_HASH",
    "DEFAULT_MAX_FILE_BYTES",
    "SynapseGateError",
    "ValidationError",
    "PathSecurityError",
    "SchemaVersionError",
    "EvidenceConflictError",
    "StaleWorkConflictError",
    "ReadOnlyGateError",
    "validate_provider",
    "EvidenceSnapshot",
    "ExternalMemoryItem",
    "ExternalMemoryPort",
    "OfflineExternalAdapter",
    "CallableExternalAdapter",
    "CircuitBreakingAdapter",
    "make_mem0_adapter",
    "make_zep_adapter",
    "make_mories_adapter",
    "MoriesItemState",
    "MoriesEvidenceAdapter",
    "OfflineMoriesAdapter",
    "CallableMoriesAdapter",
    "LocalFileEvidenceAdapter",
    "WorkLease",
    "CachedStepOutcome",
    "KVPinnedContextPlan",
    "NormativeVerdict",
    "NormativeGatePort",
    "SynapseCoreGateAdapter",
    "GateCheckResult",
    "HybridEvidenceGate",
    "migrate_database",
]
