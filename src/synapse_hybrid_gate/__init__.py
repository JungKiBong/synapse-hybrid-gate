"""Public package interface for synapse-hybrid-gate (Apache-2.0)."""
from .adapters import (
    CallableExternalAdapter,
    CircuitBreakingAdapter,
    DEFAULT_MAX_FILE_BYTES,
    EvidenceSnapshot,
    ExternalMemoryItem,
    ExternalMemoryPort,
    LocalFileEvidenceAdapter,
    OfflineExternalAdapter,
    validate_provider,
)
from .context_cache import CachedStepOutcome, KVPinnedContextPlan, WorkLease
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
    SCHEMA_VERSION,
)

__version__ = "0.4.0"

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
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
    "LocalFileEvidenceAdapter",
    "WorkLease",
    "CachedStepOutcome",
    "KVPinnedContextPlan",
    "GateCheckResult",
    "HybridEvidenceGate",
]
