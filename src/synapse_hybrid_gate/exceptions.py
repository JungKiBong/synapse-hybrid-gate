"""Structured exception hierarchy for synapse-hybrid-gate.

All domain exceptions inherit from ``SynapseGateError(ValueError)`` so callers
can either catch specific error classes (e.g., ``StaleWorkConflictError``,
``PathSecurityError``) or catch ``ValueError`` for backward compatibility.
"""
from __future__ import annotations


class SynapseGateError(ValueError):
    """Base exception for all deterministic validation, security, and state errors."""

    def __init__(self, code: str) -> None:
        self.code = str(code)
        super().__init__(self.code)


class ValidationError(SynapseGateError):
    """Raised when an identifier, SHA-256 hex digest, provider slug, or argument is malformed."""


class PathSecurityError(SynapseGateError):
    """Raised when a local file path violates root bounds, symlink rules, file type, or size ceilings."""


class SchemaVersionError(SynapseGateError):
    """Raised when opening a SQLite database with an incompatible schema or mismatched project root."""


class EvidenceConflictError(SynapseGateError):
    """Raised when overwriting an evidence ID across incompatible providers or registering inactive evidence."""


class StaleWorkConflictError(SynapseGateError):
    """Raised when parallel work attempts to commit a receipt after bound dependencies mutated in flight."""


class ReadOnlyGateError(SynapseGateError):
    """Raised when a write operation is attempted on a gate opened with ``read_only=True``."""
