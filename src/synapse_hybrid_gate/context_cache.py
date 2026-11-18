"""Data structures for lossless token-saving caching, KV-prefix pinning, and parallel work leases."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WorkLease:
    """Snapshot token acquired via ``begin_work(task_id)`` before parallel agent execution.

    Passing ``lease.dependency_digest`` as ``expected_dependency_digest`` to
    ``record_receipt`` or ``store_verified_outcome`` guarantees optimistic concurrency:
    if any bound file or external memory item changes while the worker is running,
    the stale commit is rejected with ``StaleWorkConflictError``.
    """

    task_id: str
    dependency_digest: str
    evidence_digests: tuple[tuple[str, str], ...]
    issued_ns: int


@dataclass(frozen=True, slots=True)
class CachedStepOutcome:
    """Result returned by ``lookup_verified_outcome`` and ``run_cached_step``."""

    task_id: str
    cache_hit: bool
    decision: str
    reason: str
    payload_text: str | None = None
    outcome_sha256: str | None = None
    receipt_id: str | None = None
    saved_input_tokens: int = 0
    saved_output_tokens: int = 0


@dataclass(frozen=True, slots=True)
class KVPinnedContextPlan:
    """Lossless deterministic context partition maximizing LLM KV-prefix cache hits.

    Unchanged active dependencies (``stable_prefix_ids``) are placed first in a
    canonical deterministic order so consecutive turns and parallel subagents share
    an identical byte prefix. Newly mutated or unverified dependencies
    (``changed_suffix_ids``) are placed after the prefix with 100% full raw text
    preserved (zero lossy summarization), followed by the task question at the tail.
    """

    task_id: str
    stable_prefix_ids: tuple[str, ...]
    changed_suffix_ids: tuple[str, ...]
    rendered_prompt: str = ""
    prefix_char_length: int = 0
