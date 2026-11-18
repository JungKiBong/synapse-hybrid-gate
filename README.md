# synapse-hybrid-gate

**Zero-dependency, zero-stale LLM outcome cache & KV-prefix evidence gate for multi-session and parallel AI agents (`Apache-2.0`).**

Ordinary semantic/prompt caches break in real engineering workflows because a question string stays the same while upstream specifications, code files, or long-term memories (`Mem0`, `Zep/Graphiti`, `PostgreSQL`, `Mories`) change underneath. `synapse-hybrid-gate` tracks exact cryptographic pointers in local SQLite WAL with **zero external runtime dependencies**:

- **100% Lossless Token Savings**:
  - **Verified Step Bypass (`run_cached_step`)**: Skips 100% of input + output tokens (`0.15ms` check) when bound files and external memories match their verified `(epoch, revision, sha256)`, and immediately invalidates (`HOLD`) on a 1-byte edit or memory revocation.
  - **KV-Prefix Pinning (`build_kv_pinned_prompt`)**: Never summarizes or truncates evidence. Deterministically pins unchanged shared specs at the front of the prompt and places mutated specs + the task question at the tail so parallel subagents and follow-up questions share maximum cloud/local LLM KV Prefix Cache.
- **Multi-Session & Parallel Subagent Safety**:
  - **Optimistic Concurrency Leases (`begin_work`)**: Blocks parallel workers from committing stale results (`StaleWorkConflictError`) if another session edits a bound spec mid-flight.
  - **Lock-Free Read-Only Workers (`read_only=True`)** + `SQLITE_BUSY` retry jitter + `CircuitBreakingAdapter` preventing N+1 timeout cascades.
- **Vendor-Neutral Universal Memory Port**: Works 100% standalone (`providers=None`) or plugs into `Mem0`, `Zep/Graphiti`, `PostgreSQL`, or `Mories` simultaneously with per-provider fail-closed outage isolation.

---

## 5-Minute Quickstart

```bash
pip install .
```

### 1. Standalone + Lossless LLM Caching & KV-Prefix Pinning

```python
from synapse_hybrid_gate import HybridEvidenceGate

with HybridEvidenceGate("gate.db", project_root=".") as gate:
    gate.register_local_evidence("ev:arch", "docs/architecture.md")
    gate.register_task("task:security_review", "Review gateway security")
    gate.bind_task("task:security_review", ["ev:arch"])

    # Build a 100% lossless KV-prefix-pinned prompt (shared across parallel subagents)
    plan = gate.build_kv_pinned_prompt(
        "task:security_review",
        question="Verify TLS timeout invariants against architecture.md.",
    )

    # First call invokes your LLM; repeat calls with unchanged evidence spend 0 tokens!
    outcome = gate.run_cached_step(
        "task:security_review",
        plan.rendered_prompt,
        lambda prompt: ("{\"safe\": true}", 1800, 120),  # replace with your LLM call
    )
    print(outcome.cache_hit, gate.token_monitoring_report())
```

### 2. Plugging in `Mem0`, `Zep/Graphiti`, or Custom Stores (Zero Lock-in)

```python
from synapse_hybrid_gate import (
    CircuitBreakingAdapter,
    HybridEvidenceGate,
    make_mem0_adapter,
    make_zep_adapter,
)

with HybridEvidenceGate(
    "multi.db",
    project_root=".",
    providers={
        "mem0": CircuitBreakingAdapter(make_mem0_adapter(lambda k: mem0_client.get(k))),
        "zep": CircuitBreakingAdapter(make_zep_adapter(lambda k: zep_graph.get_edge(k))),
    },
) as gate:
    gate.register_external_evidence("ev:rule1", "m0_101", provider="mem0", require_certified=False)
    gate.register_external_evidence("ev:fact1", "zep_88", provider="zep", require_certified=True)
```

### 3. Parallel Subagent Optimistic Concurrency Guard

```python
with HybridEvidenceGate("gate.db", project_root=".") as gate:
    lease = gate.begin_work("task:security_review")
    # ... subagent runs in parallel; if another session edits architecture.md before commit,
    # record_receipt raises StaleWorkConflictError instead of recording a stale approval!
    gate.record_receipt(
        "task:security_review",
        outcome_sha256="a" * 64,
        expected_dependency_digest=lease.dependency_digest,
    )
```

---

## CLI Reference

Exit codes: `0` (`ALLOW` / OK), `2` (`HOLD` — stale, revoked, or offline dependency), `3` (`ERROR` / `DENY` / tampered chain / invalid CLI flag).

```bash
synapse-hybrid-gate --db gate.db --project-root . init
synapse-hybrid-gate --db gate.db --project-root . register-local --evidence-id ev:spec --file spec.md
synapse-hybrid-gate --db gate.db bind-task --task-id task:t1 --title "Check spec" --evidence-id ev:spec
synapse-hybrid-gate --db gate.db record-receipt --task-id task:t1 --outcome-sha256 $(printf 'a%.0s' {1..64})
synapse-hybrid-gate --db gate.db --read-only check-task --task-id task:t1
synapse-hybrid-gate --db gate.db monitor --format table
synapse-hybrid-gate --db gate.db backup --dest gate.backup.db
synapse-hybrid-gate --db gate.db verify-chain
```

---

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Security & Scope Notes

- Enforces bounded `project_root`, intermediate symlink rejection (`lstat` + `O_NOFOLLOW`), regular-file checks, a configurable `max_file_bytes` ceiling (default `64 MiB`), `0600` owner-only SQLite file permissions on POSIX, and SHA-256 hash-chained receipts.
- Zero-copy local inspection verifies file digests at check time; standard OS filesystem TOCTOU windows between `check_task()` and subsequent external process reads apply unless content is read via `build_kv_pinned_prompt()`.
- Licensed under the **Apache License, Version 2.0** (`LICENSE`).
