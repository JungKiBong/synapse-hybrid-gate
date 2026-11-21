# Changelog

All notable changes to `synapse-hybrid-gate` are documented in this file.

## [0.4.0] - 2026-11-21

### Breaking Changes (Hardening & Slim-Down)
- **Schema `v4` (`synapse-hybrid-gate-sqlite-v4`) & Removal of Pre-OSS Migrations**: Removed `LEGACY_SCHEMA_V1`, `LEGACY_SCHEMA_V2`, `migrate_database`, and the `migrate` CLI subcommand. Opening pre-`v4` databases fails closed with `SchemaVersionError`.
- **100% Lock-Free Read Paths**: Removed read-path `BEGIN IMMEDIATE` telemetry counter writes from `lookup_verified_outcome()` and `build_kv_pinned_prompt()`, along with `gate_meta` token/USD counters, `token_savings_summary()`, `token_monitoring_report()`, and the `monitor` / `token-stats` CLI subcommands. `CachedStepOutcome.saved_input_tokens` and `saved_output_tokens` remain available on every cache hit with zero SQLite writes.
- **Vendor-Neutral Adapters Only**: Removed legacy Mories compatibility aliases (`MoriesItemState`, `MoriesEvidenceAdapter`, `OfflineMoriesAdapter`, `CallableMoriesAdapter`, `mories_adapter=`, `register_mories_evidence`, `refresh_mories_evidence`) and hardcoded `provider == "mories"` branches. Attach Mories via `providers={"mories": make_mories_adapter(...)}` and `register_external_evidence(..., provider="mories")`.
- **Removed Orphaned / Dead Surfaces**: Removed `core_hook.py` (`NormativeVerdict`, `NormativeGatePort`, `SynapseCoreGateAdapter`), the orphaned `fast_file_cache` table (`fast_record`, `fast_check`, `fast-*` CLI), and the dead-end `register-external` / `register-mories` CLI subcommands.

### Security & Bug Fixes
- **Fail-Closed `external_texts` Verification (`store.py`)**: `build_kv_pinned_prompt()` now rejects caller-supplied `external_texts` with `ValidationError` whenever the live external item is `REVOKED`, `UNAVAILABLE`, or `UNKNOWN`, adds `state="UNAVAILABLE"` to unavailable pointers, and isolates suffix `<EVIDENCE>` delimiter escalation so mutated suffix payloads cannot bust the stable KV prefix.
- **OCC Preflight Outside SQLite Write Lock (`store.py`)**: Moved live external RPCs and bounded local file hashing out of `BEGIN IMMEDIATE` in `record_receipt()` and `store_verified_outcome()`.
- **Circuit Breaker Single-Item Adapter Bypass Fix (`adapters.py`)**: Added `has_batch_lookup` gating so `CircuitBreakingAdapter.inspect_many()` properly short-circuits wrapped single-item `CallableExternalAdapter` instances (such as `make_mem0_adapter(fn)`) after `failure_threshold` failures instead of looping `N × timeout`.
- **Real Mem0 / Zep / Mories SDK Compatibility (`plugins.py`)**: `make_mem0_adapter` now treats `None` as `KeyError` (no false breaker trips), falls back to `"text"`, and maps `"replaced_by"` to `REVOKED`; `make_zep_adapter` accepts `None` and Pydantic/dataclass `EntityEdge` objects; `make_mories_adapter` treats `None` as `KeyError`.
- **Audit Chain & CLI Robustness (`store.py`, `cli.py`, `adapters.py`)**: Recomputed `head_row` hash in `_verify_receipt_row_and_head()`, streamed `verify_chain()` with `O(1)` RAM, wrapped `status_summary()` in `_read_snapshot()`, normalized relative URIs with `.as_posix()`, and added `O_NONBLOCK` FIFO protection in CLI bounded file reads.

## [0.3.2] - 2026-11-21

### Fixed
- **KV-Prefix Stability Ordering**: Added deterministic ordering via `bind_seq`, `last_mutated_ns`, and optional `pin_order` across `bind_task`, `partition_for_kv_cache`, and `build_kv_pinned_prompt` (with backward-compatible read-only access and idempotent `migrate_database` support for pre-patch `v3` databases), preventing alphabetical re-sort prefix thrashing when mutated evidence is re-bound.
- **Question XML Delimiter Isolation**: Isolated `<CONTEXT>`/`<EVIDENCE>` delimiter escalation strictly to `system_header` + evidence payloads and escalated `<QUESTION>` tags independently, ensuring user questions referencing `<EVIDENCE>` or `</CONTEXT>` never invalidate the cached KV prefix.
- **Batched External Provider Inspection**: Consolidated external dependency checks inside `build_kv_pinned_prompt` and `partition_for_kv_cache` into a single batched `inspect_many` call per external provider (with single-pass `inspect` fallback), eliminating redundant `2N` per-item RPC overhead.
- **Zep Adapter Temporal `as_of` TTL Evaluation**: Fixed `make_zep_adapter` to evaluate temporal bounds against `as_of` / `as_of_fn` rather than treating any non-empty field as revoked—future `invalid_at`/`expired_at` stays `ACTIVE`, empty/whitespace strings are treated as unset, and `valid_at > as_of` or malformed timestamps fail closed to `UNKNOWN`.
- **Mories Adapter Metadata Preservation**: Preserved rich Mories snapshot metadata (`namespace`, `namespace_epoch`, `collection_epoch`, `valid_from`, `valid_to`, `last_mutated_ns`, `pin_seq`, `verbatim_text`) on `EvidenceSnapshot.metadata` (with fail-closed validation and SHA-256 verification for `verbatim_text`).

### Added
- **KV-Prefix & Adapter Regression Suite**: Added 8 targeted regression tests in `tests/test_kv_and_plugins_regressions.py` (`34 passed` total).

## [0.3.1] - 2026-11-18

### Added
- **CLI Token-Saving & Parallel Lease Parity**: Added `begin-work`, `build-prompt` (`--format json|raw`), `cache-lookup`, and `cache-store` CLI subcommands with `O_NOFOLLOW` bounded file reads so shell hooks and non-Python agents (Claude Code, Codex, OpenCode) can use KV-prefix pinning and lossless outcome caching directly.
- **Public 26-Scenario Verification Suite**: Expanded `tests/test_synapse_hybrid_gate.py` from 4 smoke tests to 26 comprehensive `unittest`/`pytest` scenarios covering dual tamper detection, 8-subagent KV-prefix sharing (`>95%`), adversarial XML tag-escape escalation, 6-process SQLite WAL concurrency, `backup_to`, `v1 -> v3` migration, and CLI exit-code separation (`0`/`2`/`3`).
- **Runnable Zero-API-Key Demo & Governance Docs**: Added `examples/demo_lossless_savings.py`, `SECURITY.md`, `CHANGELOG.md`, and 4-language tabbed documentation (`README.md`, `README.ko.md`, `README.zh-CN.md`, `README.ja.md`).
- **Circuit Breaker Introspection**: Added `CircuitBreakingAdapter.is_open` property.

### Fixed
- **Multi-Process WAL Read Snapshot Consistency**: Added `_ReadSnapshotContext` (`BEGIN DEFERRED` MVCC snapshot) around multi-statement reads in `verify_chain()`, `check_task()`, and `lookup_verified_outcome()`, eliminating false-negative `tail_truncation_or_head_mismatch` torn reads when concurrent writers append receipts mid-inspection.

## [0.3.0] - 2026-11-18

### Added
- Initial public `Apache-2.0` release with SQLite WAL schema `v3`, `run_cached_step`, `build_kv_pinned_prompt` lossless KV-prefix pinning, `begin_work` optimistic concurrency leases, `token_monitoring_report()` + `monitor` CLI, `CircuitBreakingAdapter`, `backup_to`, `migrate_database` (`v1/v2 -> v3`), and vendor-neutral adapters (`Mem0`, `Zep/Graphiti`, `PostgreSQL`, `Mories`, standalone).
