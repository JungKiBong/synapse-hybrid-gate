# Changelog

All notable changes to `synapse-hybrid-gate` are documented in this file.

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
