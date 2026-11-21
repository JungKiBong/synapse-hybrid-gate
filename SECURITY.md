# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `0.4.x` | ✅ Supported |
| `< 0.4.0` | ❌ Upgrade to `0.4.0+` (new `v4` ledger) |

## Built-in Security Guarantees

`synapse-hybrid-gate` is designed for strict corporate DLP/EDR environments:

1. **Zero Network Interception (`network_calls = 0`)**:
   - Opens **zero** TCP/UDP ports, spawns **zero** background daemons or HTTP/HTTPS MITM proxies, and never reads or intercepts LLM API keys.
2. **Bounded Filesystem Isolation**:
   - Enforces `project_root` containment on all local evidence paths.
   - Rejects both leaf and intermediate directory symlinks (`lstat` + `O_NOFOLLOW`), FIFOs, sockets, and device nodes.
   - Enforces `max_file_bytes` (default `64 MiB`) and `max_payload_bytes` ceilings against memory-exhaustion DoS.
   - Applies `0600` owner-only permissions on SQLite `.db`, `-wal`, `-shm`, and `backup_to` files on POSIX platforms.
3. **Cryptographic Cache & Ledger Integrity**:
   - Cross-verifies every cached outcome against SHA-256 hash-chained `audit_receipts` (`outcome_sha256`, `dependency_digest`, `prev_chain_sha256`, and `head_chain_sha256`) inside an atomic SQLite WAL MVCC read snapshot.
   - Deterministically escalates XML wrapper tags (`EVIDENCE` -> `EVIDENCE_1`, `CONTEXT_1`, `QUESTION_1`) if untrusted evidence text contains closing delimiter sequences, preventing prompt-delimiter breakout with `0%` character loss.

## Explicit Architectural Boundaries (Out of Scope)

- **Local Superuser / Root Replacement**: If an attacker with local OS owner/root privileges rewrites both `verified_outcome_cache`, `audit_receipts`, and `gate_meta` simultaneously with recomputed SHA-256 chains, external HSM/PKI signing is required.
- **External Process TOCTOU**: `check_task()` verifies file digests at check time; if a separate external tool reads the file later without `build_kv_pinned_prompt()`, standard OS filesystem TOCTOU windows apply.
- **Network Filesystems**: SQLite WAL concurrency guarantees require local POSIX/OS storage (not NFS/SMB without locking support).

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately via [GitHub Security Advisories](https://github.com/JungKiBong/synapse-hybrid-gate/security/advisories/new) rather than opening a public issue. Include a minimal reproduction script and expected vs. observed behavior.
