<div align="center">

<h1>synapse-hybrid-gate</h1>

<p><b>Zero-dependency, zero-stale LLM outcome cache &amp; KV-prefix evidence gate for multi-session and parallel AI agents (<code>Apache-2.0</code>)</b></p>

<p>
  <kbd>🇺🇸 <b>English ✓</b></kbd>
  &nbsp;
  <a href="./README.ko.md"><kbd>🇰🇷 한국어</kbd></a>
  &nbsp;
  <a href="./README.zh-CN.md"><kbd>🇨🇳 简体中文</kbd></a>
  &nbsp;
  <a href="./README.ja.md"><kbd>🇯🇵 日本語</kbd></a>
</p>

</div>

---

Ordinary semantic or prompt-string caches fail in real software engineering workflows because **a question string stays identical while upstream specifications, source files, or external agent memories (`Mem0`, `Zep/Graphiti`, `PostgreSQL`, `Mories`) change underneath**. Meanwhile, compressing unchanged documents into lossy summaries destroys cross-document footnote reasoning and spikes model thinking latency.

`synapse-hybrid-gate` tracks exact cryptographic pointers `(epoch, revision, content_sha256)` in a local SQLite WAL ledger with **zero external runtime dependencies**, **zero background proxy/daemon processes**, and **zero context loss**:

- **100% Lossless Token Savings (`-53.5%` Uncached Input Tokens, `30/30` Exact Fields)**:
  - **Verified Step Bypass (`run_cached_step`)**: Skips `100%` of input + output tokens when all bound local files and external memories match their verified cryptographic state (`ALLOW`) and prompt/model parameters match—and immediately invalidates (`HOLD`) on a 1-byte file edit or external memory revocation.
  - **KV-Prefix Pinning (`build_kv_pinned_prompt`)**: Never summarizes or truncates a single character. Deterministically pins unchanged (`ALLOW`) evidence at the front prefix and places newly mutated (`HOLD`) specs + the task question at the tail so follow-up queries and parallel subagents share up to **`87.4%`–`95.6%`** of the LLM KV Prefix Cache.
- **Multi-Session & Parallel Subagent Safety**:
  - **Optimistic Concurrency Leases (`begin_work`)**: Blocks parallel workers from committing stale approvals (`StaleWorkConflictError`) if another session edits a bound spec or revokes a memory mid-flight.
  - **Lock-Free Read-Only Workers (`read_only=True`)** + `SQLITE_BUSY` jittered backoff + `CircuitBreakingAdapter` preventing N+1 timeout cascades.
- **Enterprise-Safe Local Architecture & Vendor-Neutral Memory Port**:
  - Runs 100% in-process (`network_calls=0`, no MITM proxy, no open ports, no API key interception) standalone (`providers=None`) or plugged into `Mem0`, `Zep/Graphiti`, `PostgreSQL`, or `Mories` simultaneously.

---

## Empirical Benchmark Data (4-Arm × 6-Round Live Agent Evaluation)

Evaluated across **16 isolated live agent calls** (`6` rounds × `5` cross-document engineering & safety fields = **`30` scored fields**, pre-frozen SHA-256 contract, `0` external file/search tool leaks):

### 1. Overall 4-Arm Accuracy, Token & Cost Comparison

| Arm | Strategy | Round Accuracy | Field Accuracy (`30`) | Safety Misses / Stale Leaks | LLM Calls | Raw Input Sent | KV-Prefix Cached | Uncached Input Tokens | Output Tokens | Effective Cost (`90%` KV Discount) | Verdict |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **Arm 0** | Full Raw Unpinned (Question First) | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | `0` / `0` | `6` | `10,151` | `3,584` | `6,567` | `270` | `8,005.4` (Baseline `0.0%`) | Baseline |
| **Arm 1** | Naive Question-String Cache | `50.0%` (`3/6`) | `63.3%` (`19/30`) | **`3` / `5`** | `2` | `3,360` | `0` | `3,360` | `86` | `3,752.0` (`-53.1%`) | ❌ **Rejected** (Stale hazard) |
| **Arm 2** | Lossy Summary Context Diet | **`33.3%`** (`2/6`) | **`53.3%`** (`16/30`) | Overload missed (`+1.0A` vs `-3.5A`) / `1` | `4` | `3,623` | `256` | `3,367` | `155` | `4,122.2` (`-48.5%`, **5.2× slower**) | ❌ **Rejected** (Quality collapse) |
| **Arm 3** | **`synapse-hybrid-gate` (Exact Gate + KV-Prefix Pinning)** | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | **`0` / `0`** | **`4` (`-33.3%`)** | **`6,767` (`-33.3%`)** | **`3,712`** | **`3,055` (`-53.5%`)** | **`184` (`-31.9%`)** | **`4,162.2` (`-48.0%` vs Arm 0; `-62.9%` vs no-KV)** | ✅ **Adopted** (`0%` quality loss) |

> **Why Lossy Summary Substitution (`Arm 2`) Was Rejected**: When `thermal_spec` raised sub-zero charging current (`18A -> 24A`) in `R3`, summarizing the unchanged `connector_spec` stripped a Section 4.3 footnote (`Pin-B2 derated to 20.5A below 0°C over >1.8m`). The agent miscalculated a `-3.5A` overload hazard as **`+1.0A` safe**, returned `null` (`0/5`) on the `R4` deep cross-spec query, and expanded internal reasoning from **`228` chars (`17.8s` in Arm 3) to `7,726` chars (`93.3s` in Arm 2 — 33.9× thinking blowup, 5.2× latency spike)** trying to reconstruct missing constraints.

<details>
<summary><b>📊 Click to expand Round-by-Round Token &amp; KV-Cache Breakdown (R1–R6: Arm 0 vs Arm 3)</b></summary>

<br>

| Round | Scenario Event | Arm 0 Mode & Input (`KV Hit`) | Arm 3 (`synapse-hybrid-gate`) Mode & Input (`KV Hit`) | Arm 3 Uncached Input | Arm 3 Accuracy |
|---|---|---|---|---:|---:|
| **R1** | Initial 5-field multi-spec safety audit | `LLM_CALL` · `1,675` tok (`0` KV) | `LLM_CALL` · `1,675` tok (`0` KV) | `1,675` tok | `5/5` (`100%`) |
| **R2** | Repeat check (zero upstream changes) | `LLM_CALL` · `1,675` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · `0` in / `0` out (`100%` skipped)** | **`0` tok** | `5/5` (`100%`) |
| **R3** | Local spec edit (`thermal_spec`: `18A -> 24A` overload) | `LLM_CALL` · `1,698` tok (`256` KV, `15.1%`) | **`LLM_CALL` · `1,698` tok (`1,152` KV, `67.8%` — 4.5× KV reuse)** | **`546` tok** | `5/5` (`100%`) |
| **R4** | **Brand-new deep cross-footnote query** | `LLM_CALL` · `1,685` tok (**`0` KV, `0.0%`**) | **`LLM_CALL` · `1,685` tok (`1,472` KV, `87.4%` prefix hit)** | **`213` tok** | `5/5` (`100%`) |
| **R5** | External memory `mem:bypass_policy` revoked | `LLM_CALL` · `1,709` tok (`0` KV, `0.0%`) | **`LLM_CALL` · `1,709` tok (`1,088` KV, `63.7%` prefix hit)** | **`621` tok** | `5/5` (`100%`) |
| **R6** | Post-revocation repeat verification | `LLM_CALL` · `1,709` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · `0` in / `0` out (`100%` skipped)** | **`0` tok** | `5/5` (`100%`) |
| **Total** | **6-Round Cumulative** | **`6` calls · `6,567` uncached in · `270` out** | **`4` calls · `3,055` uncached in (`-53.5%`) · `184` out (`-31.9%`)** | **`3,055` tok** | **`30/30` (`100%`)** |

*Note: Under a `50%` KV-cache discount model, Arm 3 still achieves a **`-40.2%`** effective cost reduction (`5,647.0` vs `9,439.0`) with `100%` accuracy.*

</details>

### 2. Engine Runtime, Security & Multi-Process Benchmarks (`v0.3.0`)

| Metric | Verified Result | Scope / Condition |
|---|---|---|
| **Verification Suite** | **`32 / 32` PASS** (`34` assertion groups) | `H01`–`H12` hardening + `U01`–`U10` universal port + `F01`–`F12` core gate + isolated wheel (`python3 -I -B`) |
| **8-Subagent Prefix Sharing (`H07`)** | **`95.6%`** shared prefix bytes | 8 parallel subagents querying distinct tasks over shared pinned specifications |
| **Multi-Process SQLite WAL (`H08`)** | **`0` lock errors** across **6 OS processes** | 4 concurrent `read_only=True` workers + 2 concurrent writers with OCC conflict blocking |
| **Memory & Execution Footprint** | **`48.86 MiB` Peak RSS** (`6.37s` full suite) | Pure Python `>=3.11` standard library (`0` external pip dependencies) |
| **Tamper & Escape Defenses (`H06`, `H07`)** | **`100%` blocked** (`HOLD` / `DENY`) | Dual cache+receipt hash-chain cross-verification, adversarial `</EVIDENCE>` tag escalation (`EVIDENCE_1`), `O_NOFOLLOW` symlink rejection, `0600` DB mode |

---

## 5-Minute Quickstart

```bash
pip install git+https://github.com/JungKiBong/synapse-hybrid-gate.git@v0.3.0
# Or from a local clone:
pip install .
```

### 1. Standalone Lossless LLM Caching, KV-Prefix Pinning & Token Telemetry

```python
from synapse_hybrid_gate import HybridEvidenceGate

with HybridEvidenceGate("gate.db", project_root=".") as gate:
    gate.register_local_evidence("ev:arch", "docs/architecture.md")
    gate.register_task("task:security_review", "Review gateway security")
    gate.bind_task("task:security_review", ["ev:arch"])

    # 100% lossless KV-prefix-pinned prompt (unchanged specs pinned first, question at tail)
    plan = gate.build_kv_pinned_prompt(
        "task:security_review",
        question="Verify TLS timeout invariants against architecture.md.",
    )

    # First call invokes your LLM; repeat calls with unchanged evidence spend 0 tokens!
    outcome = gate.run_cached_step(
        "task:security_review",
        plan.rendered_prompt,
        lambda prompt: ('{"safe": true}', 1800, 120),  # replace with your LLM API call
    )
    print(outcome.cache_hit, gate.token_monitoring_report())
```

### 2. Plugging in `Mem0`, `Zep/Graphiti`, `PostgreSQL`, or `Mories` (Zero Lock-in)

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
    # ... subagent runs in parallel; if another session edits architecture.md mid-flight,
    # record_receipt raises StaleWorkConflictError instead of recording a stale approval!
    gate.record_receipt(
        "task:security_review",
        outcome_sha256="a" * 64,
        expected_dependency_digest=lease.dependency_digest,
    )
```

---

## CLI Reference & Live Token Savings Monitor

Exit codes: `0` (`ALLOW` / OK), `2` (`HOLD` — stale, revoked, or offline dependency), `3` (`ERROR` / `DENY` / tampered chain / invalid CLI flag).

```bash
synapse-hybrid-gate --db gate.db --project-root . init
synapse-hybrid-gate --db gate.db --project-root . register-local --evidence-id ev:spec --file spec.md
synapse-hybrid-gate --db gate.db bind-task --task-id task:t1 --title "Check spec" --evidence-id ev:spec
synapse-hybrid-gate --db gate.db record-receipt --task-id task:t1 --outcome-sha256 $(printf 'a%.0s' {1..64})
synapse-hybrid-gate --db gate.db --read-only check-task --task-id task:t1

# View cumulative avoided LLM calls, saved input/output tokens, hit rate %, and KV-pinned tokens:
synapse-hybrid-gate --db gate.db monitor --format table
synapse-hybrid-gate --db gate.db monitor --format json

# Online safe SQLite backup (0600, symlink-safe) & hash-chain verification:
synapse-hybrid-gate --db gate.db backup --dest gate.backup.db
synapse-hybrid-gate --db gate.db verify-chain
```

---

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Enterprise Security & Architectural Boundaries

- **Zero Network Interception**: Never installs a local HTTP/HTTPS proxy, never intercepts API keys or TLS traffic, and opens zero network ports—compatible with strict corporate DLP/EDR policies and per-project opt-in integration across Claude Code, Codex, OpenCode, Cursor, and custom Python agents.
- **Filesystem & Ledger Hardening**: Enforces bounded `project_root`, intermediate symlink rejection (`lstat` + `O_NOFOLLOW`), regular-file checks, a configurable `max_file_bytes` ceiling (default `64 MiB`), `0600` owner-only SQLite file permissions on POSIX, and SHA-256 hash-chained receipts.
- **Explicit Schema Upgrades**: Opening an older `v1`/`v2` SQLite ledger raises `SchemaVersionError` until explicitly upgraded via `migrate_database(db_path)` or `synapse-hybrid-gate --db gate.db migrate`.
- Licensed under the **Apache License, Version 2.0** ([LICENSE](./LICENSE)).
