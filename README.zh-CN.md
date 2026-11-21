<div align="center">

<h1>synapse-hybrid-gate</h1>

<p><b>零外部依赖 · 零过期污染 · 面向多会话与并行 AI 智能体的无损 LLM 结果缓存与 KV-Prefix 证据门控 (<code>Apache-2.0</code>)</b></p>

<p>
  <a href="./README.md"><kbd>🇺🇸 English</kbd></a>
  &nbsp;
  <a href="./README.ko.md"><kbd>🇰🇷 한국어</kbd></a>
  &nbsp;
  <kbd>🇨🇳 <b>简体中文 ✓</b></kbd>
  &nbsp;
  <a href="./README.ja.md"><kbd>🇯🇵 日本語</kbd></a>
</p>

</div>

---

普通的语义缓存或提示词（Prompt）字符串缓存在真实的软件研发工作流中极易失效——**因为用户的提问字符串往往保持不变，但底层的架构规范、源代码文件或外部长期记忆（`Mem0`、`Zep/Graphiti`、`PostgreSQL`、`Mories`）已经在后台发生了变化**。反之，如果为了省 Token 而将未改动文档替换为有损摘要，则会破坏跨文档细节脚注的交叉推理，并引发模型内部推理（Thinking）延迟暴涨。

`synapse-hybrid-gate` 在本地 SQLite WAL 账本中精确追踪加密状态指针 `(epoch, revision, content_sha256)`，实现 **零外部运行时依赖**、**零后台代理/守护进程** 与 **零上下文质量损失**：

- **100% 无损 Token 节省（非缓存输入 Token `-53.5%`，`30/30` 字段 `100%` 精确）**：
  - **已验证步骤直通跳过（`run_cached_step`）**：仅当绑定的所有本地文件与外部记忆均匹配已验证的 `(epoch, revision, sha256)` 状态（`ALLOW`）且提示词/模型参数一致时，**`100%` 跳过输入与输出 Token**；一旦文件发生 1 字节修改或外部记忆被撤销（`revoked`），立即触发 `HOLD` 强制重新验证。
  - **无损 KV-Prefix 前缀锁定（`build_kv_pinned_prompt`）**：绝不摘要或删减任何一个字符。将未变更（`ALLOW`）的共享证据按确定性顺序锁定在提示词最前端（Prefix），将刚发生变更（`HOLD`）的文档与问题（`<QUESTION>`）置于末尾，使后续追问与并行子智能体共享高达 **`87.4%`–`95.6%`** 的 LLM KV 前缀缓存。
- **多会话与并行子智能体安全**：
  - **乐观并发租约（`begin_work`）**：若并行子智能体执行期间其他会话修改了绑定文档或撤销了记忆，提交旧版本审批回执时将立即抛出 `StaleWorkConflictError` 予以拦截。
  - **无锁只读工作进程（`read_only=True`）** + `SQLITE_BUSY` 抖动退避重试 + 防止 N+1 超时雪崩的 `CircuitBreakingAdapter` 断路器。
- **符合企业安全合规的本地架构与厂商中立记忆端口**：
  - 100% 进程内运行（`network_calls=0`，零本地 HTTP/MITM 代理，零开放端口，零 API 密钥劫持），既可独立运行（`providers=None`），也可同时接入 `Mem0`、`Zep/Graphiti`、`PostgreSQL` 或 `Mories`。

---

## 实测基准数据（4 对照组 × 6 轮真实智能体隔离评测）

基于预先冻结的 SHA-256 评测契约（`freeze.json`），通过 **16 次隔离的真实智能体调用**（`6` 轮演进 × 跨文档脚注与安全裕度 `5` 项指标 = **共 `30` 个评分字段**，经审计外部文件/搜索工具泄漏为 `0` 次）实测得出：

### 1. 四组策略（4-Arm）准确率、Token 与成本综合对比

| 对照组 (Arm) | 策略说明 | 轮次准确率 | 字段准确率 (`30`项) | 安全误判 / 过期泄漏 | LLM 调用数 | 发送总输入 Token | KV-Prefix 命中 Token | 非缓存输入 Token (`Uncached`) | 输出 Token | 有效计费成本（按 `90%` KV 折扣） | 最终判定 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **Arm 0** | 原始全文未对齐基线（问题置顶） | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | `0` / `0` | `6` 次 | `10,151` | `3,584` | `6,567` | `270` | `8,005.4`（基线 `0.0%`） | 基线 |
| **Arm 1** | 传统纯问题字符串缓存 | `50.0%` (`3/6`) | `63.3%` (`19/30`) | **`3` 次 / `5` 次** | `2` 次 | `3,360` | `0` | `3,360` | `86` | `3,752.0` (`-53.1%`) | ❌ **淘汰**（严重过期误判） |
| **Arm 2** | 有损摘要上下文瘦身 | **`33.3%`** (`2/6`) | **`53.3%`** (`16/30`) | 漏报过流(`+1.0A` 误判) / `1` 次 | `4` 次 | `3,623` | `256` | `3,367` | `155` | `4,122.2`（`-48.5%`，**延迟暴增 5.2 倍**） | ❌ **淘汰**（推理质量崩溃） |
| **Arm 3** | **`synapse-hybrid-gate`（精确门控 + KV-Prefix 锁定）** | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | **`0` 次 / `0` 次** | **`4` 次 (`-33.3%`)** | **`6,767` (`-33.3%`)** | **`3,712`** | **`3,055` (`-53.5%`)** | **`184` (`-31.9%`)** | **`4,162.2`（较 Arm 0 `-48.0%` · 较无缓存 `-62.9%`）** | ✅ **采纳**（`0%` 质量损失） |

> **为何淘汰有损摘要替换（`Arm 2`）**：在 `R3` 轮次中，当 `thermal_spec` 将低温充电电流从 `18A` 上调至 `24A` 时，未修改文档 `connector_spec` 的摘要丢失了第 4.3 节脚注（`低于 0°C 且线缆 >1.8m 时 Pin-B2 降额至 20.5A`），导致智能体将 `-3.5A` 的过流风险误判为 **`+1.0A` 安全**，并在 `R4` 深度跨文档查询中全部返回 `null`（`0/5`）。同时，由于模型试图在内部反推缺失约束，其内部推理文本从 **`Arm 3` 的 `228` 字符（`17.8 秒`）暴涨至 `Arm 2` 的 `7,726` 字符（`93.3 秒`，推理量激增 33.9 倍，延迟飙升 5.2 倍）**。

<details>
<summary><b>📊 点击展开逐轮（R1–R6）输入/输出 Token 与 KV 前缀命中明细（Arm 0 vs Arm 3）</b></summary>

<br>

| 轮次 | 场景事件 | Arm 0 模式与输入 (`KV 命中`) | Arm 3 (`synapse-hybrid-gate`) 模式与输入 (`KV 命中`) | Arm 3 非缓存输入 | Arm 3 准确率 |
|---|---|---|---|---:|---:|
| **R1** | 初始 5 字段多文档安全性审查 | `LLM_CALL` · `1,675` tok (`0` KV) | `LLM_CALL` · `1,675` tok (`0` KV) | `1,675` tok | `5/5` (`100%`) |
| **R2** | 上游零变更重复检查 | `LLM_CALL` · `1,675` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · `0` 输入 / `0` 输出（`100%` 跳过调用）** | **`0` tok** | `5/5` (`100%`) |
| **R3** | 本地规范修改（`thermal_spec`: `18A -> 24A` 过流） | `LLM_CALL` · `1,698` tok (`256` KV, `15.1%`) | **`LLM_CALL` · `1,698` tok（`1,152` KV, `67.8%` — KV 复用提升 4.5 倍）** | **`546` tok** | `5/5` (`100%`) |
| **R4** | **全新跨文档深层脚注综合提问** | `LLM_CALL` · `1,685` tok (**`0` KV, `0.0%`**) | **`LLM_CALL` · `1,685` tok（`1,472` KV, `87.4%` 前缀命中）** | **`213` tok** | `5/5` (`100%`) |
| **R5** | 外部记忆 `mem:bypass_policy` 被撤销（`revoked`） | `LLM_CALL` · `1,709` tok (`0` KV, `0.0%`) | **`LLM_CALL` · `1,709` tok（`1,088` KV, `63.7%` 前缀命中）** | **`621` tok** | `5/5` (`100%`) |
| **R6** | 记忆撤销后重复验证 | `LLM_CALL` · `1,709` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · `0` 输入 / `0` 输出（`100%` 跳过调用）** | **`0` tok** | `5/5` (`100%`) |
| **合计** | **6 轮累计** | **`6` 次调用 · 非缓存输入 `6,567` · 输出 `270`** | **`4` 次调用 · 非缓存输入 `3,055` (`-53.5%`) · 输出 `184` (`-31.9%`)** | **`3,055` tok** | **`30/30` (`100%`)** |

*注：即便按保守的 `50%` KV 缓存折扣计算，Arm 3 在保持 `100%` 准确率的同时仍比 Arm 0 降低 **`-40.2%`** 有效计费成本（`5,647.0` vs `9,439.0`）。*

</details>

### 2. 引擎运行时、安全性与多进程并发基准指标（`v0.4.0`）

| 测试维度 | 实测结果 | 验证条件与范围 |
|---|---|---|
| **完整验证套件** | **内置公开 `32 / 32` 通过** | 公开 `tests/`（`0.44s`, `unittest`/`pytest`）— 无锁读取、Fail-Closed `external_texts`、写锁外 OCC、断路器与 SDK 回归 |
| **8 并行子智能体前缀共享率（`H07`）** | **`95.6%`** 前缀字节完全一致 | 8 个并行子智能体基于共享锁定规范文档执行不同子任务 |
| **多进程 SQLite WAL 并发（`H08`）** | **6 个 OS 进程 `0` 锁与快照错误** | 4 个并发 `read_only=True` MVCC 快照进程 + 2 个并发写入进程及乐观并发冲突拦截 |
| **零依赖与内存控制** | **零外部运行时依赖** | 纯 Python `>=3.11` 标准库实现（`dependencies = []`），`O(1)` 内存流式 `verify_chain()` |
| **防篡改与防提示词逃逸（`H06`, `H07`）** | **`100%` 拦截（`HOLD` / `DENY`）** | 缓存行与哈希链回执双重校验、前缀/后缀/问题独立 XML 标签升级、`O_NOFOLLOW`/`O_NONBLOCK` 防护、POSIX `0600` 权限 |

---

## 5 分钟快速上手

```bash
pip install git+https://github.com/JungKiBong/synapse-hybrid-gate.git@v0.4.0
# 或在本地克隆目录中安装并免 API 密钥运行秒级演示：
pip install .
python3 examples/demo_lossless_savings.py
```

### 1. 独立运行无损 LLM 缓存与无锁 KV-Prefix 锁定

```python
from synapse_hybrid_gate import HybridEvidenceGate

with HybridEvidenceGate("gate.db", project_root=".") as gate:
    gate.register_local_evidence("ev:arch", "docs/architecture.md")
    gate.register_task("task:security_review", "审查网关安全性")
    gate.bind_task("task:security_review", ["ev:arch"])

    # 生成 100% 无损 KV-Prefix 锁定提示词（未变更文档固定在最前，问题置于末尾）
    plan = gate.build_kv_pinned_prompt(
        "task:security_review",
        question="对照 architecture.md 验证 TLS 超时不变式。",
    )

    # 首次调用触发 LLM；若绑定证据未变，后续调用耗费 0 Token 直接返回已验证结果！
    outcome = gate.run_cached_step(
        "task:security_review",
        plan.rendered_prompt,
        lambda prompt: ('{"safe": true}', 1800, 120),  # 替换为您的实际 LLM API 调用
    )
    print(outcome.cache_hit, outcome.saved_input_tokens, outcome.saved_output_tokens)
```

### 2. 接入 `Mem0`、`Zep/Graphiti`、`PostgreSQL` 或 `Mories`（零厂商锁定）

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

### 3. 并行子智能体乐观并发控制（OCC）

```python
with HybridEvidenceGate("gate.db", project_root=".") as gate:
    lease = gate.begin_work("task:security_review")
    # ... 子智能体并行执行；若期间其他会话修改了 architecture.md，
    # record_receipt 将抛出 StaleWorkConflictError 阻止写入过期审批结果！
    gate.record_receipt(
        "task:security_review",
        outcome_sha256="a" * 64,
        expected_dependency_digest=lease.dependency_digest,
    )
```

---

## CLI 命令参考

退出码（Exit Code）：`0`（`ALLOW` / 正常），`2`（`HOLD` — 文档已变更、记忆已撤销或外部适配器离线），`3`（`ERROR` / `DENY` / 哈希链篡改 / CLI 参数错误）。

```bash
synapse-hybrid-gate --db gate.db --project-root . init
synapse-hybrid-gate --db gate.db --project-root . register-local --evidence-id ev:spec --file spec.md
synapse-hybrid-gate --db gate.db bind-task --task-id task:t1 --title "Check spec" --evidence-id ev:spec

# 在 Shell 钩子（Claude Code / Codex / OpenCode）中直接生成 KV-Prefix 提示词并读写无损缓存：
synapse-hybrid-gate --db gate.db --project-root . begin-work --task-id task:t1
synapse-hybrid-gate --db gate.db --project-root . build-prompt --task-id task:t1 --question "验证规范不变式" --format json
synapse-hybrid-gate --db gate.db --project-root . cache-store --task-id task:t1 --prompt-sha256 <SHA256> --payload '{"safe":true}' --input-tokens 1675 --output-tokens 43
synapse-hybrid-gate --db gate.db --project-root . cache-lookup --task-id task:t1 --prompt-sha256 <SHA256>
synapse-hybrid-gate --db gate.db --read-only check-task --task-id task:t1

# 查看账本状态、在线热备份 SQLite（0600 权限，防符号链接）与流式哈希链完整性校验：
synapse-hybrid-gate --db gate.db status
synapse-hybrid-gate --db gate.db backup --dest gate.backup.db
synapse-hybrid-gate --db gate.db verify-chain
```

---

## 运行测试与演示

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 examples/demo_lossless_savings.py
```

## 企业安全与架构边界说明

- **零网络流量劫持（Zero-Proxy / Zero-Daemon）**：绝不安装本地 HTTP/HTTPS 代理，绝不拦截 API 密钥或 TLS 流量，不监听任何网络端口。完全符合企业安全（DLP/EDR）审计要求，可按项目（Opt-in）安全集成至 Claude Code、Codex、OpenCode、Cursor 及自研 Python 智能体中。
- **文件系统与账本安全加固**：强制 `project_root` 目录边界校验、拒绝中间符号链接穿透（`lstat` + `O_NOFOLLOW` + `O_NONBLOCK`）、常规文件检查、可配置大文件 DoS 上限（`max_file_bytes`，默认 `64 MiB`）、POSIX `0600` 仅所有者可读写权限、无锁 MVCC 读路径以及 SHA-256 哈希链防篡改回执。
- **严格 Schema 隔离（`v4`）**：打开不兼容的旧版（`v4` 之前）SQLite 账本时将直接抛出 `SchemaVersionError` 而不就地修改旧数据。
- 本项目基于 **Apache License, Version 2.0**（[LICENSE](./LICENSE)）开源许可发布。
