<div align="center">

<h1>synapse-hybrid-gate</h1>

<p><b>外部依存ゼロ · 陳腐化汚染ゼロ · マルチセッション＆並列 AI エージェント向け完全無損失 LLM 結果キャッシュ＆ KV-Prefix 根拠ゲート (<code>Apache-2.0</code>)</b></p>

<p>
  <a href="./README.md"><kbd>🇺🇸 English</kbd></a>
  &nbsp;
  <a href="./README.ko.md"><kbd>🇰🇷 한국어</kbd></a>
  &nbsp;
  <a href="./README.zh-CN.md"><kbd>🇨🇳 简体中文</kbd></a>
  &nbsp;
  <kbd>🇯🇵 <b>日本語 ✓</b></kbd>
</p>

</div>

---

一般的なセマンティックキャッシュやプロンプト文字列キャッシュは、実際のソフトウェア開発ワークフローでは容易に破綻します。**質問文自体は同じでも、前提となる設計仕様書・ソースコード・外部長期メモリ（`Mem0`、`Zep/Graphiti`、`PostgreSQL`、`Mories`）が裏側で更新されるため**です。一方、トークン削減のために未変更ドキュメントを要約文へ置換すると、文書間の細かな脚注の交差推論が崩れ、モデルの内部推論（Thinking）レイテンシが逆爆発します。

`synapse-hybrid-gate` は、ローカルの SQLite WAL 台帳で暗号学的ポインタ `(epoch, revision, content_sha256)` を厳密に追跡し、**外部ランタイム依存ゼロ**・**バックグラウンドプロキシ／デーモンゼロ**・**コンテキスト品質劣化ゼロ**でトークンを削減します。

- **100% 無損失トークン削減（非キャッシュ入力トークン `-53.5%`、`30/30` 項目 `100%` 一致）**：
  - **検証済みステップ即時バイパス（`run_cached_step`）**：紐付けられた全ローカルファイルおよび外部メモリが検証時の `(epoch, revision, sha256)` と完全一致（`ALLOW`）し、プロンプト／モデル設定が同一の場合のみ入出力トークンを **`100%` スキップ**します。1 バイトの編集や外部メモリの失効（`revoked`）が発生した瞬間に `HOLD` となり再検証を強制します。
  - **無損失 KV-Prefix 固定整列（`build_kv_pinned_prompt`）**：原文を 1 文字も要約・削除しません。未変更（`ALLOW`）の共通根拠をプロンプト先頭（Prefix）に決定論的順序で固定し、更新された（`HOLD`）仕様書と質問（`<QUESTION>`）を末尾に配置することで、追加質問や並列サブエージェント間で最大 **`87.4%`〜`95.6%`** の LLM KV プレフィックスキャッシュ共有を実現します。
- **マルチセッション＆並列サブエージェント安全性**：
  - **楽観的並行制御リース（`begin_work`）**：並列ワーカーの実行中に別セッションが仕様書を編集・メモリを失効させた場合、古い承認レシートのコミットを `StaleWorkConflictError` で即座に遮断します。
  - **ロックフリー読み取り専用ワーカー（`read_only=True`）** + `SQLITE_BUSY` ジッター再試行 + N+1 タイムアウト連鎖を防ぐ `CircuitBreakingAdapter` を標準搭載。
- **企業セキュリティ準拠のローカル設計＆ベンダー中立メモリポート**：
  - 100% インプロセス動作（`network_calls=0`、ローカル HTTP/MITM プロキシなし、待受ポートゼロ、API キー傍受ゼロ）で社内 DLP/EDR ポリシーに抵触せず、単体利用（`providers=None`）から `Mem0`、`Zep/Graphiti`、`PostgreSQL`、`Mories` の同時接続まで対応します。

---

## 実証ベンチマーク数値データ（4 群 × 6 ラウンド実エージェント隔離評価）

事前凍結された SHA-256 評価契約（`freeze.json`）のもと、**16 回の隔離された実エージェント呼び出し**（`6` ラウンド × 文書間脚注・安全マージン `5` 項目 ＝ **計 `30` 採点フィールド**、外部ファイル／検索ツール漏洩 `0` 回を監査済み）で計測した定量データです。

### 1. 4 比較群（4-Arm）精度・トークン・コスト総合比較

| 比較群 (Arm) | 手法概要 | ラウンド精度 | フィールド精度 (`30`項目) | 安全誤判定 / 陳腐化漏洩 | LLM 呼出数 | 送信総入力トークン | KV-Prefix キャッシュ一致 | 非キャッシュ入力 (`Uncached`) | 出力トークン | 実効課金コスト (`90%` KV 割引基準) | 最終判定 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **Arm 0** | 原文非整列ベースライン（質問先頭配置） | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | `0` / `0` | `6` 回 | `10,151` | `3,584` | `6,567` | `270` | `8,005.4`（基準 `0.0%`） | ベースライン |
| **Arm 1** | 単純質問文字列キャッシュ | `50.0%` (`3/6`) | `63.3%` (`19/30`) | **`3` 件 / `5` 件** | `2` 回 | `3,360` | `0` | `3,360` | `86` | `3,752.0` (`-53.1%`) | ❌ **棄却**（陳腐化による重大誤判定） |
| **Arm 2** | 有損失要約コンテキスト圧縮 | **`33.3%`** (`2/6`) | **`53.3%`** (`16/30`) | 過電流見逃し(`+1.0A` 誤認) / `1` 件 | `4` 回 | `3,623` | `256` | `3,367` | `155` | `4,122.2`（`-48.5%`、**遅延 5.2 倍悪化**） | ❌ **棄却**（推論品質崩壊） |
| **Arm 3** | **`synapse-hybrid-gate`（厳密ゲート + KV-Prefix 固定）** | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | **`0` 件 / `0` 件** | **`4` 回 (`-33.3%`)** | **`6,767` (`-33.3%`)** | **`3,712`** | **`3,055` (`-53.5%`)** | **`184` (`-31.9%`)** | **`4,162.2`（Arm 0 比 `-48.0%`・キャッシュなし比 `-62.9%`）** | ✅ **採用**（品質劣化 `0%`） |

> **有損失要約置換（`Arm 2`）を棄却した理由**：`R3` で `thermal_spec` の氷点下充電電流が `18A -> 24A` へ引き上げられた際、未変更仕様書 `connector_spec` の要約で第 4.3 節の脚注（`0°C 未満かつ 1.8m 超では Pin-B2 を 20.5A にディレーティング`）が欠落したため、実際の `-3.5A` 過電流危険を **`+1.0A` 安全**と誤算し、`R4` の深層横断クエリでは全 5 項目で `null`（`0/5`）を返しました。さらに欠落条件を内部推論で補おうとした結果、思考テキスト量が **`Arm 3` の `228` 文字（`17.8 秒`）から `Arm 2` では `7,726` 文字（`93.3 秒`、推論量 33.9 倍・応答時間 5.2 倍）**へ逆爆発しました。

<details>
<summary><b>📊 ラウンド別（R1〜R6）入出力トークン＆KV プレフィックス一致内訳を展開（Arm 0 vs Arm 3）</b></summary>

<br>

| ラウンド | シナリオイベント | Arm 0 モード＆入力 (`KV 一致`) | Arm 3 (`synapse-hybrid-gate`) モード＆入力 (`KV 一致`) | Arm 3 非キャッシュ入力 | Arm 3 精度 |
|---|---|---|---|---:|---:|
| **R1** | 初回 5 項目マルチ仕様書安全性監査 | `LLM_CALL` · `1,675` tok (`0` KV) | `LLM_CALL` · `1,675` tok (`0` KV) | `1,675` tok | `5/5` (`100%`) |
| **R2** | 上流変更なしでの再検証 | `LLM_CALL` · `1,675` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · `0` in / `0` out（`100%` 呼出スキップ）** | **`0` tok** | `5/5` (`100%`) |
| **R3** | ローカル仕様更新（`thermal_spec`: `18A -> 24A` 過電流発生） | `LLM_CALL` · `1,698` tok (`256` KV, `15.1%`) | **`LLM_CALL` · `1,698` tok（`1,152` KV, `67.8%` — KV 再利用 4.5 倍）** | **`546` tok** | `5/5` (`100%`) |
| **R4** | **全く新しい深層脚注横断クエリ** | `LLM_CALL` · `1,685` tok (**`0` KV, `0.0%`**) | **`LLM_CALL` · `1,685` tok（`1,472` KV, `87.4%` プレフィックス一致）** | **`213` tok** | `5/5` (`100%`) |
| **R5** | 外部メモリ `mem:bypass_policy` の失効（`revoked`） | `LLM_CALL` · `1,709` tok (`0` KV, `0.0%`) | **`LLM_CALL` · `1,709` tok（`1,088` KV, `63.7%` プレフィックス一致）** | **`621` tok** | `5/5` (`100%`) |
| **R6** | 失効反映後の再確認 | `LLM_CALL` · `1,709` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · `0` in / `0` out（`100%` 呼出スキップ）** | **`0` tok** | `5/5` (`100%`) |
| **合計** | **6 ラウンド累計** | **`6` 回呼出 · 非キャッシュ入力 `6,567` · 出力 `270`** | **`4` 回呼出 · 非キャッシュ入力 `3,055` (`-53.5%`) · 出力 `184` (`-31.9%`)** | **`3,055` tok** | **`30/30` (`100%`)** |

*注：保守的な `50%` KV キャッシュ割引モデルでも、Arm 3 は `100%` の精度を維持しつつ Arm 0 比 **`-40.2%`** の実効コスト削減（`5,647.0` vs `9,439.0`）を達成します。*

</details>

### 2. エンジン実行性能・セキュリティ・マルチプロセス並行性指標（`v0.3.1`）

| 検証項目 | 実測値 | 検証範囲・条件 |
|---|---|---|
| **統合検証スイート** | **内蔵公開 `26 / 26` PASS** + **リリース `32 / 32` PASS** | 公開 `tests/test_synapse_hybrid_gate.py`（`0.35 秒`）+ 隔離 Wheel（`python3 -I -B`） |
| **8 並列サブエージェント Prefix 共有率（`H07`）** | **`95.6%`** プレフィックスバイト完全一致 | 共通仕様書を参照しつつ個別サブタスクを並列実行する 8 サブエージェント間の比較 |
| **マルチプロセス SQLite WAL 並行性（`H08`）** | **6 OS プロセスでロック・スナップショットエラー `0` 件** | 同時 `read_only=True` MVCC スナップショットワーカー 4 + 同時 Writer 2 および OCC 競合遮断 |
| **メモリ使用量＆実行時間** | **Peak RSS `48.86 MiB`**（全スイート `6.37 秒`） | 純粋な Python `>=3.11` 標準ライブラリのみ（外部 pip 依存パッケージ `0` 個） |
| **改ざん検知＆プロンプト脱出防御（`H06`, `H07`）** | **`100%` 遮断（`HOLD` / `DENY`）** | キャッシュ行とハッシュチェーンレシートの二重照合、敵対的 `</EVIDENCE>` タグ自動昇格（`EVIDENCE_1`）、`O_NOFOLLOW` シンボリックリンク拒否、POSIX `0600` 権限 |

---

## 5 分クイックスタート

```bash
pip install git+https://github.com/JungKiBong/synapse-hybrid-gate.git@v0.3.1
# またはローカルクローン後、API キー不要のデモを即座に実行：
pip install .
python3 examples/demo_lossless_savings.py
```

### 1. 単体利用での無損失 LLM キャッシュ・KV-Prefix 固定・トークン監視

```python
from synapse_hybrid_gate import HybridEvidenceGate

with HybridEvidenceGate("gate.db", project_root=".") as gate:
    gate.register_local_evidence("ev:arch", "docs/architecture.md")
    gate.register_task("task:security_review", "ゲートウェイのセキュリティ監査")
    gate.bind_task("task:security_review", ["ev:arch"])

    # 原文損失 0% の KV-Prefix 固定プロンプトを生成（未変更仕様書を先頭固定、質問を末尾配置）
    plan = gate.build_kv_pinned_prompt(
        "task:security_review",
        question="architecture.md に基づき TLS タイムアウト不変条件を検証せよ。",
    )

    # 初回のみ LLM を呼び出し、根拠が未変更なら次回以降は 0 トークンで検証済み結果を即座に返却！
    outcome = gate.run_cached_step(
        "task:security_review",
        plan.rendered_prompt,
        lambda prompt: ('{"safe": true}', 1800, 120),  # 実際の LLM API 呼び出しに置換
    )
    print(outcome.cache_hit, gate.token_monitoring_report())
```

### 2. `Mem0`、`Zep/Graphiti`、`PostgreSQL`、`Mories` との接続（ロックインゼロ）

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

### 3. 並列サブエージェント向け楽観的並行制御（OCC）

```python
with HybridEvidenceGate("gate.db", project_root=".") as gate:
    lease = gate.begin_work("task:security_review")
    # ... サブエージェントが並列実行中に別セッションが architecture.md を変更した場合、
    # record_receipt は StaleWorkConflictError を送出し、古い承認結果の記録を防止します！
    gate.record_receipt(
        "task:security_review",
        outcome_sha256="a" * 64,
        expected_dependency_digest=lease.dependency_digest,
    )
```

---

## CLI リファレンス＆トークン削減量リアルタイム監視（`monitor`）

終了コード（Exit Code）：`0`（`ALLOW` / 正常）、`2`（`HOLD` — ファイル変更・メモリ失効・外部アダプタオフライン）、`3`（`ERROR` / `DENY` / ハッシュチェーン改ざん / CLI 引数エラー）。

```bash
synapse-hybrid-gate --db gate.db --project-root . init
synapse-hybrid-gate --db gate.db --project-root . register-local --evidence-id ev:spec --file spec.md
synapse-hybrid-gate --db gate.db bind-task --task-id task:t1 --title "Check spec" --evidence-id ev:spec

# シェルフック（Claude Code / Codex / OpenCode）から直接 KV-Prefix プロンプト生成＆無損失キャッシュ保存・参照：
synapse-hybrid-gate --db gate.db --project-root . begin-work --task-id task:t1
synapse-hybrid-gate --db gate.db --project-root . build-prompt --task-id task:t1 --question "仕様の不変条件を監査せよ" --format json
synapse-hybrid-gate --db gate.db --project-root . cache-store --task-id task:t1 --prompt-sha256 <SHA256> --payload '{"safe":true}' --input-tokens 1675 --output-tokens 43
synapse-hybrid-gate --db gate.db --project-root . cache-lookup --task-id task:t1 --prompt-sha256 <SHA256>
synapse-hybrid-gate --db gate.db --read-only check-task --task-id task:t1

# 回避した LLM 呼出回数、節約した入出力トークン数、キャッシュヒット率(%)、KV-Prefix 固定トークン数を表示：
synapse-hybrid-gate --db gate.db monitor --format table
synapse-hybrid-gate --db gate.db monitor --format json

# オンライン安全な SQLite バックアップ（0600 権限・シンボリックリンク拒否）＆ハッシュチェーン検証：
synapse-hybrid-gate --db gate.db backup --dest gate.backup.db
synapse-hybrid-gate --db gate.db verify-chain
```

---

## テストとデモの実行

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 examples/demo_lossless_savings.py
```

## 企業セキュリティとアーキテクチャ境界

- **通信傍受ゼロ（Zero-Proxy / Zero-Daemon）**：ローカル HTTP/HTTPS プロキシの起動、API キーや TLS 通信の傍受、ネットワークポートの待受を一切行いません。企業の厳格なセキュリティ（DLP/EDR）ポリシーに準拠し、Claude Code、Codex、OpenCode、Cursor、自社製 Python エージェントへプロジェクト単位（Opt-in）で安全に導入できます。
- **ファイルシステム＆台帳の堅牢化**：`project_root` 境界強制、中間シンボリックリンク拒否（`lstat` + `O_NOFOLLOW`）、通常ファイル検証、巨大ファイル DoS 上限（`max_file_bytes`、既定 `64 MiB`）、POSIX `0600` 所有者限定 DB 権限、SHA-256 ハッシュチェーンレシートを徹底しています。
- **明示的スキーマ移行**：旧バージョン（`v1`/`v2`）の SQLite 台帳を開くと `SchemaVersionError` で安全に停止し、`migrate_database(db_path)` または `synapse-hybrid-gate --db gate.db migrate` による明示的なアップグレードを要求します。
- 本プロジェクトは **Apache License, Version 2.0**（[LICENSE](./LICENSE)）のもとで公開されています。
