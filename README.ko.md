<div align="center">

<h1>synapse-hybrid-gate</h1>

<p><b>외부 의존성 0개 · 컨텍스트 손실 0% · 멀티세션 및 병렬 AI 에이전트용 무손실 LLM 결과 캐시 &amp; KV-Prefix 근거 게이트 (<code>Apache-2.0</code>)</b></p>

<p>
  <a href="./README.md"><kbd>🇺🇸 English</kbd></a>
  &nbsp;
  <kbd>🇰🇷 <b>한국어 ✓</b></kbd>
  &nbsp;
  <a href="./README.zh-CN.md"><kbd>🇨🇳 简体中文</kbd></a>
  &nbsp;
  <a href="./README.ja.md"><kbd>🇯🇵 日本語</kbd></a>
</p>

</div>

---

일반적인 프롬프트 문자열·시맨틱 캐시는 실제 소프트웨어 개발 환경에서 쉽게 깨집니다. **질문 문장은 그대로인데 그 밑바탕이 되는 설계 문서, 소스 파일, 외부 장기 기억(`Mem0`, `Zep/Graphiti`, `PostgreSQL`, `Mories`)이 수시로 바뀌기 때문**입니다. 반대로 토큰을 아끼겠다고 문서를 요약본으로 치환하면 세부 각주 교차 추론이 무너지고 모델의 내부 추론(Thinking) 지연이 역폭발합니다.

`synapse-hybrid-gate`는 로컬 SQLite WAL 원장에 정확한 암호학적 포인터 `(epoch, revision, content_sha256)`를 기록하여 **외부 런타임 의존성 0개**, **백그라운드 프록시/데몬 0개**, **컨텍스트 품질 저하 0%**로 토큰을 절감합니다.

- **100% 무손실 토큰 절감 (비캐시 입력 토큰 `-53.5%`, 정확도 `30/30` 100%)**:
  - **검증 단계 즉시 우회 (`run_cached_step`)**: 연결된 로컬 파일과 외부 메모리가 검증 당시의 `(epoch, revision, sha256)`과 100% 일치(`ALLOW`)하고 프롬프트/모델 파라미터가 같을 때만 입·출력 토큰을 **`100%` 생략**하며, 파일이 단 1바이트만 바뀌거나 외부 기억이 철회(`revoked`)되면 즉시 `HOLD`로 재검증을 강제합니다.
  - **무손실 KV-Prefix 고정 정렬 (`build_kv_pinned_prompt`)**: 원문을 단 한 글자도 요약·삭제하지 않습니다. 변경되지 않은(`ALLOW`) 근거들을 프롬프트 앞단(Prefix)에 결정론적 순서로 고정하고, 방금 수정된(`HOLD`) 문서와 질문(`<QUESTION>`)을 맨 뒤에 배치하여 후속 복합 질문과 병렬 서브에이전트 간 **`87.4%`~`95.6%`**의 LLM KV 프리픽스 캐시 적중률을 달성합니다.
- **멀티세션 & 병렬 서브에이전트 동시성 보호**:
  - **낙관적 동시성 리스 (`begin_work`)**: 서브에이전트가 작업하는 도중 다른 세션이 설계 문서를 수정하거나 기억을 철회하면 구버전 승인 커밋을 `StaleWorkConflictError`로 즉시 차단합니다.
  - **무잠금 읽기 전용 워커 (`read_only=True`)** + `SQLITE_BUSY` 지터 재시도 + 외부 메모리 장애 전파를 막는 `CircuitBreakingAdapter` 내장.
- **기업 보안 친화적 로컬 구조 & 벤더 중립 메모리 포트**:
  - 네트워크 포트 오픈 0개, API 키/트래픽 가로채기(MITM 프록시) 0개로 사내 보안(DLP/EDR) 정책과 충돌하지 않으며, 단독(`providers=None`) 실행은 물론 `Mem0`, `Zep/Graphiti`, `PostgreSQL`, `Mories`와 동시에 연결됩니다.

---

## 객관적 실증 수치 데이터 (4-Arm × 6라운드 실제 에이전트 실험)

사전 동결(`freeze.json`)된 시나리오 위에서 **16회 격리된 실제 에이전트 호출**(`6`라운드 × 문서 간 각주·안전 마진 `5`개 문항 = **총 `30`개 채점 필드**, 외부 파일/검색 도구 누출 `0`회 감사 완료)로 측정한 정량 결과입니다.

### 1. 4개 대조군(4-Arm) 정확도 · 토큰 · 비용 종합 비교

| 비교군 (Arm) | 기법 설명 | 라운드 정확도 | 필드 정확도 (`30`개) | 안전 오판 / Stale 누출 | LLM 호출 수 | 총 전송 입력 토큰 | KV-Prefix 캐시 적중 | 비캐시 입력 토큰 (`Uncached`) | 출력 토큰 | 유효 과금 비용 (`90%` KV 할인 기준) | 최종 판정 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **Arm 0** | 원문 무정렬 기준선 (질문 선행 배치) | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | `0` / `0` | `6`회 | `10,151` | `3,584` | `6,567` | `270` | `8,005.4` (기준 `0.0%`) | 기준선 |
| **Arm 1** | 기존 단순 질문 문자열 캐시 | `50.0%` (`3/6`) | `63.3%` (`19/30`) | **`3`건 / `5`건** | `2`회 | `3,360` | `0` | `3,360` | `86` | `3,752.0` (`-53.1%`) | ❌ **폐기** (Stale 오답 참사) |
| **Arm 2** | 손실형 요약본 컨텍스트 다이어트 | **`33.3%`** (`2/6`) | **`53.3%`** (`16/30`) | 과전류 미탐(`+1.0A` 오판) / `1`건 | `4`회 | `3,623` | `256` | `3,367` | `155` | `4,122.2` (`-48.5%`, **지연 5.2배 폭증**) | ❌ **폐기** (컨텍스트 품질 붕괴) |
| **Arm 3** | **`synapse-hybrid-gate` (무손실 Gate + KV-Prefix 고정)** | **`100.0%`** (`6/6`) | **`100.0%`** (`30/30`) | **`0`건 / `0`건** | **`4`회 (`-33.3%`)** | **`6,767` (`-33.3%`)** | **`3,712`** | **`3,055` (`-53.5%`)** | **`184` (`-31.9%`)** | **`4,162.2` (Arm 0 대비 `-48.0%` · 무캐시 대비 `-62.9%`)** | ✅ **최종 채택** (품질 손실 `0%`) |

> **손실형 요약 치환(`Arm 2`) 기각 사유**: `R3`에서 `thermal_spec`의 영하 충전 전류가 `18A -> 24A`로 상향되었을 때, 무변경 문서 `connector_spec`의 요약본에서 4.3절 각주(`영하·1.8m 초과 시 Pin-B2 20.5A 제한`)가 누락되면서 실제 `-3.5A` 과전류 위험을 **`+1.0A` 안전**으로 오판했고, `R4` 심층 교차 질의에서는 5개 문항 전수 `null`(`0/5`)을 반환했습니다. 또한 빠진 제약을 역추적하느라 모델 내부 추론량이 **`Arm 3` `228`자(`17.8초`) → `Arm 2` `7,726`자(`93.3초`, 추론량 33.9배 · 응답 지연 5.2배)**로 역폭발했습니다.

<details>
<summary><b>📊 라운드별(R1~R6) 상세 입·출력 토큰 및 KV 프리픽스 적중 데이터 펼치기 (Arm 0 vs Arm 3)</b></summary>

<br>

| 라운드 | 시나리오 이벤트 | Arm 0 실행 모드 및 입력 (`KV 적중`) | Arm 3 (`synapse-hybrid-gate`) 실행 모드 및 입력 (`KV 적중`) | Arm 3 비캐시 입력 | Arm 3 정확도 |
|---|---|---|---|---:|---:|
| **R1** | 초기 5개 항목 다중 문서 안전성 검토 | `LLM_CALL` · `1,675` tok (`0` KV) | `LLM_CALL` · `1,675` tok (`0` KV) | `1,675` tok | `5/5` (`100%`) |
| **R2** | 무변경 상태 재검토 요청 | `LLM_CALL` · `1,675` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · 입·출력 `0` tok (`100%` 호출 생략)** | **`0` tok** | `5/5` (`100%`) |
| **R3** | 로컬 스펙 수정 (`thermal_spec`: `18A -> 24A` 과전류 발생) | `LLM_CALL` · `1,698` tok (`256` KV, `15.1%`) | **`LLM_CALL` · `1,698` tok (`1,152` KV, `67.8%` — KV 재사용 4.5배)** | **`546` tok** | `5/5` (`100%`) |
| **R4** | **완전히 새로운 심층 각주 교차 질문** | `LLM_CALL` · `1,685` tok (**`0` KV, `0.0%`**) | **`LLM_CALL` · `1,685` tok (`1,472` KV, `87.4%` 프리픽스 적중)** | **`213` tok** | `5/5` (`100%`) |
| **R5** | 외부 메모리 `mem:bypass_policy` 철회(`revoked`) | `LLM_CALL` · `1,709` tok (`0` KV, `0.0%`) | **`LLM_CALL` · `1,709` tok (`1,088` KV, `63.7%` 프리픽스 적중)** | **`621` tok** | `5/5` (`100%`) |
| **R6** | 철회 반영 이후 반복 검증 | `LLM_CALL` · `1,709` tok (`1,664` KV) | **`GATE_ALLOW_REUSE` · 입·출력 `0` tok (`100%` 호출 생략)** | **`0` tok** | `5/5` (`100%`) |
| **합계** | **6라운드 누적** | **`6`회 호출 · 비캐시 입력 `6,567` · 출력 `270`** | **`4`회 호출 · 비캐시 입력 `3,055` (`-53.5%`) · 출력 `184` (`-31.9%`)** | **`3,055` tok** | **`30/30` (`100%`)** |

*참고: 보수적인 `50%` KV 캐시 할인율을 적용하더라도 Arm 3는 `100%` 정확도를 유지하면서 Arm 0 대비 **`-40.2%`** 유효 비용 절감(`5,647.0` vs `9,439.0`)을 달성합니다.*

</details>

### 2. 엔진 런타임 · 보안 · 멀티프로세스 동시성 실측 지표 (`v0.3.0`)

| 측정 항목 | 검증 수치 | 검증 범위 및 조건 |
|---|---|---|
| **통합 검증 시나리오** | **`32 / 32` 전수 PASS** (`34`개 단언 그룹) | 하드닝(`H01`~`H12`) + 범용 포트(`U01`~`U10`) + 기본 게이트(`F01`~`F12`) + 클린 Wheel(`python3 -I -B`) 격리 실행 |
| **8개 병렬 서브에이전트 프리픽스 공유율 (`H07`)** | **`95.6%`** 바이트 완전 일치 | 공통 아키텍처 스펙 위에서 서로 다른 하위 과업을 병렬 수행하는 8개 서브에이전트 프롬프트 비교 |
| **멀티프로세스 SQLite WAL 동시성 (`H08`)** | **6개 OS 프로세스 락 에러 `0`건** | 동시 `read_only=True` 워커 4개 + 동시 Writer 2개 병렬 실행 및 OCC 충돌 차단 확인 |
| **메모리 점유율 및 실행 속도** | **Peak RSS `48.86 MiB`** (전체 스위트 `6.37초`) | 순수 Python `>=3.11` 표준 라이브러리만 사용 (외부 패키지 의존성 `0`개) |
| **위변조 및 프롬프트 탈출 방어 (`H06`, `H07`)** | **`100%` 차단 (`HOLD` / `DENY`)** | 캐시 테이블·해시체인 영수증 이중 무결성 대조, 적대적 `</EVIDENCE>` 구분자 자동 승격(`EVIDENCE_1`), `O_NOFOLLOW` 심볼릭링크 차단, `0600` 권한 강제 |

---

## 5분 빠른 시작 (Quickstart)

```bash
pip install git+https://github.com/JungKiBong/synapse-hybrid-gate.git@v0.3.0
# 또는 로컬 클론 폴더에서 설치:
pip install .
```

### 1. 단독 실행 무손실 LLM 캐싱 · KV-Prefix 고정 · 토큰 절감량 모니터링

```python
from synapse_hybrid_gate import HybridEvidenceGate

with HybridEvidenceGate("gate.db", project_root=".") as gate:
    gate.register_local_evidence("ev:arch", "docs/architecture.md")
    gate.register_task("task:security_review", "게이트웨이 보안 검토")
    gate.bind_task("task:security_review", ["ev:arch"])

    # 원문 손실 0% KV-Prefix 고정 프롬프트 생성 (불변 스펙 앞단 고정, 질문은 맨 뒤 배치)
    plan = gate.build_kv_pinned_prompt(
        "task:security_review",
        question="architecture.md 기준으로 TLS 타임아웃 불변식을 검증하라.",
    )

    # 최초 1회만 LLM 호출; 근거 파일이 그대로면 다음 호출부터는 입·출력 토큰 0개로 즉시 반환!
    outcome = gate.run_cached_step(
        "task:security_review",
        plan.rendered_prompt,
        lambda prompt: ('{"safe": true}', 1800, 120),  # 실제 LLM API 호출 함수로 교체
    )
    print(outcome.cache_hit, gate.token_monitoring_report())
```

### 2. `Mem0`, `Zep/Graphiti`, `PostgreSQL`, `Mories` 범용 어댑터 연결 (락인 0%)

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

### 3. 병렬 서브에이전트 낙관적 동시성(OCC) 보호

```python
with HybridEvidenceGate("gate.db", project_root=".") as gate:
    lease = gate.begin_work("task:security_review")
    # ... 서브에이전트 병렬 작업 수행 중 다른 세션이 architecture.md를 수정하면,
    # 구버전 승인 영수증 커밋 시 StaleWorkConflictError를 발생시켜 오염을 차단합니다!
    gate.record_receipt(
        "task:security_review",
        outcome_sha256="a" * 64,
        expected_dependency_digest=lease.dependency_digest,
    )
```

---

## CLI 레퍼런스 및 실시간 토큰 절감량 조회 (`monitor`)

종료 코드(Exit Code): `0` (`ALLOW` / 정상), `2` (`HOLD` — 문서 변경·기억 철회·외부 어댑터 오프라인), `3` (`ERROR` / `DENY` / 해시체인 위변조 / 잘못된 CLI 인자).

```bash
synapse-hybrid-gate --db gate.db --project-root . init
synapse-hybrid-gate --db gate.db --project-root . register-local --evidence-id ev:spec --file spec.md
synapse-hybrid-gate --db gate.db bind-task --task-id task:t1 --title "Check spec" --evidence-id ev:spec
synapse-hybrid-gate --db gate.db record-receipt --task-id task:t1 --outcome-sha256 $(printf 'a%.0s' {1..64})
synapse-hybrid-gate --db gate.db --read-only check-task --task-id task:t1

# 생략된 LLM 호출 수, 절약된 입·출력 토큰, 캐시 적중률(%), KV-Prefix 고정 토큰 실시간 리포트:
synapse-hybrid-gate --db gate.db monitor --format table
synapse-hybrid-gate --db gate.db monitor --format json

# 무중단 온라인 SQLite 백업 (0600 권한, 심볼릭링크 차단) 및 영수증 해시체인 무결성 검증:
synapse-hybrid-gate --db gate.db backup --dest gate.backup.db
synapse-hybrid-gate --db gate.db verify-chain
```

---

## 테스트 실행

```bash
python3 -m unittest discover -s tests -v
```

## 기업 보안 및 아키텍처 경계 안내

- **네트워크 가로채기 0% (Zero-Proxy / Zero-Daemon)**: 로컬 HTTP/HTTPS 프록시를 띄우거나 API 키·TLS 패킷을 가로채지 않으며 외부 포트를 일절 열지 않습니다. 사내 보안(DLP/EDR) 위반 우려 없이 Claude Code, Codex, OpenCode, Cursor 및 자체 Python 에이전트에 프로젝트 단위(Opt-in)로 안전하게 적용할 수 있습니다.
- **파일시스템 및 원장 하드닝**: 지정된 `project_root` 경계 강제, 중간 경로 심볼릭 링크 거부(`lstat` + `O_NOFOLLOW`), 일반 파일 검증, 대용량 파일 DoS 상한(`max_file_bytes`, 기본 `64 MiB`), POSIX `0600` 소유자 전용 DB 권한, SHA-256 해시체인 영수증을 기본 적용합니다.
- **명시적 스키마 마이그레이션**: 구버전(`v1`/`v2`) SQLite 원장을 열면 자동 변경 대신 `SchemaVersionError`로 안전하게 차단하며, `migrate_database(db_path)` 또는 `synapse-hybrid-gate --db gate.db migrate`로 명시적 승격을 수행합니다.
- 본 프로젝트는 **Apache License, Version 2.0** ([LICENSE](./LICENSE)) 라이선스로 배포됩니다.
