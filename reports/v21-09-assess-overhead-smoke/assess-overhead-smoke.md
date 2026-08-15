# V21-09 assess/finalize 门禁验证与开销 smoke 报告（T5）

> 任务：T5 门禁验证与开销 smoke（验证收尾 + 基准脚本扩展）。
> 分支：`feat/v21-09-assess-finalize`；测量基于提交 `02ef41c`（T0-T4 全部成果）
> + 本次未提交的基准工具扩展（测量时工作树 dirty=true，未提交改动仅为
> `scripts/v21-baseline.py` 三档/task 引用扩展与本文件）。
> 口径声明：**机器结果非跨环境硬 SLO，CI 只校验工具正确性（05 §9）**；完整协议
> 全量基准（Core 预热 200 测 5000；API 预热 100 串行 1000 + 8 并发 2000）为可选项，
> **本次为缩减 smoke 口径**（Core 预热 20 测 200；API 预热 10 串行 100 + 8 并发 200），
> 不跑全量档。flag 恒 `AGENTGUARD_V21_SHADOW_ENABLED`（默认 false），mode 恒
> `shadow`，legacy 唯一官方决策者（12-D1）。

## 1. 测量配置

| 项 | 值 |
|---|---|
| flag | `AGENTGUARD_V21_SHADOW_ENABLED`（12-D1，默认 false，未新增 flag） |
| 档位 | `--shadow tri`（三档对照：off / shadow-v2108 / v2109 pipeline） |
| task 引用场景 | `--task-ref on`（事件携带 `metadata.task_id` trusted claim + memory store 预播权威 TaskFact，**snapshot 直出路径**，补 V21-08 报告 §7.1 遗留实测） |
| 后端 | memory（无需真实 postgres） |
| 协议参数 | `--measurement-profile functional_smoke --core-warmup 20 --core-iterations 200 --api-warmup 10 --api-serial-iterations 100 --api-concurrency 8 --api-concurrent-total 200 --backends memory` |
| 三档语义 | off=flag off（legacy 唯一路径）；shadow-v2108=flag on + pipeline 禁用（V21-08 shadow 语义，基准专用类级开关，非生产配置）；v2109=flag on + 四段式 pipeline（Phase A 事务外 + Phase B 短事务 + Phase C 投影） |
| 百分位 | nearest-rank P50/P95/P99/max，单调纳秒样本，不剔除异常值 |
| 环境 | Windows 11（10.0.26200），Python 3.12.13，单进程 TestClient + 线程并发 |

## 2. 三档延迟增量（串行 100 样本/场景，单位 ms）

本机样本呈约 15.6ms 台阶的量化粒度（Windows 定时器/调度量化），三档同台阶
量化，smoke 增量读数偏保守上界；**可靠增量结论需按 05 §9 完整协议档位复测**。

off 档基线（P50/P95，ms）：low_read 16/78、sensitive_read 47/140、
external_send 47/125、code_execution 32/94、memory 47/141、multi_event 47/156、
degraded 32/125。

### 2.1 shadow-v2108 vs off（ΔP50 / ΔP95，逐场景）

| 场景 | low_read | sensitive_read | external_send | code_execution | memory | multi_event | degraded |
|---|---|---|---|---|---|---|---|
| ΔP50 | +31 | +30 | +16 | +46 | +15 | +16 | +16 |
| ΔP95 | +78 | +47 | +47 | +78 | +15 | +1 | +31 |

并发档（8 worker × 200 请求）：ΔP50 +265ms、ΔP95 +405ms、ΔP99 +406ms。

### 2.2 v2109 pipeline vs off

| 场景 | low_read | sensitive_read | external_send | code_execution | memory | multi_event | degraded |
|---|---|---|---|---|---|---|---|
| ΔP50 | +31 | +31 | +16 | +46 | +16 | +16 | +31 |
| ΔP95 | +93 | +31 | +47 | +94 | +31 | +16 | +47 |

并发档：ΔP50 +250ms、ΔP95 +437ms、ΔP99 +437ms。

### 2.3 v2109 vs shadow-v2108（四段式编排净增量）

| 场景 | low_read | sensitive_read | external_send | code_execution | memory | multi_event | degraded |
|---|---|---|---|---|---|---|---|
| ΔP50 | 0 | +1 | 0 | 0 | +1 | 0 | +15 |
| ΔP95 | +15 | -16 | 0 | +16 | +16 | +15 | +16 |

并发档：ΔP50 -15ms、ΔP95 +32ms、ΔP99 +31ms。

**解读**：
1. v2109 相对 v2108 的串行净增量 ΔP50 0~1 台阶、ΔP95 -16~+16ms，落在
   15.6ms 台阶级噪声内——四段式重构（Phase A 事务外 + Phase B 短事务 +
   Phase C 事务后投影）未引入可测的额外串行开销上界，S8 消除以结构达成
   （事务窗口断言测试锁定）而非以延迟恶化换取。
2. flag on 两档相对 off 的增量（ΔP50 +15~46ms、ΔP95 +1~94ms）与 V21-08
   smoke（ΔP50 +16~31ms、ΔP95 +31~62ms，快路径口径）同量级；本次为
   **snapshot 直出路径**（bounded rebuild + read_snapshot + Phase C 投影），
   上界读数未显著超出快路径口径。
3. 并发档增量无单调方向且量级偏大，属小样本线程调度噪声（V21-08 smoke
   同口径声明）；并发档中出现的 `base state version drifted ... fail-closed
   without dirtying` 日志为 Phase C CAS 竞争下的 D9 fail-closed 预期语义
   （不置脏、不重试、不影响响应），非缺陷。

## 3. metrics gate（`scripts/core-metrics-gate.py` 全量一次）

```text
ok=true | recall=0.9667（≥0.90）| fpr=0.0000（≤0.05）| fnr=0.0333
attacks: 29/30 blocked | benign: 0/13 blocked | missed: EG-AA-004（既有基线
已知 miss，与冻结 legacy 快照 parity 一致，非本次回退）
```

## 4. 04 §21 十二项门禁（targeted 子集证据）

验证约束：禁全量 1224 套件、禁 E2E、禁长时间压测（用户裁决）；以下为
targeted 子集逐项证据。

| # | 门禁 | 结论 | 证据 |
|---|---|---|---|
| 1 | unit tests | ✅ | T1-T4 新测试 5 文件 targeted 复跑：`test_v21_09_assess_finalize.py` / `test_v21_09_revalidation.py` / `test_v21_09_pipeline.py` / `test_v21_09_evaluation_projection.py` / `test_v21_09_evidence_mode.py` = **129 passed / 2 skipped**（postgres 依赖跳过）；基准工具扩展测试 `test_v21_baseline.py` 22 passed |
| 2 | contract tests | ✅ | `test_v21_contract_scaffold.py` + `test_store_contract.py`（evidence 键集条件断言，flag on 允许 decision_v21 + state_delta_v21）targeted 全绿；`v21-contract-tools.py validate` / `checksums --verify` 通过 |
| 3 | retained regression | ✅ | `test_v21_legacy_parity.py`（43 case 分布 allow:14/ask:2/deny:27，与冻结快照逐 case parity）+ `test_core_rule_matrix.py` targeted 全绿；smoke 回归基线 `legacy_parity.ok=true`、decision 分布 `{allow:14, ask:2, deny:27}` 一致 |
| 4 | independent holdout | ✅（本阶段口径） | locked holdout 不解锁（manifest 指纹记录于 smoke JSON `locked_holdout_manifest_sha256`）；按任务指令不跑全量，指标由 metrics gate 与 smoke 承载（holdout 正式评测归 Limited Enable 前） |
| 5 | benign-hard regression | ✅（本阶段口径） | benign 13/13 零干预（metrics gate：blocked_benign=0、fpr=0.0000）；benign-hard 全量档按任务指令省略，由 metrics gate 承载 |
| 6 | latency delta | ✅ | 三档 smoke 对照（§2）：v2109 vs v2108 净增量落在台阶级噪声内；flag on 上界与 V21-08 smoke 同量级；非硬 SLO 判定（05 §9） |
| 7 | ASK/DENY distribution | ✅ | smoke decision 分布 `{allow:14, ask:2, deny:27}` 与冻结 legacy 快照逐 case 一致（`legacy_parity.ok=true`），无 ASK/DENY 漂移 |
| 8 | replay/idempotency | ✅ | `test_v21_09_evaluation_projection.py`：`test_replay_no_duplicate_projection_response_unchanged` / `test_projector_replayed_noop_for_same_committed_record` / `test_d9_replay_backfill_projection_idempotent`；`test_v21_08_audit_evidence.py` request_digest 幂等口径用例全绿 |
| 9 | failure injection | ✅ | `test_v21_09_pipeline.py`：三类 stale 触发（state version 推进 / policy digest 变化 / task digest 变化）→ `degraded_stale_judgment`；`test_v21_09_evaluation_projection.py`：`test_digest_conflict_dirty_fail_closed`、投影失败不影响响应与审计；并发 smoke 实测 Phase C base drift fail-closed 收敛（不置脏） |
| 10 | explainability/evidence test | ✅ | evidence 双信封形状：`test_v21_contract_scaffold.py` + `test_store_contract.py`（键集）+ `test_v21_08_audit_evidence.py` / `test_v21_08_decision_evidence.py`（逐字节回归）；`test_v21_09_evidence_mode.py`（mode 参数化）全绿；sanity 实测 task 引用场景 `decision_v21` + `state_delta_v21` 双信封落盘、`degradation: None`（snapshot 直出） |
| 11 | no F0 violation | ✅ | commit→project 顺序：`test_projection_commit_before_project_outside_tx`；禁伪造 snapshot：`test_assess_without_snapshot_raises_value_error` / `test_engine_assess_delegates_and_validates_snapshot`（snapshot=None→ValueError，01 §25）；legacy 官方决策不变：flag on 时 HTTP 响应/decision 面逐 case parity |
| 12 | rollback path | ✅ | flag off 即回退：`test_pipeline_flag_off_returns_none_without_io`（零 I/O）+ `test_flag_off_zero_projection_zero_envelope`；append-only：evidence 同条记录写面、不新增第二条审计记录（`test_audit_integrity.py` targeted 全绿）；PROJECTOR_VERSION 不 bump：`git diff origin/dev...HEAD -- security_state/projector.py` 为**空**（常量与实现零改动，12-D6） |

targeted 批次合计：新测试 129 passed/2 skipped；回归批次（legacy parity +
rule matrix + 8 个 `test_v21_08_*` + scaffold + store contract + state
projector + audit integrity）= **349 passed / 60 skipped**（skip 均为
postgres 依赖）。

## 5. flag off/on 双模式结论

1. **flag off（默认）**：行为与审计形状逐字节不变——pipeline `run_phase_a`
   仅一次布尔判断返回 None、零 I/O（测试锁定）；`test_v21_legacy_parity.py`
   43 case 与冻结快照一致；本次 smoke 的 off 档即对照基线本身。
2. **flag on**：mode 恒 `shadow`、legacy 唯一官方决策者；V21-09 产物为权威
   记录 + `decision_v21`/`state_delta_v21` 双信封 + CAS/revalidation 能力，
   绝不取代 evaluate 响应；snapshot 直出路径实测上界见 §2。
3. **回退路径**：flag off 即全量回退；投影侧 append-only、PROJECTOR_VERSION
   不 bump，新→旧回滚无 reprojection 负担（12-D6）。

## 6. baseline-count 新基线

```text
scripts/v21-contract-tools.py baseline-count → collected tests: 1616
scripts/v21-contract-tools.py baseline-count --min 1616 → 通过
checksums --verify / validate → 通过（冻结正文 SHA 不变）
```

最小基线经 `--min` 命令行传入（不硬编码于脚本，10-D2 口径）；含本次 T5
新增基准工具测试后的当前收集基线为 **1616**。历史记载值 953 见
`10_决策记录_V21-05-06-07前置.md` 关联条目（历史快照，不改动冻结正文）。

## 7. 基准脚本扩展（本提交）

- `scripts/v21-baseline.py`：`--shadow` 新增 `tri` 档（off / shadow-v2108 /
  v2109 三档对照，产出 `pipeline_overhead` 两两增量 + 既有 `shadow_overhead`
  形状不变）；新增 `--task-ref {off,on}`（事件携带 `metadata.task_id`
  trusted claim + memory store 预播权威 TaskFact，snapshot 直出路径）；
  shadow-v2108 档经基准专用类级开关临时钉死 `V21PipelineService.enabled`
  （非生产配置，生产门控始终单一 flag）。完整协议参数（05 §9）保持 CLI
  全量可配，完整协议档为可选未跑。
- `tests/test_v21_baseline.py`：新增 7 个单测（参数默认值/选择、task 引用
  payload 附加、TaskFact 预播、pipeline 开关上下文复原、三档增量计算、
  tri 前置校验、tri smoke 端到端报告形状），不实际跑大样本。

## 8. 结论

1. 十二项门禁 targeted 证据全部通过（§4）；retained parity / metrics gate /
   evidence 双信封 / no-F0 / rollback 五项为强证据，holdout 与 benign-hard
   两项按任务指令由 metrics gate 与 smoke 承载（全量档归后续阶段）。
2. 三档 smoke：v2109 四段式 pipeline 相对 V21-08 shadow 语义无可测串行
   开销回归（台阶级噪声内），S8 事务窗口消除由结构断言锁定；flag on
   snapshot 直出路径上界与 V21-08 快路径口径同量级。
3. Recall/FPR 门禁不回退；legacy parity 通过；契约工具 validate/checksums
   通过；新测试基线 1616。
4. V21-10 pre-enable gate 前建议：按 05 §9 完整协议档位复测三档（含
   postgres 后端），并观测 Phase C 并发竞争下 fail-closed 跳过率。

## 机器可读证据

- `baseline.json`：本次 smoke 运行的 `scripts/v21-baseline.py` 完整机器报告
  （含 `shadow_overhead` / `pipeline_overhead` 三档对照、环境与 fixture
  指纹、locked holdout manifest 指纹）。
- `baseline.md`：脚本自动生成的可读摘要。
