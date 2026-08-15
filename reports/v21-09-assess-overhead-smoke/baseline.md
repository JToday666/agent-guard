# AgentGuard V21-00 基线报告

> 状态：`functional_smoke_passed`；冻结包为 `frozen`。

## 回归基线

- retained fixture：30 attack / 13 benign，仅作 regression baseline。
- decision 分布：`{"allow": 14, "ask": 2, "deny": 27}`。
- Attack Recall：0.9667；FNR：0.0333；missed：['EG-AA-004']。
- Benign ASK：0.0000；DENY：0.0000；Intervention：0.0000。
- Legacy 逐 case decision/rule hits 一致：`True`。
- retained fixture 标注漂移：14 cases；单列记录，不作为 69efe2f 行为快照。
- 以上比例的 Wilson 95% CI 见机器可读 JSON。

## 性能与执行证据

- 测量档位：`functional_smoke`；正式性能基线：`deferred_by_user_scope`。
- shadow 档位：`tri`。
- task 引用场景：`task_v2109_bench`。
- Core：`measured`。
- Guard API Memory：`measured`。
- Guard API PostgreSQL：`not_requested`。
- Semantic：`not_applicable`（尚未实现）。
- Final ASR：`not_measured`；Runtime Prevention：`not_measured`（没有完整 runtime attack bench）。

## Shadow 开销对照（flag off vs on，memory 后端）

- 串行 `code_execution`：P50 增量 31000000ns、P95 增量 78000000ns、P99 增量 94000000ns、max 增量 94000000ns。
- 串行 `degraded`：P50 增量 30000000ns、P95 增量 47000000ns、P99 增量 16000000ns、max 增量 62000000ns。
- 串行 `external_send`：P50 增量 16000000ns、P95 增量 47000000ns、P99 增量 31000000ns、max 增量 -1000000ns。
- 串行 `low_read`：P50 增量 46000000ns、P95 增量 78000000ns、P99 增量 46000000ns、max 增量 46000000ns。
- 串行 `memory`：P50 增量 15000000ns、P95 增量 15000000ns、P99 增量 15000000ns、max 增量 -32000000ns。
- 串行 `multi_event`：P50 增量 16000000ns、P95 增量 1000000ns、P99 增量 15000000ns、max 增量 32000000ns。
- 串行 `sensitive_read`：P50 增量 16000000ns、P95 增量 31000000ns、P99 增量 32000000ns、max 增量 16000000ns。
- 并发：P50 增量 265000000ns、P95 增量 405000000ns、P99 增量 406000000ns。

> 机器结果非跨环境硬 SLO，CI 只校验工具正确性（05 §9）；基准事件携带 task 引用（metadata.task_id trusted claim + memory store 预播权威 TaskFact），shadow/pipeline 走 snapshot 直出路径（bounded rebuild + read_snapshot），补 V21-08 §7.1 遗留实测。

## 三档开销对照（off / shadow-v2108 / v2109 pipeline，memory 后端）

- v2108 vs off：串行 ΔP50 15000000~46000000ns、ΔP95 1000000~78000000ns；并发 ΔP50 265000000ns、ΔP95 405000000ns。逐场景明细见机器可读 JSON。
- v2109 vs off：串行 ΔP50 16000000~46000000ns、ΔP95 16000000~94000000ns；并发 ΔP50 250000000ns、ΔP95 437000000ns。逐场景明细见机器可读 JSON。
- v2109 vs v2108：串行 ΔP50 0~15000000ns、ΔP95 -16000000~16000000ns；并发 ΔP50 -15000000ns、ΔP95 32000000ns。逐场景明细见机器可读 JSON。

> 机器结果非跨环境硬 SLO，CI 只校验工具正确性（05 §9）；基准事件携带 task 引用（metadata.task_id trusted claim + memory store 预播权威 TaskFact），shadow/pipeline 走 snapshot 直出路径（bounded rebuild + read_snapshot），补 V21-08 §7.1 遗留实测。

## 边界与阻塞

- 无
- 当前机器结果是基线证据，不是跨环境硬 SLO。
- nearest-rank P50/P95/P99/max 基于全部单调纳秒样本，不剔除异常值。
