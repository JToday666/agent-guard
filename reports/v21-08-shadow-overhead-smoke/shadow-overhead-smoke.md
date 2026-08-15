# V21-08 Shadow 开销验证报告（smoke 档）

> 任务：T8 性能验收与开销报告（benchmark-only）。
> 分支：`feat/v21-08-fusion-shadow`；测量基于提交 `f66d944` + 本提交新增的
> `--shadow` 工具扩展（测量时工作树 dirty=true，未提交改动仅为本报告的
> benchmark 工具自身）；工作树含 T1-T7 全部成果。
> 口径声明：**机器结果非跨环境硬 SLO，CI 只校验工具正确性（05 §9）**；完整协议
> 全量基准（Core 预热 200 测 5000；API 预热 100 串行 1000 + 8 并发 2000）为可选项，
> **本次为缩减 smoke 口径**（Core 预热 20 测 200；API 预热 10 串行 100 + 8 并发 200），
> 不跑全量档。

## 1. 测量配置

| 项 | 值 |
|---|---|
| flag | `AGENTGUARD_V21_SHADOW_ENABLED`（D3，默认 false） |
| 档位 | `--shadow both`（flag off/on 双跑对照） |
| 后端 | memory（无需真实 postgres） |
| 协议参数 | `--measurement-profile functional_smoke --core-warmup 20 --core-iterations 200 --api-warmup 10 --api-serial-iterations 100 --api-concurrency 8 --api-concurrent-total 200` |
| 百分位 | nearest-rank P50/P95/P99/max，单调纳秒样本，不剔除异常值 |
| shadow 路径 | 基准事件不携带 task 引用 → `degraded_no_snapshot` 快路径（覆盖评估侧旁路开销上界） |
| 环境 | Windows 11（AMD64 Family 25 Model 116），Python 3.12.13，单进程 TestClient + 线程并发 |

## 2. flag off 相对基线 delta

flag off 代码路径**构造上逐字节不变**（D3：编排器仅一次布尔判断后返回 None；
audit evidence 形状与现状完全一致），已由 `tests/test_v21_08_shadow_service.py`
（flag off 全量回归）与 `tests/test_v21_08_audit_evidence.py`（flag off evidence
形状）锁定。本次 smoke 的 flag off 档即对照基线本身，无独立历史基线可比；
legacy retained fixture parity：`ok=true`（43 case 分布与冻结快照一致）。

## 3. flag on evaluate 延迟增量（shadow-on vs shadow-off，串行 100 样本/场景）

单位：纳秒（1ms = 1,000,000ns）。对照锚点：T1 冻结预算以 05 §8.2 Fast Path
P95≤50ms target 余量为锚；本节只产数据，不做硬 SLO 判定。

| 场景 | off P50 | on P50 | ΔP50 | off P95 | on P95 | ΔP95 | ΔP99 | Δmax |
|---|---|---|---|---|---|---|---|---|
| low_read | 16ms | 47ms | +31ms | 93ms | 125ms | +32ms | +62ms | +78ms |
| sensitive_read | 31ms | 47ms | +16ms | 109ms | 156ms | +47ms | +62ms | +47ms |
| external_send | 31ms | 47ms | +16ms | 94ms | 141ms | +47ms | +48ms | +61ms |
| code_execution | 31ms | 47ms | +16ms | 94ms | 156ms | +62ms | +47ms | +47ms |
| memory | 31ms | 47ms | +16ms | 109ms | 140ms | +31ms | +31ms | +15ms |
| multi_event | 31ms | 62ms | +31ms | 110ms | 141ms | +31ms | +32ms | +63ms |
| degraded | 31ms | 47ms | +16ms | 94ms | 125ms | +31ms | 0 | +15ms |

并发档（8 worker × 200 请求）：ΔP50 +173ms、ΔP95 0、ΔP99 -47ms、Δmax -16ms。
并发增量无单调方向，属小样本线程调度噪声。

**数据口径注意**：本机样本呈现约 15.6ms 台阶的量化粒度（Windows 定时器/调度
量化），off 与 on 两侧同台阶量化，smoke 增量读数偏保守上界；**可靠增量结论
需按 05 §9 完整协议档位复测**（预热 100 / 串行 1000 / 8 并发 2000）。flag on
增量主要来自：`shadow_assess` 快路径（ActionIR 构建 + authority/coverage +
fusion 求值 + 五元组 digest 计算）与信封落盘的 redaction/bounded projection +
64KiB evidence 预算序列化。

## 4. metrics gate（`scripts/core-metrics-gate.py` 全量一次）

```text
ok=true | recall=0.9667（≥0.90）| fpr=0.0000（≤0.05）| fnr=0.0333
attacks: 29/30 blocked | benign: 0/13 blocked | missed: EG-AA-004（既有基线已知 miss，
与冻结 legacy 快照 parity 一致，非本次回退）
```

## 5. 审计完整性（验收项 d）

`tests/test_audit_integrity.py` + `tests/test_v21_08_audit_evidence.py` targeted
运行：11 passed / 1 skipped（postgres 依赖跳过）。decision_v21 为 append-only
审计键，不新增第二条审计记录，`request_digest` 口径不变。

## 6. 结论

1. flag off：行为与审计形状逐字节不变（测试锁定），无 delta 风险。
2. flag on：smoke 口径串行 ΔP50 +16~31ms、ΔP95 +31~62ms，受 15.6ms 台阶级
   量化主导，为上界读数；不构成对 05 §8.2 预算的判定证据。
3. Recall/FPR 门禁不回退；审计完整性全绿；legacy parity 通过。
4. V21-10 pre-enable gate 前建议：按 05 §9 完整协议档位复测 shadow-on/off，
   并评估信封落盘热路径（redaction/budget 序列化）的优化空间。

## 机器可读证据

- `baseline-smoke.json`：本次 smoke 运行的 `scripts/v21-baseline.py` 完整
  机器报告（含 `shadow_overhead` 对照、环境与 fixture 指纹）。
