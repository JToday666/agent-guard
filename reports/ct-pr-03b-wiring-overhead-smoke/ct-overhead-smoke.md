# CT-PR-03b 接线开销 smoke 报告

> 任务：CT-PR-03b 门禁——开销 smoke（步骤 4 后验收证据）。
> 分支：`feat/ct-pr-03b-state-wiring`；口径声明：**机器结果非跨环境硬
> SLO，CI 只校验工具正确性（05 §9 同源口径）**；本次为缩减 smoke 口径
> （预热 5 测 50，memory 后端，单进程），不跑全量协议档。
> pipeline flag（`AGENTGUARD_V21_SHADOW_ENABLED`）两档恒定 on；对照变量
> 仅 `AGENTGUARD_CT_FACT_PROJECTION_ENABLED`（默认 false）。

## 1. 测量配置

| 项 | 值 |
|---|---|
| 对照变量 | CT flag：baseline=off / treatment=on（pipeline 两档恒 on） |
| workload | `tool_result_produced` 真实形状事件 + `task_ingress` 权威 task（每次迭代新 event_id，含事务外 bundle 构建 → 事务内信封提交 → 事务后投影全链路） |
| 后端 | memory |
| 协议参数 | warmup 5 / iterations 50，nearest-rank P50/P95/P99/max，不剔除异常值 |
| 环境 | Windows 11（10.0.26200），Python 3.12.13，单进程直调 EvaluationService |

## 2. 两档延迟对照（50 样本，单位 ms）

本机样本呈约 15.6ms 台阶的量化粒度（Windows 定时器/调度量化，与
V21-08/V21-09 smoke 同声明），smoke 增量读数为保守上界。

| 档位 | P50 | P95 | P99 | max | mean |
|---|---|---|---|---|---|
| CT off（pipeline on） | 16.16 | 47.09 | 63.49 | 63.49 | 17.53 |
| CT on（pipeline on） | 25.03 | 71.86 | 88.45 | 88.45 | 30.54 |
| Δ（CT 净增量） | +8.86 | +24.77 | +24.96 | +24.96 | +13.01 |

**解读**：
1. CT on 相对 pipeline-only 基线的净增量 ΔP50 ≈ +8.9ms（不足一个量化
   台阶）、ΔP95 ≈ +24.8ms（约 +1~2 台阶）——覆盖事务外 bundle 构建
   （facts 映射 + delta 预检 + ActionIR 构造）、事务内信封合并、事务后
   锁内投影（含前向漂移 rebase 重算 delta）全链路，量级与 V21-09
   Phase C 投影同台阶口径，未引入超出影子旁路预期的串行开销上界。
2. CT flag off 时全部入口仅一次布尔判断返回（`enabled` 门控），
   evaluate 热路径零新增 I/O（e2e 场景②测试锁定：flag off 与基线
   键集/响应逐字节一致，零投影登记）。
3. 事务内零新增存储往返（信封随既有 `record_evaluation` 写入；bundle
   材料全部取自 Phase A 产物），性能纪律结构性达成，非以延迟换取。

## 3. 关联门禁证据（本 worktree 实测）

| 门禁 | 结论 | 证据 |
|---|---|---|
| ruff（apps/packages/tests 基线口径） | ✅ | `All checks passed!` |
| pyright | ✅ | `0 errors, 0 warnings, 0 informations` |
| 新增 e2e 测试 | ✅ | `tests/test_ct_state_wiring.py` 7 passed（DoD 七场景） |
| CT 既有套件 | ✅ | `test_ct_fact_builder*.py` + `test_ct_delta_builder.py` 全绿 |
| V21-09 套件 | ✅ | `test_v21_09_pipeline.py` + `test_v21_09_evaluation_projection.py` = 121 passed / 2 skipped（含 CT 套件合跑） |
| guard-api / 审计完整性 | ✅ | `test_guard_api.py` + `test_audit_integrity.py` = 128 passed |
| 全量回归 | ✅ | `pytest -q` = 1793 passed / 136 skipped（1929 collected ≥ 基线 1922，无回退） |
| 契约工具 | ✅ | `scripts/ct-contract-tools.py validate` / `checksums --verify` 通过 |
| packages/ 零 diff | ✅ | `git status` 仅 apps/guard-api 与 tests 变更 |

## 机器可读证据

- `ct-overhead-smoke.json`：本次 smoke 完整机器报告（两档百分位 +
  增量 + 环境指纹）。
