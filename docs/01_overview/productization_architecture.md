# 产品化架构与目录职责

## 1. 文档定位

本文定义 Productization Alpha 已完成基线所建立的稳定产品边界、依赖方向和目录职责。详细事件字段以[接口契约](../02_core/interface_contract.md)为准；Alpha 里程碑完成度与限制以[Productization Alpha Status](../06_delivery/productization_alpha_status.md)为准；当前能力路线与硬依赖见根目录 [`ROADMAP.md`](../../ROADMAP.md)。

历史竞赛和答辩材料位于 [`docs/archive/competition-2026/`](../archive/competition-2026/README.md)，不再决定产品目录或默认运行模式。

## 2. 产品运行链路

```text
Runtime / Agent
  -> Runtime Adapter
  -> Guard API / Control Plane
  -> agentguard-core
  -> GuardDecision (allow / deny / ask)
  -> Runtime enforcement + receipt
  -> Audit / Approval / Trace / Metrics
  -> Dashboard or CLI
```

权威边界：

- Core 产生策略决定，但不声称副作用已经或没有发生。
- 不可信数据可以参与受限推理，但不能自行产生 authority、approval、policy 或可信 provenance。
- LLM 不是 trust boundary、sanitizer 或最终安全裁决者；其输出必须继续经过确定性契约和执行前控制。
- 产品目标不变量是 Runtime Adapter 在副作用前执行决定并回传 receipt；各 Adapter 当前能否满足该不变量，必须以 capability/receipt 覆盖证据为准。缺失 receipt 不能证明副作用未发生，覆盖率必须与阻断率分开展示。
- Guard API 是身份、策略快照、审批、审计和持久化的唯一 Control Plane。
- Dashboard/CLI 是消费者，不重新裁决，不把 shadow 结果标记为 official。
- AttackBench、Mock Tools 和演示 Agent 是评测基础设施，不是产品 runtime。

## 3. 目录职责

| 目录 | 稳定职责 | 不应放入 |
| --- | --- | --- |
| `apps/guard-api/` | HTTP、鉴权、审批、审计、指标、Trace、PostgreSQL | Core 规则副本、前端状态 |
| `apps/cli/` | 无头控制面客户端和验收入口 | 数据库直连、策略判定 |
| `apps/dashboard/` | Guard API 的监督与调查 UI | token、数据库访问、独立裁决 |
| `packages/agentguard-core/` | 无状态事件规范化、检测、策略与决定 | 网络、数据库、审批状态 |
| `packages/agentguard-langgraph-adapter/` | LangGraph 事件映射、执行前 gate、receipt | Core 策略或评测数据集 |
| `packages/agentguard-openclaw-plugin/` | OpenClaw 24-hook runtime 接入 | Dashboard 逻辑、演示专用绕过 |
| `schemas/` | 对外 JSON Schema | 与运行时模型独立演化的字段 |
| `tests/` | 跨组件、契约、存储和应用链路测试 | 手工运行报告 |
| `agentguard_langgraph_bench/` | runner、数据集、沙箱、评测/演示 Agent | 产品 API 或发布包公共门面 |
| `benchmarks/` | 外部 runtime 的本地 benchmark 工具 | Control Plane 业务逻辑 |
| `examples/` | 干净 clone 可运行的最小示例 | `.env`、临时报告、真实秘密 |
| `scripts/` | 自动化入口；按 dev/bench/release 逐步归类，旧入口保留兼容包装 | 产品库代码和不可复现证据 |
| `docs/` | 当前架构、接口、运维与交付事实 | 未标注状态的未来设计 |
| `docs/archive/` | 冻结的历史材料与清单 | 当前安装或生产操作入口 |

## 4. 依赖与真值规则

1. Adapter 可以依赖公开 Core/HTTP 契约，Core 不反向依赖 Adapter。
2. Guard API 调用 Core；Core 不读取 Guard API 配置或存储。
3. Dashboard 的真实 API 模式和 CLI 的控制面命令只通过 Guard API 工作；Dashboard mock 仅用于 UI 开发，`agentguardctl openclaw verify` 等本机维护命令只封装仓库脚本，不构成第二套控制面。
4. Pydantic 模型是运行时校验来源；`schemas/` 是对外契约，两者由 contract tests 保持一致。
5. PostgreSQL 完整 AuditEvent 与哈希链是持久化权威；派生列、Dashboard cache 和报告可重建。
6. 根目录 `ROADMAP.md` 是人工维护的能力与硬依赖路线，不决定任务 lifecycle、贡献限制或完成证据；已验证状态仍由对应状态页、契约、测试和发布证据说明。
7. `official`、`shadow`、`demo`、`mock` 必须在类型、API、UI 和文档中保持可辨识。

## 5. 产品化变更准入

涉及以下任一项时，变更必须包含迁移/兼容说明和相应 contract/integration 测试：

- GuardEvent、GuardDecision、AuditEvent 或 runtime receipt 字段；
- token scope、审批状态机、策略快照或审计哈希；
- 数据库 schema 和 Alembic migration；
- official/shadow 权威选择；
- fail-open/fail-closed 行为；
- 对外 Python/npm/HTTP API。

演示便利性不能弱化上述边界。需要不同运行口径时，使用显式 profile/flag，并让默认产品模式保持保守和可审计。

## 6. 结构演进建议

当前大型 runner、store、测试和 Dashboard 组件需要渐进拆分，但不在一次重构中同时改变安全语义。建议顺序：

1. 先固定 public contract 与测试分类。
2. 再按 runtime/providers/scoring/artifacts、store repositories、UI projection/components 拆模块。
3. 每次迁移保持兼容导入或提供明确移除说明。
4. 清理兼容层前更新 CHANGELOG、升级说明和调用方。
