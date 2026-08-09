# 系统总体架构

## 1. 文档定位

本文是 AgentGuard 的架构入口，说明系统分层、依赖方向、状态归属、事件流和当前边界。系统以“纯安全判定 Core + Guard API / Control Plane + Adapter + Dashboard / Evaluation”为稳定结构；未实施能力会明确标注，不写成当前事实。

关联入口：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [`agentguard-core` 设计](../02_core/core_design.md)
- [实施路线与验收标准](../06_delivery/implementation_plan.md)

## 2. 四层架构

AgentGuard 采用四层目标架构：

```text
┌────────────────────────────────────────────────────────────┐
│ Dashboard / Evaluation                                     │
│ 审计展示 / 审批处理 / 指标分析 / 调用链追踪 / AttackBench    │
└──────────────────────────────▲─────────────────────────────┘
                               │ HTTP REST
┌──────────────────────────────┴─────────────────────────────┐
│ Guard API / Control Plane                                   │
│ HTTP API / 鉴权 / 策略管理 / 审计 / 告警 / 审批 / 指标 / Trace │
│ 内部 service layer：PolicyService、AuditService、Approval... │
└──────────────────────────────▲─────────────────────────────┘
                               │ Python function call
┌──────────────────────────────┴─────────────────────────────┐
│ agentguard-core                                             │
│ 无状态安全判定：事件模型 / 检测器 / 策略匹配 / 风险评分 / 决策  │
└──────────────────────────────▲─────────────────────────────┘
                               │ GuardEvent / GuardDecision
┌──────────────────────────────┴─────────────────────────────┐
│ Runtime Adapter                                             │
│ LangGraph / OpenClaw / Generic hooks、事件映射、执行控制      │
└──────────────────────────────▲─────────────────────────────┘
                               │
                         Agent Runtime
```

| 层级                      | 核心职责                                                                                                                         | 部署形态                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| Runtime Adapter           | 接入 Agent runtime，拦截工具调用、文件访问、代码执行、记忆写入，映射标准事件并执行 `allow` / `deny` / `ask` 等决策               | 嵌入 Agent 进程                       |
| Guard API / Control Plane | 对外提供统一 API；负责鉴权、策略快照加载、审计入库、审批状态、指标聚合、调用链查询、runtime credential 和评测结果 | `guard-api` 单体后端 |
| agentguard-core           | 纯 Python 安全判定库；只处理事件、检测器、策略匹配、风险评分、证据生成和决策输出                                                 | 被 `guard-api` 或离线评测进程引用     |
| Dashboard / Evaluation    | 展示审计、告警、阻断、审批、指标和攻击链路；AttackBench 可走 `guard-api` 完整链路或直接调用 core 做无状态评测                    | Web 前端 / 评测进程                   |

## 3. 状态归属

所有需要持久化、查询、配置或管理的系统状态，逻辑上属于 Control Plane：

- 策略、策略版本、策略快照；
- 审计日志、告警记录、调用链 trace；
- 人工审批、approval wait 状态、审批结果；
- 指标聚合、评测任务、AttackBench 运行结果；
- Agent 注册、API Key、adapter token、control token；
- Dashboard browser session、CSRF token、launch code；
- PostgreSQL 中的 Control Plane 数据。

当前不单独拆出 `guard-control-plane` 微服务。上述能力在代码上放入 `guard-api`
内部 service layer，由 FastAPI route 统一暴露；部署上是一个 `guard-api` 后端应用。
若以后引入消息队列、后台任务或推送，它们仍属于 Control Plane，但不能视为当前已实现。

## 4. 核心数据流

工具调用前的正式链路：

```text
Agent Runtime
→ Runtime Adapter
→ POST /v1/guard/evaluate
→ Guard API 鉴权并加载 PolicySnapshot
→ agentguard-core.evaluate(event, policies)
→ GuardDecision
→ Guard API 写审计并按决定创建审批
→ Runtime Adapter 执行 allow / deny / ask
→ Adapter 上报 after-event
→ Dashboard / CLI / Evaluation 通过 HTTP 查询审计、指标和调用链
```

关键约束：

- `agentguard-core` 不读写数据库，不创建审批记录，不管理会话或 CSRF，不暴露 HTTP API。
- `guard-api` 是 Control Plane 的唯一对外入口，负责所有状态副作用和 Dashboard 查询。
- Adapter 只做运行时映射和执行控制，不持久化状态，不生成最终安全结论。
- Dashboard 只调用 `guard-api`，不直接连接数据库、不直接调用 `agentguard-core`、不接触 Agent runtime。
- Redteam / AttackBench 提供 ground truth；评测指标由 Control Plane 或 runner 基于审计与样本标签计算，不能由 Dashboard 推断。

## 5. 当前与后续边界

当前主链已经具备统一 evaluate 入口、三态决策、策略快照、原子审批、审计哈希链、
provenance、原子审计窗口、历史 cohort、Dashboard/CLI 和 OpenClaw runtime gate。
LangGraph SDK 与靶场逻辑按当前版本冻结。

动作执行覆盖指标、`risk_breakdown`、结构化 `context_sources`、LLM 职责、记忆生命周期、
生产级多租户和供应链自动化都不是可从现有能力推导出的“已完成项”；其实施边界见
[项目状态与后续边界](../TODO.md)，涉及 Core 或跨端契约时必须单独确认。

## 6. 验收证据

目标态架构验收必须能展示：

1. Adapter 在工具执行前调用 `guard-api`，而不是直接访问数据库或 Dashboard。
2. `guard-api` 调用无状态 `agentguard-core.evaluate(...)` 得到 `GuardDecision`。
3. `ask` 只由 core 表示“需要审批”的决策意图，审批记录和原子状态转换由 Control Plane 管理。
4. 危险工具调用被 Adapter 阻断，审计日志由 `guard-api` 写入。
5. Dashboard 只通过 `guard-api` 展示 trace、风险分数、命中规则、阻断原因和审批状态。
6. AttackBench 可同时支持直接调用 core 的无状态评测和走 `guard-api` 的完整链路评测。
