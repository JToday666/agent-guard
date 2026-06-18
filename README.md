# AgentGuard

AgentGuard 是面向大模型智能体的运行时行为监督与攻击检测系统。项目目标是让接入工具、文件、API、代码执行和记忆能力的 Agent 在执行外部动作前具备可审计、可解释、可阻断的安全控制。

## 架构定位

采用 **四层目标架构**：

- **Runtime Adapter**：接入 LangGraph、OpenClaw 或通用工具运行时，负责事件映射和执行控制。
- **Guard API / Control Plane**：统一 HTTP 入口，负责鉴权、策略管理、审计、告警、审批、指标和调用链状态。
- **agentguard-core**：无状态安全判定库，负责事件规范化、检测器、策略匹配、风险评分和 `GuardDecision` 输出。
- **Dashboard / Evaluation**：监督展示、审批处理、指标分析和 AttackBench 评测。

LangGraph 和 OpenClaw 是四层架构下的运行时接入与演示场景，不再作为总体架构层级。

## 开发入口

| 入口                                                                               | 说明                         |
| ---------------------------------------------------------------------------------- | ---------------------------- |
| [docs/README.md](docs/README.md)                                                   | 完整文档地图和开发阅读路径   |
| [docs/01_overview/architecture.md](docs/01_overview/architecture.md)               | 总体架构和运行链路           |
| [docs/02_core/interface_contract.md](docs/02_core/interface_contract.md)           | Guard API / Control Plane API、事件模型和决策契约 |
| [docs/06_delivery/implementation_plan.md](docs/06_delivery/implementation_plan.md) | P0/P1/P2 开发顺序和验收标准  |

## 答辩入口

| 入口                                                                                                               | 说明                             |
| ------------------------------------------------------------------------------------------------------------------ | -------------------------------- |
| [docs/00_requirements/requirement_traceability_matrix.md](docs/00_requirements/requirement_traceability_matrix.md) | 命题要求到模块和证据的追踪矩阵   |
| [docs/05_redteam/attackbench.md](docs/05_redteam/attackbench.md)                                                   | 攻击样本、评测指标和 runner 设计 |
| [docs/06_delivery/demo_script.md](docs/06_delivery/demo_script.md)                                                 | 防御前后对比演示脚本             |

## 最小闭环

```text
AttackCase
→ LangGraph Agent
→ Runtime Adapter
→ Guard API / Control Plane
→ agentguard-core.evaluate(...)
→ GuardDecision
→ Control Plane state services
→ Dashboard
```
