# AgentGuard

AgentGuard 是面向大模型智能体的运行时行为监督与攻击检测系统。项目目标是让接入工具、文件、API、代码执行和记忆能力的 Agent 在执行外部动作前具备可审计、可解释、可阻断的安全控制。

## 架构定位

采用 **一核两壳**：

- **一核**：Agent Security Core，统一事件模型、风险检测、策略决策、审批、审计和指标。
- **壳一**：LangGraph + LangChain Core + Mock Tools，用作可控评测靶场和 P0 保底闭环。
- **壳二**：OpenClaw + Security Plugin，用作开源智能化应用接入和演示。

## 开发入口

| 入口                                                                               | 说明                         |
| ---------------------------------------------------------------------------------- | ---------------------------- |
| [docs/README.md](docs/README.md)                                                   | 完整文档地图和开发阅读路径   |
| [docs/01_overview/architecture.md](docs/01_overview/architecture.md)               | 总体架构和运行链路           |
| [docs/02_core/interface_contract.md](docs/02_core/interface_contract.md)           | Core API、事件模型和决策契约 |
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
→ ToolNode wrapper
→ Agent Security Core
→ allow / deny / ask
→ AuditEvent
→ Dashboard
```
