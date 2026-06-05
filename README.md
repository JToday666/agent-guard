# AgentGuard

AgentGuard 是面向大模型智能体的运行时行为监督与攻击检测系统。

## 架构定位

采用 **一核两壳**：

- **一核**：Agent Security Core，统一事件模型、风险检测、策略决策、审批、审计和指标。
- **壳一**：LangGraph + LangChain Core + Mock Tools，用作可控评测靶场。
- **壳二**：OpenClaw + Security Plugin，用作真实智能体应用接入与演示。

## 文档入口

| 文档 | 说明 |
|---|---|
| [docs/README.md](docs/README.md) | 文档地图 |
| [docs/repo_structure.md](docs/repo_structure.md) | 仓库结构与目录职责 |
| [docs/architecture.md](docs/architecture.md) | 系统总体架构 |
| [docs/interface_contract.md](docs/interface_contract.md) | 接口契约与事件模型 |
| [docs/threat_model.md](docs/threat_model.md) | 威胁模型 |
| [docs/core_design.md](docs/core_design.md) | Core 设计 |
| [docs/langgraph_adapter.md](docs/langgraph_adapter.md) | LangGraph 评测靶场 |
| [docs/openclaw_plugin.md](docs/openclaw_plugin.md) | OpenClaw 插件接入 |
| [docs/dashboard_design.md](docs/dashboard_design.md) | Dashboard 与审批 |
| [docs/attackbench.md](docs/attackbench.md) | 攻击样本与评测指标 |
| [docs/implementation_plan.md](docs/implementation_plan.md) | 实施计划 |
| [docs/demo_script.md](docs/demo_script.md) | 演示脚本 |

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
