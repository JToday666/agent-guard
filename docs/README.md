# 文档地图

本目录是 AgentGuard 的完整文档入口。文档体系按代码模块组织，优先服务开发实现，同时保留命题追踪和答辩证据。

## 1. 目录结构

```text
docs/
├── README.md
├── 00_requirements/      # 命题、题目解读、要求追踪矩阵
├── 01_overview/          # 总体架构、仓库结构
├── 02_core/              # Core、接口契约、威胁模型
├── 03_adapters/          # LangGraph、OpenClaw 接入
├── 04_apps/              # Dashboard 与审批
├── 05_redteam/           # AttackBench、攻击样本与评测
└── 06_delivery/          # 实施路线、演示脚本
```

## 2. 开发阅读路径

### P0 最小闭环

1. [总体架构](01_overview/architecture.md)
2. [接口契约与事件模型](02_core/interface_contract.md)
3. [`agentguard-core` 设计](02_core/core_design.md)
4. [LangGraph 评测靶场](03_adapters/langgraph_adapter.md)
5. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
6. [Dashboard 与审批流](04_apps/dashboard_design.md)
7. [实施路线与验收标准](06_delivery/implementation_plan.md)

### Core 开发

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [`agentguard-core` 设计](02_core/core_design.md)
3. [威胁模型](02_core/threat_model.md)
4. [实施路线与验收标准](06_delivery/implementation_plan.md)

### Adapter 开发

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [LangGraph 评测靶场](03_adapters/langgraph_adapter.md)
3. [OpenClaw Security Plugin](03_adapters/openclaw_plugin.md)
4. [OpenClaw 与 LangChain/LangGraph Hook 清单](03_adapters/runtime_hooks_inventory.md)

### Dashboard 开发

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [Dashboard 与审批流](04_apps/dashboard_design.md)
3. [实施路线与验收标准](06_delivery/implementation_plan.md)

### Redteam 开发

1. [命题要求追踪矩阵](00_requirements/requirement_traceability_matrix.md)
2. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
3. [演示脚本](06_delivery/demo_script.md)

### 答辩准备

1. [命题要求追踪矩阵](00_requirements/requirement_traceability_matrix.md)
2. [总体架构](01_overview/architecture.md)
3. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
4. [演示脚本](06_delivery/demo_script.md)

## 3. 文档职责

| 文档                                                                                     | 职责                                                        |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| [命题.pdf](00_requirements/命题.pdf)                                                     | 原始题目材料                                                |
| [命题一\_题目解读总结.md](00_requirements/命题一_题目解读总结.md)                        | 命题一解读、攻击场景和成果形态建议                          |
| [requirement_traceability_matrix.md](00_requirements/requirement_traceability_matrix.md) | 命题要求、模块设计和验收证据的追踪矩阵                      |
| [architecture.md](01_overview/architecture.md)                                           | 系统总体架构、核心链路和模块关系                            |
| [repo_structure.md](01_overview/repo_structure.md)                                       | 仓库目录职责和边界规则                                      |
| [interface_contract.md](02_core/interface_contract.md)                                   | Guard API / Control Plane API、事件模型、决策模型和冻结规则 |
| [core_design.md](02_core/core_design.md)                                                 | 无状态 Core 职责、检测器、策略和风险判定设计 |
| [threat_model.md](02_core/threat_model.md)                                               | 保护目标、攻击面、攻击链和非目标            |
| [langgraph_adapter.md](03_adapters/langgraph_adapter.md)                                 | LangGraph 接入点、Mock Tools 和 P0 靶场链路 |
| [openclaw_plugin.md](03_adapters/openclaw_plugin.md)                                     | OpenClaw 插件接入、Hook 映射和配置审计      |
| [runtime_hooks_inventory.md](03_adapters/runtime_hooks_inventory.md)                     | OpenClaw 与 LangChain/LangGraph Hook、中间件、扩展面和数据结构统计 |
| [dashboard_design.md](04_apps/dashboard_design.md)                                       | Dashboard 页面、数据来源、审批和指标展示    |
| [attackbench.md](05_redteam/attackbench.md)                                              | 攻击样本格式、runner、成功条件和评测指标    |
| [implementation_plan.md](06_delivery/implementation_plan.md)                             | P0/P1/P2 开发顺序、任务边界和验收标准       |
| [demo_script.md](06_delivery/demo_script.md)                                             | 防御前后对比演示和答辩叙事                  |

## 4. 维护规则

- 根目录 `README.md` 只保留项目门面和关键入口，完整文档地图只维护在本文件。
- 接口字段变更必须先更新 [interface_contract.md](02_core/interface_contract.md)，再同步 schemas 和实现。
- Core 不依赖 Adapter，不暴露 HTTP API，不读写数据库；Adapter 不写核心规则；Dashboard 不直连运行时。
- 攻击样本真值由 Redteam 提供，评测指标由 AttackBench runner 汇总。
- 命题要求变化或答辩口径变化时，优先更新追踪矩阵。
