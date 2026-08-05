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
├── 06_delivery/          # 部署使用、实施路线、演示脚本
├── 07_auth/              # Capability Auth、前端与适配器鉴权
└── 08_api/               # 跨端 API 目标契约、联调结构与迁移清单
```

## 2. 开发阅读路径

### P0 最小闭环

1. [部署、安装与使用说明](06_delivery/deployment_install_usage.md)
2. [总体架构](01_overview/architecture.md)
3. [接口契约与事件模型](02_core/interface_contract.md)
4. [`agentguard-core` 设计](02_core/core_design.md)
5. [LangGraph 评测靶场](03_adapters/langgraph_adapter.md)
6. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
7. [Dashboard 与审批流](04_apps/dashboard_design.md)
8. [实施路线与验收标准](06_delivery/implementation_plan.md)

### Core 开发

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [`agentguard-core` 设计](02_core/core_design.md)
3. [威胁模型](02_core/threat_model.md)
4. [实施路线与验收标准](06_delivery/implementation_plan.md)

### Adapter 开发

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [LangGraph 评测靶场](03_adapters/langgraph_adapter.md)
3. [OpenClaw Security Plugin](03_adapters/openclaw_plugin.md)
4. [OpenClaw 插件部署、安装与配置](03_adapters/openclaw_plugin_deployment.md)
5. [OpenClaw 与 LangChain/LangGraph Hook 清单](03_adapters/runtime_hooks_inventory.md)

### Dashboard 开发

1. [部署、安装与使用说明](06_delivery/deployment_install_usage.md)
2. [接口契约与事件模型](02_core/interface_contract.md)
3. [Dashboard 与审批流](04_apps/dashboard_design.md)
4. [Dashboard 前端与 UI 设计规范](04_apps/dashboard_ui_spec.md)
5. [证据链与溯源 API 目标契约](08_api/evidence_trace_api_contract.md)
6. [Dashboard 指标作用域与审计窗口 API 协作契约](08_api/dashboard_metrics_api_contract.md)
7. [实施路线与验收标准](06_delivery/implementation_plan.md)

### API 联调与契约评审

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [证据链与溯源 API 目标契约](08_api/evidence_trace_api_contract.md)
3. [Dashboard 指标作用域与审计窗口 API 协作契约](08_api/dashboard_metrics_api_contract.md)
4. [Capability Auth 总体方案](07_auth/鉴权总体方案.md)
5. [Dashboard 前端与 UI 设计规范](04_apps/dashboard_ui_spec.md)

### Redteam 开发

1. [命题要求追踪矩阵](00_requirements/requirement_traceability_matrix.md)
2. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
3. [OpenClaw AttackBench 轮转验证与检测启用](05_redteam/openclaw_attackbench.md)
4. [演示脚本](06_delivery/demo_script.md)

### 答辩准备

1. [命题要求追踪矩阵](00_requirements/requirement_traceability_matrix.md)
2. [总体架构](01_overview/architecture.md)
3. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
4. [演示脚本](06_delivery/demo_script.md)

## 3. 文档职责

| 文档                                                                                     | 职责                                                                           |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [命题.pdf](00_requirements/命题.pdf)                                                     | 原始题目材料                                                                   |
| [命题一\_题目解读总结.md](00_requirements/命题一_题目解读总结.md)                        | 命题一解读、攻击场景和成果形态建议                                             |
| [requirement_traceability_matrix.md](00_requirements/requirement_traceability_matrix.md) | 命题要求、模块设计和验收证据的追踪矩阵                                         |
| [architecture.md](01_overview/architecture.md)                                           | 系统总体架构、核心链路和模块关系                                               |
| [repo_structure.md](01_overview/repo_structure.md)                                       | 仓库目录职责和边界规则                                                         |
| [interface_contract.md](02_core/interface_contract.md)                                   | Guard API / Control Plane API、事件模型、决策模型和冻结规则                    |
| [core_design.md](02_core/core_design.md)                                                 | 无状态 Core 职责、检测器、策略和风险判定设计                                   |
| [threat_model.md](02_core/threat_model.md)                                               | 保护目标、攻击面、攻击链和非目标                                               |
| [langgraph_adapter.md](03_adapters/langgraph_adapter.md)                                 | LangGraph 接入点、Mock Tools 和 P0 靶场链路                                    |
| [openclaw_plugin.md](03_adapters/openclaw_plugin.md)                                     | OpenClaw 插件接入、Hook 映射和配置审计                                         |
| [openclaw_plugin_deployment.md](03_adapters/openclaw_plugin_deployment.md)               | OpenClaw 插件部署、安装、配置、验证和卸载                                      |
| [runtime_hooks_inventory.md](03_adapters/runtime_hooks_inventory.md)                     | OpenClaw 与 LangChain/LangGraph Hook、中间件、扩展面和数据结构统计             |
| [dashboard_design.md](04_apps/dashboard_design.md)                                       | Dashboard 页面、数据来源、审批和指标展示                                       |
| [dashboard_ui_spec.md](04_apps/dashboard_ui_spec.md)                                     | Dashboard 信息架构、视觉层级、交互模式和前端实现规范                           |
| [attackbench.md](05_redteam/attackbench.md)                                              | 攻击样本格式、runner、成功条件和评测指标                                       |
| [openclaw_attackbench.md](05_redteam/openclaw_attackbench.md)                            | OpenClaw 自动轮转 AttackBench、bench shim、bench tools、检测启用和验证流程     |
| [deployment_install_usage.md](06_delivery/deployment_install_usage.md)                   | Core、Guard API、CLI、Dashboard、OpenClaw 插件和评测 runner 的安装、部署与使用 |
| [implementation_plan.md](06_delivery/implementation_plan.md)                             | P0/P1/P2 开发顺序、任务边界和验收标准                                          |
| [demo_script.md](06_delivery/demo_script.md)                                             | 防御前后对比演示和答辩叙事                                                     |
| [鉴权总体方案.md](07_auth/鉴权总体方案.md)                                               | Capability Auth、control token、adapter token、browser session 与接口鉴权      |
| [适配器鉴权建议.md](07_auth/适配器鉴权建议.md)                                           | Adapter / Plugin token 使用边界和 scope                                        |
| [前端鉴权建议.md](07_auth/前端鉴权建议.md)                                               | Dashboard browser session、CSRF 和 launch code 边界                            |
| [evidence_trace_api_contract.md](08_api/evidence_trace_api_contract.md)                  | 已冻结的证据链与溯源目标结构、示例、兼容策略和迁移清单                        |
| [dashboard_metrics_api_contract.md](08_api/dashboard_metrics_api_contract.md)            | Dashboard 指标作用域、原子审计窗口、历史 cohort、兼容与验收契约                |

## 4. 维护规则

- 根目录 `README.md` 只保留项目门面和关键入口，完整文档地图只维护在本文件。
- 根目录 `DEPLOYMENT_LOCAL.md` 只保留最小启动入口；完整部署、安装和故障排查只维护在 [deployment_install_usage.md](06_delivery/deployment_install_usage.md)。
- `08_api/` 保存目标契约及迁移状态；目标冻结后，先在 [interface_contract.md](02_core/interface_contract.md) 区分当前实现与冻结目标，再同步 schemas、类型、存储和实现。目标契约不得被描述为当前能力。
- Core 不依赖 Adapter，不暴露 HTTP API，不读写数据库；Adapter 不写核心规则；Dashboard 不直连运行时。
- 攻击样本真值由 Redteam 提供，评测指标由 AttackBench runner 汇总。
- `agentguard_langgraph_bench/` 下的 runner、样本和演示适配器属于评测边界，产品主链路文档只引用其稳定入口，不复制其内部实现说明。
- 命题要求变化或答辩口径变化时，优先更新追踪矩阵。
