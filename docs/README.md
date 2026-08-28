# 文档地图

本目录是 AgentGuard 的完整文档入口。Productization Alpha 是已完成的产品基线；当前开发方向和能力依赖由根目录人工维护的 Roadmap 展示。文档入口优先服务产品安装、开发、运维和可验证交付；命题、竞赛、答辩与演示证据只作为标明边界的历史资料保留。

## 1. 目录结构

```text
docs/
├── README.md
├── 01_overview/          # 总体架构、仓库结构
├── 02_core/              # Core、接口契约、威胁模型
├── 03_adapters/          # LangGraph、OpenClaw 接入
├── 04_apps/              # Dashboard 与审批
├── 05_redteam/           # AttackBench、攻击样本与评测
├── 06_delivery/          # 部署使用、兼容性与里程碑状态
├── 07_auth/              # Capability Auth、前端与适配器鉴权
├── 08_api/               # 跨端 API 目标契约、联调结构与迁移清单
├── archive/              # 历史竞赛要求、演示证据与 Alpha 治理证据
├── AgentGuard_Core_V2.1_Final_Contract_Freeze/              # Core V2.1 最终契约
├── AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/    # Context/Taint 最终 RC 契约
└── AgentGuard_Runtime_Enforcement_Contract_v1_Final/        # Runtime Enforcement 契约冻结
```

## 2. 开发阅读路径

### 产品安装与维护

1. [能力与依赖路线图](../ROADMAP.md)
2. [Productization Alpha Status](06_delivery/productization_alpha_status.md)
3. [仓库治理收尾记录](06_delivery/repository_governance_closeout.md)
4. [安装、升级和故障排查](06_delivery/install_upgrade_troubleshooting.md)
5. [兼容矩阵](06_delivery/compatibility_matrix.md)
6. [产品化架构与目录职责](01_overview/productization_architecture.md)
7. [接口契约与事件模型](02_core/interface_contract.md)
8. [安全策略](../SECURITY.md)
9. [贡献指南](../CONTRIBUTING.md)
10. [细粒度技术待办](TODO.md)

### 最小产品闭环

1. [部署、安装与使用说明](06_delivery/deployment_install_usage.md)
2. [总体架构](01_overview/architecture.md)
3. [接口契约与事件模型](02_core/interface_contract.md)
4. [`agentguard-core` 设计](02_core/core_design.md)
5. [LangGraph 评测靶场](03_adapters/langgraph_adapter.md)
6. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
7. [Dashboard 与审批流](04_apps/dashboard_design.md)
8. [能力与依赖路线图](../ROADMAP.md)

### Core 开发

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [`agentguard-core` 设计](02_core/core_design.md)
3. [威胁模型](02_core/threat_model.md)
4. [能力与依赖路线图](../ROADMAP.md)

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
5. [Agent 运行时安全可观测与动态治理设计](04_apps/runtime_safety_observability_design.md)
6. [证据链与溯源 API 目标契约](08_api/evidence_trace_api_contract.md)
7. [Dashboard 指标作用域与审计窗口 API 协作契约](08_api/dashboard_metrics_api_contract.md)
8. [能力与依赖路线图](../ROADMAP.md)

### API 联调与契约评审

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [证据链与溯源 API 目标契约](08_api/evidence_trace_api_contract.md)
3. [Agent 运行时安全可观测与动态治理设计](04_apps/runtime_safety_observability_design.md)
4. [Dashboard 指标作用域与审计窗口 API 协作契约](08_api/dashboard_metrics_api_contract.md)
5. [Capability Auth 总体方案](07_auth/鉴权总体方案.md)
6. [Dashboard 前端与 UI 设计规范](04_apps/dashboard_ui_spec.md)

### Redteam 开发

1. [威胁模型](02_core/threat_model.md)
2. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
3. [OpenClaw AttackBench 轮转验证与检测启用](05_redteam/openclaw_attackbench.md)

### 历史竞赛与答辩资料

1. [Competition 2026 archive](archive/competition-2026/README.md)
2. [命题要求追踪矩阵](archive/competition-2026/requirements/requirement_traceability_matrix.md)
3. [Productization Alpha 治理证据](archive/productization-alpha-2026/README.md)

归档材料可能记录 ignored staging、临时路径或当时的演示口径，不能作为干净 clone 安装说明、当前产品能力或正式效果结论。失效的答辩脚本和强绑定候选设计不在当前文档树中保留，需要时通过 Git 历史追溯。

## 3. 文档职责

| 文档                                                                                     | 职责                                                                           |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [architecture.md](01_overview/architecture.md)                                           | 系统总体架构、核心链路和模块关系                                               |
| [repo_structure.md](01_overview/repo_structure.md)                                       | 仓库目录职责和边界规则                                                         |
| [productization_architecture.md](01_overview/productization_architecture.md)             | Productization Alpha 的产品边界、目录治理和变更准入                            |
| [interface_contract.md](02_core/interface_contract.md)                                   | Guard API / Control Plane API、事件模型、决策模型和冻结规则                    |
| [core_design.md](02_core/core_design.md)                                                 | 无状态 Core 职责、检测器、策略和风险判定设计                                   |
| [threat_model.md](02_core/threat_model.md)                                               | 保护目标、攻击面、攻击链和非目标                                               |
| [langgraph_adapter.md](03_adapters/langgraph_adapter.md)                                 | LangGraph 接入点、Mock Tools 和受支持的评测链路                                |
| [openclaw_plugin.md](03_adapters/openclaw_plugin.md)                                     | OpenClaw 插件接入、Hook 映射和配置审计                                         |
| [openclaw_plugin_deployment.md](03_adapters/openclaw_plugin_deployment.md)               | OpenClaw 插件部署、安装、配置、验证和卸载                                      |
| [runtime_hooks_inventory.md](03_adapters/runtime_hooks_inventory.md)                     | OpenClaw 与 LangChain/LangGraph Hook、中间件、扩展面和数据结构统计             |
| [dashboard_design.md](04_apps/dashboard_design.md)                                       | Dashboard 页面、数据来源、审批和指标展示                                       |
| [dashboard_ui_spec.md](04_apps/dashboard_ui_spec.md)                                     | Dashboard 信息架构、视觉层级、交互模式和前端实现规范                           |
| [runtime_safety_observability_design.md](04_apps/runtime_safety_observability_design.md) | 执行轨迹、代表性验收链、事实投影、联动视图和动态刷新冻结设计                 |
| [attackbench.md](05_redteam/attackbench.md)                                              | 攻击样本格式、runner、成功条件和评测指标                                       |
| [openclaw_attackbench.md](05_redteam/openclaw_attackbench.md)                            | OpenClaw 自动轮转 AttackBench、bench shim、bench tools、检测启用和验证流程     |
| [deployment_install_usage.md](06_delivery/deployment_install_usage.md)                   | Core、Guard API、CLI、Dashboard、OpenClaw 插件和评测 runner 的安装、部署与使用 |
| [install_upgrade_troubleshooting.md](06_delivery/install_upgrade_troubleshooting.md)     | 干净 clone、升级、测试和故障排查入口                                           |
| [compatibility_matrix.md](06_delivery/compatibility_matrix.md)                           | 运行环境、组件、浏览器和模式兼容范围                                           |
| [productization_alpha_status.md](06_delivery/productization_alpha_status.md)             | Productization Alpha 里程碑能力、限制、最终 SHA 与门禁快照                     |
| [repository_governance_closeout.md](06_delivery/repository_governance_closeout.md)       | 路线图迁移后的仓库治理收尾范围、验收口径与剩余风险                   |
| [ROADMAP.md](../ROADMAP.md)                                                              | 人工维护的能力节点、硬依赖、当前路线和后续候选                                 |
| [TODO.md](TODO.md)                                                                       | 不决定方向和阶段状态的细粒度技术 backlog                                       |
| [鉴权总体方案.md](07_auth/鉴权总体方案.md)                                               | Capability Auth、control token、adapter token、browser session 与接口鉴权      |
| [适配器鉴权建议.md](07_auth/适配器鉴权建议.md)                                           | Adapter / Plugin token 使用边界和 scope                                        |
| [前端鉴权建议.md](07_auth/前端鉴权建议.md)                                               | Dashboard browser session、CSRF 和 launch code 边界                            |
| [evidence_trace_api_contract.md](08_api/evidence_trace_api_contract.md)                  | 已冻结的证据链与溯源结构、示例、写入归属和验收清单                            |
| [dashboard_metrics_api_contract.md](08_api/dashboard_metrics_api_contract.md)            | Dashboard 指标作用域、原子审计窗口、历史 cohort 与验收契约                    |
| [AgentGuard_Core_V2.1_Final_Contract_Freeze/](AgentGuard_Core_V2.1_Final_Contract_Freeze/README.md) | Core V2.1 语义、权威、证据与兼容边界的最终契约 |
| [AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/](AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/README.md) | Context 隔离、Taint 追踪、溯源与验收边界的最终 RC 契约 |
| [AgentGuard_Runtime_Enforcement_Contract_v1_Final/](AgentGuard_Runtime_Enforcement_Contract_v1_Final/00_README_设计包索引.md) | Runtime Enforcement 契约冻结、字段/Schema/指标口径与 PR-RTE 实施计划 |
| [Competition 2026 archive](archive/competition-2026/README.md) | 历史命题要求、竞赛演示证据与不可扩大边界 |
| [Productization Alpha archive](archive/productization-alpha-2026/README.md) | Alpha 阶段依赖治理输入、分诊与回读证据 |

## 4. 维护规则

- 根目录 `README.md` 只保留项目门面和关键入口，完整文档地图只维护在本文件。
- 根目录 `ROADMAP.md` 是唯一当前能力与依赖路线入口，并由开发者直接维护；`TODO.md` 只保存可执行技术 backlog，二者不重复维护路线状态。
- 根目录 `DEPLOYMENT_LOCAL.md` 只保留最小启动入口；产品安装、升级和故障排查从 [install_upgrade_troubleshooting.md](06_delivery/install_upgrade_troubleshooting.md) 进入，完整配置细节维护在 [deployment_install_usage.md](06_delivery/deployment_install_usage.md)。
- `08_api/` 保存目标契约及迁移状态；目标冻结后，先在 [interface_contract.md](02_core/interface_contract.md) 区分当前实现与冻结目标，再同步 schemas、类型、存储和实现。目标契约不得被描述为当前能力。
- Core 不依赖 Adapter，不暴露 HTTP API，不读写数据库；Adapter 不写核心规则；Dashboard 不直连运行时。
- 攻击样本真值由 Redteam 提供，评测指标由 AttackBench runner 汇总。
- `agentguard_langgraph_bench/` 下的 runner、样本和演示适配器属于评测边界，产品主链路文档只引用其稳定入口，不复制其内部实现说明。
- `docs/archive/` 内容默认只读；迁移历史证据时保留来源、摘要和不可复现边界，不把 ignored 文件或临时目录重新设为产品依赖。
- 历史竞赛或答辩口径只在归档中保存，不反向扩大产品能力声明。
