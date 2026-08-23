# 文档地图

本目录是 AgentGuard 的完整文档入口。当前入口优先服务产品安装、开发、运维和可验证交付；命题、竞赛、答辩与演示证据只作为标明边界的历史资料保留。

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
├── 08_api/               # 跨端 API 目标契约、联调结构与迁移清单
├── archive/              # 历史竞赛、答辩与演示材料；非产品入口
├── AgentGuard_Runtime_Enforcement_Contract_v1_Final/  # Runtime Enforcement 契约冻结
└── AgentGuard_Runtime_Supervision_Console_Design/      # 运行时监督控制台增强设计候选稿
```

## 2. 开发阅读路径

### 产品安装与维护

1. [Productization Alpha Status](06_delivery/productization_alpha_status.md)
2. [安装、升级和故障排查](06_delivery/install_upgrade_troubleshooting.md)
3. [兼容矩阵](06_delivery/compatibility_matrix.md)
4. [产品化架构与目录职责](01_overview/productization_architecture.md)
5. [接口契约与事件模型](02_core/interface_contract.md)
6. [安全策略](../SECURITY.md)
7. [贡献指南](../CONTRIBUTING.md)

### P0 最小闭环

1. [部署、安装与使用说明](06_delivery/deployment_install_usage.md)
2. [总体架构](01_overview/architecture.md)
3. [接口契约与事件模型](02_core/interface_contract.md)
4. [`agentguard-core` 设计](02_core/core_design.md)
5. [LangGraph 评测靶场](03_adapters/langgraph_adapter.md)
6. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
7. [Dashboard 与审批流](04_apps/dashboard_design.md)
8. [实施路线与验收标准](06_delivery/implementation_plan.md)
9. [全轨实施路线图与执行控制面](06_delivery/roadmap/README.md)

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
5. [Agent 运行时安全可观测与动态治理设计](04_apps/runtime_safety_observability_design.md)
6. [运行时监督控制台增强设计包](AgentGuard_Runtime_Supervision_Console_Design/00_README_设计包索引.md)
7. [证据链与溯源 API 目标契约](08_api/evidence_trace_api_contract.md)
8. [Dashboard 指标作用域与审计窗口 API 协作契约](08_api/dashboard_metrics_api_contract.md)
9. [实施路线与验收标准](06_delivery/implementation_plan.md)

### API 联调与契约评审

1. [接口契约与事件模型](02_core/interface_contract.md)
2. [证据链与溯源 API 目标契约](08_api/evidence_trace_api_contract.md)
3. [Agent 运行时安全可观测与动态治理设计](04_apps/runtime_safety_observability_design.md)
4. [运行时监督控制台增强设计包](AgentGuard_Runtime_Supervision_Console_Design/00_README_设计包索引.md)
5. [Dashboard 指标作用域与审计窗口 API 协作契约](08_api/dashboard_metrics_api_contract.md)
6. [Capability Auth 总体方案](07_auth/鉴权总体方案.md)
7. [Dashboard 前端与 UI 设计规范](04_apps/dashboard_ui_spec.md)

### Redteam 开发

1. [威胁模型](02_core/threat_model.md)
2. [AttackBench 攻击样本与评测](05_redteam/attackbench.md)
3. [OpenClaw AttackBench 轮转验证与检测启用](05_redteam/openclaw_attackbench.md)
4. [命题要求追踪矩阵](00_requirements/requirement_traceability_matrix.md)

### 历史竞赛与答辩资料

1. [Competition 2026 archive](archive/competition-2026/README.md)
2. [命题要求追踪矩阵](00_requirements/requirement_traceability_matrix.md)
3. [演示脚本（旧路径兼容）](06_delivery/demo_script.md)
4. [现场演示运行手册（旧路径兼容）](06_delivery/demo_live_runbook.md)
5. [Demo 复现指南（旧路径兼容）](06_delivery/demo_reproduction_guide.md)
6. [OpenClaw E2E 演示设计（旧路径兼容）](06_delivery/openclaw_e2e_demo_design.md)

归档材料可能记录 ignored staging、临时路径或当时的演示口径，不能作为干净 clone 安装说明、当前产品能力或正式效果结论。上述四份演示文档暂留 `06_delivery/` 仅为一个里程碑周期的链接兼容，已降级为 historical/unsupported；后续物理迁移不得破坏 roadmap 证据引用。

## 3. 文档职责

| 文档                                                                                     | 职责                                                                           |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [命题.pdf](00_requirements/命题.pdf)                                                     | 原始题目材料                                                                   |
| [命题一\_题目解读总结.md](00_requirements/命题一_题目解读总结.md)                        | 命题一解读、攻击场景和成果形态建议                                             |
| [requirement_traceability_matrix.md](00_requirements/requirement_traceability_matrix.md) | 命题要求、模块设计和验收证据的追踪矩阵                                         |
| [architecture.md](01_overview/architecture.md)                                           | 系统总体架构、核心链路和模块关系                                               |
| [repo_structure.md](01_overview/repo_structure.md)                                       | 仓库目录职责和边界规则                                                         |
| [productization_architecture.md](01_overview/productization_architecture.md)             | Productization Alpha 的产品边界、目录治理和变更准入                            |
| [interface_contract.md](02_core/interface_contract.md)                                   | Guard API / Control Plane API、事件模型、决策模型和冻结规则                    |
| [core_design.md](02_core/core_design.md)                                                 | 无状态 Core 职责、检测器、策略和风险判定设计                                   |
| [threat_model.md](02_core/threat_model.md)                                               | 保护目标、攻击面、攻击链和非目标                                               |
| [langgraph_adapter.md](03_adapters/langgraph_adapter.md)                                 | LangGraph 接入点、Mock Tools 和 P0 靶场链路                                    |
| [openclaw_plugin.md](03_adapters/openclaw_plugin.md)                                     | OpenClaw 插件接入、Hook 映射和配置审计                                         |
| [openclaw_plugin_deployment.md](03_adapters/openclaw_plugin_deployment.md)               | OpenClaw 插件部署、安装、配置、验证和卸载                                      |
| [runtime_hooks_inventory.md](03_adapters/runtime_hooks_inventory.md)                     | OpenClaw 与 LangChain/LangGraph Hook、中间件、扩展面和数据结构统计             |
| [dashboard_design.md](04_apps/dashboard_design.md)                                       | Dashboard 页面、数据来源、审批和指标展示                                       |
| [dashboard_ui_spec.md](04_apps/dashboard_ui_spec.md)                                     | Dashboard 信息架构、视觉层级、交互模式和前端实现规范                           |
| [runtime_safety_observability_design.md](04_apps/runtime_safety_observability_design.md) | 执行轨迹、真实演示链、事实投影、联动视图和动态刷新冻结设计                     |
| [attackbench.md](05_redteam/attackbench.md)                                              | 攻击样本格式、runner、成功条件和评测指标                                       |
| [openclaw_attackbench.md](05_redteam/openclaw_attackbench.md)                            | OpenClaw 自动轮转 AttackBench、bench shim、bench tools、检测启用和验证流程     |
| [deployment_install_usage.md](06_delivery/deployment_install_usage.md)                   | Core、Guard API、CLI、Dashboard、OpenClaw 插件和评测 runner 的安装、部署与使用 |
| [install_upgrade_troubleshooting.md](06_delivery/install_upgrade_troubleshooting.md)     | 干净 clone、升级、测试和故障排查入口                                           |
| [compatibility_matrix.md](06_delivery/compatibility_matrix.md)                           | 运行环境、组件、浏览器和模式兼容范围                                           |
| [productization_alpha_status.md](06_delivery/productization_alpha_status.md)             | 当前产品化状态、未完成项、最终 SHA 与门禁结果                                  |
| [implementation_plan.md](06_delivery/implementation_plan.md)                             | P0/P1/P2 开发顺序、任务边界和验收标准                                          |
| [roadmap/](06_delivery/roadmap/README.md)                                                 | CORE/CT/RTE/Console 全轨任务、Gate、Stage、证据状态和并行 worktree 控制面        |
| [demo_script.md](06_delivery/demo_script.md)                                             | 防御前后对比演示和答辩叙事                                                     |
| [鉴权总体方案.md](07_auth/鉴权总体方案.md)                                               | Capability Auth、control token、adapter token、browser session 与接口鉴权      |
| [适配器鉴权建议.md](07_auth/适配器鉴权建议.md)                                           | Adapter / Plugin token 使用边界和 scope                                        |
| [前端鉴权建议.md](07_auth/前端鉴权建议.md)                                               | Dashboard browser session、CSRF 和 launch code 边界                            |
| [evidence_trace_api_contract.md](08_api/evidence_trace_api_contract.md)                  | 已冻结的证据链与溯源结构、示例、写入归属和验收清单                            |
| [dashboard_metrics_api_contract.md](08_api/dashboard_metrics_api_contract.md)            | Dashboard 指标作用域、原子审计窗口、历史 cohort 与验收契约                    |
| [AgentGuard_V2.1_Master_Roadmap_Final_Freeze_v2.md](AgentGuard_V2.1_Master_Roadmap_Final_Freeze_v2.md) | CORE / CT / RTE 三轨实施总路线图候选稿（Implementation Freeze Candidate；效力低于三套正式冻结分册，冲突时以分册为准） |
| [AgentGuard_Runtime_Enforcement_Contract_v1_Final/](AgentGuard_Runtime_Enforcement_Contract_v1_Final/00_README_设计包索引.md) | Runtime Enforcement 契约冻结、字段/Schema/指标口径与 PR-RTE 实施计划 |
| [AgentGuard_Runtime_Supervision_Console_Design/](AgentGuard_Runtime_Supervision_Console_Design/00_README_设计包索引.md) | 基于现有 Trace 控制台的任务监督图、CT 内容流、审批依据、字段/API 冻结与 S0-S6 实施验收候选方案 |

## 4. 维护规则

- 根目录 `README.md` 只保留项目门面和关键入口，完整文档地图只维护在本文件。
- 根目录 `DEPLOYMENT_LOCAL.md` 只保留最小启动入口；产品安装、升级和故障排查从 [install_upgrade_troubleshooting.md](06_delivery/install_upgrade_troubleshooting.md) 进入，完整配置细节维护在 [deployment_install_usage.md](06_delivery/deployment_install_usage.md)。
- `08_api/` 保存目标契约及迁移状态；目标冻结后，先在 [interface_contract.md](02_core/interface_contract.md) 区分当前实现与冻结目标，再同步 schemas、类型、存储和实现。目标契约不得被描述为当前能力。
- Core 不依赖 Adapter，不暴露 HTTP API，不读写数据库；Adapter 不写核心规则；Dashboard 不直连运行时。
- 攻击样本真值由 Redteam 提供，评测指标由 AttackBench runner 汇总。
- `agentguard_langgraph_bench/` 下的 runner、样本和演示适配器属于评测边界，产品主链路文档只引用其稳定入口，不复制其内部实现说明。
- `docs/archive/` 内容默认只读；迁移历史证据时保留来源、摘要和不可复现边界，不把 ignored 文件或临时目录重新设为产品依赖。
- 竞赛或答辩口径变化只更新追踪矩阵或归档，不反向扩大产品能力声明。
