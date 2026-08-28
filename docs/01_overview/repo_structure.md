# 仓库结构与目录职责

## 1. 文档定位

本文定义 AgentGuard 的仓库边界和目录职责，帮助开发者判断代码、样本、策略、schemas 和文档应该放在哪里。

关联入口：

- [产品化架构与目录职责](productization_architecture.md)
- [系统总体架构](architecture.md)
- [接口契约与事件模型](../02_core/interface_contract.md)
- [能力与依赖路线图](../../ROADMAP.md)

## 2. 当前结构

以下结构以仓库当前实现为准。`agentguard_langgraph_bench/` 同时包含评测 runner、样本和演示适配器；产品主链路的 SDK、API 和 Dashboard 位于 `packages/` 与 `apps/`。

```text
agent-guard/
├── README.md
├── ROADMAP.md          # 人工维护的能力节点、硬依赖和开发路线
├── DEPLOYMENT_LOCAL.md  # 根目录最小启动入口
├── apps/
│   ├── cli/
│   ├── guard-api/
│   └── dashboard/
├── packages/
│   ├── agentguard-core/
│   ├── agentguard-langgraph-adapter/
│   └── agentguard-openclaw-plugin/
├── benchmarks/
│   └── openclaw-bench-tools/
├── agentguard_langgraph_bench/
│   ├── bench/          # AttackBench runner、样本、沙箱和评测逻辑
│   ├── adapter/        # 旧导入路径兼容层
│   ├── adapters/       # 外部 Agent 适配器
│   └── demo_agent/     # LangGraph 演示 Agent
├── schemas/
├── examples/         # 干净 clone 可运行的最小示例
├── tests/
├── scripts/
└── docs/
    └── archive/      # 历史证据；非产品入口
```

## 3. 文档结构

```text
docs/
├── 00_requirements/
├── 01_overview/
├── 02_core/
├── 03_adapters/
├── 04_apps/
├── 05_redteam/
├── 06_delivery/
├── 07_auth/
├── 08_api/
└── archive/
```

文档目录按开发模块组织。命题材料放在 `00_requirements/`，但开发入口从 `01_overview/` 和 `02_core/` 开始。`08_api/` 保存跨端 API 目标契约和迁移清单；目标冻结后先同步稳定接口契约中的当前/目标边界，再同步 schemas 和实现。

## 4. 目录职责

| 目录                                       | 职责                                                                        |
| ------------------------------------------ | --------------------------------------------------------------------------- |
| `apps/guard-api`                           | Guard API / Control Plane 后端，负责 HTTP、鉴权、审计、审批、指标和状态服务 |
| `apps/dashboard`                           | Vue 3 监督端页面，只通过 Guard API 获取数据和提交审批                       |
| `apps/cli`                                 | `agentguardctl` 无头控制与验收命令                                          |
| `packages/agentguard-core`                 | 无状态安全判定库，负责事件规范化、检测、策略匹配、风险评分和决策输出        |
| `packages/agentguard-langgraph-adapter`    | LangGraph 风格工具执行的事件映射和执行前控制                                |
| `packages/agentguard-openclaw-plugin`      | OpenClaw runtime hook 插件                                                  |
| `benchmarks/openclaw-bench-tools`          | OpenClaw AttackBench 本地工具桥接                                           |
| `agentguard_langgraph_bench/`              | AttackBench runner、样本、沙箱、演示 Agent 和外部 Agent 适配器              |
| `schemas/`                                 | GuardEvent、GuardDecision、AuditEvent 与 AttackCase JSON Schema             |
| `examples/`                                | 不依赖本地 staging、外部服务或临时目录的最小可运行示例                       |
| `tests/`                                   | unit、contract、integration、PostgreSQL、E2E 与手动 live 测试               |
| `scripts/`                                 | 本地开发、插件安装验证和辅助命令                                            |
| `docs/`                                    | 架构、稳定接口、API 目标契约、适配器、部署、鉴权和评测文档                  |
| `docs/archive/`                            | 历史竞赛、答辩和演示材料；不作为安装、生产或正式效果证据入口                 |

完整部署流程以 `docs/06_delivery/deployment_install_usage.md` 为唯一事实来源；
根目录 `DEPLOYMENT_LOCAL.md` 只提供快速导航和最小启动命令。

## 5. 边界规则

- Core 不依赖 Adapter，不读取 Dashboard 状态，不暴露 HTTP API，不读写数据库。
- Adapter 不写核心规则，只把运行时事件映射成 AgentGuard Event。
- Dashboard 不直连运行时，不直接判断攻击成功。
- Guard API / Control Plane API 采用统一 Capability Auth；Adapter 使用 adapter token，Dashboard 使用 browser session。
- Redteam 提供 ground truth，runner 负责统计指标。
- 策略模型位于 `packages/agentguard-core/agentguard_core/policies/`，不硬编码进 Adapter。
- Core/Guard API 的 Pydantic 模型是运行时校验来源；`schemas/` 是对外 JSON Schema，
  必须通过契约测试与模型保持一致，不能独立演化。
- `official`、`shadow`、`demo`、`mock` 在 API、UI、文档与证据中必须保持可辨识；展示层不能扩大权威声明。
- 产品示例不得依赖 `.openclaw-dev`、`/tmp`、开发者本地 `.env` 或未跟踪报告。

## 6. 验收证据

仓库结构验收检查：

1. P0 代码和样本能按目录职责放置，无跨目录职责混杂。
2. `schemas/` 与 [接口契约](../02_core/interface_contract.md) 字段一致。
3. `agentguard_langgraph_bench/bench/datasets/` 样本能被 runner 读取并生成指标。
4. Dashboard 只通过 Guard API 获取数据和提交审批。
