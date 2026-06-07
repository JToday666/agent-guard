# 仓库结构与目录职责

## 1. 文档定位

本文定义 AgentGuard 的仓库边界和目录职责，帮助开发者判断代码、样本、策略、schemas 和文档应该放在哪里。

关联入口：

- [系统总体架构](architecture.md)
- [接口契约与事件模型](../02_core/interface_contract.md)
- [实施路线与验收标准](../06_delivery/implementation_plan.md)

## 2. 目标结构

```text
agent-guard/
├── README.md
├── apps/
│   ├── guard-api/
│   ├── dashboard/
│   └── demo-agent/
├── packages/
│   ├── agentguard-core/
│   ├── agentguard-sdk/
│   ├── agentguard-adapters/
│   └── agentguard-openclaw-plugin/
├── redteam/
│   ├── datasets/
│   ├── scripts/
│   ├── runners/
│   ├── checkers/
│   └── reports/
├── policies/
│   ├── default.yaml
│   ├── strict.yaml
│   ├── demo.yaml
│   └── rules/
├── schemas/
├── tests/
├── scripts/
├── deploy/
├── data/
├── artifacts/
└── docs/
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
└── 06_delivery/
```

文档目录按开发模块组织。命题材料放在 `00_requirements/`，但开发入口从 `01_overview/` 和 `02_core/` 开始。

## 4. 目录职责

| 目录                                  | 职责                                                 |
| ------------------------------------- | ---------------------------------------------------- |
| `apps/guard-api`                      | FastAPI 服务入口，只封装 Core API                    |
| `apps/dashboard`                      | Vue 3 监督端页面，只通过 Core API 获取数据和提交审批 |
| `apps/demo-agent`                     | 被保护的 LangGraph 示例 Agent 和 Mock Tools          |
| `packages/agentguard-core`            | 唯一安全判断中心                                     |
| `packages/agentguard-sdk`             | Core 客户端、事件构造、运行时接入辅助                |
| `packages/agentguard-adapters`        | LangGraph 等运行时适配层                             |
| `packages/agentguard-openclaw-plugin` | OpenClaw 插件包                                      |
| `redteam/`                            | 攻击样本、正常样本、runner、成功条件、报告           |
| `policies/`                           | 策略、规则、权限配置                                 |
| `schemas/`                            | JSON Schema 与 OpenAPI                               |
| `tests/`                              | 单元测试、契约测试、集成测试                         |
| `artifacts/`                          | 截图、trace、视频、大结果，默认不入库                |

## 5. 边界规则

- Core 不依赖 Adapter，不读取 Dashboard 状态。
- Adapter 不写核心规则，只把运行时事件映射成 AgentGuard Event。
- Dashboard 不直连运行时，不直接判断攻击成功。
- Core API 采用统一 Capability Auth；Adapter 使用 adapter token，Dashboard 使用 browser session。
- Redteam 提供 ground truth，runner 负责统计指标。
- Policies 不硬编码进 Adapter。
- Schemas 是 API 和事件字段的唯一结构来源。

## 6. 验收证据

仓库结构验收检查：

1. P0 代码和样本能按目录职责放置，无跨目录职责混杂。
2. `schemas/` 与 [接口契约](../02_core/interface_contract.md) 字段一致。
3. `redteam/` 样本能被 runner 读取并生成指标。
4. Dashboard 只通过 Core API 获取数据和提交审批。
