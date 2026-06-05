# 仓库结构与目录职责

## 1. 总体原则

仓库采用简化 monorepo：

```text
apps/       可运行应用
packages/   可复用代码包
redteam/    攻击样本与评测脚本
policies/   策略与权限配置
schemas/    统一接口契约
docs/       正式项目文档
```

## 2. 推荐结构

```text
agent-guard/
├── README.md
├── LICENSE
├── pyproject.toml
├── package.json
├── pnpm-workspace.yaml
├── docker-compose.yml
├── .env.example
├── Makefile
│
├── docs/
├── schemas/
├── apps/
│   ├── guard-api/
│   ├── dashboard/
│   └── demo-agent/
│
├── packages/
│   ├── agentguard-core/
│   ├── agentguard-sdk/
│   ├── agentguard-adapters/
│   └── agentguard-openclaw-plugin/
│
├── redteam/
│   ├── datasets/
│   ├── scripts/
│   ├── runners/
│   ├── checkers/
│   └── reports/
│
├── policies/
│   ├── default.yaml
│   ├── strict.yaml
│   ├── demo.yaml
│   ├── permissions/
│   └── rules/
│
├── data/
├── tests/
├── scripts/
├── deploy/
├── examples/
└── artifacts/
```

## 3. 目录职责

| 目录 | 职责 |
|---|---|
| `apps/guard-api` | FastAPI 服务入口，只封装 Core API |
| `apps/dashboard` | 监督端页面，只连接 Core |
| `apps/demo-agent` | 被保护的示例 Agent |
| `packages/agentguard-core` | 唯一安全判断中心 |
| `packages/agentguard-sdk` | 运行时接入 SDK |
| `packages/agentguard-adapters` | LangGraph 等适配层 |
| `packages/agentguard-openclaw-plugin` | OpenClaw 插件包 |
| `redteam/` | 攻击样本、脚本、runner、成功条件 |
| `policies/` | 策略和权限配置 |
| `schemas/` | 统一 JSON Schema 与 OpenAPI |
| `artifacts/` | 截图、trace、视频、大结果，默认不入库 |

## 4. 边界规则

- Core 不依赖 Adapter。
- Adapter 不写核心规则。
- Dashboard 不直连运行时。
- Redteam 提供 ground truth。
- Policies 不硬编码进 Adapter。
