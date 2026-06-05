# AgentGuard Dashboard

AgentGuard Dashboard 是监督端前端应用，只通过 Core API 读取审计事件、审批项、trace 和指标数据，不直接访问 LangGraph、OpenClaw、Mock Tools 或 redteam runner 的内部状态。

## 技术栈

- Vue 3
- TypeScript
- Vite
- Sass
- Pinia
- pnpm

## 命令

在仓库根目录执行：

```bash
pnpm --filter @agentguard/dashboard dev
pnpm --filter @agentguard/dashboard typecheck
pnpm --filter @agentguard/dashboard build
```

## 目录

```text
apps/dashboard/
├── docs/                 # 前端内部设计、规范和维护约定
├── src/
│   ├── stores/           # Pinia store
│   └── styles/           # 全局样式
├── index.html
├── package.json
├── tsconfig*.json
└── vite.config.ts
```

## 文档

- [前端文档索引](docs/README.md)
- [前端 UI 设计规范](docs/04-规范/前端UI设计规范.md)
- [文档维护约定](docs/04-规范/文档维护约定.md)

## 边界

- Dashboard 只读 Core API。
- API 字段真相源以根目录 `docs/02_core/interface_contract.md` 和后续 `schemas/` 为准。
- 前端内部文档只维护页面、状态、组件、store、样式和交互约定。
