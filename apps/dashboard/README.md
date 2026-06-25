# AgentGuard Dashboard

AgentGuard Dashboard 是监督端前端应用，只通过 Guard API 读取审计事件、审批项和评测指标，再从审计事件聚合 trace；不直接访问 LangGraph、OpenClaw、沙箱工具或 AttackBench runner 的内部状态。

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
pnpm dashboard:dev
pnpm dashboard:dev:mock
pnpm dashboard:test:e2e
pnpm dashboard:typecheck
pnpm dashboard:build
pnpm --filter @agentguard/dashboard test:unit
```

## 环境配置

默认配置已经可以直接运行。需要覆盖 API 路径、后端地址或 Mock 延迟时，将示例文件复制为本地配置：

```bash
cp apps/dashboard/.env.example apps/dashboard/.env.local
```

`.env.local` 和 `.env.*.local` 已被 Git 忽略，只用于本机地址和延迟配置，不得写入长期 token。
数据源不通过环境变量切换：`dashboard:dev` 使用 Guard API，`dashboard:dev:mock` 使用本地场景数据。`VITE_API_BASE_URL` 控制浏览器 API 前缀，`VITE_BACKEND_TARGET` 只由 Vite 开发代理使用。

## Mock 模式测试

Mock 模式不需要启动 PostgreSQL 或 Guard API。在仓库根目录执行：

```bash
pnpm dashboard:dev:mock
```

打开终端显示的访问地址，默认是 `http://localhost:5173/`。页面会直接进入本地场景，能够查看调查、审批、Trace 和指标。Mock 模式不启动 PostgreSQL 或 Guard API，也不建立 browser session。

## 浏览器测试

项目依赖已声明固定版本的 Playwright。首次准备浏览器环境时安装 Chromium 和所需系统库：

```bash
pnpm --filter @agentguard/dashboard exec playwright install chromium
pnpm --filter @agentguard/dashboard exec playwright install-deps chromium
```

依赖版本记录在 `package.json` 和 `pnpm-lock.yaml`；Chromium 位于用户缓存，系统库由操作系统包管理器维护。完成一次环境准备后，日常从仓库根目录运行：

```bash
pnpm dashboard:test:e2e
```

测试使用 mock 数据，在 Chromium 中覆盖桌面、平板和手机视口，不需要启动 Guard API。

## API 模式联调

API 模式需要本机已经安装项目依赖，并准备好根 `.env`、PostgreSQL 用户和对应数据库。

先在一个终端中从仓库根目录启动 Guard API：

```bash
pnpm guard-api:dev
```

该命令自动加载根 `.env`，Guard API 启动时会执行数据库 migration。然后在第二个终端启动 Dashboard：

```bash
pnpm dashboard:dev
```

在第三个终端创建一次性 launch code：

```bash
pnpm guard-api:launch
```

命令只输出形如 `http://localhost:5173/?launch_code=lc_xxx` 的完整地址，不输出 control token。将该地址直接粘贴到目标浏览器后，前端通过 Vite 代理交换 browser session，并从地址栏移除 launch code。launch code 只能使用一次；VS Code 内置浏览器、外部浏览器和不同浏览器配置文件需要分别运行一次 `pnpm guard-api:launch`。始终使用 `localhost`，不要与 `127.0.0.1` 混用。

如果直接访问 `http://localhost:5173/`，浏览器尚无 session，`GET /v1/auth/browser/me` 返回 `401` 属于预期行为。API 请求失败时不会自动切换到 Mock 数据。

Dashboard 在页面可见时每 10 秒串行刷新事件、指标、审批和健康状态；上一轮完成后才会安排下一轮。页面隐藏时暂停轮询，恢复可见后立即刷新。Skeleton 仅在首次加载显示，后台刷新和短暂连接异常会保留当前页面与用户选择。

## 比赛演示路径

1. 总览确认 Guard API、指标和数据更新时间。
2. 调查页查看阻断原因、命中规则、资源与 Trace ID。
3. 审批中心处理 `ask`，仅支持 `allow_once` 和 `deny`。
4. 调查详情按真实 AuditEvent 的 `trace_id` 展示证据序列。
5. 评测页展示 ASR、Block Rate、FPR 和判定延迟；API 未提供的指标显示 `--`。

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

- Dashboard 只读 Guard API，不直接调用 Core。
- API 字段真相源以根目录 `docs/02_core/interface_contract.md` 和后续 `schemas/` 为准。
- 前端内部文档只维护页面、状态、组件、store、样式和交互约定。
