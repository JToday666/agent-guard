# AgentGuard Dashboard

AgentGuard Dashboard 是监督端前端应用，只通过 Guard API 读取审计事件、审批项、Trace 详情、评测指标、健康状态和只读策略快照；不直接访问 LangGraph、OpenClaw、沙箱工具或 AttackBench runner 的内部状态。

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

在第三个终端加载根 `.env` 并创建一次性 launch code：

```bash
set -a
. ./.env
set +a
uv run agentguardctl launch
```

命令只输出形如 `http://localhost:5173/?launch_code=lc_xxx` 的完整地址，不输出 control token。将该地址直接粘贴到目标浏览器后，前端通过 Vite 代理交换 browser session，并从地址栏移除 launch code。launch code 只能使用一次；VS Code 内置浏览器、外部浏览器和不同浏览器配置文件需要分别运行一次 `uv run agentguardctl launch`。始终使用 `localhost`，不要与 `127.0.0.1` 混用。

`uv run agentguardctl launch` 只创建登录地址，不启动 Vite 页面服务。如果浏览器显示 `ERR_CONNECTION_REFUSED localhost:5173`，说明 `pnpm dashboard:dev` 没有运行或端口不是 `5173`。`pnpm guard-api:launch` 仍保留为兼容脚本。

如果直接访问 `http://localhost:5173/`，浏览器尚无 session，`GET /v1/auth/browser/me` 返回 `401` 属于预期行为。API 请求失败时不会自动切换到 Mock 数据。

Dashboard 在页面可见时每 10 秒串行刷新事件、指标、审批、健康状态和只读策略状态；上一轮完成后才会安排下一轮。页面隐藏时暂停轮询，恢复可见后立即刷新。调查详情页会按需读取 `GET /v1/traces/{trace_id}`，失败时回退到已加载审计事件窗口。Skeleton 仅在首次加载显示，后台刷新和短暂连接异常会保留当前页面与用户选择。

## 比赛演示路径

1. 总览确认 Guard API、指标和数据更新时间。
2. 调查页查看阻断原因、命中规则、资源与 Trace ID。
3. 审批中心处理 `ask`，仅支持 `allow_once` 和 `deny`。
4. 调查详情优先读取 Trace detail，展示完整证据序列和 `event_id` 定位。
5. 评测页展示 Block Rate、FPR、FNR 和判定延迟；ASR 仅在 API 提供 before / after 数据时展示。
6. 系统页查看 Guard API 健康状态、browser session、轮询状态和只读策略快照。

## 测试文件边界

`src/**/*.node.test.ts` 覆盖 mapper、状态快照、审批证据关联、调查筛选、格式化和鉴权错误等长期逻辑，`e2e/*.spec.ts` 覆盖 mock 模式下的页面导航和视口行为。这些测试文件属于长期维护资产。`apps/dashboard/test-results/` 是 Playwright 运行产物，已被 `.gitignore` 忽略，可随时清理并由测试重新生成。

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
- [根部署、安装与使用说明](../../docs/06_delivery/deployment_install_usage.md)

## 边界

- Dashboard 只读 Guard API，不直接调用 Core。
- API 字段真相源以根目录 `docs/02_core/interface_contract.md` 和后续 `schemas/` 为准。
- 前端内部文档只维护页面、状态、组件、store、样式和交互约定。
