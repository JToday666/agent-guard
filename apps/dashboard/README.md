# AgentGuard Dashboard

AgentGuard Dashboard 是监督端前端应用。它只通过 Guard API 读取审计事件、审批项、Trace 详情、评测指标、健康状态、插件状态和只读策略快照；不直接访问 LangGraph、OpenClaw、沙箱工具或 AttackBench runner 的内部状态。

## 技术栈

- Vue 3
- TypeScript
- Vite
- Sass
- Pinia
- pnpm

## 运行模式

在仓库根目录执行。

真实 API 模式：

```bash
pnpm guard-api:dev
pnpm dashboard:dev
```

随后加载根 `.env` 并生成一次性登录地址：

```bash
set -a
. ./.env
set +a
uv run agentguardctl launch
```

浏览器打开 `http://localhost:5173/?launch_code=...` 后，前端会通过 Vite 代理交换 browser session，并移除地址栏中的 launch code。launch code 只能使用一次；换浏览器、换配置文件或超时后需要重新生成。

Mock 模式：

```bash
pnpm dashboard:dev:mock
```

Mock 模式不需要 PostgreSQL、Guard API、launch code 或 browser session，适合前端页面演示和离线截图。

Dashboard 默认通过同源代理路径访问 Guard API：

```dotenv
VITE_API_BASE_URL=/api/v1
VITE_API_HEALTH_URL=/api/health
VITE_API_REQUEST_TIMEOUT_MS=10000
VITE_RUNTIME_SUPERVISION_S1_ENABLED=true
```

`VITE_API_REQUEST_TIMEOUT_MS` 必须为正数，非法值回退到 10 秒。`VITE_RUNTIME_SUPERVISION_S1_ENABLED` 默认开启；明确设为 `false`、`0`、`off` 或 `no` 时回退到 S0 只读监督，并拒绝全部审批写入。API 与健康地址应保持为同源代理路径；`VITE_BACKEND_TARGET` 只配置 Vite 代理连接的后端地址，不支持浏览器跨域直连 Guard API。

## 常用命令

```bash
pnpm dashboard:dev
pnpm dashboard:dev:mock
pnpm dashboard:format
pnpm dashboard:format:check
pnpm dashboard:lint
pnpm dashboard:check:changed
pnpm dashboard:check
pnpm dashboard:test:e2e
pnpm dashboard:test:e2e:api
pnpm dashboard:typecheck
pnpm dashboard:build
pnpm --filter @agentguard/dashboard test:unit
```

首次运行浏览器测试时，可安装 Playwright Chromium 和系统依赖：

```bash
pnpm --filter @agentguard/dashboard exec playwright install chromium
pnpm --filter @agentguard/dashboard exec playwright install-deps chromium
```

## 页面能力

- 总览：展示 Guard API 健康状态、关键指标、规则命中分布和高风险事件。
- 调查：筛选审计事件，查看阻断原因、命中规则、资源目标和 Trace ID。
- 证据链：展示 Trace 时间线、provenance graph、节点证据和审计完整性。
- 审批：处理 `ask` 决策，当前支持 `allow_once` 和 `deny`。
- 评测：展示阻断率、误报率、漏报率、判定延迟、混淆矩阵和运行时延迟对比。
- 系统：展示 Guard API、browser session、轮询状态、适配器状态、配置审计摘要和策略快照。

## 数据与鉴权边界

- Dashboard 不保存 control token，不直接连接数据库，不直接调用 Core。
- 真实 API 模式下，请求依赖 HttpOnly browser session；状态改变请求使用内存中的 CSRF token，审批唯一性由服务端原子状态转换保证。
- 直接访问 `http://localhost:5173/` 且没有 session 时，`GET /v1/auth/browser/me` 返回 `401` 属于预期行为。
- API 请求失败时，真实 API 模式不会自动切换到 Mock 数据。
- 页面可见时每 10 秒串行刷新核心数据；页面隐藏时暂停轮询，恢复可见后立即刷新。

## 目录

```text
apps/dashboard/
├── src/
│   ├── api/          # Guard API client 和 mapper
│   ├── components/   # 页面组件
│   ├── data/         # mock/API 数据源与测试数据
│   ├── layouts/      # Dashboard shell
│   ├── pages/        # overview、evidence、approvals 等页面
│   ├── stores/       # Pinia store
│   └── styles/       # 全局样式
├── e2e/              # Playwright 页面测试
├── index.html
├── package.json
├── tsconfig*.json
└── vite.config.ts
```

## 提交说明

本目录内保留 Dashboard 源码、测试和本 README。内部设计过程文档不需要进入竞赛可执行压缩包；页面行为以源码、测试和根 README 中的运行说明为准。
