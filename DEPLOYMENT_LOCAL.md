# AgentGuard 本地部署与验收说明

本文面向评委、复现实验人员和无头机器验收场景，说明如何从仓库根目录启动 AgentGuard、Dashboard、CLI、OpenClaw 插件和 LangGraph / AttackBench 靶场。

## 环境要求

- Python 3.12 或更新版本。
- `uv`，用于安装依赖和执行 Python 命令。
- Node 24.18.0。
- pnpm 11.9.0。
- PostgreSQL，本地真实 API 模式和集成测试需要。
- 可选：OpenClaw 2026.6.6，用于真实插件验证。

所有命令默认在仓库根目录执行。

## 初始化

```bash
uv sync
pnpm install
cp .env.example .env
```

编辑 `.env`，至少确认以下变量指向本机可用资源：

```dotenv
AGENTGUARD_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard
AGENTGUARD_TEST_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard_test
AGENTGUARD_ADAPTER_TOKEN=change-me-adapter-token
AGENTGUARD_CONTROL_TOKEN=change-me-control-token
AGENTGUARD_HOST=127.0.0.1
AGENTGUARD_PORT=8088
```

`.env` 已被忽略，不得提交真实密码、token、launch code、CSRF token、approval nonce 或 browser session。`AGENTGUARD_DATABASE_URL` 和 `AGENTGUARD_TEST_DATABASE_URL` 应指向不同数据库。

## 启动真实 API 链路

第一个终端：

```bash
pnpm guard-api:dev
```

该命令加载根目录 `.env`，启动 Guard API，并在启动时执行数据库 migration。

第二个终端：

```bash
pnpm dashboard:dev
```

第三个终端：

```bash
set -a
. ./.env
set +a
uv run agentguardctl launch
```

CLI 输出一次性登录地址，例如：

```text
http://localhost:5173/?launch_code=lc_xxx
```

用浏览器打开该地址后，Dashboard 会交换 browser session，并清理地址栏中的 launch code。launch code 默认只能使用一次；如果换浏览器或超时，重新运行 `uv run agentguardctl launch`。

## 无头 CLI 验收

在已启动 Guard API 的前提下：

```bash
set -a
. ./.env
set +a

uv run agentguardctl health --check-db
uv run agentguardctl audit export --limit 10
uv run agentguardctl metrics --json
uv run agentguardctl trace get <trace_id> --provenance
uv run agentguardctl openclaw verify
uv run agentguardctl eval run --help
```

CLI 默认读取 `AGENTGUARD_API_URL`；未设置时使用 `AGENTGUARD_HOST` 和 `AGENTGUARD_PORT`。需要鉴权的 CLI 命令读取 `AGENTGUARD_CONTROL_TOKEN`。

## Dashboard Mock 模式

Mock 模式不需要 PostgreSQL、Guard API、launch code 或 browser session：

```bash
pnpm dashboard:dev:mock
```

打开终端输出的地址，默认是 `http://localhost:5173/`。该模式适合前端页面演示，不代表真实后端链路。

## OpenClaw 插件验收

开发安装：

```bash
pnpm openclaw:plugin:install
```

验证插件配置和 Guard API 接入：

```bash
pnpm openclaw:plugin:verify
uv run agentguardctl openclaw verify
```

运行 E2E：

```bash
pnpm openclaw:plugin:e2e
```

运行 reliability：

```bash
pnpm openclaw:plugin:reliability
```

卸载开发安装：

```bash
pnpm openclaw:plugin:uninstall
```

AgentGuard OpenClaw 插件是 hook-only `definePluginEntry` 插件。若 `openclaw plugins validate` 按 simple tool plugin 规则报告 metadata 缺失，不作为本插件失败标准；以安装、inspect、doctor、gateway 状态、hook 触发和 Guard API 审计记录为准。

## LangGraph / AttackBench 靶场

查看 runner 参数：

```bash
uv run agentguardctl eval run --help
```

离线 runner 示例：

```bash
uv run python -m agentguard_langgraph_bench.bench.cli --dataset agentguard_langgraph_bench/bench/datasets/attack_cases --defense off
uv run python -m agentguard_langgraph_bench.bench.cli --dataset agentguard_langgraph_bench/bench/datasets/attack_cases --defense on --fake-core
```

真实 Guard API 链路评测需要先启动 Guard API，并确认 `.env` 中的 adapter token 与 runner 参数一致。`--fake-core` 仅用于验证靶场、工具副作用和指标汇总，不代表真实防御效果。

## 常用验证命令

```bash
uv run pytest tests/test_core_engine.py tests/test_schemas.py -q
uv run pytest tests/test_openclaw_plugin_contract.py -q
uv run pytest agentguard_langgraph_bench/bench/tests/test_langgraph_adapter.py agentguard_langgraph_bench/bench/tests/test_core_client.py -q
pnpm --filter @agentguard/openclaw-plugin test
pnpm --filter @agentguard/openclaw-bench-tools test
pnpm --filter @agentguard/dashboard typecheck
```

本轮文档整理不要求运行完整测试；上述命令用于提交前或现场复核。

## 故障排查

### Dashboard 无法访问

`uv run agentguardctl launch` 只创建登录地址，不启动前端。先确认：

```bash
pnpm dashboard:dev
```

浏览器应使用 `localhost:5173`，不要与 `127.0.0.1:5173` 混用。

### Guard API 连接失败

确认 API 进程正在运行：

```bash
pnpm guard-api:dev
```

若使用非默认地址，设置：

```bash
export AGENTGUARD_API_URL=http://host:port
```

### 缺少 control token

需要鉴权的 CLI 命令应先加载 `.env`：

```bash
set -a
. ./.env
set +a
```

### HTTP 401 或 403

`401` 通常表示 token 缺失或无效。`403` 通常表示 token scope 不匹配，例如把 adapter token 用在 CLI 查询接口。CLI 查询审计、指标和 Trace 使用 control token；运行时 adapter 使用 adapter token。

### OpenClaw 安装扫描失败

不要直接把 workspace 包目录安装进 OpenClaw。使用仓库脚本生成本地 staging：

```bash
pnpm openclaw:plugin:install
```

### PostgreSQL 集成测试风险

`AGENTGUARD_TEST_DATABASE_URL` 必须指向独立测试库。不要把测试库变量指向开发库或生产库。
