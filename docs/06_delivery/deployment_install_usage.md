# AgentGuard 部署、安装与使用说明

## 1. 定位与组件关系

本文是 AgentGuard 当前 MVP 的统一运行手册，覆盖本地开发、演示验收、无头机器使用和生产化边界。当前系统按以下职责拆分：

| 组件                      | 部署形态                | 职责                                                                                                           |
| ------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------- |
| AgentGuard Core          | Python 库               | 无状态安全判定内核，负责事件规范化、检测器、策略匹配、风险评分和 `GuardDecision` 输出。                        |
| Guard API / Control Plane | FastAPI 服务            | 对外 HTTP 入口，负责鉴权、调用 core、审计入库、审批、指标、Trace、策略快照和 Dashboard 查询。                  |
| `agentguardctl` CLI       | Python console script   | 无图形界面机器上的工程控制台，通过 Guard API 做健康检查、登录链接、审计导出、指标、Trace、插件验证和评测委托。 |
| Dashboard                 | Vue/Vite 前端           | 图形化监督端，只通过 Guard API 读取审计、审批、Trace、指标和策略状态。                                         |
| OpenClaw 插件             | OpenClaw runtime plugin | Runtime Adapter，通过 adapter token 把 OpenClaw hook 事件送入 Guard API，不保存 Dashboard 会话。               |
| AttackBench runner        | Python 评测入口         | 运行攻击样本和正常样本，生成阻断率、误报、漏报和延迟指标。                                                     |

依赖方向固定为：Runtime Adapter 调用 Guard API，Guard API 调用 AgentGuard Core，Dashboard 和 CLI 都只调用 Guard API。Core 不启动服务、不访问数据库、不读取 token。

## 2. 前置条件

在仓库根目录准备依赖：

```bash
uv sync
pnpm install
```

当前根 `package.json` 声明 Node `24.18.0` 和 pnpm `11.5.2`。Python 依赖通过 `uv` 管理，根 `pyproject.toml` 以 editable 方式接入 `aegis-agentguard-core`、`aegis-agentguard-api` 和 `aegis-agentguard-cli`。

Beta 发布后也可以从 PyPI 安装统一入口或独立组件：

```bash
pip install --pre aegis-agentguard
pip install "aegis-agentguard[api]==0.1.0b1"
pip install "aegis-agentguard[cli]==0.1.0b1"
pip install "aegis-agentguard[all]==0.1.0b1"

pip install aegis-agentguard-core==0.1.0b1
pip install aegis-agentguard-api==0.1.0b1
pip install aegis-agentguard-cli==0.1.0b1
```

主包提供稳定门面：

```python
from aegis_agentguard import GuardDecision, GuardEngine, GuardEvent, PolicyBundle, evaluate
```

组件级 import 保持为 `agentguard_core`、`guard_api` 和 `agentguard_cli`；console script 保持为
`agentguard-api` 和 `agentguardctl`。本项目不提供顶层 `agentguard` Python 模块。

准备本地配置：

```bash
cp .env.example .env
```

`.env` 最小内容：

```dotenv
AGENTGUARD_ENV=development
AGENTGUARD_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard
AGENTGUARD_TEST_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard_test
AGENTGUARD_ADAPTER_TOKEN=ag_adapter_xxx
AGENTGUARD_CONTROL_TOKEN=ag_control_xxx
AGENTGUARD_HOST=127.0.0.1
AGENTGUARD_PORT=8088
AGENTGUARD_LLM_APPROVAL_ENABLED=false
AGENTGUARD_LLM_APPROVAL_BASE_URL=https://api.openai.com/v1
AGENTGUARD_LLM_APPROVAL_API_KEY=
AGENTGUARD_LLM_APPROVAL_MODEL=
AGENTGUARD_LLM_APPROVAL_TIMEOUT_SECONDS=3
```

`.env` 已被 Git 忽略。不得提交真实数据库密码、adapter token、control token、launch code、CSRF token、approval nonce 或 browser session。

`AGENTGUARD_LLM_APPROVAL_ENABLED=true` 后，Guard API 会对 Core 已创建的 `ask` approval 尝试同步 LLM 自动审批。LLM 只消费 approval evidence；`deny` 不进入 LLM。低/中风险 `ask` 可被自动 resolve 为 `allow_once`，高/严重风险不允许被 LLM 自动放行。LLM 配置缺失、超时或返回非法 JSON 时，approval 保持 `pending`，仍可由人工审批接管。

Guard API 需要 PostgreSQL，并要求 `AGENTGUARD_DATABASE_URL` 指向的用户和数据库已存在。启动 API 时会执行当前 migration。

PostgreSQL 集成测试要求 `AGENTGUARD_TEST_DATABASE_URL` 指向独立测试库，例如 `agent_guard_test`。不要把该变量指向开发库或生产库。

## 3. Core 使用与验证

AgentGuard Core（PyPI 分发名 `aegis-agentguard-core`）不是独立进程，不需要单独部署。它被 Guard API 和离线评测进程以 Python 库方式引用。

验证 core 可导入：

```bash
uv run python -c "from agentguard_core import GuardEngine, GuardEvent, PolicyBundle; print('aegis-agentguard-core ok')"
```

运行 core 相关测试：

```bash
uv run pytest tests/test_core_engine.py tests/test_schemas.py -q
```

Core 边界：

- 不读取 `.env`。
- 不管理 token、browser session、CSRF 或 approval nonce。
- 不直接写数据库。
- 不调用 Dashboard、OpenClaw 或 LangGraph。

## 4. 本地真实 API 模式

本模式用于开发联调和演示真实 Guard API 数据链路。

第一个终端启动 Guard API：

```bash
pnpm guard-api:dev
```

该脚本会加载根目录 `.env`，并按 `AGENTGUARD_HOST`、`AGENTGUARD_PORT` 启动 `uvicorn guard_api.main:app`。

第二个终端启动 Dashboard：

```bash
pnpm dashboard:dev
```

第三个终端加载 `.env` 并创建 Dashboard 登录地址：

```bash
set -a
. ./.env
set +a
uv run agentguardctl launch
```

命令输出形如：

```text
http://localhost:5173/?launch_code=lc_xxx
```

将该地址粘贴到浏览器。Dashboard 使用一次性 `launch_code` 换取 HttpOnly browser session，并从地址栏移除 code。

注意：

- `agentguardctl launch` 只创建登录 URL，不启动 Dashboard 页面服务。
- 如果浏览器显示 `ERR_CONNECTION_REFUSED localhost:5173`，说明 `pnpm dashboard:dev` 没有运行或端口不是 `5173`。
- launch code 只能使用一次，默认有效 300 秒。失败或换浏览器时重新运行 `uv run agentguardctl launch`。
- 浏览器访问 Dashboard 时始终使用 `localhost:5173`，不要和 `127.0.0.1:5173` 混用，否则 cookie 不共享。
- `pnpm guard-api:launch` 仍保留为兼容脚本，但新文档和无头使用优先写 `uv run agentguardctl launch`。

健康检查：

```bash
uv run agentguardctl health --check-db
pnpm openclaw:plugin:e2e
```

也可以直接访问：

```bash
curl -s "http://127.0.0.1:8088/health?check_db=true"
```

## 5. Dashboard Mock 模式

Mock 模式只用于前端页面开发和无后端演示，不需要 PostgreSQL、Guard API、launch code 或 browser session。

```bash
pnpm dashboard:dev:mock
```

直接打开终端输出的地址，默认是：

```text
http://localhost:5173/
```

Mock 模式使用本地场景数据。API 请求失败时，真实 API 模式不会自动切换到 Mock 模式。

## 6. CLI 使用

首选运行方式：

```bash
uv run agentguardctl --help
```

如果要直接执行 `agentguardctl`，需要先激活虚拟环境或把 `.venv/bin` 放入 `PATH`：

```bash
source .venv/bin/activate
agentguardctl health
```

CLI 默认读取：

```text
AGENTGUARD_API_URL
```

如果未设置，则使用：

```text
http://${AGENTGUARD_HOST:-127.0.0.1}:${AGENTGUARD_PORT:-8088}
```

需要鉴权的 CLI 命令读取：

```text
AGENTGUARD_CONTROL_TOKEN
```

常用命令：

```bash
uv run agentguardctl health --check-db
uv run agentguardctl launch
uv run agentguardctl audit export --limit 10
uv run agentguardctl audit export --limit 10 --output /tmp/agentguard-audit.jsonl
uv run agentguardctl metrics --json
uv run agentguardctl trace get <trace_id> --provenance
uv run agentguardctl openclaw verify
uv run agentguardctl eval import --help
```

CLI 边界：

- CLI 不替代 Dashboard。
- CLI 不实现安全检测逻辑。
- CLI 不直接连接数据库。
- CLI 不处理审批 resolve。
- CLI 不写策略、不安装或卸载 OpenClaw 插件。
- `openclaw verify` 只封装 `pnpm openclaw:plugin:verify`。
- `eval import` 只负责导入通用评测结果；公开 CLI 不依赖 LangGraph runner。

## 7. 无头机器模式

无图形界面的机器上可以只运行 Guard API、CLI 和 runtime 插件。

最小流程：

```bash
uv sync
pnpm install
cp .env.example .env
pnpm guard-api:dev
```

另一个终端加载环境并验收：

```bash
set -a
. ./.env
set +a

uv run agentguardctl health --check-db
uv run agentguardctl audit export --limit 10 --output /tmp/agentguard-audit.jsonl
uv run agentguardctl metrics --json
uv run agentguardctl openclaw verify
```

如果 Dashboard 运行在无头机器上，可以从本机做端口转发：

```bash
ssh -L 5173:127.0.0.1:5173 -L 8088:127.0.0.1:8088 -L 18789:127.0.0.1:18789 user@server
```

然后在服务器启动：

```bash
pnpm guard-api:dev
pnpm dashboard:dev
```

在服务器生成 launch URL，或在本机设置 `AGENTGUARD_API_URL=http://127.0.0.1:8088` 后运行：

```bash
uv run agentguardctl launch
```

浏览器打开输出的 `http://localhost:5173/?launch_code=...`。

## 8. OpenClaw 插件安装与验证

插件详细流程见 [OpenClaw 插件部署、安装与配置](../03_adapters/openclaw_plugin_deployment.md)。

基础检查：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
openclaw gateway status
```

安装开发版插件：

```bash
pnpm openclaw:plugin:install
```

验证插件：

```bash
uv run agentguardctl openclaw verify
```

等价底层命令：

```bash
pnpm openclaw:plugin:verify
```

卸载开发安装：

```bash
pnpm openclaw:plugin:uninstall
```

不要直接从 `packages/agentguard-openclaw-plugin` 安装到 OpenClaw；workspace 目录可能包含 `node_modules` symlink，会触发 OpenClaw local install safety scan。使用 `pnpm openclaw:plugin:install` 生成 repo-local ignored staging。

## 9. AttackBench 评测

公开 CLI 只保留通用评测结果导入，不携带 LangGraph runner。查看导入参数：

```bash
uv run agentguardctl eval import --help
```

评测 runner 由各自项目独立运行；生成结果后通过 `eval import` 写入 Guard API。这样 `agentguardctl` 发布物不引入 LangGraph 依赖。

## 10. 生产化边界

当前文档不是完整生产运维手册。当前实现适合本地开发、无头验收、演示复现和单机原型部署。

当 `AGENTGUARD_ENV=production` 时，Guard API 会拒绝使用默认 token 或默认数据库 URL。生产化至少需要：

- 更换 `AGENTGUARD_CONTROL_TOKEN` 和 `AGENTGUARD_ADAPTER_TOKEN`。
- 使用真实 PostgreSQL 账号、强密码和受限网络访问。
- 不把 control token 注入浏览器、Dashboard env、前端构建产物或日志。
- 通过 TLS 或可信内网访问 Guard API 和 Dashboard。
- 用 systemd、容器或进程管理器托管 Guard API 和 Dashboard。
- 配置日志脱敏、数据库备份、恢复演练和 token 轮换流程。

当前 MVP 不提供：

```text
多租户
用户登录
OAuth / SSO
token 生成、轮换、撤销 CLI
数据库备份自动化
OpenClaw install/uninstall 的 agentguardctl 子命令
CLI 审批 resolve
策略写入 CLI
```

## 11. 常见故障

### `agentguardctl: command not found`

`agentguardctl` 安装在 uv 管理的虚拟环境里。使用：

```bash
uv run agentguardctl health
```

或：

```bash
source .venv/bin/activate
agentguardctl health
```

### Guard API 连接失败

确认 API 已启动：

```bash
pnpm guard-api:dev
```

如果不是默认地址，设置：

```bash
export AGENTGUARD_API_URL=http://host:port
```

### 缺少 `AGENTGUARD_CONTROL_TOKEN`

需要鉴权的 CLI 命令必须加载 `.env`：

```bash
set -a
. ./.env
set +a
```

### HTTP `401` 或 `403`

`401` 通常表示 token 缺失或无效。`403 SCOPE_DENIED` 通常表示用了错误 token，例如把 adapter token 用在 CLI 只读接口上。CLI 读审计、指标、Trace 和策略使用 control token；OpenClaw/LangGraph adapter 使用 adapter token。

### Dashboard `ERR_CONNECTION_REFUSED localhost:5173`

`agentguardctl launch` 不启动 Dashboard。先运行：

```bash
pnpm dashboard:dev
```

然后重新生成 launch URL。

### OpenClaw install safety scan

不要直接安装 workspace 包目录。使用：

```bash
pnpm openclaw:plugin:install
```

### `openclaw plugins validate` 报 metadata 缺失

当前 AgentGuard 插件是 hook-only `definePluginEntry`，不是 simple tool plugin。真实验证标准是：

```bash
uv run agentguardctl openclaw verify
openclaw plugins inspect agentguard-security --runtime --json
openclaw gateway status
```
