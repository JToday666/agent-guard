# AgentGuard

AgentGuard 是面向大模型智能体的运行时行为监督与攻击检测系统。项目目标是让接入工具、文件、API、代码执行和记忆能力的 Agent 在执行外部动作前具备可审计、可解释、可阻断的安全控制。

## 架构定位

采用 **四层目标架构**：

- **Runtime Adapter**：接入 LangGraph、OpenClaw 或通用工具运行时，负责事件映射和执行控制。
- **Guard API / Control Plane**：统一 HTTP 入口，负责鉴权、策略管理、审计、告警、审批、指标和调用链状态。
- **agentguard-core**：无状态安全判定库，负责事件规范化、检测器、策略匹配、风险评分和 `GuardDecision` 输出。
- **Dashboard / Evaluation**：监督展示、审批处理、指标分析和 AttackBench 评测。

LangGraph 和 OpenClaw 是四层架构下的运行时接入与演示场景，不再作为总体架构层级。

## 快速安装

以下命令均在仓库根目录执行。首次准备依赖：

```bash
uv sync
pnpm install
```

创建本地后端配置，并确认配置的 PostgreSQL 用户和数据库已经存在：

```bash
cp .env.example .env
```

`.env` 已被 Git 忽略，不得提交真实数据库密码、adapter token 或 control token。

完整部署、安装、使用和故障排查说明见 [部署、安装与使用说明](docs/06_delivery/deployment_install_usage.md)。

## 本地真实 API 模式

在第一个终端启动 Guard API。该命令会自动加载根 `.env`，无需显式传入 `--env-file`：

```bash
pnpm guard-api:dev
```

在第二个终端启动 Dashboard：

```bash
pnpm dashboard:dev
```

在第三个终端加载 `.env` 并创建一次性 launch code：

```bash
set -a
. ./.env
set +a
uv run agentguardctl launch
```

命令会输出形如 `http://localhost:5173/?launch_code=lc_xxx` 的完整地址。将该地址直接粘贴到目标浏览器后，Dashboard 使用 launch code 换取 browser session，并从地址栏移除 code。launch code 只能使用一次；VS Code 内置浏览器、外部浏览器和不同浏览器配置文件需要分别生成新地址。始终使用 `localhost`，不要与 `127.0.0.1` 混用，否则 cookie 不共享。

`agentguardctl launch` 只创建登录地址，不启动 Dashboard。如果浏览器显示 `ERR_CONNECTION_REFUSED localhost:5173`，先确认 `pnpm dashboard:dev` 正在运行。`pnpm guard-api:launch` 仍保留为兼容脚本。

## 无头 CLI

无图形界面机器可以直接使用 CLI 验收 Guard API 和导出数据：

```bash
uv run agentguardctl health --check-db
uv run agentguardctl audit export --limit 10
uv run agentguardctl metrics --json
uv run agentguardctl trace get <trace_id> --provenance
uv run agentguardctl openclaw verify
uv run agentguardctl eval run --help
```

需要鉴权的命令读取 `AGENTGUARD_CONTROL_TOKEN`。CLI 默认连接 `AGENTGUARD_API_URL`，未设置时使用 `http://${AGENTGUARD_HOST:-127.0.0.1}:${AGENTGUARD_PORT:-8088}`。

## Mock 模式

Mock 模式只需启动 Dashboard，不需要 PostgreSQL、Guard API、launch code 或 browser session：

```bash
pnpm dashboard:dev:mock
```

直接访问 `http://localhost:5173/`。该模式使用本地场景数据，不需要 PostgreSQL、Guard API、launch code 或 browser session。

## 开发入口

| 入口                                                                               | 说明                                              |
| ---------------------------------------------------------------------------------- | ------------------------------------------------- |
| [docs/README.md](docs/README.md)                                                   | 完整文档地图和开发阅读路径                        |
| [docs/06_delivery/deployment_install_usage.md](docs/06_delivery/deployment_install_usage.md) | 部署、安装、使用、无头 CLI 和故障排查             |
| [docs/01_overview/architecture.md](docs/01_overview/architecture.md)               | 总体架构和运行链路                                |
| [docs/02_core/interface_contract.md](docs/02_core/interface_contract.md)           | Guard API / Control Plane API、事件模型和决策契约 |
| [docs/06_delivery/implementation_plan.md](docs/06_delivery/implementation_plan.md) | P0/P1/P2 开发顺序和验收标准                       |

## 答辩入口

| 入口                                                                                                               | 说明                             |
| ------------------------------------------------------------------------------------------------------------------ | -------------------------------- |
| [docs/00_requirements/requirement_traceability_matrix.md](docs/00_requirements/requirement_traceability_matrix.md) | 命题要求到模块和证据的追踪矩阵   |
| [docs/05_redteam/attackbench.md](docs/05_redteam/attackbench.md)                                                   | 攻击样本、评测指标和 runner 设计 |
| [docs/06_delivery/demo_script.md](docs/06_delivery/demo_script.md)                                                 | 防御前后对比演示脚本             |

## 最小闭环

```text
AttackCase
→ LangGraph Agent
→ Runtime Adapter
→ Guard API / Control Plane
→ agentguard-core.evaluate(...)
→ GuardDecision
→ Control Plane state services
→ Dashboard
```
