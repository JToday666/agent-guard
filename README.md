# AgentGuard

AgentGuard 是面向大模型智能体的运行时行为监督、攻击检测与审计系统。它不替代基础模型或 Agent 框架，而是在智能体准备执行外部动作时，将工具调用、消息发送、模型输入输出、工具结果和记忆写入等行为转换为统一安全事件，并在副作用发生前完成判定、阻断、审批和留证。

本仓库可作为竞赛材料提交：代码、可执行入口、Dashboard、OpenClaw 插件、LangGraph 评测靶场和必要说明均在仓库内。若提交压缩包时移除顶层历史文档目录、报告目录和单独风险报告，评委仍可通过本文件、部署说明和各包 README 理解与运行项目。

## 核心架构

AgentGuard 采用四层结构：

| 层级 | 主要目录 | 职责 |
| ---- | -------- | ---- |
| Runtime Adapter | `packages/agentguard-langgraph-adapter/`、`packages/agentguard-openclaw-plugin/`、`agentguard_langgraph_bench/adapters/` | 接入 LangGraph、OpenClaw 或外部 Agent，把运行时行为映射为 GuardEvent，并执行 `allow`、`deny`、`ask` 决策。 |
| Guard API / Control Plane | `apps/guard-api/` | 提供 HTTP 入口、鉴权、策略快照、审计入库、审批、指标、Trace、插件状态和 Dashboard 查询接口。 |
| agentguard-core | `packages/agentguard-core/` | 无状态安全判定内核，负责事件规范化、检测器、策略匹配、风险评分和 GuardDecision 输出。 |
| Dashboard / Evaluation | `apps/dashboard/`、`agentguard_langgraph_bench/bench/` | 展示审计、审批、证据链、评测指标，并运行 AttackBench 风格攻击样本。 |

最小闭环：

```text
AttackCase
-> Runtime Adapter
-> Guard API / Control Plane
-> agentguard-core.evaluate(...)
-> GuardDecision
-> AuditEvent / Approval / Trace
-> Dashboard / CLI / Evaluation report
```

## 已实现能力

- 工具执行前拦截：文件读写、邮件外发、API 调用、代码执行、MCP 工具调用、消息发送和记忆写入等行为进入统一判定链路。
- 三态决策：`allow` 直接放行，`deny` 阻断副作用，`ask` 进入人工审批或受限自动审批。
- 可解释检测：覆盖敏感资源、外发泄露、工具画像不一致、任务偏离、危险命令、提示注入、模型输出泄露、环境污染、记忆污染和凭证风险。
- 审计证据：Guard API 记录 AuditEvent、决策原因、规则命中、风险分、Trace ID、RFC 8785 审计哈希链、数据库外签名检查点和 provenance graph。
- Dashboard：提供总览、调查、证据链、审批、评测和系统状态页面。
- 评测靶场：内置 LangGraph demo agent、OpenClaw 外部 Agent 适配、Mock Tools、浏览器和 MCP/RAG 沙箱。
- OpenClaw 插件：hook-only security plugin，默认注册 23 个 hook；模型输入使用正式 `before_agent_run` gate，关键执行和持久化边界固定 fail closed。

## 数据集规模

当前仓库内 `attack_cases` 目录共 60 条 AttackCase JSONL：

| 数据集 | 用例数 |
| ------ | -----: |
| `agent_abuse.jsonl` | 10 |
| `benign.jsonl` | 10 |
| `file_exfiltration.jsonl` | 10 |
| `memory_poisoning.jsonl` | 10 |
| `prompt_injection.jsonl` | 10 |
| `tool_hijacking.jsonl` | 10 |
| 合计 | 60 |

样本覆盖 `prompt_injection`、`tool_hijacking`、`memory_poisoning`、`file_exfiltration`、`agent_abuse` 和 `benign`。PoisonedRAG、MCP Safety 和 Instrumentation 资源属于独立专项资源，不计入上述 60 条。

## 环境准备

要求：

- Python 3.12 或更新版本，使用 `uv` 管理依赖和命令。
- Node 24.18.0 和 pnpm 11.9.0。
- PostgreSQL，用于 Guard API、审计、审批和指标存储。
- 可选：OpenClaw 2026.6.6，用于真实 runtime plugin 验证。

首次在仓库根目录准备依赖：

```bash
uv sync
pnpm install
cp .env.example .env
```

`.env` 只用于本机，不得提交真实数据库密码、adapter token、control token、launch code、CSRF token 或 browser session。默认示例使用本地 PostgreSQL；正式演示前应确认 `AGENTGUARD_DATABASE_URL` 和 `AGENTGUARD_TEST_DATABASE_URL` 指向已存在的独立数据库。

开发环境可以不启用外部审计检查点；`production` 或非 loopback 监听必须同时配置绝对路径 `AGENTGUARD_AUDIT_CHECKPOINT_PATH`、至少 32 字节的 base64url 密钥 `AGENTGUARD_AUDIT_CHECKPOINT_KEY` 和非秘密标识 `AGENTGUARD_AUDIT_CHECKPOINT_KEY_ID`。检查点应写入 PostgreSQL 之外、由部署侧保护的持久卷；完整配置和轮换步骤见[部署、安装与使用说明](docs/06_delivery/deployment_install_usage.md)。

## 质量门禁

GitHub CI 会在面向 `dev`、`main` 的 push 和 pull request 上执行 Python lint、类型检查、根测试、LangGraph Adapter 测试与 PostgreSQL migration 测试，并执行 Dashboard 静态检查、单元测试、构建、Chromium 浏览器 E2E、OpenClaw 插件、bench tools 和本地 shim 检查。本地可分别运行：

```bash
uv run ruff check apps packages scripts tests
uv run pyright
uv run pytest -q tests packages/agentguard-langgraph-adapter/tests
pnpm --filter @agentguard/dashboard check
pnpm --filter @agentguard/dashboard test:e2e
pnpm --filter @agentguard/dashboard test:e2e:api
pnpm --filter @agentguard-ai/openclaw-plugin test
pnpm --filter @agentguard/openclaw-bench-tools test
pnpm openclaw:bench-shim:test
```

## 本地真实 API 模式

第一个终端启动 Guard API：

```bash
pnpm guard-api:dev
```

首次接入某个运行时，在加载 `.env` 后签发与其身份绑定的凭证；完整 token 只显示一次，把它配置到对应 Adapter 的 `AGENTGUARD_ADAPTER_TOKEN`，不要配置成 Guard API 的静态密码：

```bash
set -a
. ./.env
set +a
uv run agentguardctl credential issue --runtime openclaw --agent-id main
```

第二个终端启动 Dashboard：

```bash
pnpm dashboard:dev
```

第三个终端加载 `.env` 并创建一次性 Dashboard 登录地址：

```bash
set -a
. ./.env
set +a
uv run agentguardctl launch
```

命令输出形如 `http://localhost:5173/?launch_code=lc_xxx` 的地址。将该地址粘贴到浏览器后，Dashboard 会换取 HttpOnly browser session 并移除地址栏中的 code。launch code 只能使用一次；换浏览器、换浏览器配置文件或超时后需要重新生成。浏览器侧始终使用 `localhost:5173`，不要与 `127.0.0.1:5173` 混用。

## Mock 模式

只查看前端和演示页面时，可不启动 PostgreSQL 和 Guard API：

```bash
pnpm dashboard:dev:mock
```

打开终端输出的地址，默认是 `http://localhost:5173/`。Mock 模式使用本地场景数据，不建立 browser session，也不会自动切换到真实 API。

## CLI 验收入口

加载 `.env` 后可用 CLI 做无头验收：

```bash
uv run agentguardctl health --check-db
uv run agentguardctl audit export --limit 10
uv run agentguardctl metrics \
  --evaluated-from 2026-08-01T00:00:00Z \
  --evaluated-to 2026-08-02T00:00:00Z \
  --json
uv run agentguardctl trace get <trace_id> --provenance
uv run agentguardctl credential list
uv run agentguardctl credential issue --runtime openclaw --agent-id main
uv run agentguardctl credential revoke <credential_id>
uv run agentguardctl openclaw verify
uv run agentguardctl eval import --help
```

需要鉴权的命令读取 `AGENTGUARD_CONTROL_TOKEN`。CLI 默认连接 `AGENTGUARD_API_URL`；未设置时使用 `AGENTGUARD_HOST` 和 `AGENTGUARD_PORT`。

## OpenClaw 验证入口

开发安装、验证和卸载 OpenClaw 插件：

```bash
pnpm openclaw:plugin:install
pnpm openclaw:plugin:verify
pnpm openclaw:plugin:e2e
pnpm openclaw:plugin:reliability
pnpm openclaw:plugin:uninstall
```

E2E 和 reliability 报告写入系统临时目录下的 `agentguard-openclaw-*.json` 与 `agentguard-openclaw-*.md`。插件的详细配置见 `packages/agentguard-openclaw-plugin/README.md`。

## 靶场入口

LangGraph / AttackBench 靶场可直接通过 runner 或 CLI 使用。常用入口：

```bash
uv run agentguardctl eval import --help
uv run python -m agentguard_langgraph_bench.bench.cli --dataset agentguard_langgraph_bench/bench/datasets/attack_cases --defense off
uv run python -m agentguard_langgraph_bench.bench.cli --dataset agentguard_langgraph_bench/bench/datasets/attack_cases --defense on --fake-core
```

`--fake-core` 只用于验证 runner、沙箱和指标链路；真实防护效果应通过 Guard API 和当前策略链路验证。

## 推荐演示顺序

1. 启动 Guard API 和 Dashboard，使用 launch code 登录真实 API 模式。
2. 在 Dashboard 总览页确认健康状态、审计链、规则命中和指标。
3. 运行一个攻击样本，展示工具执行前被阻断或进入审批。
4. 在调查页查看命中规则、资源目标、风险原因和 Trace ID。
5. 进入证据链页查看事件时间线、provenance graph 和审计完整性。
6. 运行 OpenClaw E2E 或 AttackBench runner，展示跨运行时接入与批量评测能力。

## 目录速览

```text
apps/
  cli/                 # agentguardctl
  guard-api/           # FastAPI Control Plane
  dashboard/           # Vue Dashboard
packages/
  agentguard-core/     # 无状态安全判定库
  agentguard-langgraph-adapter/
  agentguard-openclaw-plugin/
benchmarks/
  openclaw-bench-tools/
agentguard_langgraph_bench/
  bench/               # AttackCase、runner、沙箱、Mock Tools
  adapter/             # 兼容导入路径
  adapters/            # 外部 Agent adapter
  demo_agent/          # LangGraph demo agent
schemas/               # GuardEvent、GuardDecision、AuditEvent JSON Schema
scripts/               # OpenClaw 和 LangGraph 辅助脚本
tests/                 # 根项目测试
```

## 提交包说明

竞赛提交包建议保留本仓库源码、可执行入口、靶场数据、插件包、Dashboard 和本文件。顶层历史文档目录、报告目录和单独风险分析报告可作为论文或答辩材料单独提交，不需要放入可执行靶场压缩包。
