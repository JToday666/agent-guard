# AgentGuard

AgentGuard 是面向大模型智能体的运行时行为监督、攻击检测与审计系统。它不替代基础模型或 Agent 框架，而是在智能体准备执行外部动作时，将工具调用、消息发送、模型输入输出、工具结果和记忆写入等行为转换为统一安全事件，并在副作用发生前完成判定、阻断、审批和留证。

Productization Alpha 已完成并构成当前已验证的产品基线。后续开发按根目录 Roadmap 中人工维护的能力节点与硬依赖路线推进；Roadmap 记录开发方向，不替代契约、状态证据或发布结论。贡献范围与当前限制以贡献规范为准。历史竞赛与答辩材料不是默认产品入口，也不能替代当前验收。开始使用或参与开发前请阅读：

- [能力与依赖路线图](ROADMAP.md)
- [Productization Alpha Status](docs/06_delivery/productization_alpha_status.md)
- [安装、升级和故障排查](docs/06_delivery/install_upgrade_troubleshooting.md)
- [产品化架构与目录职责](docs/01_overview/productization_architecture.md)
- [兼容矩阵](docs/06_delivery/compatibility_matrix.md)
- [贡献规范](CONTRIBUTING.md)

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
- OpenClaw 插件：hook-only security plugin，默认注册 24 个 hook；明确 fail-closed 的有效阶段仅为 `before_tool_call`、`before_install`、`before_agent_run`、`before_agent_finalize`、`tool_result_persist`、`before_message_write`。观察型 hook 不阻断；`message_sending` 会把插件内 Guard API 错误映射为 cancel，但宿主未捕获异常/timeout 仍是已知 fail-open 边界。

## 数据集规模

当前仓库内 `attack_cases` 目录共 70 条 AttackCase JSONL，并由
`dataset_manifest.json` 固定文件摘要、分类数量和聚合摘要：

| 数据集 | 用例数 |
| ------ | -----: |
| `agent_abuse.jsonl` | 10 |
| `benign.jsonl` | 10 |
| `file_exfiltration.jsonl` | 10 |
| `jailbreak.jsonl` | 10 |
| `memory_poisoning.jsonl` | 10 |
| `prompt_injection.jsonl` | 10 |
| `tool_hijacking.jsonl` | 10 |
| 合计 | 70 |

样本覆盖 `prompt_injection`、`jailbreak`、`tool_hijacking`、`memory_poisoning`、`file_exfiltration`、`agent_abuse` 和 `benign`。PoisonedRAG、MCP Safety 和 Instrumentation 资源属于独立专项资源，不计入上述 70 条。

## 环境准备

要求：

- Python 3.12，使用 `uv` 管理依赖和命令；更高版本尚未进入正式 CI 矩阵。
- Node 24.18.0 和 pnpm 11.9.0。
- PostgreSQL，用于 Guard API、审计、审批和指标存储。
- 可选：OpenClaw 2026.6.6 或 2026.7.1-2，用于 runtime plugin 验证；Strong Approval Binding 的宿主能力限制仍保留。

首次在仓库根目录准备依赖：

```bash
uv sync --locked --all-groups
pnpm install --frozen-lockfile
cp .env.example .env
```

`.env` 只用于本机，不得提交真实数据库密码、adapter token、control token、launch code、CSRF token 或 browser session。默认配置使用本地 PostgreSQL；联调前应确认 `AGENTGUARD_DATABASE_URL` 和 `AGENTGUARD_TEST_DATABASE_URL` 分别指向已存在的开发库和独立测试库。

开发环境可以不启用外部审计检查点；`production` 或非 loopback 监听必须同时配置绝对路径 `AGENTGUARD_AUDIT_CHECKPOINT_PATH`、至少 32 字节的 base64url 密钥 `AGENTGUARD_AUDIT_CHECKPOINT_KEY` 和非秘密标识 `AGENTGUARD_AUDIT_CHECKPOINT_KEY_ID`。检查点应写入 PostgreSQL 之外、由部署侧保护的持久卷；完整配置和轮换步骤见[部署、安装与使用说明](docs/06_delivery/deployment_install_usage.md)。

## 质量门禁

CI 配置将 Python 测试划分为 `unit`、`contract`、`integration`、`postgres`、`e2e`，并为 PostgreSQL 16 migration/tests、Dashboard build 和 Playwright Chromium E2E 定义独立 job；`live` 只允许手动 opt-in。新增配置只有在目标 GitHub Actions 对最终提交实际通过后才构成验证证据，不能从本文或 workflow 文件反推为已经通过。当前核验结果记录在 [Productization Alpha Status](docs/06_delivery/productization_alpha_status.md)。本地可分别运行：

```bash
uv run ruff check apps packages scripts tests examples conftest.py \
  agentguard_langgraph_bench/bench/tests/conftest.py
uv run pyright
uv run pytest -q -m unit
uv run pytest -q -m contract
uv run pytest -q -m integration
uv run pytest -q -m e2e
# 设置独立的 AGENTGUARD_TEST_DATABASE_URL 后：
uv run pytest -q -m postgres
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

## 推荐产品验收顺序

1. 先运行 `examples/` 中的 benign/blocked Core 示例，确认干净 clone 基线。
2. 启动 Guard API 和 Dashboard，使用 launch code 登录真实 API 模式。
3. 在 Dashboard 总览页确认健康状态、审计链、规则命中和指标。
4. 运行一个 benign 和一个攻击样本，验证工具执行前决策与 runtime receipt 分开留证。
5. 在调查页查看命中规则、资源目标、风险原因和 Trace ID。
6. 进入证据链页查看事件时间线、provenance graph 和审计完整性。
7. 按需运行 OpenClaw E2E 或 AttackBench；Mock/stub/沙箱结果必须按其真实模式标注。

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
examples/              # 干净 clone 可运行的最小示例
scripts/               # OpenClaw 和 LangGraph 辅助脚本
tests/                 # 根项目测试
docs/archive/          # 历史竞赛、答辩与演示证据；非产品入口
```

## 历史材料与当前状态

2026 年竞赛与答辩阶段的受审查材料位于 [`docs/archive/competition-2026/`](docs/archive/competition-2026/README.md)。其中部分历史运行依赖当时的 ignored staging 和临时输出，只用于追溯，不是干净 clone 复现说明、正式效果结论或生产就绪证据。Productization Alpha 的里程碑能力、限制和门禁快照以 [Productization Alpha Status](docs/06_delivery/productization_alpha_status.md) 为准；当前开发路线见 [Roadmap](ROADMAP.md)，贡献限制见 [CONTRIBUTING.md](CONTRIBUTING.md)。
