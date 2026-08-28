# OpenClaw AttackBench 真实自主测试与检测启用

## 1. 目标与边界

本文说明如何让 OpenClaw 作为真实自主 Agent 执行 AttackBench case，并让 Guard API、数据库和 Dashboard 看到 OpenClaw 事件与指标。官方运行口径只有真实自主测试：shim 不向模型说明自己在运行 AttackBench，不注入 case/trace、metadata、oracle 或验证提示词。

当前小样本目标是链路稳定性，不是全量 AttackBench：

- 固定执行 `BN-001`、`BN-002`、`BN-003` 三个 benign case。
- 不修改现有 OpenClaw HTTP adapter、Guard API 后端或 Dashboard。
- Dashboard 只检查现有 10s polling 能看到 OpenClaw 事件和指标变化，不新增 case 级实时进度页。
- OpenClaw bench tools 插件只做工具桥接，不内置靶场规则，不替代 `BenchmarkToolServer` 或 `GuardedToolGateway`。
- 内部日志、结果文件和数据库仍保留 `case_id` / `trace_id`，但这些字段不能进入 OpenClaw 模型可见 prompt、工具描述、工具 observation 或 session key。

## 2. 真实执行链路

```text
agentguardctl eval run
→ existing openclaw HTTP adapter
→ OpenClaw bench shim: POST /run
→ openclaw agent --agent local-task-runner
→ agentguard-bench-tools plugin
→ BenchmarkToolServer HTTP tool endpoint
→ GuardedToolGateway
→ Guard API / agentguard-core
→ PostgreSQL audit / metrics
→ Dashboard 10s polling
```

关键点：

- runner 自动按 `--case-id` 顺序轮转 case，不需要在前端或后端手动逐个发布任务。
- 每个 case 调一次 shim 的 `POST /run`，shim 为该 case 生成独立 OpenClaw session key。
- 每个 case 开始前，shim 写入 `.openclaw-dev/bench-tools-runtime.json`，bench tools 插件据此找到当前 case 的 `tool_invocation_base_url`。
- shim 发送给 OpenClaw 的 message 只包含用户任务和明确允许给 agent 看的公共 MCP catalog；不会包含 `Case ID`、`Trace ID`、source trust/type、metadata、oracle 或完整工具 manifest。
- OpenClaw 调用的 `read_file`、`write_file`、`send_email` 等工具会转发给当前 case 的 `BenchmarkToolServer`。
- HTTP tool server 的完整事件只写入 `events()` / 结果产物；返回给 agent 的 observation 会剥离 event、audit、compatibility、case/trace 和 policy 字段。
- 开启 `--defense on` 后，工具调用经过 `GuardedToolGateway`，再进入真实 Guard API 和 `agentguard-core` 判定。

## 3. 前置条件

在仓库根目录执行所有命令。需要先完成：

- `uv sync` 和 `pnpm install`。
- 根目录 `.env` 已配置 Guard API、数据库和 token。
- PostgreSQL 可连接，且 `.env` 中的 `AGENTGUARD_DATABASE_URL` 指向本次测试数据库。
- OpenClaw 已安装，Gateway 可启动。
- `agentguard-security` OpenClaw 插件已安装或准备安装。

`.env` 至少需要：

```dotenv
AGENTGUARD_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard
AGENTGUARD_ADAPTER_TOKEN=ag_adapter_xxx
AGENTGUARD_CONTROL_TOKEN=ag_control_xxx
AGENTGUARD_HOST=127.0.0.1
AGENTGUARD_PORT=8088
```

加载 `.env` 到当前 shell：

```bash
set -a
. ./.env
set +a
```

作用：

- `set -a` 让后续从 `.env` 读取的变量自动 export 给子进程。
- `. ./.env` 在当前 shell 加载配置，不新开 shell。
- `set +a` 关闭自动 export，避免后续无关变量被意外导出。

## 4. 一次性安装与校验

先安装负责 OpenClaw runtime hook 审计和拦截的安全插件：

```bash
pnpm openclaw:plugin:install
pnpm openclaw:plugin:verify
```

命令作用：

| 命令                           | 作用                                                                                                                                                 |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm openclaw:plugin:install` | 构建 `agentguard-security`，安装到 `.openclaw-dev/agentguard-security`，写入 Guard API URL 和 adapter token，刷新 OpenClaw registry 并重启 Gateway。 |
| `pnpm openclaw:plugin:verify`  | 检查 `agentguard-security` runtime 状态、hook 数量和 Gateway 健康状态。                                                                              |

再安装 AttackBench 工具桥接插件：

```bash
pnpm openclaw:bench-tools:build
pnpm openclaw:bench-tools:install
pnpm openclaw:bench-tools:verify
```

命令作用：

| 命令                                | 作用                                                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pnpm openclaw:bench-tools:build`   | 构建 `@agentguard/openclaw-bench-tools`，并让 OpenClaw 校验插件 bundle。                                                                                     |
| `pnpm openclaw:bench-tools:install` | 重建 `.openclaw-dev/agentguard-bench-tools`，安装 `agentguard-bench-tools`，向 OpenClaw config 注册 `local-task-runner` agent，刷新 registry 并重启 Gateway。 |
| `pnpm openclaw:bench-tools:verify`  | 执行 `openclaw plugins inspect agentguard-bench-tools --runtime --json`，确认插件 `status=loaded`。                                                          |

`local-task-runner` agent 的 OpenClaw 配置会限制工具为本地任务工具 allowlist，并仅对该 agent 设置：

```json
{
  "contextInjection": "never",
  "identity": {
    "name": "Local Task Runner",
    "theme": "Local task automation"
  },
  "sandbox": { "mode": "off" },
  "tools": {
    "profile": "full",
    "allow": [
      "read_file",
      "write_file",
      "send_email",
      "call_api",
      "code_exec",
      "memory_write",
      "memory_read",
      "memory_search",
      "browser_start",
      "browser_navigate",
      "browser_input",
      "browser_click",
      "browser_extract_text",
      "browser_inspect",
      "mcp_call",
      "rag_retrieve",
      "rag_answer",
      "local_tool_call"
    ]
  }
}
```

这里设置 `profile=full` 和 `sandbox.mode=off` 的原因是 OpenClaw 默认工具 profile 或 sandbox 策略会在 agent 启动前过滤掉本地 bench 插件工具。安全控制仍由 `BenchmarkToolServer`、`GuardedToolGateway` 和 Guard API 执行。

## 5. 启动真实链路

建议使用四个终端，方便观察日志。

终端 1：启动 Guard API。

```bash
pnpm guard-api:dev
```

作用：

- 读取根目录 `.env`。
- 启动 `guard_api.main:app`。
- 默认监听 `http://127.0.0.1:8088`。
- 负责接收 `GuardedToolGateway` 和 OpenClaw security 插件写入的检测、决策、审计和指标。

终端 2：启动 Dashboard。

```bash
pnpm dashboard:dev
```

作用：

- 启动前端开发服务。
- 默认监听 `http://localhost:5173/`。
- Dashboard 使用现有 10s polling 拉取 Guard API 数据。

终端 3：确认或重启 OpenClaw Gateway。

```bash
systemctl --user restart openclaw-gateway
openclaw gateway status
```

作用：

- 让 OpenClaw runtime 重新加载插件、agent 和配置。
- `openclaw gateway status` 应显示 runtime running 和 connectivity probe ok。

终端 4：启动 bench shim。

```bash
pnpm openclaw:bench-shim -- --port 18190
```

作用：

- 启动 `GET /health` 和 `POST /run`。
- 兼容现有 `openclaw` HTTP adapter payload。
- 每次收到 `/run` 时写入当前 case runtime config。
- 调用 `openclaw agent --agent local-task-runner --json --session-key ... --message ...`。

可选参数：

| 参数                       | 作用                                                                |
| -------------------------- | ------------------------------------------------------------------- |
| `--host 127.0.0.1`         | 指定 shim 监听地址，默认 `127.0.0.1`。                              |
| `--port 18190`             | 指定 shim 监听端口，默认 `18190`。                                  |
| `--agent local-task-runner` | 指定 OpenClaw agent id。                                           |
| `--timeout 600`            | 指定单个 OpenClaw case 的超时时间，单位秒。                         |
| `--model <model>`          | 覆盖 OpenClaw 默认模型；不传则使用 OpenClaw 当前 agent/model 配置。 |
| `--runtime-config <path>`  | 覆盖 bench tools runtime config 文件路径。                          |

最小真实测试可继续使用默认超时。全量遍历时建议提高 shim 的单 case OpenClaw agent 超时时间：

```bash
pnpm openclaw:bench-shim -- --port 18190 --timeout 900
```

全量遍历命令中的 `--timeout` 应大于或等于 shim 的 `--timeout`，否则 HTTP adapter 可能先于 OpenClaw agent 返回前超时。

## 6. 打开 Dashboard

生成一次性 Dashboard 登录地址：

```bash
pnpm guard-api:launch
```

作用：

- 使用 `.env` 中的 `AGENTGUARD_CONTROL_TOKEN` 调 Guard API。
- 创建一次性 browser launch code。
- 输出完整地址，例如 `http://localhost:5173/?launch_code=...`。

把输出地址复制到浏览器。Dashboard 登录后会每 10 秒轮询 Guard API。测试过程中只要求看到 OpenClaw adapter 状态、OpenClaw audit events 和 metrics 计数变化，不要求显示每个 AttackBench case 的实时进度。

## 7. 执行最小真实测试

```bash
set -a
. ./.env
set +a

uv run agentguardctl eval run \
  --agent-adapter openclaw \
  --agent-endpoint http://127.0.0.1:18190/run \
  --tool-server-mode http \
  --tool-server-port 18090 \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/benign.jsonl \
  --case-id BN-001 \
  --case-id BN-002 \
  --case-id BN-003 \
  --defense on \
  --core-url http://127.0.0.1:8088 \
  --token "$AGENTGUARD_ADAPTER_TOKEN" \
  --core-api-mode guard-api-v0.3 \
  --runtime langgraph \
  --timeout 600
```

参数说明：

| 参数                                          | 作用                                                                                                                                                              |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--agent-adapter openclaw`                    | 让 runner 使用现有 OpenClaw HTTP adapter。                                                                                                                        |
| `--agent-endpoint http://127.0.0.1:18190/run` | 把 adapter 请求发给 bench shim。                                                                                                                                  |
| `--tool-server-mode http`                     | 为 case 工具启动 HTTP `BenchmarkToolServer`。                                                                                                                     |
| `--tool-server-port 18090`                    | HTTP tool server 的起始端口。                                                                                                                                     |
| `--dataset .../benign.jsonl`                  | 使用 benign 验证集。                                                                                                                                              |
| `--case-id BN-001`                            | 只选择指定 case；多个 `--case-id` 会按顺序轮转执行。                                                                                                              |
| `--defense on`                                | 启用 GuardedToolGateway 和真实 Guard API 检测。                                                                                                                   |
| `--core-url http://127.0.0.1:8088`            | 指向真实 Guard API。                                                                                                                                              |
| `--token "$AGENTGUARD_ADAPTER_TOKEN"`         | adapter 访问 Guard API 的 bearer token。                                                                                                                          |
| `--core-api-mode guard-api-v0.3`              | 使用当前 Guard API v0.3 事件/决策协议。                                                                                                                           |
| `--runtime langgraph`                         | 当前 `BN-001`、`BN-002`、`BN-003` 的 `runtime_targets` 是 `langgraph`，需要该参数让 runner 不过滤掉这些 case；这不改变实际 agent adapter，实际执行仍是 OpenClaw。 |
| `--timeout 600`                               | 整体评测超时时间，单位秒。                                                                                                                                        |

`guard-api-v0.3` 是 SDK 与 Bench 的默认协议。旧 Core 兼容调用必须显式传入
`--core-api-mode legacy`；legacy 仅支持旧的工具评估和单事件审计路由，不支持当前非工具
运行时事件与 Guard API 审批等待接口。legacy 将在后续发布周期继续保留，但已进入弃用窗口。

## 8. 执行全量数据集自动遍历

全量遍历使用 `attack_cases` 目录作为 dataset。runner 会自动加载该目录下所有 `*.jsonl` AttackCase，并按加载顺序自动轮转执行。本文的“全量”仅指当前仓库内：

```text
agentguard_langgraph_bench/bench/datasets/attack_cases/
```

不包含外部 raw 数据源或尚未转换为 AttackCase JSONL 的数据。

执行命令：

```bash
set -a
. ./.env
set +a

uv run agentguardctl eval run \
  --agent-adapter openclaw \
  --agent-endpoint http://127.0.0.1:18190/run \
  --tool-server-mode http \
  --tool-server-port 18090 \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --defense on \
  --core-url http://127.0.0.1:8088 \
  --token "$AGENTGUARD_ADAPTER_TOKEN" \
  --core-api-mode guard-api-v0.3 \
  --runtime langgraph \
  --strict-runtime-targets \
  --scenario-stateful \
  --timeout 900 \
  --results-dir agentguard_langgraph_bench/bench/results/openclaw_all_attack_cases
```

参数说明：

| 参数                                                               | 作用                                                                                                                                                |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--dataset agentguard_langgraph_bench/bench/datasets/attack_cases` | 使用目录输入；runner 会自动加载目录下所有 `*.jsonl`。                                                                                               |
| `--runtime langgraph`                                              | 当前全部 AttackCase 的 `runtime_targets` 是 `langgraph`，该参数用于避免被过滤；实际执行仍由 `--agent-adapter openclaw` 和 `--agent-endpoint` 决定。 |
| `--strict-runtime-targets`                                         | 如果未来有 case 不匹配当前 runtime label，直接失败，避免静默跳过。                                                                                  |
| `--scenario-stateful`                                              | 支持 memory poisoning stateful 数据集按 `metadata.scenario_id` 保留同组 memory 状态，不同 scenario 默认隔离。                                       |
| `--timeout 900`                                                    | HTTP adapter 等待 shim 响应的单 case 超时时间，单位秒；应大于或等于 bench shim 的 `--timeout`。                                                     |
| `--results-dir .../openclaw_all_attack_cases`                      | 将全量运行结果单独归档到 `agentguard_langgraph_bench/bench/results/openclaw_all_attack_cases/run_<run_id>/`。                                       |

全量验收标准：

- shim 日志中 `/run` 次数应接近全量 case 数；当前 `attack_cases` 目录合计 60 条 case，未来以实际数据集为准。
- `summary_<run_id>.json` 中 `case_count` 应等于实际加载并执行的 case 数。
- `run_valid_rate`、`invalid_case_count` 和 `artifact_integrity.ok` 是主要质量判断字段。
- 每个 case 目录仍应包含 `case_result.json`、`tool_results.jsonl`、`policy_decisions.jsonl` 和 `audit_events.jsonl`。
- `uv run agentguardctl metrics --runtime openclaw --json` 的 `event_count` 应持续增加。
- Dashboard 只检查现有 10s polling 能看到 OpenClaw audit events 和 metrics 变化，不要求 case 级进度条。

全量运行成本明显高于 3-case 最小测试。建议先完成最小真实测试，再启动全量遍历。

## 9. 如何判断任务自动轮转成功

执行期间，bench shim 日志应出现三次 `/run`。这些日志是内部观测，不会进入 OpenClaw prompt：

```text
[openclaw-bench-shim] /run case_id=BN-001 trace_id=...
[openclaw-bench-shim] /run case_id=BN-002 trace_id=...
[openclaw-bench-shim] /run case_id=BN-003 trace_id=...
```

每个 case 的 OpenClaw session key 应不同，且不包含 case id 或 trace id，格式类似：

```text
agent:local-task-runner:task:4f2c1a0d9e8b7c6a
agent:local-task-runner:task:91e03b6c2fd8a554
agent:local-task-runner:task:0de74206cd54b992
```

runner 完成后会输出一个 `run_id`，结果目录为：

```text
agentguard_langgraph_bench/bench/results/run_<run_id>/
```

应重点检查：

```text
agentguard_langgraph_bench/bench/results/run_<run_id>/summary_<run_id>.json
agentguard_langgraph_bench/bench/results/run_<run_id>/cases/BN-001/case_result.json
agentguard_langgraph_bench/bench/results/run_<run_id>/cases/BN-001/tool_results.jsonl
agentguard_langgraph_bench/bench/results/run_<run_id>/cases/BN-001/policy_decisions.jsonl
agentguard_langgraph_bench/bench/results/run_<run_id>/cases/BN-001/audit_events.jsonl
```

`BN-002` 和 `BN-003` 也应有同样结构。验收标准：

- `summary_<run_id>.json` 中 `case_count=3`。
- `summary_<run_id>.json` 中 `artifact_integrity.ok=true`。
- 三个 case 的 `benchmark_run_id` 相同。
- 每个 case 的 `tool_results.jsonl` 非空，证明 OpenClaw 真实调用了工具，不是 agent 自报。
- 每个 case 的 `policy_decisions.jsonl` 非空，证明工具调用进入了 `GuardedToolGateway` 和真实 Guard API。
- 每个 case 的 `audit_events.jsonl` 非空，证明结果证据被写入 case 产物。

OpenClaw 通过外部 HTTP adapter 执行时，runner 内部的 `llm_prompts/round_1_redacted.json` 和
`llm_responses/round_1_redacted.json` 可能不会生产；`evidence_index.json` 会把它们记录为
`not produced`。这类缺失不应影响 OpenClaw 轮转链路验收。

## 10. 后端、数据库和前端检查

检查 Guard API 和数据库：

```bash
uv run agentguardctl health --check-db
```

预期输出：

```text
Guard API: ok, database: ok
```

检查 OpenClaw 指标：

```bash
uv run agentguardctl metrics --runtime openclaw --json
```

关注：

- `event_count` 是否增加。
- `allow_count`、`deny_count`、`blocked_count` 是否符合测试情况。
- benign 小样本一般不应出现 FPR 增加。

导出 OpenClaw 审计事件：

```bash
uv run agentguardctl audit export --runtime openclaw --limit 20
```

关注：

- 是否出现 `tool_call_proposed`。
- 是否出现 `tool_result_produced`。
- 是否出现 `model_call_started` 和 `model_call_ended`。
- metadata 中是否能看到 OpenClaw model、session key、tool name 或 case id。

检查 Dashboard：

```bash
curl -fsS -I http://127.0.0.1:5173/
```

预期 HTTP 200。浏览器中等待 10 到 20 秒，OpenClaw audit events 和 metrics 计数应随后端数据变化而刷新。

## 11. 稳定性复核建议

只复核轮转稳定性时，不需要跑全量 AttackBench。建议连续执行两轮最小真实测试：

1. 每轮只跑 `BN-001`、`BN-002`、`BN-003`。
2. 每轮应生成新的 `run_<run_id>` 目录。
3. 每轮内部三个 case 的 `benchmark_run_id` 应相同。
4. 每轮 shim 都应出现三次 `/run`。
5. 每轮 session key 都应随 case 或 trace id 变化，但 key 本身不暴露原始 case 或 trace。
6. 每轮 `tool_results.jsonl` 和 `policy_decisions.jsonl` 都应非空。
7. `uv run agentguardctl metrics --runtime openclaw --json` 的 `event_count` 应比上一轮增加。
8. `summary_<run_id>.json` 的 `artifact_integrity.ok` 应为 `true`。

这能证明 runner 不是停在第一个 case，OpenClaw 能连续接收任务，工具桥接和 Guard API 检测链路能重复工作。

## 12. 常见问题

### `case_count=0`

当前三个 benign case 的 `runtime_targets` 是 `langgraph`。执行最小真实测试时必须带：

```bash
--runtime langgraph
```

这只是让 runner 不过滤 case，不会把 agent 执行改回 LangGraph；实际 agent 仍由 `--agent-adapter openclaw` 和 `--agent-endpoint http://127.0.0.1:18190/run` 决定。

### OpenClaw 报 `No callable tools remain`

重新安装 bench tools：

```bash
pnpm openclaw:bench-tools:install
pnpm openclaw:bench-tools:verify
```

该错误通常说明 OpenClaw 的工具 profile 或 sandbox 策略过滤了本地任务插件工具。安装脚本会为 `local-task-runner` 写入 `tools.profile=full`、本地任务工具 allowlist、`contextInjection=never` 和 `sandbox.mode=off`。

### shim 没有出现三次 `/run`

检查 eval 命令中的 endpoint：

```bash
--agent-endpoint http://127.0.0.1:18190/run
```

并确认 shim 正在运行：

```bash
curl -fsS http://127.0.0.1:18190/health
```

### `tool_results.jsonl` 为空

说明 OpenClaw 没有真实调用 bench 工具，或工具调用没有到达 `BenchmarkToolServer`。检查：

- `pnpm openclaw:bench-tools:verify`
- shim 日志中的 session key 和错误信息
- `uv run agentguardctl audit export --runtime openclaw --limit 20`
- OpenClaw agent 是否使用了 `local-task-runner`

### `policy_decisions.jsonl` 为空

说明工具调用没有进入 GuardedToolGateway 或 Guard API。检查：

- eval 命令是否带 `--defense on`
- `--core-url` 是否指向正在运行的 Guard API
- `--token "$AGENTGUARD_ADAPTER_TOKEN"` 是否和 `.env` 一致
- `uv run agentguardctl health --check-db`

### Dashboard 看不到新数据

先确认后端有数据：

```bash
uv run agentguardctl metrics --runtime openclaw --json
uv run agentguardctl audit export --runtime openclaw --limit 5
```

再确认前端地址使用 `pnpm guard-api:launch` 输出的 launch code。Dashboard 只做 10s polling，不会显示 case 级实时进度条。

## 13. 停止测试、服务与回滚

正常停止顺序：

1. 停止正在运行的 eval：在执行 `uv run agentguardctl eval run ...` 的终端按 `Ctrl-C`。
2. 停止 bench shim：在运行 `pnpm openclaw:bench-shim ...` 的终端按 `Ctrl-C`。
3. 停止 Dashboard：在运行 `pnpm dashboard:dev` 的终端按 `Ctrl-C`。
4. 停止 Guard API：在运行 `pnpm guard-api:dev` 的终端按 `Ctrl-C`。
5. 如需关闭 OpenClaw Gateway：

```bash
openclaw gateway stop
# 或
systemctl --user stop openclaw-gateway
```

停止状态检查：

```bash
pgrep -af 'agentguardctl eval run|openclaw-bench-shim|openclaw agent --agent local-task-runner' || true
curl -fsS http://127.0.0.1:18190/health
openclaw gateway status
curl -fsS -I http://127.0.0.1:5173/
uv run agentguardctl health --check-db
```

预期结果：

- `pgrep` 无输出表示 eval、shim、bench agent 没有遗留进程。
- shim 停止后，`curl -fsS http://127.0.0.1:18190/health` 应连接失败。
- OpenClaw Gateway 如已停止，`openclaw gateway status` 不应显示 runtime running。
- Guard API 和 Dashboard 是否停止，取决于是否已在对应终端按 `Ctrl-C`。
- PostgreSQL 通常不随测试停止；只有明确需要关闭数据库时才运行：

```bash
sudo systemctl stop postgresql@16-main
```

卸载 bench tools 插件：

```bash
pnpm openclaw:bench-tools:uninstall
```

卸载 OpenClaw security 插件：

```bash
pnpm openclaw:plugin:uninstall
```

本地 OpenClaw 开发 staging 和备份位于：

```text
.openclaw-dev/
```

该目录已被 Git 忽略。
