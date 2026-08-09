# OpenClaw Security Plugin

## 1. 文档定位

当前仓库已有真实 OpenClaw 插件包：

```text
packages/agentguard-openclaw-plugin/
```

它不是 `agentguard_langgraph_bench/adapters/openclaw/` 的 AttackBench 外部 adapter。当前范围是 OpenClaw runtime 插件：P1 注册 `before_tool_call`、`message_sending`、`before_prompt_build` 和 `llm_input` 执行型阻断面，把事件映射成 `GuardEvent(schema_version="0.3", runtime="openclaw")`，调用 Guard API，并按 `GuardDecision` 放行、阻断或等待审批；`llm_output` 与 `before_agent_finalize` 串联为最终输出 revise 面。P2 增加 `before_install` 配置审计、`tool_result_persist` 工具结果隔离，以及 session/gateway/model/subagent/cron/exec-env 观察型审计。

关联入口：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [Dashboard 与审批流](../04_apps/dashboard_design.md)
- [OpenClaw 插件部署、安装与配置](openclaw_plugin_deployment.md)
- [演示脚本](../06_delivery/demo_script.md)

## 2. 当前实现

```text
packages/agentguard-openclaw-plugin/
├── package.json
├── openclaw.plugin.json
├── README.md
├── src/
│   ├── guard-api-client.ts
│   ├── index.ts
│   ├── mapping/
│   └── types.ts
└── test/
    ├── client.test.mjs
    ├── mapping.test.mjs
    ├── p2.test.mjs
    └── plugin-entry.test.mjs
```

包名为 `@agentguard-ai/openclaw-plugin`，OpenClaw manifest id 为 `agentguard-security`。入口是 `dist/index.js`，通过 `openclaw/plugin-sdk/plugin-entry` 的 `definePluginEntry` 注册 typed hooks。

## 3. 配置

`openclaw.plugin.json` 暴露以下配置：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `guardApiBaseUrl` | `http://127.0.0.1:8088` | Guard API base URL |
| `adapterToken` | 空 | 可由 OpenClaw 插件配置提供 |
| `requestTimeoutMs` | `5000` | 单次 Guard API 请求超时 |
| `approvalPollIntervalMs` | `1000` | 审批轮询间隔 |
| `approvalTimeoutMs` | `120000` | 审批总等待超时 |

`adapterToken` 也可从 `AGENTGUARD_ADAPTER_TOKEN` 读取。token 只进入 HTTP `Authorization` header，不写入 GuardEvent、metadata、审计内容、错误消息或日志。

本机开发安装、OpenClaw profile patch、persisted plugin registry refresh、Gateway restart 和卸载流程见 [OpenClaw 插件部署、安装与配置](openclaw_plugin_deployment.md)。

## 4. Hook 状态

| Hook | 状态 | 行为 |
| --- | --- | --- |
| `before_tool_call` | 已实现并通过本机 OpenClaw runtime 验证 | 映射为 `tool_call_proposed`；`allow` 放行，`deny` block，`ask` 等待 Guard approval |
| `message_sending` | 已实现并通过本机 OpenClaw runtime 验证 | 映射为 `message_send_proposed`；`allow` 放行，`deny`/拒绝/超时 cancel |
| `before_prompt_build` | 已实现，需运行本机 OpenClaw hook 复验 | 映射为 `context_assembled`；`allow` 放行，`deny`/未批准 `ask` block；Guard API 失败按默认 fail-closed block |
| `llm_input` | 已实现，需运行本机 OpenClaw hook 复验 | 映射为 `model_input_prepared`；`allow` 放行，`deny`/未批准 `ask` block；Guard API 失败按默认 fail-closed block |
| `llm_output` / `before_agent_finalize` | 已实现，需运行本机 OpenClaw hook 复验 | 映射为 `model_output_produced`；最终输出命中 `deny`/未批准 `ask` 或本地凭据检测时要求 runtime revise |
| `before_install` | 已实现，需运行本机 OpenClaw install 验证 | 调用 Guard API config audit；high/critical 阻断安装；Guard API 失败 fail-closed |
| `tool_result_persist` | 已实现，需运行本机 OpenClaw hook 验证 | 映射为 `tool_result_produced`；`deny`/未批准 `ask` 不持久化原文，返回安全占位；本地凭据和持久化指令仍会同步清洗 |
| `gateway_start` / `gateway_stop` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，写 `AuditEvent(event_type=runtime_observation, runtime=openclaw)`；失败 fail-open |
| `session_start` / `session_end` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录会话边界 |
| `before_compaction` / `after_compaction` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录压缩前后事件 |
| `subagent_spawned` / `subagent_ended` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录多 agent lineage |
| `model_call_started` / `model_call_ended` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录模型调用遥测 |
| `cron_changed` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录自动化任务变更 |
| `resolve_exec_env` | 已实现，需运行本机 OpenClaw runtime 验证 | 仅审计 exec env 风险；不注入敏感环境变量；Guard API 失败时不新增 env 变更 |

## 5. 事件映射

`before_tool_call` 使用 OpenClaw 的 `toolName`、`params`、`toolKind`、`toolInputKind`、`toolCallId`、`runId` 构造 `tool_call_proposed`。`derivedPaths` 只作为 best-effort 资源提示，不作为唯一安全解析依据。

`message_sending` 使用 `to`、`content`、`channelId`、`sessionKey`、`messageId` 构造 `message_send_proposed`。该 hook 不强依赖 `runId`，优先用 `sessionKey` 关联 trace。

`tool_result_persist` 使用工具名、调用 id、结果内容预览、content type、是否进入上下文和是否持久化构造 `tool_result_produced`。该 hook 是工具结果进入持久化上下文前的隔离面；Guard API 返回 `deny` 或未批准 `ask` 时，插件返回安全占位消息，不让原始工具结果持久化。

`before_prompt_build` 使用 prompt、session messages 和 source trust 构造 `context_assembled`。`llm_input` / `llm_output` 使用 prompt/output preview、provider、model 和 tool plan 构造模型输入/输出事件。`before_prompt_build` 与 `llm_input` 是前置阻断面；`llm_output` 的最终发送控制由 `before_agent_finalize` revise 承接。非 bundled 插件要启用 `llm_input` / `llm_output`，OpenClaw config 必须为 `agentguard-security` 设置 `hooks.allowConversationAccess=true`。

`before_install` 构造 `ConfigAuditEvent(runtime="openclaw")`，当前会识别 `allowConversationAccess`、`allowPromptInjection` 和 exec-like 权限等高风险配置。`high`/`critical` findings 会返回 block。

P2 observation hooks 构造 `AuditEvent(event_type="runtime_observation", runtime="openclaw")` 并写入 `/v1/audit/events`；metadata 会递归脱敏 token/secret/password/authorization/credential 字段。

## 6. 决策映射

| GuardDecision / Approval | OpenClaw 行为 |
| --- | --- |
| `allow` | 放行，返回 `undefined` |
| `deny` | 工具调用、prompt build、model input 返回 `block`；消息发送返回 `cancel`；工具结果和最终输出返回安全替代或 revise |
| `ask` + `allow_once` | 插件轮询 Guard API approval wait 后放行 |
| `ask` + `deny` / `timeout` / `error` | fail-closed：工具 block，消息 cancel |

P1 审批真源是 AgentGuard Guard API / Dashboard。OpenClaw `requireApproval` 不作为 P1 审批权威源。

默认 fail-closed stages 包含 `before_tool_call`、`message_sending`、`before_install`、`before_prompt_build` 和 `llm_input`。Guard API evaluate 失败、请求超时、approval wait 超时或失败时，这些执行前面固定 fail-closed。

## 7. 鉴权边界

OpenClaw 插件以 adapter token 调用 Guard API：

```http
Authorization: Bearer <AGENTGUARD_ADAPTER_TOKEN>
```

adapter token 的最小 scopes：

```text
event:evaluate
event:audit:write
approval:wait
adapter:status:write
```

该 token 必须由 `agentguardctl credential issue --runtime openclaw --agent-id main` 签发；Guard API 不接受 `.env` 中任意填写的未注册静态 token。OpenClaw 插件不拥有 `approval:resolve`，不创建 browser session，不读取 Dashboard 数据。

## 8. 本机验收记录

代码验证：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
uv run pytest \
  tests/test_guard_api.py::test_ask_approval_resolve_and_wait_flow \
  tests/test_guard_api.py::test_guard_evaluate_writes_dashboard_audit_and_metrics \
  tests/test_guard_api.py::test_p1_message_send_approval_can_resolve_and_wait \
  tests/test_guard_api.py::test_audit_events_plural_write_and_filter_for_dashboard -q
```

OpenClaw 2026.6.6 验证：

```bash
pnpm openclaw:plugin:install
pnpm openclaw:plugin:verify
```

`inspect --runtime --json` 验证结果包含：

```json
{
  "plugin": { "id": "agentguard-security", "status": "loaded", "hookCount": 22 },
  "shape": "hook-only",
  "typedHooks": [
    { "name": "before_tool_call", "priority": 100 },
    { "name": "message_sending", "priority": 100 },
    { "name": "before_install", "priority": 100 },
    { "name": "message_received", "priority": 0 },
    { "name": "before_prompt_build", "priority": 0 },
    { "name": "llm_input", "priority": 0 },
    { "name": "llm_output", "priority": 0 },
    { "name": "tool_result_persist", "priority": 0 },
    { "name": "before_message_write", "priority": 100 },
    { "name": "before_agent_finalize", "priority": 100 },
    { "name": "gateway_start", "priority": 0 },
    { "name": "gateway_stop", "priority": 0 },
    { "name": "session_start", "priority": 0 },
    { "name": "session_end", "priority": 0 },
    { "name": "before_compaction", "priority": 0 },
    { "name": "after_compaction", "priority": 0 },
    { "name": "subagent_spawned", "priority": 0 },
    { "name": "subagent_ended", "priority": 0 },
    { "name": "model_call_started", "priority": 0 },
    { "name": "model_call_ended", "priority": 0 },
    { "name": "cron_changed", "priority": 0 },
    { "name": "resolve_exec_env", "priority": 0 }
  ]
}
```

Gateway 重启后日志包含 `http server listening (14 plugins: agentguard-security, ...)`，说明本机长驻 OpenClaw gateway 已加载该插件。

### 部署安装入口

本机安装、配置、验证、卸载、回滚和故障排查步骤统一维护在 [OpenClaw 插件部署、安装与配置](openclaw_plugin_deployment.md)。设计文档只保留 hook-only 插件的行为契约和验收摘要，避免安装流程重复分散。

OpenClaw 2026.6.6 的 `openclaw plugins validate --root ... --entry ...` 面向 simple tool plugin；当前插件是 hook-only `definePluginEntry`，真实验证以 `pnpm openclaw:plugin:verify`、runtime inspect、Gateway status 和 hook runner/E2E 结果为准。

### 本机 live API 验收摘要

已通过本机 OpenClaw runtime hook runner 触发 `before_tool_call`、`message_sending`、`before_install` 和 `tool_result_persist`，并通过 Guard API 查询 audit、integrity 和 provenance 证据。详细复查入口和操作命令见 [部署文档](openclaw_plugin_deployment.md) 与 E2E 报告。

## 9. 当前限制

- 本仓库 pnpm workspace 包目录内可能有 `node_modules` symlink。直接 `openclaw plugins install -l packages/agentguard-openclaw-plugin` 会被 OpenClaw install safety scan 拦截。正式开发安装使用不含 `node_modules` 的 `.openclaw-dev/agentguard-security` staging 目录，流程见 [部署文档](openclaw_plugin_deployment.md)。
- 当前仍不实现消息改写、参数改写、prompt/model 内容改写、OpenClaw 原生 `requireApproval` 审批 UI 接管。
- 本机 OpenClaw 持久配置通过 `pnpm openclaw:plugin:install` 启用 `agentguard-security` 并指向 `.openclaw-dev/agentguard-security`；正式联调时需在 `.env` 中提供真实 `AGENTGUARD_ADAPTER_TOKEN`。

## 10. E2E 验收报告

最近一次本机真实 E2E 验收报告保存在：

```text
<系统临时目录>/agentguard-openclaw-e2e-acceptance-report.md
```

该验收使用 OpenClaw 2026.6.6、Guard API、独立 PostgreSQL 测试库和确定性 hook runner，覆盖 `before_tool_call`、`message_sending`、`before_prompt_build`、`llm_input`、`llm_output`、`before_install`、`tool_result_persist`、audit integrity 和 provenance。
