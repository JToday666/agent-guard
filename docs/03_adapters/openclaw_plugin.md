# OpenClaw Security Plugin

## 1. 文档定位

当前仓库已有真实 OpenClaw 插件包：

```text
packages/agentguard-openclaw-plugin/
```

它不是 `agentguard_langgraph_bench/adapters/openclaw/` 的 AttackBench 外部 adapter。当前范围是 OpenClaw runtime 插件：P1 注册 `before_tool_call` 和 `message_sending` 执行前阻断面，把事件映射成 `GuardEvent(schema_version="0.3", runtime="openclaw")`，调用 Guard API，并按 `GuardDecision` 放行、阻断或等待审批；P2 增加 `before_install` 配置审计、`tool_result_persist` 工具结果事件，以及 session/gateway/model/subagent/cron/exec-env 观察型审计。

关联入口：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [Dashboard 与审批流](../04_apps/dashboard_design.md)
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
│   ├── mapping.ts
│   └── types.ts
└── test/
    ├── client.test.mjs
    ├── mapping.test.mjs
    ├── p2.test.mjs
    └── plugin-entry.test.mjs
```

包名为 `@agentguard/openclaw-plugin`，OpenClaw manifest id 为 `agentguard-security`。入口是 `dist/index.js`，通过 `openclaw/plugin-sdk/plugin-entry` 的 `definePluginEntry` 注册 typed hooks。

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

## 4. Hook 状态

| Hook | 状态 | 行为 |
| --- | --- | --- |
| `before_tool_call` | 已实现并通过本机 OpenClaw runtime 验证 | 映射为 `tool_call_proposed`；`allow` 放行，`deny` block，`ask` 等待 Guard approval |
| `message_sending` | 已实现并通过本机 OpenClaw runtime 验证 | 映射为 `message_send_proposed`；`allow` 放行，`deny`/拒绝/超时 cancel |
| `before_install` | 已实现，需运行本机 OpenClaw install 验证 | 调用 Guard API config audit；high/critical 阻断安装；Guard API 失败 fail-closed |
| `tool_result_persist` | 已实现，需运行本机 OpenClaw hook 验证 | 映射为 `tool_result_produced`，调用 Guard evaluate 写审计/provenance；失败 fail-open |
| `gateway_start` / `gateway_stop` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，写 `AuditEvent(event_type=runtime_observation, runtime=openclaw)`；失败 fail-open |
| `session_start` / `session_end` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录会话边界 |
| `before_compaction` / `after_compaction` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录压缩前后事件 |
| `subagent_spawned` / `subagent_ended` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录多 agent lineage |
| `model_call_started` / `model_call_ended` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录模型调用遥测 |
| `cron_changed` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录自动化任务变更 |
| `resolve_exec_env` | 已实现，需运行本机 OpenClaw runtime 验证 | 仅审计 exec env 风险；不注入敏感环境变量；Guard API 失败时不新增 env 变更 |
| `before_prompt_build` / `llm_input` / `llm_output` | 未纳入本轮 | 需要 conversation access 配置和内容脱敏策略后再验证 |

## 5. 事件映射

`before_tool_call` 使用 OpenClaw 的 `toolName`、`params`、`toolKind`、`toolInputKind`、`toolCallId`、`runId` 构造 `tool_call_proposed`。`derivedPaths` 只作为 best-effort 资源提示，不作为唯一安全解析依据。

`message_sending` 使用 `to`、`content`、`channelId`、`sessionKey`、`messageId` 构造 `message_send_proposed`。该 hook 不强依赖 `runId`，优先用 `sessionKey` 关联 trace。

`tool_result_persist` 使用工具名、调用 id、结果内容预览、content type、是否进入上下文和是否持久化构造 `tool_result_produced`。该 hook 不作为阻断面；Guard API 失败时不影响 OpenClaw 持久化路径。

`before_install` 构造 `ConfigAuditEvent(runtime="openclaw")`，当前会识别 `allowConversationAccess`、`allowPromptInjection` 和 exec-like 权限等高风险配置。`high`/`critical` findings 会返回 block。

P2 observation hooks 构造 `AuditEvent(event_type="runtime_observation", runtime="openclaw")` 并写入 `/v1/audit/events`；metadata 会递归脱敏 token/secret/password/authorization/credential 字段。

## 6. 决策映射

| GuardDecision / Approval | OpenClaw 行为 |
| --- | --- |
| `allow` | 放行，返回 `undefined` |
| `deny` | 工具调用返回 `block`；消息发送返回 `cancel` |
| `ask` + `allow_once` | 插件轮询 Guard API approval wait 后放行 |
| `ask` + `deny` / `timeout` / `error` | fail-closed：工具 block，消息 cancel |

P1 审批真源是 AgentGuard Guard API / Dashboard。OpenClaw `requireApproval` 不作为 P1 审批权威源。

Guard API evaluate 失败、请求超时、approval wait 超时或失败时固定 fail-closed。

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
```

OpenClaw 插件不拥有 `approval:resolve`，不创建 browser session，不读取 Dashboard 数据。

## 8. 本机验收记录

代码验证：

```bash
pnpm --filter @agentguard/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
uv run pytest \
  tests/test_guard_api.py::test_ask_approval_resolve_and_wait_flow \
  tests/test_guard_api.py::test_guard_evaluate_writes_dashboard_audit_and_metrics \
  tests/test_guard_api.py::test_p1_message_send_approval_can_resolve_and_wait \
  tests/test_guard_api.py::test_audit_events_plural_write_and_filter_for_dashboard -q
```

OpenClaw 2026.6.6 验证：

```bash
openclaw plugins validate --root packages/agentguard-openclaw-plugin --entry dist/index.js
openclaw plugins install -l /tmp/agentguard-openclaw-plugin-install-p2
openclaw plugins inspect agentguard-security --runtime --json
openclaw plugins doctor
openclaw gateway restart --safe
openclaw gateway status
```

`inspect --runtime --json` 验证结果包含：

```json
{
  "plugin": { "id": "agentguard-security", "status": "loaded", "hookCount": 16 },
  "shape": "hook-only",
  "typedHooks": [
    { "name": "before_tool_call", "priority": 100 },
    { "name": "message_sending", "priority": 100 },
    { "name": "before_install", "priority": 100 },
    { "name": "tool_result_persist", "priority": 0 },
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

### OpenClaw validate 说明

OpenClaw 2026.6.6 的 `openclaw plugins validate --root ... --entry ...` 是 simple tool plugin 元数据验证命令，要求入口由 `defineToolPlugin` 生成 metadata。当前插件是 hook-only `definePluginEntry`，因此该命令会返回：

```text
plugin entry does not expose defineToolPlugin metadata
```

hook-only 插件的真实验证命令以 `plugins install -l`、`plugins inspect --runtime --json`、`plugins doctor`、gateway restart/status 和 hook runner 触发测试为准。

### 本机 live API 验收

启动 Guard API：

```bash
uv run uvicorn guard_api.main:app --host 127.0.0.1 --port 8088
```

通过本机 OpenClaw runtime hook runner 触发 `before_tool_call` 和 `message_sending`，插件调用真实 Guard API 后返回：

```json
{
  "toolResult": { "block": true },
  "messageResult": { "cancel": true }
}
```

随后用 Dashboard 同源 browser session 查询：

```http
GET /v1/audit/events?runtime=openclaw
GET /v1/audit/integrity
GET /v1/traces/<trace_id>/provenance
```

能看到两条 `runtime=openclaw` 审计事件：

| event_type | trace_id | decision | rule_hits |
| --- | --- | --- | --- |
| `tool_call_proposed` | `run_openclaw_live_api` | `deny` | `P001_sensitive_file_access`, `P002_tool_identity_mismatch` |
| `message_send_proposed` | `agent:main:openclaw-live-api` | `deny` | `P005_external_send` |
| `tool_result_produced` | `<run_id>` | `allow/deny` | 取决于 Core policy |
| `runtime_observation` | `<session/run id>` | `allow` | observation-only |

## 9. 当前限制

- 本仓库 pnpm workspace 包目录内有 `node_modules` symlink。直接 `openclaw plugins install -l packages/agentguard-openclaw-plugin` 会被 OpenClaw install safety scan 拦截。真实本机测试使用不含 `node_modules` 的 staging 目录 `/tmp/agentguard-openclaw-plugin-install-p2`。
- 当前仍不实现消息改写、参数改写、prompt/model content hooks、OpenClaw 原生 `requireApproval` 审批 UI 接管。
- 本机 OpenClaw 持久配置已启用 `agentguard-security` 并指向 staging 路径；正式联调时需在 OpenClaw 插件配置或进程环境中提供真实 `adapterToken`。
