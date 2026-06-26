# OpenClaw Security Plugin

## 1. 文档定位

当前仓库已有真实 OpenClaw 插件包：

```text
packages/agentguard-openclaw-plugin/
```

它不是 `agentguard_langgraph_bench/adapters/openclaw/` 的 AttackBench 外部 adapter。P1 范围是 OpenClaw runtime 插件：注册 `before_tool_call` 和 `message_sending`，把事件映射成 `GuardEvent(schema_version="0.3", runtime="openclaw")`，调用 Guard API，并按 `GuardDecision` 放行、阻断或等待审批。

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

| Hook | 状态 | P1 行为 |
| --- | --- | --- |
| `before_tool_call` | 已实现并通过本机 OpenClaw runtime 验证 | 映射为 `tool_call_proposed`；`allow` 放行，`deny` block，`ask` 等待 Guard approval |
| `message_sending` | 已实现并通过本机 OpenClaw runtime 验证 | 映射为 `message_send_proposed`；`allow` 放行，`deny`/拒绝/超时 cancel |
| `before_prompt_build` | 未纳入 P1 | P2 再评估 |
| `after_tool_call` | 未纳入 P1 | P2 再评估 |
| `tool_result_persist` | 未纳入 P1 | P2 再评估 |
| `llm_input` / `llm_output` | 未纳入 P1 | 需要 conversation access 配置后再验证 |
| `before_install` / Config Audit | 未纳入 P1 | P2 |

## 5. 事件映射

`before_tool_call` 使用 OpenClaw 的 `toolName`、`params`、`toolKind`、`toolInputKind`、`toolCallId`、`runId` 构造 `tool_call_proposed`。`derivedPaths` 只作为 best-effort 资源提示，不作为唯一安全解析依据。

`message_sending` 使用 `to`、`content`、`channelId`、`sessionKey`、`messageId` 构造 `message_send_proposed`。该 hook 不强依赖 `runId`，优先用 `sessionKey` 关联 trace。

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
openclaw plugins install -l /tmp/agentguard-openclaw-plugin-install-p1
openclaw plugins inspect agentguard-security --runtime --json
openclaw plugins doctor
openclaw gateway restart --safe
openclaw gateway status
```

`inspect --runtime --json` 验证结果包含：

```json
{
  "plugin": { "id": "agentguard-security", "status": "loaded", "hookCount": 2 },
  "shape": "hook-only",
  "typedHooks": [
    { "name": "before_tool_call", "priority": 100 },
    { "name": "message_sending", "priority": 100 }
  ]
}
```

Gateway 重启后日志包含 `http server listening (14 plugins: agentguard-security, ...)`，说明本机长驻 OpenClaw gateway 已加载该插件。

### OpenClaw validate 说明

OpenClaw 2026.6.6 的 `openclaw plugins validate --root ... --entry ...` 是 simple tool plugin 元数据验证命令，要求入口由 `defineToolPlugin` 生成 metadata。当前插件是 hook-only `definePluginEntry`，因此该命令会返回：

```text
plugin entry does not expose defineToolPlugin metadata
```

P1 hook-only 插件的真实验证命令以 `plugins install -l`、`plugins inspect --runtime --json`、`plugins doctor`、gateway restart/status 和 hook runner 触发测试为准。

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
```

能看到两条 `runtime=openclaw` 审计事件：

| event_type | trace_id | decision | rule_hits |
| --- | --- | --- | --- |
| `tool_call_proposed` | `run_openclaw_live_api` | `deny` | `P001_sensitive_file_access`, `P002_tool_identity_mismatch` |
| `message_send_proposed` | `agent:main:openclaw-live-api` | `deny` | `P005_external_send` |

## 9. 当前限制

- 本仓库 pnpm workspace 包目录内有 `node_modules` symlink。直接 `openclaw plugins install -l packages/agentguard-openclaw-plugin` 会被 OpenClaw install safety scan 拦截。真实本机测试使用不含 `node_modules` 的 staging 目录 `/tmp/agentguard-openclaw-plugin-install-p1`。
- 当前 P1 不实现消息改写、参数改写、Config Audit、`tool_result_persist`、prompt/model hooks。
- 本机 OpenClaw 持久配置已启用 `agentguard-security` 并指向 staging 路径；正式联调时需在 OpenClaw 插件配置或进程环境中提供真实 `adapterToken`。
