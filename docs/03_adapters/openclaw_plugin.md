# OpenClaw Security Plugin

## 1. 文档定位

当前仓库已有真实 OpenClaw 插件包：

```text
packages/agentguard-openclaw-plugin/
```

它不是 `agentguard_langgraph_bench/adapters/openclaw/` 的 AttackBench 外部 adapter。当前范围是 OpenClaw runtime 插件：`before_tool_call`、`message_sending`、`before_install` 和 `before_agent_run` 使用 OpenClaw SDK 正式支持的执行控制结果；`before_agent_finalize` 请求安全重写，`message_sending` 保留最终外发取消权。`before_prompt_build`、`llm_input`、`llm_output` 及 lifecycle hooks 只做观察，不再返回 SDK 不支持的伪阻断结果。所有策略评估仍使用 `GuardEvent(schema_version="0.3", runtime="openclaw")` 和同一个 Guard API / Core。

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

| 字段                     | 默认值                  | 说明                                                  |
| ------------------------ | ----------------------- | ----------------------------------------------------- |
| `guardApiBaseUrl`        | `http://127.0.0.1:8088` | Guard API base URL                                    |
| `adapterToken`           | 必填                    | OpenClaw SecretRef；解析后的 token 只存在于插件运行时 |
| `agentId`                | `main`                  | 必须与 adapter credential 绑定的 agent id 一致        |
| `enforcementMode`        | `enforce`               | `enforce`、`observe` 或 `disabled`                    |
| `requestTimeoutMs`       | `5000`                  | 单次 Guard API 请求超时                               |
| `approvalPollIntervalMs` | `1000`                  | 审批轮询间隔                                          |
| `approvalTimeoutMs`      | `25000`                 | 唯一的审批总等待上限                                  |
| `diagnosticLogging`      | `false`                 | 是否输出已脱敏的诊断日志                              |

`adapterToken` 不接受明文，也没有插件内环境变量回退。manifest 通过 `configContracts.secretInputs` 声明该路径，OpenClaw 在激活插件前解析 SecretRef，解析失败时启动失败。开发安装脚本把根 `.env` 中的 `AGENTGUARD_ADAPTER_TOKEN` 写入权限为 `0600` 的独立 secret 文件，再由 file SecretRef 引用；token 不进入 OpenClaw 主配置、GuardEvent、metadata、审计内容、错误消息或日志。

本机开发安装、OpenClaw profile patch、persisted plugin registry refresh、Gateway restart 和卸载流程见 [OpenClaw 插件部署、安装与配置](openclaw_plugin_deployment.md)。

## 4. Hook 状态

| Hook                                      | 状态                                     | 行为                                                                                                                                                            |
| ----------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `before_tool_call`                        | 已实现并通过本机 OpenClaw runtime 验证   | 映射为 `tool_call_proposed`；`allow` 放行，`deny` block，`ask` 等待 Guard approval                                                                              |
| `message_sending`                         | 已实现并通过本机 OpenClaw runtime 验证   | 映射为 `message_send_proposed`；`allow` 放行，`deny`/拒绝/超时 cancel                                                                                           |
| `before_prompt_build`                     | 已实现                                   | 观察最终 prompt 构造前状态并缓存关联字段；不返回该 hook 不支持的 `block`                                                                                        |
| `before_agent_run`                        | 已实现                                   | 正式输入 gate：并行评估当前输入 `model_input_prepared` 与历史工具消息 `context_assembled`；任一 `deny`/`ask` 即返回 `outcome=block`，API 异常 fail closed       |
| `llm_input` / `llm_output`                | 已实现                                   | observation-only；记录实际 provider 输入/输出时点，不重复产生策略裁决                                                                                           |
| `before_agent_finalize`                   | 已实现                                   | 映射为 `model_output_produced`；命中 `deny`/`ask`、本地凭据检测或 API 异常时要求一次安全 revise                                                                 |
| `before_install`                          | 已实现，需运行本机 OpenClaw install 验证 | 调用 Guard API config audit；high/critical 阻断安装；Guard API 失败 fail-closed                                                                                 |
| `tool_result_persist`                     | 已实现                                   | SDK 同步 hook：本地同步脱敏/清洗，远端异步评估 `tool_result_produced`；远端结论不伪装成同步返回，工具消息会在下一次 `before_agent_run` 再次作为不可信上下文评估 |
| `before_message_write`                    | 已实现                                   | SDK 同步 hook：写入前本地脱敏；强制模式下本地处理异常即 `block=true`                                                                                            |
| `gateway_start` / `gateway_stop`          | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，写 `AuditEvent(event_type=runtime_observation, runtime=openclaw)`；失败 fail-open                                                             |
| `session_start` / `session_end`           | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录会话边界                                                                                                                                  |
| `before_compaction` / `after_compaction`  | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录压缩前后事件                                                                                                                              |
| `subagent_spawned` / `subagent_ended`     | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录多 agent lineage                                                                                                                          |
| `model_call_started` / `model_call_ended` | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录模型调用遥测                                                                                                                              |
| `cron_changed`                            | 已实现，需运行本机 OpenClaw runtime 验证 | observation-only，记录自动化任务变更                                                                                                                            |
| `resolve_exec_env`                        | 已实现，需运行本机 OpenClaw runtime 验证 | 仅审计 exec env 风险；不注入敏感环境变量；Guard API 失败时不新增 env 变更                                                                                       |

## 5. 事件映射

`before_tool_call` 使用 OpenClaw 的 `toolName`、`params`、`toolKind`、`toolInputKind`、`toolCallId`、`runId` 构造 `tool_call_proposed`。`derivedPaths` 只作为 best-effort 资源提示，不作为唯一安全解析依据。

`message_sending` 使用 `to`、`content`、`channelId`、`sessionKey`、`messageId` 构造 `message_send_proposed`。该 hook 不强依赖 `runId`，优先用 `sessionKey` 关联 trace。

`tool_result_persist` 使用工具名、调用 id、结果内容预览、content type、是否进入上下文和是否持久化构造 `tool_result_produced`。OpenClaw 2026.6.6 明确要求该 hook 同步返回，因此插件只在这里同步执行确定性的本地凭据脱敏和持久化指令清洗；Guard API 评估异步完成并写入策略审计。若工具消息随后进入模型输入，`before_agent_run` 会把这些消息单独标记为 `source_trust=untrusted` 并再次同步等待 Core 裁决，从而在模型读取前执行真实阻断。

`before_agent_run` 位于 prompt 构造完成、模型推理开始之前，是输入侧唯一正式 gate。当前用户输入与工具历史分开建模：用户输入走 `model_input_prepared`，只把 role 为 `tool` / `function` 或带 tool call id 的消息组成 `context_assembled`，避免把可信 system prompt 和不可信工具内容压成同一信任标签。两次评估并行执行，最终按 `deny > ask > allow` 选择最严格结论。`llm_output` 只记录实际输出时点，真正的输出策略评估由 `before_agent_finalize` 执行；其 revise 后仍由 `message_sending` 做最终外发裁决。读取 conversation 的 hooks 需要 `hooks.allowConversationAccess=true`。

`before_install` 构造 `ConfigAuditEvent(runtime="openclaw")`，当前会识别 `allowConversationAccess`、`allowPromptInjection` 和 exec-like 权限等高风险配置。`high`/`critical` findings 会返回 block。

P2 observation hooks 构造 `AuditEvent(event_type="runtime_observation", runtime="openclaw")` 并写入 `/v1/audit/events`；metadata 会递归脱敏 token/secret/password/authorization/credential 字段。

## 6. 决策映射

| GuardDecision / Approval             | OpenClaw 行为                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `allow`                              | 放行；输入 gate 返回 `outcome=pass`，其他决策 hook 返回 `undefined`                              |
| `deny`                               | 工具调用返回 `block`；输入 gate 返回 `outcome=block`；消息发送返回 `cancel`；最终输出请求 revise |
| `ask` + `allow_once`                 | 插件轮询 Guard API approval wait 后放行                                                          |
| `ask` + `deny` / `timeout` / `error` | 审批型工具/消息操作 fail closed；输入 gate 的 `ask` 直接 block；最终输出的 `ask` 请求 revise     |

P1 审批真源是 AgentGuard Guard API / Dashboard。OpenClaw `requireApproval` 不作为 P1 审批权威源。

fail-closed 阶段不是用户可调白名单，而是固定契约：`before_tool_call`、`message_sending`、`before_install`、`before_agent_run`、`before_agent_finalize`、`tool_result_persist` 和 `before_message_write`。其中前四个返回 SDK 正式阻断结果；`before_agent_finalize` 请求安全重写；两个同步持久化 hook 只对本地处理错误 fail closed，远端可用性由下一次 `before_agent_run` gate 承担。`approvalTimeoutMs` 是唯一审批等待上限，hook timeout 会覆盖初始评估、审批等待、轮询间隔和安全余量。

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
  "plugin": {
    "id": "agentguard-security",
    "status": "loaded",
    "hookCount": 23
  },
  "shape": "hook-only",
  "typedHooks": [
    { "name": "before_tool_call", "priority": 100 },
    { "name": "message_sending", "priority": 100 },
    { "name": "before_install", "priority": 100 },
    { "name": "message_received", "priority": 0 },
    { "name": "before_prompt_build", "priority": 0 },
    { "name": "before_agent_run", "priority": 100 },
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
- 当前仍不实现工具参数改写、prompt 内容改写或 OpenClaw 原生 `requireApproval` 审批 UI 接管。输出只使用 SDK 的 finalize revise 与 message cancel；持久化内容只做确定性的本地脱敏/清洗。
- `tool_result_persist` / `before_message_write` 是 OpenClaw 同步契约，不能等待网络；因此远端工具结果结论负责审计，真正的模型前阻断在 `before_agent_run` 完成。原始工具结果是否已落入 OpenClaw 自身持久化介质必须按该 SDK 边界如实理解，不能宣称远端 `deny` 已在同步 hook 内回滚持久化。
- 本机 OpenClaw 持久配置通过 `pnpm openclaw:plugin:install` 启用 `agentguard-security` 并指向 `.openclaw-dev/agentguard-security`；正式联调时需在 `.env` 中提供真实 `AGENTGUARD_ADAPTER_TOKEN`。

## 10. E2E 验收报告

最近一次本机真实 E2E 验收报告保存在：

```text
<系统临时目录>/agentguard-openclaw-e2e-acceptance-report.md
```

该验收使用 OpenClaw 2026.6.6、Guard API、独立 PostgreSQL 测试库和确定性 hook runner，覆盖 `before_tool_call`、`message_sending`、`before_agent_run`、`before_agent_finalize`、`before_install`、`tool_result_persist`、观察型 hooks、audit integrity 和 provenance。
