# OpenClaw 与 LangChain/LangGraph Hook 清单

## 1. 统计口径

本文统计 OpenClaw 与 LangChain/LangGraph 中对 AgentGuard 有用、可能有用或相关的运行时 Hook、中间件、拦截点、扩展面及其关键数据结构。复核口径以官方仓库 README、官方文档和官方 API/reference 页面为准；当前仓库实现只作为“当前支持状态”，不影响匹配程度和适用性判断。

统计范围：

- 外部资料只采用官方文档、官方 API/reference 页面或官方 GitHub 仓库页面。
- 仓库事实只采用当前仓库已有文档、Core 模型和 LangGraph bench 实现。
- 不纳入论文、媒体报道、非官方博客或未验证第三方安全资料。
- “所有”指上述范围内可发现，且和运行时观测、拦截、阻断、审批、审计、上下文、模型、工具、消息或记忆链路相关的接口面。

统一字段：

| 字段 | 含义 |
| ---- | ---- |
| 运行时 | `openclaw`、`langchain`、`langgraph` 或当前仓库的 bench/adapter |
| 名称 | Hook、中间件、扩展点、API 或数据结构名称 |
| 类型 | typed plugin hook、internal hook、中间件、HTTP API、配置面、数据结构等 |
| 阶段 | P0/P1/P2 或“相关面”；P0 是当前最小闭环，P1/P2 是后续增强 |
| 触发时机 | 该接口在运行时生命周期中何时触发 |
| 可观测输入 | AgentGuard 可从该接口读取的关键字段 |
| 可修改输出 | 该接口能否改写输入、输出、payload、环境变量或状态 |
| 阻断/取消/暂停能力 | 是否能阻止动作、取消消息、暂停等待审批或只观察 |
| 相关数据结构 | 官方或本仓库中需要映射的对象 |
| AgentGuard 映射 | 建议映射到的 `GuardEvent`、payload、`GuardDecision` 或 `AuditEvent` |
| 匹配程度 | 高/中/低；只看官方能力与 AgentGuard 问题域的贴合度，不因当前未实现而降级 |
| 适用性 | 主拦截、辅助观测、配置审计或不推荐 |
| 当前支持状态 | 已实现、已设计待验证、官方相关但仓库未接入 |
| 来源 | 官方链接或仓库相对路径 |

匹配标注规则：

- 高：能直接覆盖工具前置阻断、审批、上下文/消息改写、模型前后拦截或持久化污染控制。
- 中：能提供重要观测、追踪、配置审计、供应链审计、记忆审计或间接策略输入。
- 低：主要是兼容、deprecated、粗粒度自动化或需要较多适配才能用于 AgentGuard。
- 主拦截：可在危险动作执行前阻断、暂停、改写或缩小可用能力面。
- 辅助观测：用于审计、trace、指标、证据、上下文归因或事后净化。
- 配置审计：用于安装、manifest、权限、webhook、技能、Gateway 暴露或安全配置检查。
- 不推荐：官方标记为兼容/deprecated，或语义上不适合作为安全控制面。

## 2. 资料来源

外部官方来源：

- OpenClaw: [GitHub README](https://github.com/openclaw/openclaw)、[Plugin hooks](https://docs.openclaw.ai/plugins/hooks)、[Internal hooks](https://docs.openclaw.ai/automation/hooks)、[Tools invoke API](https://docs.openclaw.ai/gateway/tools-invoke-http-api)、[Security](https://docs.openclaw.ai/gateway/security)、[Skills](https://docs.openclaw.ai/tools/skills)、[Building plugins](https://docs.openclaw.ai/plugins/building-plugins)、[Tool plugins](https://docs.openclaw.ai/plugins/tool-plugins)、[Configuration](https://docs.openclaw.ai/gateway/configuration)。
- LangChain: [GitHub README](https://github.com/langchain-ai/langchain)、[overview](https://docs.langchain.com/oss/python/langchain/overview)、[middleware overview](https://docs.langchain.com/oss/python/langchain/middleware/overview)、[custom middleware](https://docs.langchain.com/oss/python/langchain/middleware/custom)、[prebuilt middleware](https://docs.langchain.com/oss/python/langchain/middleware/built-in)、[tools](https://docs.langchain.com/oss/python/langchain/tools)、[event streaming](https://docs.langchain.com/oss/python/langchain/event-streaming)、[HITL](https://docs.langchain.com/oss/python/langchain/human-in-the-loop)。
- LangGraph: [GitHub README](https://github.com/langchain-ai/langgraph)、[overview](https://docs.langchain.com/oss/python/langgraph/overview)、[interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts)、[stores](https://docs.langchain.com/oss/python/langgraph/stores)、[event streaming](https://docs.langchain.com/oss/python/langgraph/event-streaming)。

仓库来源：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [LangGraph 评测靶场](langgraph_adapter.md)
- [OpenClaw Security Plugin](openclaw_plugin.md)
- `packages/agentguard-core/agentguard_core/models.py`
- `agentguard_langgraph_bench/src/agentguard_langgraph_bench/adapter.py`
- `agentguard_langgraph_bench/src/agentguard_langgraph_bench/secure_tool_node.py`
- `agentguard_langgraph_bench/src/agentguard_langgraph_bench/models.py`

## 3. 总览统计

| 类别 | 数量 | 匹配结论 | AgentGuard 直接价值 |
| ---- | ---- | -------- | ------------------- |
| OpenClaw typed/plugin hook | 39 | 高/中为主 | 覆盖工具前置阻断、审批、消息投递、prompt/模型、工具结果、session、subagent、安装和 Gateway 生命周期 |
| OpenClaw `HOOK.md` internal hook | 15 | 中/低为主 | 适合 operator 自动化、粗粒度审计和演示辅助，不作为主阻断面 |
| OpenClaw 相关扩展面/API/配置面 | 13 | 中/高混合 | 覆盖插件 manifest、工具注册、可信工具策略、HTTP tool invoke、webhook ingress、skills watcher、security/config audit |
| LangChain agent middleware hook | 7 | 高/中为主 | 当前官方主接入口；覆盖模型前后、工具调用包裹、agent 起止和动态 prompt |
| LangChain provider-agnostic prebuilt middleware | 17 | 中/高混合 | 可复用 HITL、PII、摘要、调用限额、fallback/retry、工具选择、上下文编辑、文件系统和 subagent 能力 |
| LangGraph 运行时能力 | 9 | 高/中为主 | 覆盖 interrupt、Command、checkpointer、Store、stream、StateGraph、ToolNode 和当前仓库降级工具节点 |
| LangChain/LangGraph 数据结构 | 18 | 高/中为主 | 覆盖 state、runtime、model request/response、tool request/result、messages、Command、Interrupt、Store item 和 stream projections |

当前 AgentGuard 最稳接入顺序：

1. P0：LangChain/LangGraph `wrap_tool_call` 或当前 bench 的 `SecureToolNode.invoke_tool`，映射 `ToolCallPayload` 并在工具执行前调用 Guard API。
2. P0-P1：OpenClaw `before_tool_call` 作为 OpenClaw 最强主拦截面，映射 `params`、`block`、`requireApproval` 到 `GuardDecision=allow/deny/ask`。
3. P1：OpenClaw `message_sending`、`before_prompt_build`、`llm_input`、`llm_output` 和 `tool_result_persist` 已进入当前插件实现；`before_agent_run`、LangChain `before_model`、`after_model`、`HumanInTheLoopMiddleware` 作为后续候选，用于补齐更强的上下文改写、模型阻断和审批链路。
4. P2：OpenClaw install/config/security audit、Gateway lifecycle、exec env hook、session/subagent lifecycle、LangGraph Store/memory、event streaming 和多 agent/subgraph 观测。

本轮文档进度修正只同步 OpenClaw 插件真实实现与后端接口状态。LangGraph 相关行仍作为 hook inventory 和后续接入参考，不表示本轮默认质量评估或实现承诺。

## 4. OpenClaw 明细

### 4.1 Typed Plugin Hooks

OpenClaw typed plugin hooks 是 in-process 扩展点，通过 `api.on(name, handler, opts?)` 注册，支持优先级和超时配置。官方 catalog 中接受 decision 的 hook 可 block、cancel、override 或 require approval；观察型 hook 不应用作执行前安全边界。

| 名称 | 类型 | 阶段 | 触发时机 | 可观测输入 | 可修改输出 | 阻断/取消/暂停能力 | 相关数据结构 | AgentGuard 映射 | 匹配程度 | 适用性 | 当前支持状态 | 来源 |
| ---- | ---- | ---- | -------- | ---------- | ---------- | ------------------ | ------------ | --------------- | -------- | ------ | ------------ | ---- |
| `before_model_resolve` | typed plugin hook | P1 | 模型/provider 解析前 | 当前 prompt、attachment metadata、run/session context | 可返回 `providerOverride` 或 `modelOverride` | 不阻断；可改变模型路由 | model resolve event、hook context | 模型策略审计、风险升降级、模型选择证据 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `agent_turn_prepare` | typed plugin hook | P1 | agent turn 准备阶段，prompt hooks 之前 | 当前 prompt、prepared session messages、queued injections | 可返回 `prependContext` 或 `appendContext` | 不直接阻断；可改变同 turn 上下文 | agent turn prepare event | `ContextBuildEvent`；记录注入来源、信任级别、是否进入模型 | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `before_prompt_build` | typed plugin hook | P1 | prompt 构造前 | 当前 prompt、session messages | 可返回 `prependContext`、`appendContext`、`systemPrompt`、`prependSystemContext`、`appendSystemContext` | 不直接阻断；可改变模型上下文 | prompt build event | `ContextBuildEvent`；上下文污染检测和隔离 | 高 | 主拦截 | 已实现为评估型观测，映射 `context_assembled`；当前不改写 prompt | OpenClaw Plugin hooks；`docs/03_adapters/openclaw_plugin.md` |
| `before_agent_start` | typed plugin hook | P2 | 旧版 combined agent start 阶段 | `event.runId`、`ctx.runId`、prompt/上下文组合信息 | 兼容旧能力 | 视旧实现而定 | legacy before agent start event | 仅作兼容入口；新实现优先显式 phase hooks | 低 | 不推荐 | 官方兼容面，仓库未接入 | OpenClaw Plugin hooks |
| `before_agent_run` | typed plugin hook | P1 | prompt 构造后、模型读取前 | user input `prompt`、loaded session history `messages`、active system prompt | 可返回 block replacement message | 可 block；官方仅支持 `pass`/`block` | before agent run event | `model_input_prepared` 或 `context_assembled`；`deny` 映射 block | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `before_agent_reply` | typed plugin hook | P1 | agent turn 可被模型回复前 | 当前 turn、reply intent、run/session context | 可短路为 synthetic reply 或 silence | 可跳过模型回复；适合安全回复替换 | before agent reply event | 高风险输入的安全回复或静默处理；写入 `AuditEvent(stage=before_agent_reply)` | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `before_agent_finalize` | typed plugin hook | P1 | harness 即将接受自然语言最终回答时 | 最终 assistant answer、run context、retry metadata | 可 `revise` 请求额外模型 pass，或 `finalize` | 可要求一次有界修订；非 `/stop` 路径 | finalize event、retry metadata | 输出安全复核；越狱/泄露回答可请求修订并审计 | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `agent_end` | typed plugin hook | P1 | turn 结束后 | final messages、success state、duration、`runId`、`jobId` | 不改写主流程 | 观察-only；有超时保护 | agent end event | `AuditEvent(stage=turn_finished)`；trace 收尾和指标补全 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `heartbeat_prompt_contribution` | typed plugin hook | P2 | heartbeat turn 生成 prompt 时 | heartbeat 上下文、当前状态摘要 | 可返回 `prependContext` 或 `appendContext` | 不阻断 | heartbeat event | 后台监控摘要审计；不进 P0 判定 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `model_call_started` | typed plugin hook | P2 | provider/model call 开始时 | sanitized metadata、`runId`、`callId`、provider、model、api/transport | 不改写 | 观察-only；不含 raw prompt/response | model call telemetry event | 模型调用耗时/路由/预算审计，不可作为内容拦截 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `model_call_ended` | typed plugin hook | P2 | provider/model call 结束时 | duration、outcome、provider/model、bounded request-id hash、context budget | 不改写 | 观察-only | model call telemetry event | `AuditEvent(stage=model_call_ended)`；模型调用结果和失败率证据 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `llm_input` | typed plugin hook | P1 | provider input 形成后 | system prompt、prompt、history、上下文窗口预算 | 以观察为主；非官方主改写口 | 不作为主阻断；原始内容敏感 | provider input event | `model_input_prepared` 内容审计；敏感字段需脱敏写 Audit | 高 | 辅助观测 | 已实现为评估型观测，当前不阻断模型调用 | OpenClaw Plugin hooks |
| `llm_output` | typed plugin hook | P1 | provider output 产生后 | assistant output、usage、context token budget | 以观察为主 | 不作为执行前阻断 | provider output event | `model_output_produced`；输出越狱、工具计划异常检测 | 高 | 辅助观测 | 已实现为评估型观测，当前不改写模型输出 | OpenClaw Plugin hooks |
| `before_tool_call` | typed plugin hook | P0 | 工具执行前 | `toolName`、`params`、`toolKind`、`toolInputKind`、`derivedPaths`、`runId`、`toolCallId`、ctx trace/session | 可改写 `params` | 可 `block: true` 终止；可 `requireApproval` 暂停 | `BeforeToolCallResult`、tool event、hook context | `GuardEvent(event_type=tool_call_proposed, payload=ToolCallPayload)`；`allow/deny/ask` 直映射 | 高 | 主拦截 | 已实现并通过本机 OpenClaw runtime 验证 | OpenClaw Plugin hooks；`docs/03_adapters/openclaw_plugin.md` |
| `after_tool_call` | typed plugin hook | P1 | 工具执行后 | tool result、error、duration、`toolCallId`、run/session context | 观察为主 | 不能替代执行前阻断 | tool result event | `ToolResultEvent` 和 `AuditEvent(stage=after_tool_call)` | 高 | 辅助观测 | 官方已确认，仓库未接入 | OpenClaw Plugin hooks |
| `resolve_exec_env` | typed plugin hook | P2 | `exec` 环境构建后、命令执行前 | `sessionKey`、`toolName=exec`、`host`、agent/channel context | 返回 env map，经过 key policy 过滤 | 不直接阻断；影响执行环境 | exec env event、filtered env metadata | `ToolCallPayload(tool=exec)` 补充 metadata；审计环境变量注入风险 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `tool_result_persist` | typed plugin hook | P1 | 工具结果持久化前 | tool result content/details、是否进入 session、metadata | 可重写 assistant message produced from tool result | 不作为工具前阻断；可净化持久化结果 | tool result event、bounded details | `ToolResultEvent`；检测 prompt injection、敏感数据和持久化污染 | 高 | 主拦截 | 已实现，需运行本机 OpenClaw hook 验证 | OpenClaw Plugin hooks；`docs/03_adapters/openclaw_plugin.md` |
| `before_message_write` | typed plugin hook | P1 | in-progress message 写入前 | 即将写入 transcript 的消息和 tool result details | 可 inspect 或 block message write；rare | 可阻断写入但不替代工具前置控制 | message write event | `AuditEvent(stage=before_message_write)` 或 P1 memory/context 写入审计 | 中 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `inbound_claim` | typed plugin hook | P1 | inbound message 进入 agent routing 前 | 入站内容、sender、thread/message metadata | 可 claim 并返回 synthetic reply | 可短路 agent routing | inbound claim event | 高风险来源预处理；可在 agent 读取前阻断或安全回复 | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `message_received` | typed plugin hook | P1 | 入站消息被 Gateway 接收后 | 内容、sender、`threadId`、`messageId`、`senderId`、metadata、trace 字段 | 观察为主 | 观察-only | message hook event、hook context | `user_input_received`、source trust、sender 归因 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `message_sending` | typed plugin hook | P1 | 出站消息发送前 | `content`、目标 channel/receiver、`sessionKey`、`runId`、`messageId`、sender/trace | 可 rewrite `content`；可返回 `cancelReason` 和 bounded `metadata` | 可 `cancel: true`，terminal | message hook event、hook context | 消息外发 DLP；`deny` 映射 cancel，`allow` 放行，`ask` 需审批适配 | 高 | 主拦截 | 已实现并通过本机 OpenClaw runtime 验证 | OpenClaw Plugin hooks；`docs/03_adapters/openclaw_plugin.md` |
| `reply_payload_sending` | typed plugin hook | P1 | normalized reply payload 渠道投递前 | `ReplyPayload`、`presentation`、`delivery`、media refs、text | 可改写 payload | 可取消；不能授予 local media trust | `ReplyPayload` | 渠道 payload 二次 DLP 和媒体投递审计 | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `message_sent` | typed plugin hook | P1 | 出站消息投递结束后 | success/failure、目标、内容摘要、channel | 不改写 | 观察-only；handler 失败不改变投递结果 | message sent event | `AuditEvent(stage=message_sent)`；最终投递结果证据 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `before_dispatch` | typed plugin hook | P1 | outbound dispatch 交给 channel 前 | dispatch payload、reply metadata、target channel | 可 inspect 或 rewrite dispatch | 可能可作为渠道前策略面，需实现期验证细节 | dispatch event、reply metadata | 外发渠道级策略和 quoted reply 安全归因 | 中 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `reply_dispatch` | typed plugin hook | P1 | final reply-dispatch pipeline | final reply dispatch context、channel routing | 可参与 dispatch pipeline | 需实现期验证可阻断细节 | reply dispatch event | 多渠道投递归因和最终外发审计 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `session_start` | typed plugin hook | P2 | session lifecycle 开始 | session id/key、reason、agent/session metadata | 不改写主流程 | 观察-only | session lifecycle event | `AuditEvent(stage=session_start)`；会话边界和 trace 起点 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `session_end` | typed plugin hook | P2 | session lifecycle 结束或 Gateway finalizer | reason: `new/reset/idle/daily/compaction/deleted/shutdown/restart/unknown` | 不改写主流程 | 观察-only；finalizer bounded | session lifecycle event | `AuditEvent(stage=session_end)`；清理 ghost rows 和会话完整性证据 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `before_compaction` | typed plugin hook | P2 | session compaction 前 | session messages、token/message count、compaction context | 可 observe 或 annotate | 不作为主阻断 | compaction event | `ContextBuildEvent`；压缩前敏感上下文和污染统计 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `after_compaction` | typed plugin hook | P2 | session compaction 后 | summary、tokens before/after、compaction result | 可 observe 或 annotate | 不作为主阻断 | compaction event | 检查压缩摘要是否保留污染/泄露文本 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `before_reset` | typed plugin hook | P2 | `/reset` 或 programmatic reset 前 | session reset context、agent/session metadata | 观察为主 | 不作为审批主面 | reset event | 重置操作审计和 session state 清理证据 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `subagent_spawned` | typed plugin hook | P2 | subagent launch/binding 准备后 | child session binding、resolved model/provider、parent context | 观察为主 | 观察-only | subagent spawned event | `AuditEvent(stage=subagent_spawned)`；多 Agent 攻击链归因 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `subagent_ended` | typed plugin hook | P2 | subagent 完成后 | child run/session result、completion status | 观察为主 | 观察-only | subagent ended event | `AuditEvent(stage=subagent_ended)`；子任务收尾和跨 agent 证据 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `subagent_delivery_target` | typed plugin hook | P2 | 无 core session binding 可投递 completion 时 | completion routing context | compatibility routing | 兼容面 | compatibility delivery event | 仅用于老路径归因；新接入不依赖 | 低 | 不推荐 | 官方兼容面，仓库未接入 | OpenClaw Plugin hooks |
| `subagent_spawning` | typed plugin hook | P2 | 旧版 subagent spawn 前 | subagent 请求、thread routing 旧字段 | deprecated compatibility | 不推荐新实现依赖 | legacy subagent event | 多 Agent 链路审计兼容入口 | 低 | 不推荐 | 官方 deprecated 兼容面，仓库未接入 | OpenClaw Plugin hooks |
| `gateway_start` | typed plugin hook | P2 | Gateway 启动，插件服务需要 Gateway state 时 | `ctx.config`、`ctx.workspaceDir`、`ctx.getCron` | 可启动插件服务 | 不阻断正常请求 | gateway hook context | P2 运行时状态审计、后台服务初始化 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `gateway_stop` | typed plugin hook | P2 | Gateway 停止时 | 长连接、后台资源、插件状态 | 可清理资源 | 不阻断业务动作 | gateway hook context | `AuditEvent(stage=gateway_stop)`；服务生命周期证据 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `deactivate` | typed plugin hook | P2 | 旧版停用/停止兼容别名 | plugin runtime cleanup context | 兼容清理 | deprecated alias；新实现用 `gateway_stop` | compatibility lifecycle event | 只记录兼容状态，不作为新插件设计目标 | 低 | 不推荐 | 官方 deprecated alias，仓库未接入 | OpenClaw Plugin hooks |
| `cron_changed` | typed plugin hook | P2 | Gateway cron lifecycle 变化 | added/updated/removed/started/finished/scheduled、job snapshot、delivery status | 不改写主动作 | 观察/同步为主 | `PluginHookGatewayCronJob`、`PluginHookGatewayCronDeliveryStatus` | P2 自动化任务审计；防止持久任务被恶意创建或篡改 | 中 | 辅助观测 | 已在 OpenClaw 插件 P2 observation 实现，需本机 runtime 验证 | OpenClaw Plugin hooks |
| `before_install` | typed plugin hook | P2 | 插件或 skill 安装时，operator install policy 后 | install payload、`builtinScan` 兼容字段、插件 metadata | 可返回 findings | 可 `block: true`；handler 失败 fail-closed | install hook event | `AuditEvent(stage=before_install)`；插件/技能供应链审计 | 中 | 配置审计 | 已实现，需运行本机 OpenClaw install 验证 | OpenClaw Plugin hooks；`docs/03_adapters/openclaw_plugin.md` |

### 4.2 `HOOK.md` Internal Hooks

Internal hooks 是 operator 管理的文件式自动化，不是 typed plugin lifecycle control。适合本地审计、演示辅助、粗粒度联动；不建议作为 AgentGuard 主阻断层。

通用数据结构：

- Hook 目录包含 `HOOK.md` 和 `handler.ts`。
- `HOOK.md` front matter 的 `metadata.openclaw` 可包含 `emoji`、`events`、`export`、`os`、`requires`、`always`、`install`。
- handler 事件包含 `type`、`action`、`sessionKey`、`timestamp`、`messages`、`context`。
- `event.messages` 只在可回复 surface 自动投递，例如 `command:*`、`message:received`。
- Agent/tool plugin hook context 可包含 read-only W3C-compatible diagnostic `trace`。

| 名称 | 类型 | 阶段 | 触发时机 | 可观测输入 | 可修改输出 | 阻断/取消/暂停能力 | 相关数据结构 | AgentGuard 映射 | 匹配程度 | 适用性 | 当前支持状态 | 来源 |
| ---- | ---- | ---- | -------- | ---------- | ---------- | ------------------ | ------------ | --------------- | -------- | ------ | ------------ | ---- |
| `command:new` | internal hook | 相关面 | `/new` 命令发出 | session entry、previous session entry、command source、workspace、cfg | 可 push reply message | 不作为安全阻断 | hook event、command context | `AuditEvent(stage=command_new)`；记录会话重置类操作 | 低 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `command:reset` | internal hook | 相关面 | `/reset` 命令发出 | session entry、previous session entry、cfg | 可 push reply message | 不作为安全阻断 | hook event | `AuditEvent(stage=command_reset)` | 低 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `command:stop` | internal hook | 相关面 | `/stop` 命令发出 | command source、session、cfg | 可 push reply message | 不是 agent finalization gate | hook event | `AuditEvent(stage=command_stop)`；若需最终回答复核应使用 `before_agent_finalize` | 低 | 不推荐 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `command` | internal hook | 相关面 | 任意 command event | action、sessionKey、command context | 可 push reply message | 不作为主阻断 | hook event | 命令级审计或演示日志 | 低 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `session:compact:before` | internal hook | P2 | 历史压缩前 | `messageCount`、`tokenCount`、session metadata | 不建议改写主内容 | 观察为主 | compaction context | `ContextBuildEvent` 补充审计 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `session:compact:after` | internal hook | P2 | 历史压缩后 | `compactedCount`、`summaryLength`、`tokensBefore`、`tokensAfter` | 不建议改写主内容 | 观察为主 | compaction context | `AuditEvent(stage=session_compact_after)` | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `session:patch` | internal hook | P2 | session 属性被特权客户端修改时 | `sessionEntry`、`patch`、`cfg` | 不作为业务改写入口 | 观察为主 | session patch context | `MemoryEvent` 或 `AuditEvent(stage=session_patch)` | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `agent:bootstrap` | internal hook | P2 | workspace bootstrap 文件注入前 | `bootstrapFiles` mutable array、`agentId` | 可修改 `bootstrapFiles` | 可影响 agent 初始上下文和文件 | bootstrap context | P2 配置/文件注入审计 | 中 | 配置审计 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `gateway:startup` | internal hook | 相关面 | channels 启动、hooks 加载后 | Gateway 状态、cfg | 可执行本地自动化 | 不作为 typed plugin service 首选 | gateway context | `AuditEvent(stage=gateway_startup)` | 低 | 不推荐 | typed plugin 服务应优先 `gateway_start` | OpenClaw Internal hooks |
| `gateway:shutdown` | internal hook | 相关面 | Gateway shutdown 开始 | reason、restartExpectedMs、Gateway 状态 | 可执行清理 | 不阻断；best-effort bounded wait | gateway context | `AuditEvent(stage=gateway_shutdown)` | 低 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `gateway:pre-restart` | internal hook | 相关面 | 预期 restart 前 | reason、restartExpectedMs、Gateway 状态 | 可执行预重启自动化 | 不作为安全阻断 | gateway context | `AuditEvent(stage=gateway_pre_restart)` | 低 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `message:received` | internal hook | P1 | 任意渠道入站消息 | `from`、`content`、`channelId`、provider metadata、sender 字段 | 可 push reply message | 不作为主阻断 | message context | `user_input_received`；source trust 和 sender 归因 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `message:transcribed` | internal hook | P1 | 音频转写完成后 | `transcript`、`from`、`channelId`、`mediaPath` | 可 push reply message 取决于 surface | 不作为主阻断 | transcription context | P1 media input 审计；语音注入检测 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `message:preprocessed` | internal hook | P1 | media/link 预处理完成或跳过后 | `bodyForAgent`、`from`、`channelId` | 可 push reply message 取决于 surface | 不作为主阻断 | preprocess context | `ContextBuildEvent`；最终 enriched body 污染检测 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |
| `message:sent` | internal hook | P1 | 出站消息送达后 | `to`、`content`、`success`、`channelId` | lifecycle-only 通常不自动回复 | 观察-only | sent context | `AuditEvent(stage=message_sent)` | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Internal hooks |

### 4.3 OpenClaw 扩展面、API 和配置面

| 名称 | 类型 | 阶段 | 触发时机 | 可观测输入 | 可修改输出 | 阻断/取消/暂停能力 | 相关数据结构 | AgentGuard 映射 | 匹配程度 | 适用性 | 当前支持状态 | 来源 |
| ---- | ---- | ---- | -------- | ---------- | ---------- | ------------------ | ------------ | --------------- | -------- | ------ | ------------ | ---- |
| `package.json.openclaw` metadata | plugin package metadata | P2 | 插件安装/加载/兼容性检查时 | extension entries、compat、plugin SDK/Gateway version | 不改写运行时动作 | 可在安装/审计阶段阻止不兼容插件 | package metadata | Config/Plugin Audit；版本和入口完整性检查 | 中 | 配置审计 | 文档设计相关，仓库未实现 | OpenClaw Building plugins |
| `openclaw.plugin.json` manifest | plugin manifest | P2 | 插件发现、安装、运行时能力声明 | `id`、`contracts`、`activation`、`configSchema`、`toolMetadata` | 不改写动作；声明能力边界 | manifest-gated surfaces 可拒绝未声明能力 | plugin manifest | 插件供应链和能力面审计 | 高 | 配置审计 | `openclaw_plugin.md` 已设计插件 manifest | OpenClaw Building plugins；`docs/03_adapters/openclaw_plugin.md` |
| `contracts.tools` + `api.registerTool(...)` | tool registration | P1-P2 | 插件注册工具时 | tool name、description、TypeBox parameters、optional flag、active model metadata | 注册工具实现 | 工具暴露受 manifest、optional、allowlist、policy 控制 | `AgentTool` descriptor、tool metadata | `ToolDescriptor`、工具分类、最小权限工具面 | 高 | 主拦截 | 官方相关，仓库未接入 OpenClaw runtime | OpenClaw Building plugins；Tool plugins |
| `api.registerAgentToolResultMiddleware(...)` | agent tool result middleware | P1 | agent 工具结果进入后续消息/持久化链路时 | runtime id、tool result、plugin-owned metadata | 可净化或包装工具结果，具体 SDK 类型需实现期确认 | 不替代工具前阻断；适合结果净化 | agent tool result middleware contract | `ToolResultEvent`；工具结果污染和敏感数据净化 | 高 | 主拦截 | 官方 manifest gate 已确认，仓库未接入 | OpenClaw Building plugins |
| `api.registerTrustedToolPolicy(...)` | trusted tool policy | P0-P1 | ordinary `before_tool_call` hooks 之前 | policy id、tool call、host context、plugin contract | 可执行 host-trusted gate | 先于普通 hook 决策；适合 workspace/budget/reserved workflow policy | trusted tool policy contract | 高信任工具前置策略；可映射 `GuardDecision` 或 pre-Guard deny | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks；Building plugins |
| `plugins.entries.<id>.hooks.allowConversationAccess` | hook permission config | P1-P2 | 非 bundled 插件需要 raw conversation hooks 时 | plugin id、raw conversation hook request | 配置是否允许 conversation access | 配置层阻断插件读取 raw prompt/output | plugin hook config | Config Audit；限制安全插件以外的 conversation access | 中 | 配置审计 | 开发安装脚本会为 `agentguard-security` 写入；`before_install` 会审计该高风险配置 | OpenClaw Plugin hooks |
| `plugins.entries.<id>.hooks.allowPromptInjection` | hook permission config | P1-P2 | prompt-mutating hooks 或 next-turn injections 配置时 | plugin id、prompt injection setting | 可禁用 prompt injection 能力 | 配置层禁止插件注入 prompt | plugin hook config | Config Audit；防止低信任插件污染系统上下文 | 高 | 配置审计 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `api.registerSessionExtension(...)` | session extension | P2 | 插件持久化 session-scoped JSON state 时 | extension key/value、session row projection | 可更新 plugin-owned state | 不阻断动作；影响状态展示和持久化 | `pluginExtensions` | `MemoryEvent`/`AuditEvent`；插件状态写入审计 | 中 | 辅助观测 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `api.enqueueNextTurnInjection(...)` | next-turn injection | P1-P2 | 插件需要一次性把上下文带到下一 turn 时 | injection payload、TTL、idempotency key | 注入下一次 prompt context | 可影响后续模型输入；需要配置审计 | queued injection | `ContextBuildEvent`；审批恢复、策略摘要、背景风险注入 | 高 | 主拦截 | 官方相关，仓库未接入 | OpenClaw Plugin hooks |
| `POST /tools/invoke` | HTTP API | P1-P2 | 外部 HTTP 直接调用单个 Gateway 工具时 | `tool`、`action`、`args`、`sessionKey`、auth mode、scopes、tool policy | 不改写工具实现 | Gateway auth + tool policy；无额外 per-call approval prompt | HTTP request/response、Gateway auth config | 暴露面审计；不能当作低权限 API，必须按 operator access 处理 | 高 | 配置审计 | 官方相关，仓库未接入 | OpenClaw Tools invoke API |
| `hooks` webhook config | HTTP webhook ingress | P1-P2 | 外部系统经 Gateway webhook 触发工作时 | `enabled`、`token`、`path`、`defaultSessionKey`、`allowRequestSessionKey`、`mappings` | 配置路由到 agent/delivery | header-only token；payload 不可信；session key 应受 prefix 限制 | Gateway `hooks` config | 入站 untrusted content 和 webhook 暴露面审计 | 高 | 配置审计 | 官方相关，仓库未接入 | OpenClaw Configuration |
| skills watcher / skill snapshot | skills runtime surface | P2 | `SKILL.md` 改变或 remote node 连接后 | skill metadata、eligible list、env/apiKey、snapshot refresh | 改变后续系统 prompt 和 env 注入 | 不直接阻断；需要配置和供应链审计 | skill snapshot、`skills.load` config | `ContextBuildEvent`/Config Audit；技能 prompt 注入和 secret/env 风险 | 高 | 配置审计 | 官方相关，仓库未接入 | OpenClaw Skills |
| `openclaw security audit` | security/config audit command | P2 | 配置变化、暴露面变化、上线前或定期检查 | Gateway auth exposure、browser exposure、elevated allowlists、filesystem permissions、exec approvals、open-channel tools、plugins/skills findings | `--fix` 可做窄范围修复 | 配置审计；非运行时拦截 | audit findings、checkId、severity | Config/Plugin Audit；作为部署前/演示证据来源 | 中 | 配置审计 | 官方相关，仓库未接入 | OpenClaw Security |

## 5. LangChain/LangGraph 明细

### 5.1 LangChain Agent Middleware Hooks

LangChain 当前官方主接入点是 `create_agent(..., middleware=[...])`。这些 middleware 运行在返回的 LangGraph 内部，agent 作为 node/subgraph 放入更大 `StateGraph` 后仍继续生效。

| 名称 | 类型 | 阶段 | 触发时机 | 可观测输入 | 可修改输出 | 阻断/取消/暂停能力 | 相关数据结构 | AgentGuard 映射 | 匹配程度 | 适用性 | 当前支持状态 | 来源 |
| ---- | ---- | ---- | -------- | ---------- | ---------- | ------------------ | ------------ | --------------- | -------- | ------ | ------------ | ---- |
| `before_agent` | node-style middleware hook | P1 | agent invocation 开始一次 | `AgentState`、`Runtime` | 返回 dict 更新 state | 可配合 `jump_to` 早退 | `AgentState`、`Runtime` | `AuditEvent(stage=before_agent)`；初始化 trace/session/security context | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `before_model` | node-style middleware hook | P1 | 每次模型调用前 | `AgentState.messages`、custom state、`Runtime` | 返回 dict 更新 state/messages | 可用 `jump_to` 早退或改路由 | `AgentState`、`Runtime`、`AIMessage` | `ContextBuildEvent` 或 `model_input_prepared`；输入过滤、上下文隔离 | 高 | 主拦截 | 仓库文档用旧名 `pre_model_hook` 设计，实际未接入 | LangChain Custom middleware；`docs/03_adapters/langgraph_adapter.md` |
| `after_model` | node-style middleware hook | P1 | 每次模型响应后 | 最新 `AIMessage`、tool calls、usage metadata、custom state | 返回 dict 更新 state/messages | 可 `jump_to`，用于输出拦截 | `AgentState`、`Runtime`、`AIMessage` | `model_output_produced`；检测越狱输出和异常工具计划 | 高 | 主拦截 | 仓库文档用旧名 `post_model_hook` 设计，实际未接入 | LangChain Custom middleware；`docs/03_adapters/langgraph_adapter.md` |
| `after_agent` | node-style middleware hook | P1 | agent 完成一次 | final state、messages、runtime context | 返回 dict 更新最终 state | 不作为工具执行前阻断 | `AgentState`、`Runtime` | `AuditEvent(stage=turn_finished)`；指标收尾 | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `wrap_model_call` | wrap-style middleware hook | P1 | 每次模型调用外层 | `ModelRequest`、handler、model、messages、system message、tools、state、runtime | `request.override(...)` 可改 model、tools、system message；可返回 `ExtendedModelResponse` | 可 short-circuit、不调用 handler、重试、fallback | `ModelRequest`、`ModelResponse`、`ExtendedModelResponse`、`Command` | 模型输入/输出 Guard；动态工具最小权限；高风险上下文降权 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `wrap_tool_call` | wrap-style middleware hook | P0 | 每次工具调用外层 | `ToolCallRequest`、`tool_call.name`、`tool_call.args`、tool、state/runtime | 可决定是否调用 handler；可返回 `ToolMessage` 或 `Command` | 可 short-circuit；可阻断工具并返回安全 `ToolMessage` | `ToolCallRequest`、`ToolMessage`、`Command` | P0 `ToolCallPayload`；`allow` 后 handler，`deny/ask` 不执行工具 | 高 | 主拦截 | 当前仓库通过 `SecureToolNode.invoke_tool` 实现等价降级路径 | LangChain Custom middleware；`agentguard_langgraph_bench/src/agentguard_langgraph_bench/secure_tool_node.py` |
| `dynamic_prompt` | convenience middleware | P1 | 生成动态 system prompt 时 | state、runtime、用户/会话上下文 | 返回动态 prompt | 不作为主阻断 | dynamic prompt decorator、system prompt | `ContextBuildEvent`；记录系统 prompt 注入来源和安全上下文 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Custom middleware |

### 5.2 LangChain Provider-Agnostic Prebuilt Middleware

| 名称 | 类型 | 阶段 | 触发时机 | 可观测输入 | 可修改输出 | 阻断/取消/暂停能力 | 相关数据结构 | AgentGuard 映射 | 匹配程度 | 适用性 | 当前支持状态 | 来源 |
| ---- | ---- | ---- | -------- | ---------- | ---------- | ------------------ | ------------ | --------------- | -------- | ------ | ------------ | ---- |
| `SummarizationMiddleware` | prebuilt middleware | P1-P2 | 上下文达到 token/message/fraction trigger 时 | messages、token usage、model profile | 生成摘要并压缩上下文 | 不阻断；改变后续上下文 | context trigger、summary message | `ContextBuildEvent`；压缩前后污染和敏感信息留存审计 | 高 | 辅助观测 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `HumanInTheLoopMiddleware` | prebuilt middleware | P0-P1 | 配置命中的工具调用前 | tool name、args、`ToolCallRequest`、`interrupt_on` config | 人可 approve/edit/reject/respond | 通过 interrupt 暂停；需 checkpointer 和 thread id | `InterruptOnConfig`、`ToolCallRequest`、checkpointer、`Command(resume=...)` | `GuardDecision=ask` 的原生实现候选；审批结果映射 `ApprovalResolution` | 高 | 主拦截 | 官方相关；当前仓库 `ask` 只在文档层设计 | LangChain HITL |
| `ModelCallLimitMiddleware` | prebuilt middleware | P1 | 模型调用计数达到 thread/run 限制时 | model call counters、thread/run context | 可返回错误或终止 | 可限制模型循环和成本 | model call counters、exit behavior | 模型滥用/循环检测；可映射 deny 或 audit-only | 中 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `ToolCallLimitMiddleware` | prebuilt middleware | P1 | 工具调用计数达到 thread/run/tool 限制时 | tool name、thread count、run count | 可返回错误或退出 | 可限制工具循环 | tool call counters、exit behavior | 工具滥用检测；可映射为 `deny` 或审计-only | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `ModelFallbackMiddleware` | prebuilt middleware | P2 | 主模型调用失败时 | model request、异常、fallback model list | 切换 fallback model | 不做安全阻断；提升可用性 | model refs、fallback chain | 审计模型切换，避免高风险模型降级无记录 | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `PIIMiddleware` | prebuilt middleware | P1 | 输入、输出或 stream transformer 阶段 | messages、tool-call args、tool outputs、state snapshots | redact/mask/block/hash 等策略 | 可 block 或净化，取决于 strategy | PII detector、stream transformer | DLP 辅助层；命中结果写入 `rule_hits` | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `TodoListMiddleware` | prebuilt middleware | P2 | agent 需要规划/跟踪任务时 | agent plan/task list、state | 管理任务列表 | 不作为安全阻断 | task/todo state | 长任务状态审计；不应作为 Guard 主链路 | 低 | 辅助观测 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `LLMToolSelectorMiddleware` | prebuilt middleware | P1 | 主模型调用前选择相关工具 | state/context、all tools、selection model | 改写暴露给主模型的工具集合 | 不阻断已选动作，但可缩小工具面 | tool selector config、`ModelRequest.tools` | 最小权限工具暴露；工具可见性决策写入 metadata | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `ToolRetryMiddleware` | prebuilt middleware | P1-P2 | 工具调用失败时 | tool name、exception、retry config | 重试工具或返回 `ToolMessage` | 可能重复副作用；慎用于 mutating tools | retry config、`ToolMessage` | mutating tool 重试风险审计；默认不应重试已执行副作用 | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `ModelRetryMiddleware` | prebuilt middleware | P2 | 模型 API 瞬时失败时 | exception、retry config | 重试 handler | 不阻断；失败后按配置 | retry config | 可用性审计；不替代 Guard API fail-closed 策略 | 低 | 辅助观测 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `LLMToolEmulator` | prebuilt middleware | P2 | 测试或离线模拟工具执行时 | tool call、emulation prompt、model | 用 LLM 生成模拟工具结果 | 不适合真实安全拦截 | emulated tool result | 只适合评测/演示中的模拟对照，不作为生产防护 | 低 | 不推荐 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `ContextEditingMiddleware` | prebuilt middleware | P1-P2 | 管理对话上下文、裁剪或清理工具使用记录时 | messages、tool use blocks、state | trim/clear/edit context | 不执行前阻断；影响后续上下文 | context editing config | `ContextBuildEvent`；上下文污染清理和证据保留 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `ProviderToolSearchMiddleware` | prebuilt middleware | P2 | 将工具延迟到 provider server-side tool search 时 | provider tool registry、search query、tool metadata | 暴露或发现 provider-side tools | 不保证本地执行前拦截 | provider tool search config | server-side 工具暴露面审计；需额外策略控制 | 中 | 配置审计 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| Shell tool middleware | prebuilt middleware | P1-P2 | agent 获得持久 shell session 时 | shell command、session cwd/env、outputs | 执行 shell side effects | 高危能力；必须前置 Guard 或禁用 | shell tool state | `ToolCallPayload(tool=shell/exec)`；高优先级拦截对象 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `FilesystemFileSearchMiddleware` | prebuilt middleware | P1-P2 | agent 通过 Glob/Grep 搜索文件时 | paths、patterns、workspace context | 返回文件搜索结果 | 通常读路径；仍可能泄露敏感内容 | file search tool descriptors | 文件读取/枚举审计；敏感路径和越界检测 | 中 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `FilesystemMiddleware` | prebuilt middleware | P1-P2 | agent 获得用于上下文/长期记忆的 filesystem 时 | file path、operation、content、memory namespace | 读写文件/记忆 | 高危读写面；需工具前置 Guard | filesystem state、store/files | `ToolCallPayload` 与 `MemoryEvent`；文件写入和记忆持久化防护 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |
| `SubAgentMiddleware` | prebuilt middleware | P2 | agent 可 spawn subagents 时 | subagent spec、task、tools、state | 创建子 agent 执行任务 | 需限制子 agent 工具和上下文 | subagent config/run state | 多 agent 攻击链归因；子 agent 工具面继承审计 | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Prebuilt middleware |

### 5.3 LangGraph 运行时能力和基础拦截点

| 名称 | 类型 | 阶段 | 触发时机 | 可观测输入 | 可修改输出 | 阻断/取消/暂停能力 | 相关数据结构 | AgentGuard 映射 | 匹配程度 | 适用性 | 当前支持状态 | 来源 |
| ---- | ---- | ---- | -------- | ---------- | ---------- | ------------------ | ------------ | --------------- | -------- | ------ | ------------ | ---- |
| `ToolNode.wrap_tool_call` 或等价 wrapper | LangGraph/ToolNode 工具拦截 | P0 | ToolNode 执行每个 tool call 前后 | tool call name、args、id、state/runtime | 可调用或跳过原 handler | 可阻断工具；API 名称需按 pin 版本确认 | ToolNode、`ToolCallRequest`、`ToolMessage` | P0 工具执行前 Guard；首选官方方向 | 高 | 主拦截 | 仓库文档设计为首选，代码用 `SecureToolNode` 降级实现 | `docs/03_adapters/langgraph_adapter.md` |
| `SecureToolNode.invoke_tool` | 当前仓库降级实现 | P0 | bench tool registry 执行工具前 | `tool_name`、`arguments`、`security`、`trace_id`、`call_id` | 不改写工具结果；可跳过工具执行 | `deny`/`ask` 返回 blocked result，不执行 registry | `ToolExecutionResult`、`ToolCallEvent`、`PolicyDecision`、`AuditEvent` | 当前 P0 实际拦截链：build event -> Guard API/Core -> audit -> allow/blocked result | 高 | 主拦截 | 已实现 | `agentguard_langgraph_bench/src/agentguard_langgraph_bench/secure_tool_node.py` |
| 手写 `tool_node(state)` | LangGraph graph node | P0 | 自定义 StateGraph 工具节点被路由到时 | state 中的 `tool_calls`、security、trace id | 可更新 `tool_results`、清空 `tool_calls` | 可完全控制是否执行工具 | StateGraph node function、state dict | 低版本或 prebuilt agent 不便插桩时的稳定 fallback | 高 | 主拦截 | 已在 `SecureToolNode.__call__` 中等价实现 | `docs/03_adapters/langgraph_adapter.md` |
| `interrupt(...)` | LangGraph pause primitive | P0-P1 | graph node 或 tool 内部调用时 | JSON-serializable payload、当前 graph state、thread id | resume 后返回外部输入 | 暂停执行并等待外部输入；需要 checkpointer | `interrupt`、`Command(resume=...)`、`Interrupt` | `GuardDecision=ask` 的暂停机制；payload 承载 approval details | 高 | 主拦截 | 仓库文档设计，代码未接入真实审批 wait | LangGraph Interrupts；`docs/03_adapters/langgraph_adapter.md` |
| `Command(resume=...)` | LangGraph resume input | P0-P1 | interrupt 后恢复执行时 | resume value 或 interrupt id -> value map | 作为 interrupt 调用返回值进入 node | 恢复被暂停的 graph | `Command` | Dashboard/Guard API 审批结果返回 adapter 后恢复 graph | 高 | 主拦截 | 官方相关，仓库未接入 | LangGraph Interrupts |
| checkpointer + `thread_id` | LangGraph persistence | P0-P1 | 编译 graph 或运行 config 设置时 | graph state、configurable `thread_id` | 保存/恢复状态 | 支持 indefinite wait 和故障恢复 | `InMemorySaver`、`AsyncPostgresSaver`、config | `approval_id`、`trace_id`、`thread_id` 关联；`ask` 必备 | 高 | 主拦截 | 官方相关，仓库未接入持久审批恢复 | LangGraph Interrupts |
| Store / memory | LangGraph state/memory | P1-P2 | 长期记忆读写时 | namespace、key、value、context/session | 可读写 memory | 不天然阻断；需 wrapper/middleware | Store API、memory namespace/key/value、Item | `MemoryEvent`；检测记忆中毒、敏感记忆写入 | 高 | 主拦截 | 仓库文档设计 memory/store wrapper，未实现 | LangGraph Stores；`docs/03_adapters/langgraph_adapter.md` |
| `stream_events(..., version="v3")` | LangChain/LangGraph streaming | P1 | agent/graph 运行时 | raw events、messages、tool_calls、values、subgraphs、extensions、interrupts | 不改写；消费 typed projections | 观察-only；可驱动 interrupt loop | stream projections、`stream.interrupted`、`stream.interrupts` | AttackBench trace、Dashboard live trace、审批 interrupt 检测 | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Event streaming；LangGraph Event streaming |
| Custom stream transformers | middleware stream extension | P2 | stream 输出投影时 | live stream events、scope tuple | 可注册自定义 projections | 观察/投影，不阻断 | `StreamTransformer`、middleware `transformers` | 安全侧通道输出，例如 redacted tool activity 或 risk deltas | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Custom middleware |

### 5.4 LangChain/LangGraph 数据结构

| 名称 | 类型 | 阶段 | 触发时机 | 可观测输入 | 可修改输出 | 阻断/取消/暂停能力 | 相关数据结构 | AgentGuard 映射 | 匹配程度 | 适用性 | 当前支持状态 | 来源 |
| ---- | ---- | ---- | -------- | ---------- | ---------- | ------------------ | ------------ | --------------- | -------- | ------ | ------------ | ---- |
| `AgentState` | state schema | P1 | middleware 和 graph node 读取/更新 state 时 | `messages`、custom fields、counters、security context | reducer 合并 dict update | 可配合 `jump_to` 改变流程 | TypedDict state schema | 承载 `trace_id`、`case_id`、security metadata 和中间统计 | 高 | 主拦截 | 官方相关；bench 使用 plain dict state | LangChain Custom middleware |
| `Runtime` | runtime context | P1 | middleware hook 被调用时 | configurable context、runtime metadata、store/context | 通常不改写 | 不阻断 | `langgraph.runtime.Runtime` | 获取 user/session/tenant 配置并写入 `SecurityContext.metadata` | 高 | 辅助观测 | 官方相关，仓库未接入 | LangChain Custom middleware；LangGraph Stores |
| `ModelRequest` | model call request | P1 | `wrap_model_call` 中 | messages、system message、model、tools、state、runtime | `request.override(...)` 改模型、系统提示、工具集 | 可 short-circuit handler | `ModelRequest` | `ContextBuildEvent`、模型输入审计、动态工具最小权限 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `ModelResponse` | model call response | P1 | `wrap_model_call` 返回或 `after_model` 后 | AIMessage、usage、tool calls | 可包进 `ExtendedModelResponse` 更新 state | 不阻断已发生模型调用；可后续跳转 | `ModelResponse`、`AIMessage` | `model_output_produced`；模型输出和 tool plan 风险检测 | 高 | 辅助观测 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `ExtendedModelResponse` | response + state command | P1 | `wrap_model_call` 返回时 | model response、Command update | 可携带 `Command(update=...)` | 不直接暂停；更新 state | `ExtendedModelResponse`、`Command` | 写入风险分数、token usage、上下文安全标签 | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `ToolCallRequest` | tool call request | P0 | `wrap_tool_call` 或 HITL predicate | `tool_call.name`、`tool_call.args`、tool object、state/runtime | 可传给 handler 或不调用 handler | 可阻断/替代工具执行 | `ToolCallRequest` | `ToolCallPayload.tool`、`arguments`、`derived_resources` 的直接来源 | 高 | 主拦截 | 官方相关；bench 自定义等价入参 | LangChain Custom middleware；HITL |
| `ToolMessage` | tool result message | P0-P1 | 工具执行或拦截后返回给模型 | content、tool_call_id、status/error | 可返回安全消息或错误消息 | 阻断时可返回 synthetic `ToolMessage` | `ToolMessage` | `deny`/`ask` 的模型可见安全消息；`ToolResultEvent` 来源 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `Command` | graph control object | P0-P1 | middleware、node、interrupt resume | `update`、`goto`、`resume`、graph routing | 更新 state 或改路由 | `resume` 恢复暂停；`goto` 改变流程 | `Command` | 审批恢复、阻断后跳转、风险 metadata 写入 | 高 | 主拦截 | 官方相关，仓库未接入 | LangGraph Interrupts；LangChain Custom middleware |
| `Interrupt` | interrupt payload object | P0-P1 | graph 暂停后返回给 caller/stream 时 | `id`、`value`、action requests/review configs | 不改写；外部据此生成 resume | 暂停状态载体 | `Interrupt`、`stream.interrupts` | Guard approval request 展示和 `approval_id` 关联 | 高 | 主拦截 | 官方相关，仓库未接入 | LangGraph Interrupts；LangChain HITL |
| `InterruptOnConfig` | HITL config | P0-P1 | `HumanInTheLoopMiddleware` 配置命中时 | `allowed_decisions`、description、`when` predicate | 配置允许 approve/edit/reject/respond | 决定是否 interrupt | `InterruptOnConfig` | `GuardDecision=ask` 的策略配置参考 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain HITL |
| `SystemMessage` | message type | P1 | prompt/system context 构造和改写 | `content_blocks`、cache control | 可通过 middleware 改写 | 不阻断 | `SystemMessage` | `ContextBuildEvent`；系统上下文来源和注入审计 | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `AIMessage` | message type | P1 | 模型响应后 | content、tool calls、usage metadata | 可追加替代消息或 state update | 可配合 jump 终止 | `AIMessage` | `model_output_produced`、tool call proposed 提取 | 高 | 辅助观测 | 官方相关，仓库未接入 | LangChain Custom middleware |
| `HumanMessage` / user message | message type | P1 | 用户输入进入 agent | content、metadata | middleware 可改 state/messages | 可在前置 hook block | message object | `user_input_received`、source trust | 高 | 主拦截 | 官方相关，仓库未接入 | LangChain overview |
| `BaseTool` / `@tool` | tool descriptor | P0 | agent 注册工具时 | name、description、args schema | tool implementation 返回 result | tool 内可调用 `interrupt` 暂停 | LangChain tool | 构造 `ToolDescriptor` 和 category/kind 映射 | 高 | 主拦截 | 官方相关；bench 用 MockToolRegistry | LangChain Tools |
| `ToolRuntime` | tool runtime info | P1 | tool 函数需要运行时信息时 | state、store、config、tool_call_id、stream writer、execution info | tool 可写 store 或返回 result | tool 内可决定失败/中断 | `ToolRuntime` | 工具内补充 `SecurityContext.metadata`、记忆读写审计 | 高 | 辅助观测 | 官方相关，仓库未接入 | LangChain Tools |
| Store Item / namespace | memory data structure | P1-P2 | Store 读写长期记忆时 | `namespace`、`key`、`value`、`created_at`、`updated_at` | `store.put`/`store.aput` 可写入或覆盖 value | 不天然阻断；需 wrapper/middleware | Store Item、namespace tuple | `MemoryEvent`；记忆中毒、敏感持久化、跨 thread 泄露检测 | 高 | 主拦截 | 官方相关，仓库未接入 | LangGraph Stores |
| `Stream` projections | streaming data | P1-P2 | `stream_events(..., version="v3")` | `stream.messages`、`tool_calls`、`values`、`subgraphs`、`extensions`、`interrupts` | 不改写 | 观察/驱动审批 loop | stream run object | Dashboard live trace、AttackBench trace、审批状态 | 中 | 辅助观测 | 官方相关，仓库未接入 | LangChain Event streaming |
| `ToolExecutionResult` | 当前仓库数据结构 | P0 | `SecureToolNode` 返回 tool result | tool name、call id、executed、blocked、decision、status、result、side effects、event、audit event | 由 adapter 构造 | blocked result 表示工具未执行 | bench model | Runner 证据；可回传 AttackBench 指标 | 高 | 主拦截 | 已实现 | `agentguard_langgraph_bench/src/agentguard_langgraph_bench/models.py` |

## 6. AgentGuard 映射矩阵

| AgentGuard 目标事件/对象 | 首选来源 | 次选/补充来源 | 关键字段 | 决策动作 | 匹配结论 |
| ------------------------ | -------- | ------------- | -------- | -------- | -------- |
| `ToolCallPayload` / `tool_call_proposed` | LangChain `wrap_tool_call`、LangGraph `ToolNode` wrapper、bench `SecureToolNode.invoke_tool`、OpenClaw `before_tool_call` | OpenClaw `/tools/invoke` 暴露面审计、LangChain Shell/File/Filesystem tools | tool name、category/kind、call id、arguments、derived resources、trace/run/session | `allow` 执行工具；`deny` 不执行；`ask` interrupt/approval | 高/主拦截 |
| `ContextBuildEvent` | LangChain `before_model`、`wrap_model_call`、OpenClaw `before_prompt_build`、`agent_turn_prepare`、`before_agent_run` | `message:preprocessed`、session compaction hooks、skills watcher、next-turn injections | sources、source trust、will enter context、sanitized、instruction-like text | 高风险上下文可 block、sanitize、tool filter 或 audit | 高/主拦截 |
| `ToolResultEvent` | OpenClaw `tool_result_persist`、`after_tool_call`、LangChain `wrap_tool_call` after handler | stream tool output、agent tool result middleware | tool、content preview、size、will enter context、will persist、instruction-like text | 污染结果可 sanitize、not persist、audit 或 block downstream | 高/主拦截 |
| `MemoryEvent` | LangGraph Store/memory wrapper、OpenClaw session extension、skills memory surfaces | LangChain `ToolRuntime.store`、filesystem middleware、long-term memory surfaces | namespace、key、value preview、source trust、operation、will persist | untrusted memory write 可 ask/deny | 高/主拦截 |
| 消息外发事件 | OpenClaw `message_sending`、`reply_payload_sending`、`before_dispatch` | LangChain tool `send_email` / message tool call | content、recipient/channel、sender/session、sensitive pattern | `deny` cancel；`ask` require approval；`allow` send | 高/主拦截 |
| 模型输入事件 | LangChain `before_model`/`wrap_model_call`、OpenClaw `before_agent_run`/`llm_input` | event streaming message snapshots | messages、system prompt、attachments、context sources | block、sanitize、tool filter 或 audit | 高/主拦截 |
| 模型输出事件 | LangChain `after_model`、`wrap_model_call` response、OpenClaw `llm_output`、`before_agent_finalize` | `stream.messages` final output | content、tool calls、usage、reasoning availability | terminate、revise、rewrite safe message、audit | 高/主拦截 |
| `AuditEvent` | 所有 observation hook 和 adapter enforcement point | stream projections、internal hooks、security audit、config audit | trace id、runtime、stage、decision、risk、reason、links | Dashboard、指标和答辩证据来源 | 中/辅助观测 |
| `GuardDecision=ask` | LangGraph `interrupt`、LangChain `HumanInTheLoopMiddleware`、OpenClaw `before_tool_call.requireApproval` | OpenClaw approval adapter、Dashboard resolve | approval options、resource、thread id、approval id、timeout behavior | 暂停动作，等待 Guard API/Dashboard resolve | 高/主拦截 |
| Config/Plugin Audit | OpenClaw `before_install`、`security audit`、plugin manifest/config、webhook `hooks`、skills watcher | Gateway lifecycle hooks、tool policy、`/tools/invoke` auth boundary | plugin id、contracts、dangerous flags、tool policy、network exposure | P2 告警、阻断安装或要求修复配置 | 中/配置审计 |

## 7. 验证缺口

1. OpenClaw 官方已确认 `before_tool_call`、`after_tool_call`、`llm_input`、`llm_output` 等 hook 名称和主要能力；实现前仍需用最小插件实测 SDK TypeScript 类型、handler return shape、priority/timeout 交互和多插件组合顺序。
2. `before_tool_call.requireApproval` 是 OpenClaw 原生暂停能力，但要接入 AgentGuard 的 `ask`，仍需适配 Guard API 审批记录、Dashboard resolve、OpenClaw approval lifecycle 和 `onResolution` 回写。
3. OpenClaw host-trusted surfaces 的具体 SDK 类型需要在实现插件时从 `openclaw/plugin-sdk/*` 子路径确认，本文只锁定官方语义和 AgentGuard 映射。
4. LangChain middleware 与 HITL 能力需要 pin 版本后再编码：`HumanInTheLoopMiddleware.when` 依赖 `langchain>=1.3.3`，stream projections/transformers 也应按当前 pin 版本验证。
5. 当前稳定 schema 只覆盖 P0 `GuardEvent`、`ToolCallPayload`、`GuardDecision`、`AuditEvent`。P1 的上下文、工具结果、消息外发、记忆和模型事件在接口契约中已有示例，但 JSON Schema 和 Core 检测器仍需后续补齐。
6. 工具重试、模型重试和 LLM tool emulator 可能改变证据语义。凡是 `write_file`、`send_email`、`call_api`、`code_exec`、`memory_write` 等 mutating tool，AgentGuard adapter 应记录 call id、attempt、side effects，避免把重试误判为独立 benign 行为。
7. Event streaming 是优秀观测面和审批 loop 驱动面，但不是执行前阻断面。P0 阻断必须落在工具 handler 之前，不能只依赖 stream 事后检测。
8. “匹配程度/适用性”是基于官方能力与 AgentGuard 目标的适配判断，不表示当前仓库已经实现；实现状态必须以 `当前支持状态` 为准。
