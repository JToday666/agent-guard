# OpenClaw Security Plugin

## 1. 文档定位

OpenClaw 侧用于开源智能化应用接入和正式演示。P1 前必须先验证 OpenClaw 插件机制和 Hook 可用性，再实现完整拦截链路。

关联入口：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [Dashboard 与审批流](../04_apps/dashboard_design.md)
- [演示脚本](../06_delivery/demo_script.md)

## 2. 模块职责

| 模块                 | 职责                                           |
| -------------------- | ---------------------------------------------- |
| Plugin Entry         | 注册 OpenClaw 插件和 Hook                      |
| Security Core Client | 调用 Core API 并处理超时、失败和 adapter token |
| Hook Mapping         | 将 OpenClaw 原生事件映射成 AgentGuard Event    |
| Approval Adapter     | 将 `ask` 映射为 OpenClaw 审批或阻断提示        |
| Config Audit         | 检查 OpenClaw 高风险配置                       |

## 3. 插件目录

```text
packages/agentguard-openclaw-plugin/
├── package.json
├── openclaw.plugin.json
└── src/
    ├── index.ts
    ├── security_core_client.ts
    ├── hooks/
    ├── mapping/
    ├── approval/
    └── config_audit/
```

## 4. Hook 优先级

| 阶段    | Hook                       | 用途               |
| ------- | -------------------------- | ------------------ |
| P1 验证 | `before_tool_call`         | 工具执行前拦截     |
| P1 验证 | `message_sending`          | 消息外发审计       |
| P1      | `before_prompt_build`      | 上下文拼接审计     |
| P1      | `after_tool_call`          | 工具结果审计       |
| P1      | `tool_result_persist`      | 工具结果持久化审计 |
| P2      | `llm_input` / `llm_output` | 模型调用链路监控   |
| P2      | `before_install`           | 插件安装和配置审计 |

如果实际 OpenClaw Hook 名称不同，必须先更新本文和 [接口契约](../02_core/interface_contract.md)，再实现插件。

## 5. Hook Compatibility Test

OpenClaw 接入在 P1 前必须先做 Hook 兼容性验证。验证结果决定插件实现范围，不能在未验证 Hook 的情况下承诺完整拦截链路。

### Hook 验证状态

状态枚举：

| 状态     | 含义                                                   |
| -------- | ------------------------------------------------------ |
| 待验证   | 尚未完成真实 OpenClaw 运行验证                         |
| 已验证   | 已通过最小 Hook 兼容性测试                             |
| 不支持   | 当前 OpenClaw 版本不提供该 Hook 或必要能力             |
| 降级实现 | Hook 能力不完整，需要用替代 Hook 或 Adapter 侧封装完成 |

| Hook                       | 状态   | 备注                                             |
| -------------------------- | ------ | ------------------------------------------------ |
| `before_tool_call`         | 待验证 | P1 核心，决定能否做工具调用前阻断                |
| `message_sending`          | 待验证 | 外发 DLP，验证能否读取和拦截消息                 |
| `before_prompt_build`      | 待验证 | 上下文审计，验证能否读取来源和 prompt            |
| `tool_result_persist`      | 待验证 | 工具结果回流，验证能否判断是否持久化或进入上下文 |
| `llm_input` / `llm_output` | 待验证 | 模型链路监控，P2 增强项                          |

| Hook                       | 目标               | 阶段    | 必须验证的字段/能力                                                                                                                                   |
| -------------------------- | ------------------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `before_tool_call`         | 工具调用前拦截     | P1 必测 | 是否触发；`toolName`、`params`、`toolKind`、`toolCallId`、`runId`；能否 `block`、改写 `params`、`requireApproval`；能否关联 `session_id` / `trace_id` |
| `message_sending`          | 外发消息 DLP       | P1 必测 | 是否触发；外发内容、目标 channel / receiver；能否 rewrite、cancel；能否记录发送结果                                                                   |
| `before_prompt_build`      | 上下文拼接审计     | P1      | 是否触发；能否读取 prompt、session messages、来源标记；能否追加安全上下文                                                                             |
| `after_tool_call`          | 工具结果审计       | P1      | 是否触发；能否读取工具结果、错误、duration；能否关联原始 `toolCallId`                                                                                 |
| `tool_result_persist`      | 工具结果持久化审计 | P1      | 是否触发；能否改写持久化内容；能否识别结果是否会进入后续上下文                                                                                        |
| `llm_input` / `llm_output` | 模型调用链路监控   | P2      | 是否触发；能否读取模型输入/输出、usage、runId；是否需要额外 conversation access 配置                                                                  |

兼容性测试输出至少包含：

- Hook 是否触发；
- 可用字段清单；
- 支持的决策能力；
- `run_id`、`session_id`、`trace_id` 关联方式；
- 不能支持的能力和降级方案。

## 6. 决策映射

| Core 决策    | OpenClaw 行为      |
| ------------ | ------------------ |
| `allow`      | 放行               |
| `deny`       | block              |
| `ask`        | requireApproval    |
| `modify`     | 改写 params 后执行 |
| `audit_only` | 仅记录             |

## 7. 鉴权边界

OpenClaw Plugin 使用 adapter token 调用 Core：

```http
Authorization: Bearer <AGENTGUARD_ADAPTER_TOKEN>
```

P0 adapter scopes：

```text
event:evaluate
event:audit:write
approval:wait
```

OpenClaw Plugin 不得拥有 `approval:resolve`，不得创建 browser session，不能读取 Dashboard 数据。

## 8. Config Audit

P2 检查项：

- `dmPolicy = open`
- `allowFrom = *`
- `sandbox.mode = off`
- `tools.deny` 缺失
- Gateway 暴露
- 插件上下文权限过大

## 9. P0/P1/P2 开发边界

| 阶段 | 交付                                                                                       |
| ---- | ------------------------------------------------------------------------------------------ |
| P0   | 不要求 OpenClaw 完整接入，只保留设计                                                       |
| P1   | 验证 Hook、完成 `before_tool_call` 和 `message_sending`，Dashboard 显示 `runtime=openclaw` |
| P2   | Config Audit、多渠道审批、模型链路监控                                                     |

## 10. 验收证据

1. OpenClaw 中一次工具调用触发 `before_tool_call`。
2. 插件能构造 ToolCallEvent 并调用 Core。
3. `deny` 能阻断 OpenClaw 工具调用。
4. Dashboard 能显示 OpenClaw runtime 事件。
5. Config Audit 能输出至少 3 类配置风险。
