# OpenClaw Security Plugin

## 1. 定位

OpenClaw 侧用于真实应用演示和开源智能化应用接入。

采用插件方式，不优先修改 OpenClaw 源码。

## 2. 插件目录

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

## 3. Hook 优先级

P0：

- `before_tool_call`
- `message_sending`

P1：

- `before_prompt_build`
- `after_tool_call`
- `tool_result_persist`
- `message_received`

P2：

- `llm_input`
- `llm_output`
- `before_install`
- Config Audit

## 4. 决策映射

| Core 决策 | OpenClaw 行为 |
|---|---|
| allow | 放行 |
| deny | block |
| ask | requireApproval |
| modify | 改写 params |
| audit_only | 仅记录 |

## 5. Config Audit

检查：

- `dmPolicy = open`
- `allowFrom = *`
- `sandbox.mode = off`
- `tools.deny` 缺失
- Gateway 暴露
- 插件上下文权限过大
