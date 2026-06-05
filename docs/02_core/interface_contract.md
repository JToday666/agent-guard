# 接口契约与事件模型

## 1. 文档定位

本文定义 Adapter、Core、Dashboard、AttackBench 之间的公共契约。实现代码、schemas、测试和 Dashboard 页面必须以本文为准。

关联入口：

- [Agent Security Core 设计](core_design.md)
- [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)
- [Dashboard 与审批流](../04_apps/dashboard_design.md)
- [AttackBench 攻击样本与评测](../05_redteam/attackbench.md)

## 2. 统一原则

```text
Runtime Native Event
→ Adapter Mapping
→ AgentGuard Event
→ Core Decision
→ Adapter Enforcement
→ AuditEvent
```

核心约束：

- `pre_execution=true` 的工具事件必须在工具执行前送入 Core。
- Core 返回 `deny` 时，Adapter 必须阻断工具执行。
- Core 返回 `ask` 时，Adapter 必须暂停动作并等待审批。
- AuditEvent 是 Dashboard 和指标统计的共同输入。

## 3. Core API

| API | 阶段 | 用途 |
|---|---|---|
| `POST /v1/evaluate/tool-call` | P0 | 工具调用前风险判断 |
| `POST /v1/audit/event` | P0 | 写入审计事件 |
| `GET /v1/audit/events` | P0 | Dashboard 事件列表 |
| `GET /v1/metrics/eval` | P0 | 评测指标 |
| `POST /v1/evaluate/context-build` | P1 | 上下文拼接审计 |
| `POST /v1/evaluate/model-call` | P1 | 模型输入输出审计 |
| `POST /v1/evaluate/tool-result` | P1 | 工具结果回流审计 |
| `POST /v1/evaluate/message` | P1 | 消息外发审计 |
| `POST /v1/evaluate/memory-write` | P1 | 记忆写入审计 |
| `GET /v1/audit/traces/{trace_id}` | P1 | 攻击链路详情 |
| `GET /v1/metrics/runtime` | P1 | 运行时监控指标 |
| `GET /v1/approvals/pending` | P1 | 待审批动作 |
| `POST /v1/approvals/{approval_id}/resolve` | P1 | 审批处理 |

## 4. 鉴权

```http
Authorization: Bearer <AGENTGUARD_TOKEN>
```

P0 可以使用 demo token；P1 之后需要支持配置化 token 和运行时标识。

## 5. SecurityContext

`SecurityContext` 记录用户任务、来源、会话、运行时、信任级别和派生资源，是任务一致性判断的主要输入。

```json
{
  "user_task": "总结邮件内容",
  "source_type": "email",
  "source_trust": "untrusted",
  "channel": "telegram",
  "sender_id": "tg:12345",
  "session_id": "sess_001",
  "run_id": "run_001",
  "agent_id": "main",
  "current_step": "before_tool",
  "model_intent": "读取文件辅助总结",
  "context_sources": [],
  "derived_paths": ["/private/token.txt"],
  "metadata": {}
}
```

## 6. ToolCallEvent

P0 首个稳定事件模型。Adapter 必须把运行时工具调用映射成该结构。

```json
{
  "schema_version": "0.1",
  "event_id": "evt_tool_001",
  "event_type": "tool_call",
  "runtime": "langgraph",
  "trace_id": "trace_001",
  "case_id": "PI-001",
  "attack_type": "indirect_prompt_injection",
  "is_malicious": true,
  "timestamp": "2026-06-04T12:00:00+09:00",
  "security_context": {},
  "tool": {
    "name": "read_file",
    "category": "file",
    "kind": "file_read",
    "input_kind": null,
    "call_id": "call_001"
  },
  "arguments": {
    "path": "/private/token.txt"
  },
  "derived_resources": [
    {
      "resource_type": "file",
      "operation": "read",
      "target": "/private/token.txt",
      "data_classification": "secret",
      "direction": "local"
    }
  ],
  "pre_execution": true,
  "metadata": {}
}
```

## 7. PolicyDecision

Core 对每个评估请求返回一个决策。P0 必须支持 `allow`、`deny`、`ask`。

```json
{
  "decision_id": "dec_001",
  "decision": "deny",
  "risk_score": 92,
  "severity": "high",
  "rule_hits": [
    {
      "rule_id": "P001_sensitive_file_access",
      "rule_name": "Sensitive File Access",
      "severity": "critical",
      "evidence": ["target path contains token.txt"]
    }
  ],
  "reason": "请求读取敏感文件，且与当前用户任务不一致",
  "safe_message": "该工具调用涉及敏感资源，已被阻断。",
  "approval": null,
  "latency_ms": 18
}
```

## 8. AuditEvent

AuditEvent 是 Dashboard、指标和答辩证据的共同数据来源。

```json
{
  "audit_id": "audit_001",
  "trace_id": "trace_001",
  "runtime": "langgraph",
  "stage": "before_tool_call",
  "event_type": "tool_call",
  "summary": "Agent attempted to read /private/token.txt",
  "decision": "deny",
  "risk_score": 92,
  "severity": "high",
  "blocked": true,
  "resource_targets": ["/private/token.txt"],
  "rule_hits": ["P001_sensitive_file_access"],
  "reason": "敏感文件访问，且与当前任务不一致"
}
```

## 9. P0/P1/P2 开发边界

| 阶段 | 契约范围 |
|---|---|
| P0 | `ToolCallEvent`、`PolicyDecision`、`AuditEvent`、基础审计列表和评测指标 |
| P1 | 上下文、模型调用、工具结果、消息外发、记忆写入、trace 查询和审批 |
| P2 | `modify`、`audit_only`、`shadow_deny`、审计完整性、provenance 扩展 |

## 10. 冻结规则

- P0 后不删除 `ToolCallEvent`、`PolicyDecision`、`AuditEvent` 字段。
- 新字段只能 optional 添加。
- Dashboard 只读 Core。
- Adapter 不写核心规则。
- Core 不执行工具。
- `schema_version` 变更必须同步 `schemas/`、contract tests 和文档。

## 11. 验收证据

1. P0 三个核心模型有 JSON Schema。
2. `POST /v1/evaluate/tool-call` 能返回 `allow`、`deny`、`ask`。
3. Adapter 能依据 `PolicyDecision` 控制工具是否执行。
4. Dashboard 能基于 AuditEvent 展示阻断原因。
5. AttackBench runner 能用 `case_id`、`trace_id` 汇总指标。
