# 接口契约与事件模型

## 1. 统一原则

```text
Runtime Native Event
→ Adapter Mapping
→ AgentGuard Event
→ Core Decision
→ Adapter Enforcement
→ AuditEvent
```

## 2. 主要 API

```text
POST /v1/evaluate/context-build
POST /v1/evaluate/model-call
POST /v1/evaluate/tool-call
POST /v1/evaluate/tool-result
POST /v1/evaluate/message
POST /v1/evaluate/memory-write
POST /v1/audit/event

GET  /v1/audit/events
GET  /v1/audit/traces/{trace_id}
GET  /v1/metrics/runtime
GET  /v1/metrics/eval

GET  /v1/approvals/pending
POST /v1/approvals/{approval_id}/resolve
```

## 3. 鉴权

```http
Authorization: Bearer <AGENTGUARD_TOKEN>
```

## 4. SecurityContext

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

## 5. ToolCallEvent

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

## 6. PolicyDecision

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

## 7. AuditEvent

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

## 8. 冻结规则

- P0 后不删除 `ToolCallEvent`、`PolicyDecision`、`AuditEvent` 字段。
- 新字段只能 optional 添加。
- Dashboard 只读 Core。
- Adapter 不写核心规则。
- Core 不执行工具。
