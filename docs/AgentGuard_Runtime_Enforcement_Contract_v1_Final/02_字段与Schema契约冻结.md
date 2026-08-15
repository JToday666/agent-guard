# AgentGuard Runtime Enforcement Contract v1 — 字段与 Schema 契约冻结

> 基线：`dev@efe1c95df52b2be3e62d4b48510bfc410397c69f`  
> 本文冻结**公共字段、内部执行状态、ID 语义、Strong Approval Binding 与 Receipt 映射**。实施期不得随意改变语义；如需变更必须进行 contract review。

---

## 1. Freeze 层级

### F0 — 已有公共稳定契约，P0 不破坏

- `GuardEvent schema_version=0.3`
- `GuardDecision` 当前 wire contract
- `AuditEvent / RuntimeOutcomeReceipt schema_version=0.4`
- `POST /v1/guard/evaluate`
- `GET /v1/approvals/{approval_id}/wait`
- `POST /v1/audit/events`
- `RuntimeExecutionStatus`
- `RuntimeResultDisposition`
- `RuntimeOutcomeKind`

### F1 — 本轮新增/收敛的 Runtime 内部契约

- `EnforcementGateState`
- `RuntimeCorrelationState`
- Capability Profile
- lifecycle-aware eviction
- C2 Spike Gate

### F2 — Core V2.1 Strong Profile additive contract

- `GuardEvaluationResponse.enforcement_binding?`
- `POST /v1/approvals/{approval_id}/execution-leases/consume`
- `ExecutionLeaseConsumeRequest/Response`
- Receipt 中可选 `lease_id/consumption_id`（如后续 schema 正式扩展，必须 additive + version review）

---

## 2. ID 契约

| 字段 | 语义 | 生产者 | Retry 规则 |
|---|---|---|---|
| `trace_id` | 一次 Agent 运行/调查链 | Runtime/Adapter | 同链稳定 |
| `event_id` | 一次 GuardEvent/evaluation attempt | Adapter | transport retry 复用；新 attempt 新建 |
| `action_id` | 一个逻辑可执行动作 | Runtime-native ID 优先 | 跨 pre/post hook 必须稳定 |
| `decision_id` | 一次 Core 决策 | Core | evaluate idempotent replay 返回同事实 |
| `policy_audit_id` | policy_evaluation AuditEvent ID | Guard API | 权威关联 |
| `approval_id` | 一次审批请求 | Guard API | 不可替代 action identity |
| `audit_id` | 一条持久化审计事实 | producer 按契约 | runtime receipt deterministic |
| `lease_id` | Strong Profile 执行租约 | Guard API | consume 同键有效期内重试返回同 lease |
| `consumption_id` | one-use grant 消费事实 | Guard API | 与 grant/action/fingerprint 原子绑定 |

### 2.1 `event_id != action_id`

禁止：

```text
event_id 直接当 action_id
```

因为同一个 action 可以产生：

```text
pre-exec GuardEvent
runtime outcome
result GuardEvent
result isolation receipt
```

这些记录有不同 event_id，但应通过同一 action_id 聚合。

### 2.2 OpenClaw native ID Gate

当前 mapper 在 native `toolCallId` 缺失时会生成 local call id。该 fallback 对单次 pre-exec evaluate 有效，但**不能自动证明跨 hook C2 correlation**。

因此：

```text
C1: local fallback MAY be used
C2: MUST have stable native/cross-hook identity
```

若 `after_tool_call` 无法获得与 `before_tool_call` 相同 ID：

```text
C2 = NOT_SUPPORTED
terminal execution = unknown
```

---

## 3. EnforcementGateState 冻结

```ts
export type EnforcementGateState =
  | "evaluating"
  | "allowed"
  | "approval_pending"
  | "approval_released"
  | "blocked"
  | "timed_out"
  | "binding_failed";
```

派生：

```ts
executionAuthorized =
  gateState === "allowed" || gateState === "approval_released";
```

禁止再以单个：

```ts
released: boolean
```

承担全部 gate 语义。

上述 lowercase TS 字面量为 wire/代码规范形态；`01_Runtime_Enforcement_Contract_v1.md` §6 的 UPPERCASE 仅为图示记法，两者逐值等价映射。

---

## 4. OpenClaw RuntimeCorrelationState 冻结

这是**插件内 ephemeral state**，不是新后端事实模型。

```ts
export type RuntimeCorrelationState = {
  // Native identity
  toolCallId: string;
  runtimeActionId: string;
  correlationSource: "native_tool_call_id" | "local_fallback";

  // Guard linkage
  guardEventId: string;
  traceId: string;
  policyAuditId?: string;
  decisionId?: string;
  decision?: "allow" | "ask" | "deny";

  // Gate lifecycle
  gateState: EnforcementGateState;
  approvalId?: string | null;
  approvalStatus?: "pending" | "allowed" | "denied" | "expired" | "unknown";

  // Strong binding (P1)
  authorizationFingerprint?: string;
  runtimeBindingId?: string;
  leaseId?: string;
  consumptionId?: string;
  // leaseToken MUST NOT be stored here

  // Terminal observation
  terminalStatus?: "executed" | "failed";
  terminalObservedAt?: string;
  resultPersistObserved?: boolean;

  // Bounded lifecycle
  createdAtMs: number;
  updatedAtMs: number;

  // Existing context fields may remain temporarily
  toolName: string;
  toolKind?: string | null;
  toolInputKind?: string | null;
  derivedPaths: string[];
  // Full raw params SHOULD be reduced in P1.
};
```

### 4.1 不持久化字段

以下禁止进入 durable correlation/spool：

```text
leaseToken
raw API secret
raw credential
full tool result
unbounded prompt/context
```

### 4.2 `policyAuditId/decisionId` 写入顺序

在 `before_tool_call` 中：

```text
remember state(gate=evaluating)
→ await evaluate
→ attach decisionId + policyAuditId + decision
→ set gate state
→ await approval if needed
→ final gate state
→ RETURN handler
```

这条 happens-before 是 P0 contract invariant。

---

## 5. GuardDecision Wire 语义

当前 `GuardDecision` 的稳定 wire 字段包括：

```text
decision_id
decision
risk_score
severity
categories
rule_hits
reason
safe_message
approval_intent
latency_ms
```

Python `GuardDecision.blocked` 是 derived property；不要把它假定为 GuardDecision JSON wire field。

公共统计应使用：

```text
policy decision: decision
runtime prevention: RuntimeOutcome.evidence.execution.status
```

注：`schemas/guard_decision.schema.json` 中的 `enforcement`/`effects` 为 deprecated legacy-compat 字段（仅校验存量数据，`tests/test_schemas.py` 已断言 deprecated 标记），不属于稳定 wire 语义，新实现不得使用。

---

## 6. Strong EnforcementBinding TARGET-P1

当 Core V2.1 ActionIR/Authority 接入生产 evaluate 后，`GuardEvaluationResponse` MAY additive 增加：

```json
{
  "enforcement_binding": {
    "schema_version": "2.1",
    "action_id": "call_001",
    "authorization_fingerprint": "hmac-sha256:...",
    "runtime_binding_id": "binding_x",
    "requires_execution_lease": true
  }
}
```

建议模型：

```python
class EnforcementBinding(BaseModel):
    schema_version: Literal["2.1"] = "2.1"
    action_id: str
    authorization_fingerprint: str
    runtime_binding_id: str
    requires_execution_lease: bool
```

冻结要求：

- `action_id` 必须与本次 canonical `ActionIR.action_id` 一致；
- fingerprint 只能由服务端/Core V2.1 authoritative normalization 产生；
- Adapter 不得本地重新计算另一套授权 fingerprint；
- `audit_fingerprint` 不能替代 `authorization_fingerprint`。

Additive 语义澄清（Freeze Gate 核对补齐，ADDITIVE/TARGET）：

- **在场条件**：`enforcement_binding` MAY 仅在 `decision ∈ {allow, ask}` 且该 action 具备 C2+ 资格时返回；其余情形 MUST NOT 返回（不得对 deny/基础设施阻断附带 binding）。
- **缺失降级**：`enforcement_binding` 缺失时，Runtime MUST NOT 猜 binding、MUST NOT 发起 lease consume；按 C1 语义继续（pre-exec enforcement 成立，terminal execution 保持 unknown），并在 heartbeat capability 如实声明 C2 降级。
- **回显纪律**：`authorization_fingerprint` 仅供 Runtime 在 consume 请求中 exact 回传；MUST NOT 写入 Audit/Dashboard/Receipt/日志（与 §7.6 `lease_token` 纪律一致）；审计关联只使用 `audit_fingerprint`。
- **exact 比对**：Runtime 在进入 lease 消费前 MUST 以 `action_id + authorization_fingerprint + runtime_binding_id` 与本次评估上下文 exact 比对；不一致 → `binding_failed` + `not_invoked`（06 §8）。

---

## 7. Execution Lease API — 服从 V2.1 Frozen Contract

### 7.1 Endpoint

```text
POST /v1/approvals/{approval_id}/execution-leases/consume
Authorization scope: approval:wait
```

### 7.2 Request

```json
{
  "action_id": "action_x",
  "authorization_fingerprint": "hmac-sha256:..."
}
```

```python
class ExecutionLeaseConsumeRequest(BaseModel):
    action_id: str
    authorization_fingerprint: str
```

### 7.3 Authoritative Server Checks

单事务内验证：

1. Adapter credential principal/runtime binding；
2. approval 存在且为人工 `allow_once` 终态；
3. approval 未过期；
4. action_id exact match；
5. authorization_fingerprint exact match；
6. CapabilityGrant `remaining_uses == 1`；
7. CAS 消费成功；
8. 写 `GrantConsumption + ExecutionLease`；
9. 返回 lease。

CURRENT 注记：第 6 项 `remaining_uses == 1` 与 human approval single-use 不变量已由 `packages/agentguard-core/agentguard_core/security_context/facts.py` 的 `_enforce_approval_single_use` model_validator 在模型层强制（CURRENT）。

### 7.4 Response

```json
{
  "lease_id": "lease_x",
  "consumption_id": "consumption_x",
  "lease_token": "opaque-secret-returned-once",
  "expires_at": "2026-08-15T02:00:00+08:00"
}
```

### 7.5 Retry / Conflict

```text
same approval_id + action_id + fingerprint, lease valid
→ same lease_id + same plaintext lease_token

different action/fingerprint
→ 409 APPROVAL_CONSUMPTION_CONFLICT

same key after lease expiry
→ 410 EXECUTION_LEASE_EXPIRED
```

### 7.6 Runtime handling

Runtime MUST：

- 只在 consume 2xx 成功后进入 `approval_released`；
- 校验响应 lease identity 与当前 action/fingerprint/runtime binding（若 response 含 binding 字段）；
- `lease_token` 仅驻留最短必要作用域；不得写 Map、日志、Audit、Receipt、Dashboard；
- 不发明新的 token validate endpoint。

### 7.7 LLM allow_once 隔离

当前 legacy Approval Service 可以让低/中风险 LLM reviewer resolve `allow_once`，但 **V2 Strong Profile 不允许这种 approval 产生可消费 grant/lease**。

因此 consume service MUST 检查 `resolution_source`，至少：

```text
resolution_source == human
```

才可建立 human-approval CapabilityGrant/ExecutionLease。

---

## 8. RuntimeOutcomeReceipt 0.4 冻结

### 8.1 Required identity

```text
audit_id
schema_version=0.4
record_type=runtime_outcome
trace_id
runtime
timestamp
stage
event_type=runtime_outcome
summary
decision
risk_score
severity
blocked
links
metadata
evidence
reason
latency_ms
resource_targets
rule_hits
```

共 20 项，与 `schemas/runtime_outcome_receipt.schema.json`（L5-26）required 清单一致。其中 `latency_ms` 为 required-null：schema 中声明为 `{"type": "null"}`，必填但只允许 null。

### 8.2 Links

```text
event_id        REQUIRED
decision_id     REQUIRED
policy_audit_id REQUIRED
action_id       OPTIONAL but REQUIRED for action-level C1/C2 conformance
approval_id     OPTIONAL
parent_audit_id OPTIONAL
```

Strong Profile 后续若正式加入：

```text
lease_id
consumption_id
```

应做 additive schema review，不得直接塞进 `metadata` 规避契约。

### 8.3 Execution evidence

```python
status: Literal["not_invoked", "executed", "failed", "unknown"]
receipt_recorded: Literal[True]
invoked_at: str | None
completed_at: str
error: str | None
tool_result_entered_context: bool | None
persisted: bool | None
```

约束：

- `failed` 必须有 error；
- `not_invoked/executed` 不得带 error；
- `invoked_at <= completed_at`；
- `completed_at == receipt.timestamp`。

**强制点注记（CURRENT）**：以上四条约束 CURRENT 仅由 `packages/agentguard-core/agentguard_core/decisions/models.py`（`_validate_execution`/`_validate_receipt`）的 pydantic 校验与 Guard API 入站校验（`services/audit.py` prepare_submission → 422 `RUNTIME_OUTCOME_INVALID`）强制；`schemas/runtime_outcome_receipt.schema.json` 不含 if/then，JSON Schema 层不强制，且 `invoked_at <= completed_at` 与 `completed_at == timestamp` 属时区感知的时刻比较，JSON Schema 字符串比较无法完整表达。schema 层条件下沉为 DEFERRED，由 `tests/test_runtime_enforcement_contract.py` 负例固化。

### 8.4 Result evidence

```text
not_applicable
passed_through
modified
quarantined
unknown
```

`execution.status` 与 `result.disposition` 正交。

例如：

```text
executed + quarantined
```

表示工具已经执行，但结果被隔离。

### 8.5 Side effects

```text
measurement_status = measured | not_measured | unknown
```

- measured → count 必填；
- 非 measured → count 必须 null。

---

## 9. Outcome Kind 精确映射

### pre_execution_deny

> **示例形状标注（TARGET）**：下方示例形状（`sanitized=false`、`summary` 为非空字符串）为 TARGET——OpenClaw CURRENT 已符合（`src/mapping/audit-outcomes.ts`）；LangGraph CURRENT 写 `sanitized=None/summary=None`（`runtime_receipts.py`），对齐列入 PR-RTE-03/04。完整可校验示例以 `tests/fixtures/runtime_enforcement/*.json` 为唯一机器事实源，本节保留映射表与说明。

```json
{
  "execution": {
    "status": "not_invoked",
    "receipt_recorded": true,
    "invoked_at": null,
    "completed_at": "<same as receipt timestamp>",
    "error": null,
    "tool_result_entered_context": false,
    "persisted": false
  },
  "side_effects": {
    "measurement_status": "measured",
    "count": 0,
    "summary": "Invocation gate stopped the protected call before runtime entry."
  },
  "result": {
    "disposition": "not_applicable",
    "summary": "No tool result was produced.",
    "sanitized": false
  }
}
```

### approval_release

```text
execution.status = unknown
result.disposition = unknown
approval.status = allowed
approval.decision = allow_once
```

### execution_completed

```text
execution.status = executed
error = null
result.disposition = unknown unless hook proves stronger fact
```

### execution_failed

```text
execution.status = failed
error = bounded non-empty string
```

### tool_result_modified

```text
execution.status = executed
result.disposition = modified
```

### tool_result_quarantined

```text
execution.status = executed
result.disposition = quarantined
tool_result_entered_context = false when hook can prove it
```

---

## 10. Enforcement Violation 表达

不新增新的 `RuntimeOutcomeKind`。

如果 gate 预期阻断，但真实 terminal hook 证明已执行：

```text
metadata.outcome_kind = execution_completed | execution_failed
intervention.type = enforcement_violation
execution.status = executed | failed
policy decision remains deny/ask
```

这样既不破坏现有 schema，又保留真实矛盾事实。

---

## 11. Capability heartbeat TARGET

建议 heartbeat capability 采用结构化声明：

```json
{
  "runtime_enforcement_contract": "1.0",
  "profiles": {
    "C0_observe": true,
    "C1_pre_execution_enforcement": true,
    "C2_execution_closure": false,
    "C3_strong_approval_binding": false,
    "C4_result_isolation": true,
    "C5_side_effect_measurement": false
  },
  "correlation": {
    "stable_native_action_id": false
  }
}
```

禁止基于“代码里有函数”就宣称 capability；必须通过 conformance/smoke gate。

---

## 12. Schema 变更规则

1. F0 字段语义 P0 不允许破坏；
2. 新 optional 字段必须 additive；
3. authorization 安全字段不能偷偷塞入自由 `metadata`；
4. 任何新的 security-critical digest 必须明确白名单字段与版本；
5. RuntimeOutcome 新 outcome kind 需要同步：Python model、JSON Schema、TS type、mapper、Guard API validation、fixtures、Dashboard、metrics；
6. 本轮优先复用现有六个 outcome kind，不扩枚举。
