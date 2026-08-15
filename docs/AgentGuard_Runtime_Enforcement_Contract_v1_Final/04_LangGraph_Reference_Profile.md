# AgentGuard Runtime Enforcement Contract v1 — LangGraph Reference Enforcement Profile

> 基线：`dev@efe1c95df52b2be3e62d4b48510bfc410397c69f`  
> 定位：**Reference Enforcement Implementation（受保护调用边界内）**。

---

## 1. 为什么 LangGraph 可作为 Reference

当前 `GuardedToolGateway.invoke_tool()` 拥有一个关键性质：

> AgentGuard 自己持有实际 `tool_runtime.invoke(tool_name, arguments)` 调用点。

因此在该保护边界内，可以精确保证：

```text
evaluate
→ deny/ask gate
→ optional memory gate
→ optional tool_call_started
→ actual invoke
→ result guard
→ executed/failed outcome
```

这比旁路 hook 更容易证明 C1/C2。

---

## 2. Protected Boundary

“完全中介”声明必须写成：

> All tool invocations routed through `GuardedToolGateway` / `SecureToolNode` are mediated before execution.

不能写：

> AgentGuard 无条件中介 LangGraph 中任意 Python 直接工具调用。

如果业务绕过 Gateway 直接调用：

```python
tool_runtime.invoke(...)
```

则该调用不在当前保护域内。

---

## 3. CURRENT 能力映射

| 能力 | CURRENT |
|---|---|
| C0 Observe | PASS |
| C1 Pre-exec enforcement | PASS |
| deny → invocation count 0 | PASS |
| ASK wait / allow_once | PASS |
| approval not obtained → not_invoked | PASS |
| start observation | ASK 释放路径已实现 |
| executed terminal receipt | PASS |
| failed terminal receipt | PASS |
| result quarantine | PASS |
| sandbox snapshot/diff side effects | 支持具备 snapshot/diff 的 runtime |
| C3 V2 Strong binding | 尚未 production 接入 |

> **CURRENT 注记**：`tool_gateway.py::_resolve_approval` CURRENT 容忍 legacy 释放值 `allow/allow_session`（`runtime_receipts.py` 归一为 `allow_once`，不扩大语义），与 RTE-004「legacy 其他值不得扩大语义」兼容；收紧为仅 `allow_once` 列为 PR-RTE-03/04 DEFERRED 项（OpenClaw 侧已严格）。

---

## 4. Reference Contract 不要求重构

本轮不建议为了“架构更漂亮”拆成大量新模块。保持现有 Gateway，主要增加：

1. 与统一 RTE contract 的 conformance tests；
2. capability profile 明确声明；
3. V2.1 Strong Binding 接线时对齐 execution-lease consume；
4. 避免 bench-only approval fingerprint 机制演变成第二套公共算法。

---

## 5. ASK Strong Profile TARGET-P1

现有 bench 已有较强 approval binding 检查经验，但正式长期机制统一采用 V2.1：

```text
ActionIR.authorization_fingerprint
→ human approval CapabilityGrant
→ POST execution-leases/consume
→ one-use GrantConsumption
→ ExecutionLease
→ exact action release
```

LangGraph Runtime release 前只消费服务端给出的 authoritative binding，不本地自建另一套 hash 规则。

---

## 6. Receipt Failure 语义

当前 LangGraph ASK release 后在真实 invoke 前写 `tool_call_started` observation；若该关键 start receipt 不能记录，会阻止已审批工具执行。

该行为属于 Reference Profile 的较强 evidence policy，可以保留，但必须与 OpenClaw 区分：

- LangGraph 拥有调用边界，因此可以在调用前做这种强制；
- OpenClaw 的 terminal receipt 是事后 observation，失败不得反向声称工具没有执行。

跨 Runtime conformance 比较安全语义，而不是强行要求内部实现完全一致。

---

## 7. LangGraph 必加 Contract Tests

### LG-CF-ALLOW

```text
fixed decision=allow
→ tool_runtime.invoke == 1
→ execution_completed/executed
```

### LG-CF-DENY

```text
fixed decision=deny
→ invoke == 0
→ pre_execution_deny/not_invoked
```

### LG-CF-ASK-DENY

```text
ask + approval deny
→ invoke == 0
→ not_invoked
```

### LG-CF-ASK-ALLOW

```text
ask + allow_once
→ started observation
→ invoke == 1
→ terminal executed/failed
```

### LG-CF-TOOL-FAILURE

```text
allow/released
→ invoke raises
→ execution_failed
```

### LG-CF-RESULT-QUARANTINE

```text
tool executes
→ result guard deny
→ executed + quarantined
```

### LG-CF-DUP-RECEIPT

同一 deterministic audit_id 重投不产生重复 authoritative fact。

---

## 8. Reference Profile 验收口径

LangGraph 被称为 Reference 的前提：

- 文档明确 protected boundary；
- contract tests 保证 deny 之后 invocation count=0；
- decision/approval/execution 分离；
- terminal receipt 不由 policy result 推断；
- Strong Profile 上线后必须通过同一 consume endpoint，不得保留平行安全契约。
