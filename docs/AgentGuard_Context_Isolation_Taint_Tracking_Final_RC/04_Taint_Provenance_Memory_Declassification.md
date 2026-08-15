# 04 — Taint Propagation、Provenance、Memory 与 Declassification

> **目标**：建立最小、可解释、有界、跨 Session 的 artifact-level information flow。

# 1. Artifact-level Taint

追踪：

```text
Source / Context / ModelInput / ModelOutput
ToolResult / Action / Resource / Destination
Memory / Message / Data Artifact
```

不追踪：

```text
每 token / hidden state / attention edge
```

# 2. 五类 Taint

## UNTRUSTED

来源不能被自动当成可信 Authority/Data，不等于 malicious。

## EXTERNAL_INSTRUCTION

不可信数据中存在试图扮演 instruction 的内容，用于 indirect injection/tool result/RAG/memory poison。

## SENSITIVE

敏感业务/个人/内部/受限数据。

## CREDENTIAL

API key/token/password/private key 等，强保护。

## PERSISTENT_UNTRUSTED

不可信影响已跨越当前轮次进入持久 Agent state。

# 3. 单调传播

```text
T(target) = T(target) ∪ T(source)
```

禁止：

```text
LLM hop → taint disappears
N hops → taint expires
```

# 4. Relation 默认规则

| Relation | Taint | 默认 Strength |
|---|---|---|
| received_from | union | exact/strong by observation |
| read_from | union | exact |
| returned_by | union | exact |
| assembled_into | union | exact/strong |
| derived_from | union | mechanism-defined |
| influenced_by | union | possible |
| written_to | union | exact/strong |
| persisted_to | union + persistent | exact/strong |
| loaded_from_memory | inherit | exact/strong |
| sent_to | union | evidence-defined |

# 5. FlowStrength

## exact

直接值/identity/content digest 可复核。

## strong

确定性转换且机制在 whitelist 中。

不要预先把任意编码/hash 全部 strong；通过冻结白名单维护。

## possible

黑盒语义影响，尤其：

```text
data → LLM → output/action
```

# 6. PathStrength — TARGET-FROZEN

```text
exact > strong > possible
PathStrength = weakest(edge)
```

例如：

```text
exact → strong → possible → exact
= possible
```

# 7. LLM Influence

## Visible Set

只对真实进入当前 model call 的 source/chunk 生成 influence。

不能：

```text
scope 内出现过的所有 source
→ 每个未来 model output
```

否则会 over-taint。

## 默认

```text
source/context
→ model_output
influenced_by
possible
```

## Deterministic Upgrade

若输出/参数出现 exact credential fingerprint：

```text
credential source
→ output/action arg
derived_from
exact
```

可以同时保留：

```text
possible semantic influence
+
exact sensitive data flow
```

# 8. 避免 Over-taint

- visible context 才建 influence；
- session/scope 有界；
- 只有 persist 才跨 session；
- sticky 只保留高价值 unresolved evidence；
- historical low-value flow 可安全驱逐。

# 9. Bounded Provenance

沿用当前预算：

```text
max_depth=4
max_breadth=32
node_budget=256
```

原则：

```text
truncated != safe
```

截断：

```text
dataflow coverage → partial/unknown
```

先测：

```text
flow_truncation_rate
lookup_latency
snapshot_size
```

再决定是否调预算。

# 10. Sticky Taint

当前基线：

```text
MAX_STICKY_TAINT_SUMMARIES=16
MAX_SUMMARY_REFS=64
MAX_SUMMARY_EVIDENCE_REFS=64
```

保护：

```text
CREDENTIAL
PERSISTENT_UNTRUSTED
```

Flood test：

```text
credential read
→ many benign actions
→ egress
```

关键证据必须仍可恢复。

# 11. Memory Bridge

当前两个平面：

```text
MemoryGuardChange  # lifecycle
MemoryFact         # trust/taint
```

必须桥接但不合并。

# 12. Memory Write

输入：

```text
MemoryGuardChange + source refs + upstream taints
```

派生 `MemoryFact`。

### clean

仅在 source trusted、无 unresolved taint、policy 允许时。

### tainted

上游包含 `UNTRUSTED/EXTERNAL_INSTRUCTION`：

```text
trust_state=tainted
taints += PERSISTENT_UNTRUSTED
```

### quarantined

MemoryGuard lifecycle quarantine：

```text
trust_state=quarantined
```

默认不进入 normal context。

# 13. Memory Read

第一版优先复用：

```text
context_assembled + source_type=memory
```

建立：

```text
memory:<id>
→ current context/model_input
loaded_from_memory
```

以后有稳定 memory-read hook 再 additive 增强。

# 14. Cross-session

测试必须：

```text
Session A poison/write
→ terminate
→ restart agent
→ preferably restart Guard API
→ Session B read
```

只在单进程内不算 cross-session 证明。

# 15. ALLOW ≠ TRUST

用户可合法允许：

```text
memory.write
```

因此 Decision 可以 `ALLOW`，同时：

```text
MemoryFact.trust_state=tainted
```

两个维度不冲突。

# 16. Declassification

唯一合法路径：

```text
trusted_declassifier
→ DeclassificationFact
```

不能用：

```text
Adapter sanitized
LLM summary
LLM says safe
detector no hit
```

去污。

# 17. Declassifier Registry

Guard API 建议维护：

```text
mechanism_id
mechanism_version
allowed_removed_taints
input_types
output_types
policy_revision
implementation_digest
```

例如 credential redactor 可移除 CREDENTIAL，但仍保留：

```text
UNTRUSTED / EXTERNAL_INSTRUCTION
```

# 18. Protected Taint Removal

对：

```text
CREDENTIAL
PERSISTENT_UNTRUSTED
```

要求：

- whitelist mechanism；
- exact input/output refs；
- policy revision；
- evidence digest；
- server-only producer。

# 19. Snapshot Declassification Gap

CURRENT：

```text
SecuritySnapshot.declassifications exists
but build_snapshot() sets []
```

冻结解决方案候选：

```text
OnlineSecurityState 14 domains unchanged
```

Snapshot build：

```text
relevant source/flow/memory refs
→ bounded authoritative declassification lookup
→ snapshot.declassifications
```

lookup 失败且 dataflow required：

```text
coverage != complete
```

# 20. 不新增 OnlineState Declass 域

理由：

- 14 域已冻结；
- declass effect 已应用到 sticky；
- 不需要热状态保存所有 proof；
- Decision 只需当前 relevant bounded proof；
- authoritative registry 可重建。

结构：

```text
Effect in state
Proof in bounded Snapshot/Evidence
```

# 21. RAG Poisoning

普通 RAG：

```text
rag
→ assembled_into
→ model
→ influenced_by possible
→ action
```

不是 B4。

只有：

```text
rag → memory → future session
```

才是 B4/PERSISTENT_UNTRUSTED。

# 22. E2E

## P-01 Exact Credential

```text
file secret → read → email content → sent_to
```

期望 exact + CREDENTIAL + external sink。

## P-02 LLM Influence

恶意 Web → LLM → action：

```text
possible
```

除非额外 deterministic evidence。

## P-03 Memory

untrusted tool result → memory → restart → future action：

```text
PERSISTENT_UNTRUSTED + loaded_from_memory
```

## P-04 Declass

credential → trusted redactor → output：

只有 proof 可合法移除 CREDENTIAL。

# 23. DoD

- [ ] taint 无 hop 衰减；
- [ ] LLM 默认 possible；
- [ ] path strength 最弱边；
- [ ] exact credential 可升级；
- [ ] no visible context → no fabricated influence；
- [ ] memory 保存 source refs/taints；
- [ ] restart 后恢复；
- [ ] flood 不洗掉 sticky；
- [ ] sanitize claim 不去污；
- [ ] declass proof 进入 Snapshot；
- [ ] lookup failure 降 coverage；
- [ ] RAG 不误映射 B4。
