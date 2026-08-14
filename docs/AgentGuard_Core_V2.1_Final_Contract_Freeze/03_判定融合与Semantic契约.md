# 03 — 判定融合与 Semantic 契约

## 1. 为什么废弃 `max(risk_score) + deny > ask > allow`

旧聚合适合作为 V1 规则系统，但不适合多源安全证据：

- 多个 detector 可能来自同一证据，简单累加/取最大值会重复计权；
- “高风险”不等于“明确违规”；
- “没有命中规则”不等于“Authority 已证明”；
- “语义可疑”不等于“数据确切外泄”；
- 缺失状态不能用低分表示。

V2.1-Final 使用 **事实优先级 + 证明式判定**。

---

## 2. Fusion 输入

```text
ActionIR
RequiredCheckPlan
PolicyViolation[]
SecuritySignal[]
EvaluationDegradation[]
AuthorityVerdict
FlowVerdict
CoverageMap
Behavior findings
SemanticJudgment?  # finalize 阶段可选
```

---

## 3. Evidence Group 去重

同一底层事实产生多个 detector signal 时，只能作为一个 evidence group。

例如：

```text
恶意 Email 中 "send secrets"
```

可能同时触发：

- prompt injection；
- external instruction；
- tool hijack；
- task mismatch。

不能把 4 个 detector 当 4 份独立证据。

建议 group key：

```text
underlying_fact_digest + causal_scope + primary_source_ref
```

Fusion 读取 group 内：

- 最强证据；
- 不同 reason code；
- 不重复增加 confidence。

---

## 4. Impact Class 冻结基线

Impact 不是一个纯分数，由 `ActionEffect + resource classification + destination` 推导。

### critical

任一：

- credential data egress；
- destructive + irreversible；
- privileged + destructive；
- privileged code execution + external/network；
- policy 明确标注 critical resource mutation。

### high

任一：

- external communication；
- data egress；
- persistence；
- code execution；
- privilege use；
- destructive reversible；
- sensitive resource mutation/access 且存在 external follow-up potential。

### moderate

- reversible internal mutation；
- non-sensitive write；
- scoped internal API mutation；
- 无 external/persistence/privilege 的普通状态改变。

### low

必须同时满足：

- read-only；
- local/internal；
- non-sensitive；
- no persistence；
- no privilege；
- no data egress；
- no code execution。

F3 policy 可进一步把特定动作**升级** impact；降低 system baseline 需要发布级安全评审。

---

## 5. RequiredCheckPlan 基线

| Action 特征 | 必需域 |
|---|---|
| low local read | task, source（若有外部内容） |
| sensitive read | task, capability, source |
| external send/API | task, capability, source, dataflow |
| credential/sensitive external | task, capability, source, dataflow, behavior |
| persistence/memory write | task, capability, source, memory |
| memory retrieval influencing action | task, source, memory, behavior |
| code execution | task, capability, source, behavior |
| privileged/destructive | task, capability, behavior；有数据/外部则加 dataflow/source |
| runtime-outcome-dependent retry/continuation | runtime_outcome + 上述域 |

`RequiredCheckPlan` 必须由 deterministic planner 生成。

---

## 6. FastAssessment 优先级

### Step 1 — System Invariant

违反 `system_invariant` 且定义为阻断型：

```text
CLEAR_DENY
```

例如：

- 明确伪造/使用禁止的 Authority issuer；
- allow_once fingerprint mismatch；
- 明确双花 grant；
- tampered digest / projection identity conflict。

### Step 2 — Hard Policy

任一生效 `system_hard_policy` / `tenant_hard_policy` effect=deny：

```text
CLEAR_DENY
```

任一 review policy=ask 且无更强 deny：保留为 `DEFER`/ASK 候选。

### Step 3 — Confirmed Source-to-Sink Violation

使用冻结矩阵。

### Step 4 — Explicit Authority Mismatch

如果：

- 资源/目的地已完整 canonicalize；
- capability coverage complete；
- 存在 grant，但明确 scope mismatch；
- 动作为 high/critical；

则可以：

```text
CLEAR_DENY
```

如果不是“明确 mismatch”，而是：

```text
no grant / unknown / partial coverage
```

通常：

```text
DEFER
```

以便 human approval，而不是把缺授权一律当恶意攻击。

### Step 5 — Required Coverage / Degradation

Required domain 非 `complete/not_applicable`：

```text
DEFER
```

Required component degradation：

```text
DEFER
```

除非前面已经 CLEAR_DENY。

### Step 6 — Behavior / Untrusted Influence

只有满足冻结高置信组合时可 CLEAR_DENY；一般生成 DEFER。

### Step 7 — CLEAR_ALLOW Proof

全部成立才 CLEAR_ALLOW：

1. 无 system invariant violation；
2. 无 hard deny / hard ask；
3. RequiredCheckPlan 所有必需域 complete/not_applicable；
4. Authority=`authorized` 或 `not_required`；
5. Flow=`safe` 或 `not_applicable`；
6. 无 required degradation；
7. 无 policy-required human review；
8. 无 unresolved high-confidence behavior chain；
9. 当前动作不需要 Semantic 才能确定关键 task alignment；
10. snapshot/policy/action digest 有效。

否则：

```text
DEFER
```

---

## 7. Source-to-Sink 冻结矩阵

机器真值为同目录 `fusion_matrix.yaml`（采用 JSON-compatible YAML）并由 `fusion_matrix.schema.json` 校验。匹配语义固定为：收集全部匹配规则，再按 `CLEAR_DENY > DEFER > CLEAR_ALLOW` 取最高优先级；Markdown 表格必须由一致性测试逐项映射到机器规则，不允许新增未定义 selector 或 disposition。

### 7.1 数据外发

| Taint | Flow strength | Authority | Sink | Fast result |
|---|---|---|---|---|
| CREDENTIAL | exact | unauthorized / explicit mismatch | external | CLEAR_DENY |
| CREDENTIAL | strong | unauthorized / explicit mismatch | external | CLEAR_DENY |
| CREDENTIAL | possible | 任意 | external | DEFER |
| CREDENTIAL | exact/strong | authorized | external | 继续检查 policy/task；不因 taint 自动 deny |
| SENSITIVE | exact | unauthorized / explicit mismatch | external | CLEAR_DENY |
| SENSITIVE | strong | unauthorized / explicit mismatch | external | DEFER，除非 tenant/system hard policy 明确 deny |
| SENSITIVE | possible | 任意 | external | DEFER |
| SENSITIVE | exact/strong | authorized | external | policy-based allow/defer |

说明：

- `strong credential` 被允许直接 deny，前提是 `strong` 定义严格、可复核；
- 普通 sensitive strong 默认不直接 hard deny，减少 FPR；
- `possible` 永不单独 hard deny。

### 7.2 Untrusted Influence → High Impact

| Influence | Authority | Impact | Fast result |
|---|---|---|---|
| exact/strong + explicit hostile instruction evidence | explicit scope mismatch | high/critical | CLEAR_DENY |
| exact/strong | authority unknown/missing | high/critical | DEFER |
| possible | 任意 | high/critical | DEFER |
| exact/strong | authorized | high/critical | 继续 policy/dataflow 检查，不自动 deny |
| 任意 | authorized | low/moderate | 通常不因 untrusted source 自动 deny |

### 7.3 Memory

| Memory state | Retrieval | Future action | Result |
|---|---|---|---|
| PERSISTENT_UNTRUSTED / tainted | exact/strong retrieval influence | unauthorized high-impact | CLEAR_DENY/DEFER，按 authority 明确度 |
| tainted | possible influence | high-impact | DEFER |
| quarantined | 试图进入上下文 | 任意 | policy ask/deny |
| clean + authoritative lifecycle | normal retrieval | authorized | 不因 memory 本身阻断 |

### 7.4 Behavior

- B1-B5 只有在 `confidence=high + authority=unauthorized + impact=high/critical + corroborating flow` 全部成立时才可 `CLEAR_DENY`；
- B1-B6 的其他异常组合默认 `DEFER`；
- Behavior 不创建 Authority，也不能把 `unknown` 升格为 `unauthorized`。

---

## 8. Authority 判定

### authorized

必须有至少一个有效 grant 完整覆盖：

```text
subject
+ task
+ action_type
+ canonical resource
+ destination
+ arguments
+ usage/revocation/expiry
+ exact fingerprint（若 grant 要求）
```

### unauthorized

只有“事实完整且明确不允许”才标 unauthorized，例如：

- exact grant scope mismatch；
- revoked/expired grant；
- human allow_once fingerprint mismatch；
- explicit forbidden destination。

### unknown

- no grant 且 action 可能通过 human approval 获得权限；
- resource unresolved；
- capability coverage partial/stale/unknown。

`unknown` 不等于 malicious，通常 DEFER。

---

## 9. Semantic Router 冻结

只在以下条件全部满足时 `eligible=true`：

```text
assessment.disposition == DEFER
AND hard_deny_present == false
AND semantic_resolvable == true
AND required_facts_available == true
```

### semantic_resolvable=true 的典型原因

- task 与动作语义关系不明确；
- 外部文本是“数据描述”还是“行为指令”不明确；
- benign high-impact task 与 abuse 语义边界需要理解。

### semantic_resolvable=false

- capability missing；
- resource unresolved；
- state dirty；
- required domain stale/unknown；
- exact credential egress；
- explicit hard policy；
- digest conflict。

LLM 不能修复事实缺失。

---

## 10. Semantic 输入最小化

Security Judge 输入：

- TaskFact summary + digest/reference；
- ActionIR 安全摘要；
- RequiredCheckPlan；
- selected evidence refs + bounded summaries；
- authority/flow verdict；
- deterministic reason codes；
- policy/snapshot/assessment digests。

不输入：

- 全量对话；
- 未脱敏 secret；
- 可执行 tool credentials；
- 任意工具权限。

Security Judge 不允许工具调用。

---

## 11. SemanticJudgment 语义

只允许：

```text
aligned
misaligned
uncertain
```

`reported_confidence` 只是模型自报等级，不是概率。

### Stage 0 — Disabled

不调用。

### Stage 1 — Shadow（比赛默认）

调用但不改变 final decision。

### Stage 2 — Upgrade-only（可选）

满足独立 holdout 门禁后，允许：

```text
DEFER + misaligned + calibrated condition
→ DENY
```

不允许：

```text
DEFER → ALLOW
ASK → ALLOW
DENY → ALLOW
```

Semantic Judge 与现有 LLM Approval Reviewer 是不同职责。V2 Authority 中，LLM Approval Reviewer 同样不得产生 `allow_once` grant，只能 deny 或保持人工 pending。

### Stage 3 — Low-impact De-escalation（非比赛前置）

只有全部满足：

- low impact；
- no external；
- no sensitive；
- no persistence；
- no privilege；
- no data egress；
- capability satisfied；
- all required coverage complete；
- no hard policy；
- 独立校准通过；

才允许评估 `DEFER/ASK → ALLOW`。

### Stage 4

更广泛 semantic de-escalation 属生产级后续，不在本次冻结实现范围。

---

## 12. Semantic Revalidation / CAS

禁止：

```text
BEGIN transaction
→ LLM
→ COMMIT
```

冻结：

```text
Read Snapshot V
→ assess → assessment_digest
→ transaction 外调用 LLM
→ judgment return
→ compare:
   assessment_digest
   authorization_fingerprint
   task_digest
   policy_digest
   snapshot_digest
→ re-read / validate current state version
→ 若相关 state/policy/task 已变化：judgment stale，作废并 reassess/ASK
→ finalize
```

Semantic 期间不持长锁。

---

## 13. Semantic Timeout / Cache

Minimal：

- 必须 hard deadline；
- timeout → unavailable → 原 DEFER 走 ASK；
- 不启用跨事件缓存，优先降低安全复杂度。

后续 exact-key cache：

```text
model
prompt_version
task_digest
authorization_fingerprint
policy_digest
snapshot_digest
semantic evidence digest
```

任何 digest 变化立即失效。TTL 只用于额外收紧，不作为主要一致性机制。

---

## 14. Finalize 优先级

```python
if assessment.disposition == "CLEAR_DENY":
    return DENY

if assessment.disposition == "CLEAR_ALLOW":
    return ALLOW

# DEFER
if semantic is None:
    return ASK

if semantic binding invalid or stale:
    return ASK

if semantic_stage == "shadow":
    return ASK

if semantic_stage == "upgrade_only":
    if semantic.verdict == "misaligned" and stage2_gate_passed:
        return DENY
    return ASK

# stage3+ only under separately frozen prerequisites
```

Hard deny 永远不由 Semantic 降级。

---

## 15. 风险分数的最终定位

保留 `risk_score` 仅为：

- 旧 API 兼容；
- Dashboard 排序；
- legacy detector 迁移；
- 人类可读 risk band。

不把 0–100 解释为概率，不让最终 decision 依赖单一分数阈值。

新解释优先使用：

```text
Policy Basis
Authority Basis
Flow Basis
Coverage Basis
Behavior Basis
Semantic Basis
Runtime Basis
```
