# Dashboard 指标作用域与审计窗口 API 协作契约

## 1. 文档状态与边界

本文定义 Dashboard 指标的已冻结目标后端契约、兼容路径和验收口径。目标契约于
2026-08-05 冻结，但后端代码、Schema、存储和查询迁移尚未实施。

- 前端三作用域隔离已经实施。
- 新后端接口尚未实施，本文不表示当前 Guard API 已提供目标响应。
- 当前 Dashboard 继续读取 `GET /v1/audit/events`，在已加载记录内按稳定关联 ID 重建窗口策略指标。
- `GET /v1/metrics/eval` 只保留为历史兼容入口，不再参与当前窗口或独立评测展示。
- AuditEvent 结构、运行时回执与证据语义继续以
  [证据链与溯源 API 目标契约](evidence_trace_api_contract.md) 为准。

目标不是为 Dashboard 制造一套平行事实，而是为审计记录、策略评估、授权终态和执行事实提供明确的查询作用域。

## 2. 已确认决策

| 编号 | 决策         | 结论                                                                         |
| ---- | ------------ | ---------------------------------------------------------------------------- |
| M-01 | 指标作用域   | 当前审计窗口、历史聚合和独立评测运行完全分离                                 |
| M-02 | 当前窗口交互 | 新增原子 `GET /v1/audit/window`，同一响应返回事件、窗口元数据和策略指标      |
| M-03 | 窗口顺序     | 使用服务端审计链 `sequence` 捕获稳定快照，不使用生产者时间作为分页主键       |
| M-04 | 策略评估单位 | 新数据以 `decision_id` 表示一次评估；迁移期按 `(event_id, decision_id)` 去重 |
| M-05 | 动作结果单位 | 授权终态和执行事实以 `action_id` 聚合，不与策略评估数共用分母                |
| M-06 | `deny` 语义  | 只表示策略不授权，不表示工具已确认未调用                                     |
| M-07 | 确认阻止     | 只有运行时回执证明 `execution.status=not_invoked` 时才可统计                 |
| M-08 | 历史查询     | 使用明确的评估时间 cohort，并返回结果统计时点与覆盖率                        |
| M-09 | 兼容         | 现有数组型 `/audit/events` 和 `/metrics/eval` 在迁移期保持可用               |
| M-10 | 独立评测     | `/evaluations/latest` 只返回该次 run 自身保存的事实，不从审计指标补数        |

## 3. 统计对象

| 对象     | 稳定标识                             | 含义                                           | 可进入的指标                                       |
| -------- | ------------------------------------ | ---------------------------------------------- | -------------------------------------------------- |
| 审计记录 | `audit_id`                           | 哈希链中的一条不可变事实                       | 返回记录数、记录类型分布                           |
| 策略评估 | `decision_id`，迁移期联合 `event_id` | Core 对 GuardEvent 的一次策略判断              | allow、ask、deny、策略介入、策略 FPR/FNR、判定延迟 |
| 逻辑动作 | `action_id`                          | 一次工具调用、消息发送、记忆写入或模型输出动作 | 授权终态、执行回执、结果处置                       |
| 审批请求 | `approval_id`                        | ask 产生的审批生命周期                         | pending、allow_once、deny、expired                 |
| 独立评测 | `run_id`                             | 固定数据集上的一次已保存评测                   | ASR、per-attack、cases 和 run 自身指标             |

消费者不得：

- 用 `audit_id` 作为新数据的策略评估 ID；
- 用 trace、工具名、时间邻近关系猜测逻辑动作；
- 把多个合法策略评估按 `action_id` 合并成一次评估；
- 把 `decision=deny` 或旧 `blocked=true` 解释为执行回执。

## 4. 策略指标定义

### 4.1 基础计数

```text
evaluation_count = 逻辑唯一 policy_evaluation 数
allow_count      = decision=allow
ask_count        = decision=ask
deny_count       = decision=deny
unknown_decision_count = 旧数据中无法恢复决定的 policy_evaluation
```

新数据必须满足：

```text
allow_count + ask_count + deny_count = evaluation_count
```

迁移期若存在未知决定，响应必须单独返回 `unknown_decision_count`，不得将其归入 allow。

### 4.2 策略率

```text
intervention_count    = ask_count + deny_count
intervention_rate     = intervention_count / evaluation_count
policy_deny_rate      = deny_count / evaluation_count
approval_trigger_rate = ask_count / evaluation_count
```

新接口不使用 `blocked_count` 或 `block_rate` 命名这些字段。

### 4.3 策略 FPR/FNR

策略指标把 `ask | deny` 定义为“策略介入”，把 `allow` 定义为“策略未介入”：

```text
policy_intervention_fpr =
  benign 且 decision in (ask, deny)
  / 有已知策略决定的 benign 评估数

policy_intervention_fnr =
  malicious 且 decision=allow
  / 有已知策略决定的 malicious 评估数
```

要求：

- `is_malicious=null` 不进入任一分母；
- 未知策略决定不进入任一分母；
- `benign_label_count`、`malicious_label_count` 分别返回实际可用于 FPR、FNR 的分母；
- `unlabeled_count` 只统计 `is_malicious=null`；它可与 `unknown_decision_count` 重叠，三个字段不承诺共同构成互斥分区；
- 分母为零时返回 `null`，不得返回 `0`；
- Dashboard 使用“策略误报率”“策略漏报率”，不称为最终执行 FPR/FNR。

### 4.4 判定延迟

`average_decision_latency_ms` 只统计 `policy_evaluation.latency_ms`，并同时返回
`latency_sample_count`。

`runtime_outcome` 的执行、等待、隔离或结果处理耗时不得进入判定延迟。

## 5. 当前审计窗口接口

### 5.1 请求

```http
GET /v1/audit/window
  ?limit=500
  &trace_id=
  &case_id=
  &runtime=
  &decision=
  &cursor=
```

鉴权：

- browser session；
- bearer 调用方同时具备 `audit:read` 与 `metrics:read`。

旧 `GET /v1/audit/events` 继续返回数组，不修改响应外形。

### 5.2 窗口捕获

服务端按以下顺序建立快照：

1. 捕获当前审计链 `upper_sequence`。
2. 在相同过滤条件下读取 `sequence <= upper_sequence` 的最近 `limit + 1` 条记录。
3. 返回前 `limit` 条，并由额外一条确定 `has_more` 和 `next_cursor`。
4. 以返回范围的 sequence 边界计算策略指标。
5. 后续分页固定使用相同 `snapshot_id` 或 cursor 中的 `upper_sequence`，新写入记录不得移动已有页。

生产者 `timestamp` 只用于事实发生时间和展示范围。迟到事件、相同时刻事件或不同时区表示不得改变窗口分页稳定性。

cursor 必须绑定快照、规范化 filters、排序和当前位置。客户端后续页只提交
`cursor`；若同时提交其他 filters，服务端必须校验它们与 cursor 一致，不得静默改变
cohort。cursor 失效返回明确的 `410 CURSOR_EXPIRED`，作用域不一致返回
`400 CURSOR_SCOPE_MISMATCH`。

### 5.3 响应

```json
{
  "scope": {
    "kind": "audit_window",
    "snapshot_id": "opaque",
    "outcomes_as_of": "2026-08-03T02:00:05Z",
    "order": "audit_sequence",
    "limit": 500,
    "returned_record_count": 500,
    "has_more": true,
    "next_cursor": "opaque",
    "sequence_from": 1201,
    "sequence_to": 1700,
    "occurred_from": "2026-08-03T01:00:00Z",
    "occurred_to": "2026-08-03T02:00:00Z",
    "filters": {
      "trace_id": null,
      "case_id": null,
      "runtime": null,
      "decision": null
    }
  },
  "events": [],
  "policy_metrics": {
    "metric_version": "policy_evaluation.v2",
    "evaluation_count": 437,
    "unknown_decision_count": 0,
    "allow_count": 300,
    "ask_count": 91,
    "deny_count": 46,
    "intervention_count": 137,
    "intervention_rate": 0.313501,
    "policy_deny_rate": 0.105263,
    "approval_trigger_rate": 0.208238,
    "policy_intervention_fpr": 0.016,
    "policy_intervention_fnr": 0.048,
    "benign_label_count": 125,
    "malicious_label_count": 250,
    "unlabeled_count": 62,
    "average_decision_latency_ms": 18.4,
    "latency_sample_count": 420,
    "duplicate_policy_record_count": 12,
    "legacy_fallback_count": 3,
    "deduplication": "logical_policy_evaluation"
  }
}
```

字段要求：

- `snapshot_id` 和 cursor 是不可解释字符串；
- `outcomes_as_of` 是该快照纳入授权与运行时结果的统计时点；
- `has_more` 必须由 `limit + 1` 查询确定；
- `has_more=false` 时 `next_cursor=null`；`has_more=true` 时必须返回可继续同一快照的 `next_cursor`；
- `returned_record_count` 是原始审计记录数，不能替代 `evaluation_count`；
- `sequence_from/to` 是服务端链位置；
- `occurred_from/to` 是返回记录中可解析事实时间的最小值和最大值；
- filters 返回服务端实际采用的规范化值。

### 5.4 窗口内逻辑去重

新 `policy_evaluation` 使用：

```text
(links.event_id, links.decision_id)
```

重复记录的规范行是 sequence 最小的一条。指标窗口成员资格以规范行 sequence 是否落入窗口为准，避免较晚重试把旧评估重新带入实时窗口。

迁移期：

- 缺失任一关联 ID 时回退到唯一 `audit_id`；
- 每条回退记录增加 `legacy_fallback_count`；
- 旧数组兼容路径在 `integrity.sequence` 可用时同样优先 sequence 最小的记录；sequence 缺失时保持首次返回记录，并计入迁移诊断；
- 相同逻辑键内容不一致时记录数据质量冲突，不静默合并；
- `runtime_outcome`、`runtime_observation`、`config_audit` 不增加策略计数。

## 6. 历史策略指标接口

### 6.1 请求

```http
GET /v1/metrics/policy-evaluations
  ?evaluated_from=2026-08-01T00:00:00Z
  &evaluated_to=2026-08-02T00:00:00Z
  &outcomes_as_of=2026-08-03T00:00:00Z
  &runtime=
  &case_id=
```

要求：

- `evaluated_from`、`evaluated_to` 必填，除非产品冻结了明确且可见的默认范围；
- 时间使用带时区 RFC 3339，服务端规范化到 UTC；
- cohort 以规范 `policy_evaluation.timestamp` 落入范围为准；
- `outcomes_as_of` 缺省为请求快照时刻，响应必须回显；
- 查询必须固定审计 sequence 快照，保证同一响应内一致。

### 6.2 响应作用域

```json
{
  "scope": {
    "kind": "aggregate_history",
    "evaluated_from": "2026-08-01T00:00:00Z",
    "evaluated_to": "2026-08-02T00:00:00Z",
    "outcomes_as_of": "2026-08-03T00:00:00Z",
    "snapshot_id": "opaque",
    "deduplication": "logical_policy_evaluation",
    "filters": {}
  },
  "policy_metrics": {}
}
```

P0 只要求与窗口接口相同的策略指标。历史接口不得返回没有范围说明的“全部历史”结果。

## 7. 授权终态与执行事实

本节是 P1，不阻塞 P0 策略指标。P1 直接在 `/v1/audit/window` 和
`/v1/metrics/policy-evaluations` 的同一响应中增加同级 `action_metrics`，复用同一
snapshot、策略评估 cohort 和 `outcomes_as_of`。不要为 Dashboard 自动刷新再拆出第三个
指标请求；能力未启用时省略该字段，不返回伪零值。

### 7.1 授权终态

对 cohort 中的逻辑动作按 `action_id` 聚合：

```text
automatic_allow
automatic_deny
approval_pending
approval_allow_once
approval_deny
approval_expired
authorization_unknown
```

可提供：

```text
authorization_terminal_count
authorization_denial_count
authorization_denial_rate
authorization_coverage
```

pending 不进入终态率分母，响应必须返回 pending 数与覆盖率。

### 7.2 确认阻止

下列事实同时成立时，动作才可计为确认未执行：

```text
record_type=runtime_outcome
links.action_id 存在
evidence.execution.receipt_recorded=true
evidence.execution.status=not_invoked
```

直接 deny、审批 deny 或 expired 只说明授权结果；没有运行时回执时执行状态仍为 unknown。

执行层响应至少返回：

```text
eligible_action_count
known_execution_outcome_count
confirmed_not_invoked_count
executed_count
unknown_execution_outcome_count
enforcement_coverage
```

如提供 `confirmed_prevention_rate`，其分母必须是
`known_execution_outcome_count`，并与 `enforcement_coverage` 同时展示。覆盖率不足时 Dashboard 不展示该率。

目标响应片段：

```json
{
  "action_metrics": {
    "metric_version": "action_outcome.v1",
    "eligible_action_count": 100,
    "authorization_terminal_count": 91,
    "authorization_denial_count": 20,
    "authorization_denial_rate": 0.21978,
    "approval_pending_count": 9,
    "authorization_unknown_count": 0,
    "authorization_coverage": 0.91,
    "known_execution_outcome_count": 72,
    "confirmed_not_invoked_count": 18,
    "executed_count": 54,
    "unknown_execution_outcome_count": 28,
    "confirmed_prevention_rate": 0.25,
    "enforcement_coverage": 0.72
  }
}
```

授权率的分母是已进入授权终态的动作；确认阻止率的分母是有已知执行回执的动作。两者不得使用策略评估数作为分母。

## 8. 独立评测运行

`GET /v1/evaluations/latest` 与两个审计指标作用域没有数据依赖。

要求：

- run DTO 可以只包含 `run_id`、数据集、ASR、per-attack 和 cases；
- 缺失的 run 指标保持缺失，不查询 `/metrics/eval` 补入；
- 如需 run FPR/FNR 或延迟，必须在评测生成时计算并随 run 一起持久化；
- `404 EVALUATION_NOT_FOUND` 只产生空评测状态，不影响当前审计窗口；
- Dashboard mapper 的输入只能是该 run DTO。

## 9. 旧接口兼容

### 9.1 `GET /v1/audit/events`

- 继续返回数组；
- 现有 filters 与 limit 保持；
- 新 AuditEvent 字段按存储内容返回；
- Dashboard 在目标窗口接口上线前从该数组建立
  `source=legacy_audit_events`、`has_more=null` 的客户端窗口；
- 缺失 `record_type` 时，只有 GuardEvent 规范内的已知事件类型且策略决定已知才兼容分类为 `policy_evaluation`；显式 `unknown` 或其他扩展事件保持未知并排除出策略指标；
- 客户端不得根据 `returned_count == limit` 推断截断。

### 9.2 `GET /v1/metrics/eval`

- 响应外形在迁移期保持；
- 后端 P0 仍需修复为只统计逻辑唯一 `policy_evaluation`；
- `blocked_count/block_rate` 只作为旧“策略介入”口径；
- 新 Dashboard 不自动请求或展示该接口；
- 新消费者使用 `/v1/metrics/policy-evaluations`；
- 移除前至少保留一个稳定发布周期并记录弃用。

## 10. 写入链路前置条件

指标正确性依赖以下写入约束：

1. `POST /v1/guard/evaluate` 以 `event_id + 规范化请求摘要` 实现请求级幂等。
2. 同一请求重试返回相同 `decision_id`。
3. Guard API 对一次逻辑评估只写一条 `policy_evaluation`。
4. Adapter/Plugin 不重复写策略评估，只写 runtime outcome/observation。
5. 策略审计 links 写入 `event_id`、`decision_id`、有动作时的 `action_id`，ask 时写入 `approval_id`。
6. `POST /v1/audit/events` 同 ID 同内容重试成功，同 ID 不同内容返回 `409 AUDIT_ID_CONFLICT`。
7. 策略快照、审批创建和策略审计使用同一 unit-of-work，或提供可证明等价的幂等恢复机制。

## 11. 存储与查询演进

### P0：现有 JSONB

- 使用 audit sequence 范围、record type 分类和 SQL 窗口函数完成查询；
- Memory 与 PostgreSQL 共用语义 fixture；
- 不因预估规模提前增加投影表；
- 生产者时间写入前校验 RFC 3339 并规范化到 UTC。

### P2：测量后优化

仅当真实数据量、`EXPLAIN ANALYZE` 或查询 p95 证明需要时，评估：

- `record_type`、`decision_id`、`action_id` 表达式索引或生成列；
- typed `timestamptz` 的 occurred/ingested 时间列；
- `policy_evaluation_facts`、`action_outcome_facts` 投影；
- 按时间 bucket 的增量物化。

投影必须可从审计链重建，并保存投影版本和重建状态。

## 12. 前端迁移状态

当前 Dashboard 已完成：

- `AuditWindow`、`WindowMetrics` 与 `EvaluationRun` 类型分离；
- 当前窗口以事件、scope 和策略指标作为单一对象更新；
- API 兼容模式从 `/audit/events` 客户端重建逻辑唯一策略指标；
- 客户端重复评估在 `integrity.sequence` 可用时采用最早审计记录；
- `/metrics/eval` 和 trace DTO 中的旧 `metrics` 不再映射为未消费的前端领域对象；
- evaluation run mapper 不接收外部指标；
- 趋势、攻击类型、规则分布、混淆矩阵和判定延迟只读取逻辑唯一策略评估；
- UI 使用“策略介入”“策略拒绝”“策略误报/漏报”，不声称实际阻断；
- 历史聚合仅在后端提供明确范围、去重语义与显式查询入口后按需接入。

后端目标接口上线后，只替换 data source 的窗口映射，不改变页面领域模型。

## 13. 验收矩阵

### 13.1 后端

- 同一 `(event_id, decision_id)` 多条审计只计一次；
- 同 `event_id` 同请求重试返回同 `decision_id`；
- runtime outcome/observation/config audit 不增加策略计数；
- 相同逻辑键不同内容产生数据质量诊断；
- 恰好 `limit` 条且无下一条时 `has_more=false`；
- 存在第 `limit + 1` 条时 `has_more=true`；
- 后续页 cursor 保持 snapshot 与 filters，不受并发新写入影响；
- 查询期间新写入不改变已捕获窗口；
- 未标注评估不进入策略 FPR/FNR 分母；
- policy latency 不混入 runtime latency；
- Memory/PostgreSQL 在相同 fixture 上完全一致。

### 13.2 授权与执行

- `ask → allow_once` 计入策略介入，不计授权拒绝或确认未执行；
- `ask → deny` 计入授权拒绝，无回执时执行结果为 unknown；
- direct deny 无回执时不计确认未执行；
- runtime receipt 明确 `not_invoked` 后才增加确认阻止；
- pending 和 unknown 数量、分母及覆盖率可见。
- `action_metrics` 与策略 cohort 使用同一 snapshot 和 `outcomes_as_of`。

### 13.3 前端

- 当前窗口、历史聚合和独立评测不共享一个指标对象；
- Overview/Evaluation 不请求 `/metrics/eval`；
- evaluation 404 不回填历史指标；
- outcome/observation 不重复出现在决策趋势和分布中；
- API 与 Mock 使用相同领域类型和页面组件；
- 窗口来源、范围、记录数、评估数和关键分母可见；
- 单个资源失败只影响对应区块。

## 14. 发布与回滚

1. 后端先以 feature flag 提供 `/v1/audit/window` 和新历史接口。
2. shadow 计算 legacy/v2，记录差异数量及原因，不记录敏感 payload。
3. 观察去重数量、legacy fallback、查询延迟、错误率和标签覆盖。
4. Dashboard API data source 切换目标窗口接口；领域模型与页面保持不变。
5. 保留 legacy 回退一个稳定发布周期。
6. 出现严重问题时仅回滚 data source 路由，不把历史聚合重新注入当前窗口或评测运行。
7. 稳定后标记 `/metrics/eval` deprecated，再按版本策略移除。
