# Provenance 丰富化后端实施要求

> 状态：Guard API 写入、Memory/PostgreSQL 真实联调与 Dashboard API 读链验收已完成
>
> 确认日期：2026-08-07
>
> 验收复核：2026-08-08
>
> 适用组件：AgentGuard Core、Guard API / Control Plane、LangGraph Adapter、OpenClaw Plugin、Dashboard

## 1. 文档定位

本文把[证据链与溯源 API 目标契约](evidence_trace_api_contract.md)中已经冻结的
Provenance 目标拆成可直接实施的后端要求。Guard API 已按本文实现新事件的确定性物化；
本文不改变冻结契约，也不表示生产数据已迁移或历史 Trace 已回填。

运行时安全观测的视图职责、主演示链和非对称刷新边界见
[Agent 运行时安全可观测与动态治理设计](../04_apps/runtime_safety_observability_design.md)。
该设计只引用本实施要求中的持久化事实，不允许 Dashboard 临时补图。

目标是在不补造事实的前提下，让未来新产生的真实 Trace 能够展示任务、来源、上下文、
动作、资源、规则、策略、审批、运行结果和审计之间的完整关系。历史 Trace 不自动回填，
查询接口也不得临时拼装历史节点。

## 2. 保持不变的公共边界

- 继续使用 `GET /v1/traces/{trace_id}/provenance`。
- 顶层响应继续是 `trace_id`、`nodes`、`edges`。
- `ProvenanceNode` 继续使用开放的 `kind`、`ref_id`、`metadata`。
- `ProvenanceEdge` 继续使用开放的 `relation`、`metadata`。
- 继续使用现有 `provenance_nodes`、`provenance_edges` 和 JSONB payload。
- 不返回 `x/y`、节点宽高、视口、折叠状态或关键路径计算结果。
- 不新增 Dashboard 专用证据接口，不新增 runtime outcome 接口。
- `ref_id` 保存未加展示前缀的原始实体 ID；类型前缀只属于 `node_id`。
- API 响应使用 snake_case，缺失事实保持缺失或 `null`，不得写入前端占位文案。

现有模型和表结构已经能够承载目标字段，因此本能力不要求新增表、列或 API 版本。
如果后续测量证明查询索引不足，应另立性能任务，不在本能力中预先增加索引。

## 3. 实施前置条件

完整生命周期图开始写入前，必须满足：

1. Guard API 能够读取并返回 AuditEvent `0.3 | 0.4`；基础双读与跨存储共享契约测试均已
   完成。
2. 新策略评估由 Guard API 唯一写入 `policy_evaluation`。
3. AuditEvent `0.4` 提供稳定的 `links` 和有界、脱敏的 `evidence`。
4. Adapter / Plugin 通过现有 `POST /v1/audit/events` 写入结构化
   `runtime_outcome` 或 `runtime_observation`。
5. `audit_id`、Guard evaluate 请求和 provenance upsert 具有可重试的幂等语义。
6. 事件时策略快照提供 bundle、version、revision 和 digest 中实际可用的字段。

基础的 `event → decision → audit` 关系继续服务当前 AuditEvent `0.3`。完整丰富化已经按照
冻结契约的发布顺序为新事件启用；历史 Trace 仍遵守不自动回填的边界。

## 4. 写入原则

### 4.1 只在写入时物化

Provenance writer 只能使用当前请求、实际策略快照、GuardDecision、审批记录、运行时回执、
Action Critic 结果和已经持久化的 AuditEvent。

- 不根据时间邻近、相同工具名、相似资源或页面状态猜测关系。
- 不在 `GET /provenance` 时从 AuditEvent 临时生成节点。
- 缺少稳定 link 时保留孤立但真实的节点，不创建猜测边。
- 不创建“未提供”“未知任务”等占位节点。
- 不记录模型隐藏推理；只允许明确上报的任务、上下文来源、模型意图摘要或工具计划事实。

### 4.2 稳定 ID

- `node_id` 和 `edge_id` 必须由稳定业务 ID 或规范化摘要确定。
- 相同事实重试必须得到相同 ID。
- `ref_id` 使用实体原始 ID，不带 `event:`、`audit:` 等前缀。
- 敏感路径、收件人、内容、参数或用户文本不得直接进入 ID。
- 资源摘要对完成服务端脱敏后的 `{resource_type, operation, target, direction}` 做
  UTF-8、Unicode NFC、字段排序的规范 JSON，再计算完整 SHA-256。
- 不截断 SHA-256；节点 ID 使用
  `resource:{trace_id}:sha256:{64-hex-digest}`。

### 4.3 已知事实不得退化

同一节点被再次 upsert 时：

- 允许把缺失或 `unknown` 字段补充为已知事实。
- 不允许用缺失、空串、`null` 或 `unknown` 覆盖已经记录的已知事实。
- `trace_id`、`kind`、`ref_id` 或边端点发生冲突时不得静默覆盖。
- 状态确实演进的实体，例如 approval，可更新明确的状态、时间和处置字段。

## 5. 节点写入矩阵

只有来源字段存在且通过脱敏、大小限制时才创建可选节点。

| kind             | 稳定 `node_id`                                        | 原始 `ref_id`         | 事实来源                                          | 必需 metadata                                             |
| ---------------- | ----------------------------------------------------- | --------------------- | ------------------------------------------------- | --------------------------------------------------------- |
| `task`           | `task:{trace_id}`                                     | `trace_id`            | `GuardEvent.security_context.user_task`           | `phase=input_trust`、有界摘要                             |
| `source`         | `source:{trace_id}:{source-id-or-hash}`               | source ID 或摘要 ID   | security context 或结构化 context source          | `source_type`、`source_trust`、`phase=input_trust`        |
| `context`        | `context:{event_id}`                                  | `event_id`            | `context_assembled` 或明确的 context sources      | `phase=context_intent`、来源数量                          |
| `model_intent`   | `model_intent:{event_id}`                             | `event_id`            | 显式 `model_intent` 或有界 tool plan 摘要         | `phase=context_intent`                                    |
| `event`          | `event:{event_id}`                                    | `event_id`            | 没有更具体 typed fact 的 policy evaluation        | `event_type`、阶段                                        |
| `action`         | `action:{action_id}`                                  | `action_id`           | ToolDescriptor `call_id` 或稳定 `links.action_id` | 动作名、`phase=tool_policy`                               |
| `resource`       | `resource:{trace_id}:sha256:{digest}`                 | `sha256:{digest}`     | `derive_resources(event)` 的规范资源              | 类型、操作、方向、脱敏目标摘要                            |
| `rule`           | `rule:{decision_id}:{rule_id}`                        | `rule_id`             | `GuardDecision.rule_hits`                         | `decision_id`、severity、原因摘要                         |
| `policy`         | `policy:{trace_id}:{bundle_id}:{revision-or-version}` | bundle/revision 引用  | 实际参与判定的策略快照                            | bundle、version、revision、digest                         |
| `decision`       | `decision:{decision_id}`                              | `decision_id`         | GuardDecision                                     | `risk_score`、severity、decision、`phase=tool_policy`     |
| `approval`       | `approval:{approval_id}`                              | `approval_id`         | ApprovalRequest / 终态记录                        | status、创建/过期/解决时间、`phase=outcome_audit`         |
| `runtime_result` | `runtime_result:{audit_id}`                           | `audit_id`            | `runtime_outcome` AuditEvent                      | execution、intervention、result disposition、side effects |
| `audit`          | `audit:{audit_id}`                                    | `audit_id`            | 每条已持久化 AuditEvent                           | record type、runtime、stage、integrity sequence           |
| `review`         | `review:{review_id}`                                  | `review_id`           | Action Critic 等明确复核记录                      | reviewer、verdict、confidence、degraded                   |
| `config_audit`   | `config_audit:{event_id}`                             | config audit event ID | `config_audit` AuditEvent                         | target type、finding count、severity 摘要                 |

Policy evaluation 并不天然产生 action 节点。Writer 只在 `links.action_id` 存在时物化
action；常规上下文组装和模型输入不得通过复制 `event_id` 补造动作，工具结果则必须沿用来源
工具调用的稳定 `call_id`。每个可识别 `event_id + decision_id` 的策略判断都必须有真实评估
主体：依次优先 action、`context_assembled` 的 context、显式 model intent、其他 context，
最后使用 event 回退节点，并以 `evaluated_to` 连接 decision。

已持久化的通用 `event` 节点同时承担兼容读取和 typed fact 缺失时的确定性回退：

- 查询继续原样返回，不做破坏性删除。
- 当前 `0.3` 写入可继续生成。
- 完整生命周期 writer 有对应 typed node 时不重复生成 event；没有 typed node 时不得丢失
  策略判断主体。

节点 label 只使用脱敏、可读且有事实依据的短文本。完整参数、原始上下文和长正文不进入
label 或 ID；有界详情进入 metadata 或关联 AuditEvent evidence。

策略节点必须带 `trace_id` 命名空间。当前存储以 `node_id` 为全局主键、节点又只属于一个
Trace；不带 Trace 的策略 ID 会让同一策略快照在第二条 Trace 中发生主键冲突或形成孤儿边。
该命名不改变原始 `ref_id={bundle_id}:{revision-or-version}`，也不要求数据库迁移。

## 6. 关系写入矩阵

边方向固定为来源事实到后续事实。只有两个端点都已存在时才写边。

| source → target                              | relation             | `relation_type` | 写入条件                          |
| -------------------------------------------- | -------------------- | --------------- | --------------------------------- |
| source → task                                | `received_from`      | `causal`        | 任务明确来自该来源                |
| source → context                             | `assembled_into`     | `causal`        | 来源实际进入上下文                |
| task → context                               | `influenced`         | `causal`        | 当前任务实际约束该上下文          |
| context → model_intent                       | `influenced`         | `causal`        | 明确记录模型意图摘要              |
| model_intent → action                        | `proposed_action`    | `causal`        | 该动作来自明确的 tool plan        |
| action → resource                            | `targets`            | `causal`        | 资源由该动作规范派生              |
| resource → rule                              | `detected_by`        | `detection`     | 规则命中证据引用该资源            |
| decision → policy                            | `evaluated_under`    | `policy`        | 使用的是该事件时策略快照          |
| action/context/model_intent/event → decision | `evaluated_to`       | `policy`        | Guard evaluate 的真实输入与输出   |
| decision → approval                          | `requested_approval` | `approval`      | 决策实际创建 approval             |
| approval → runtime_result                    | `released_by`        | `approval`      | runtime outcome 明确引用 approval |
| decision → runtime_result                    | `executed_as`        | `execution`     | outcome 明确引用 decision         |
| action → runtime_result                      | `produced`           | `execution`     | outcome 明确引用 action           |
| runtime_result/decision/config_audit → audit | `recorded_as`        | `audit`         | 该事实由对应 AuditEvent 持久化    |
| decision → review                            | `reviewed_by`        | `detection`     | Action Critic 明确复核该 decision |

每条边使用确定性 ID：

```text
edge:{relation}:{source_node_id}:{target_node_id}
```

`metadata.relation_type` 必须来自上表；可选短 label 只作展示提示，不改变 relation 语义。

## 7. 生命周期写入

### 7.1 策略评估

`POST /v1/guard/evaluate` 成功路径在同一次服务调用中：

1. 固定事件时策略快照。
2. Core 生成 GuardDecision。
3. 必要时创建 ApprovalRequest 和 Action Critic 记录。
4. Guard API 唯一写入 `policy_evaluation` AuditEvent。
5. writer 写入可用的 task、source、context、model intent、event fallback、action、
   resource、rule、policy、decision、approval、review、audit 节点及确定性边。
6. 返回 decision / approval。

同一 evaluate 请求的幂等重试不得重复创建节点或边；如果审计已存在但 provenance 不完整，
重试必须补齐缺失的确定性记录。

### 7.2 运行时结果和观察

`POST /v1/audit/events` 写入成功后：

- `runtime_outcome` 创建 `runtime_result` 和 `audit`。
- `runtime_observation` 至少创建 `audit`；有明确 typed fact 时再创建对应节点。
- `config_audit` 创建 `config_audit` 和 `audit`。
- 只通过 `links.action_id`、`links.decision_id`、`links.approval_id` 等稳定引用连接已有节点。
- 缺少 link 时不得按 trace 内唯一节点或最近时间猜测端点。

### 7.3 审批状态

- 创建审批时写入 `approval` 节点以及 `decision → approval`。
- resolve 或 expire 时以相同 `approval:{approval_id}` 更新明确终态。
- 审批终态本身不证明工具已执行或未执行。
- 只有收到引用该 approval 的 runtime outcome 后，才写入审批到运行结果的关系。
- nonce、CSRF token、browser session 和完整审批参数不得进入 provenance。

## 8. 一致性、失败与重试

Memory 和 PostgreSQL 必须遵循相同规则：

1. 先完成业务事实和 AuditEvent 的合法性校验。
2. AuditEvent 成功持久化后，同步执行确定性 provenance upsert。
3. 稳定 ID 冲突返回 `409 PROVENANCE_CONFLICT`，其他写入失败返回受控 5xx；不把不完整图声明为成功写入。
4. 调用方重试同一幂等请求时，不重复延长审计哈希链，并修复缺失节点或边。
5. 边写入前验证两个端点存在；禁止永久孤儿边。
6. 相同 ID 对应不同 trace、kind、ref 或端点时记录受控冲突，禁止 last-write-wins。
7. 查询按 timestamp、node ID / edge ID 确定性排序。

本能力不要求跨不同存储实现共享数据库事务，但要求“可检测失败 + 幂等重试修复”，并以共享
contract tests 保证最终状态一致。

## 9. 安全和大小边界

- 复用冻结契约的脱敏 key、字符串、数组、嵌套深度和 64 KiB 单事件 evidence 限制。
- node label、metadata、edge metadata 必须经过相同服务端脱敏。
- ID 不包含原始路径、收件人、消息内容、工具参数、用户任务或凭证值。
- metadata 不保存 control token、adapter token、session、CSRF token、approval nonce。
- 未测量副作用保持 `count=null` 和 `measurement_status=not_measured`。
- deny、ask 或 approval denied 不得单独推断 `execution.status=not_invoked`。
- Dashboard 的二次遮盖不能替代服务端最小化。

## 10. 查询、兼容和历史数据

`GET /v1/traces/{trace_id}/provenance`：

- 只读取 `provenance_nodes` 和 `provenance_edges` 中已经持久化的事实。
- 继续返回当前稀疏图、旧 kind 和旧 relation，不做破坏性过滤。
- 新消费者必须忽略未知 kind、relation 和 metadata。
- 缺少节点或关系时返回合法稀疏图，不从 AuditEvent 查询结果临时补图。

历史策略：

- 本次目标只保证功能启用后新写入的事件。
- 不自动扫描、更新或回填历史 Trace。
- 不把 AuditEvent `0.3` 在读取时伪装成 `0.4` evidence。
- 如果未来需要历史回填，必须另立迁移文档、命令、权限、速率限制、审计和回滚任务。

## 11. 组件责任

### AgentGuard Core

- 提供 GuardEvent、GuardDecision、rule hits 和规范资源事实。
- 后续提供已冻结的 risk breakdown。
- 不负责持久化、审批终态、事件时策略快照或运行时回执。

### Guard API / Control Plane

- 负责稳定 ID、脱敏、有界投影、writer、upsert、查询和冲突处理。
- 使用实际策略快照创建 policy 节点。
- 在 evaluate、audit event 和 approval 状态路径触发 writer。
- 保证 Memory / PostgreSQL 行为一致。

### LangGraph Adapter / OpenClaw Plugin

- 上报稳定 links 和结构化 runtime outcome / observation。
- 不重复写 Guard API 已生成的策略审计。
- 不提交前端坐标、完整敏感上下文或输出字段 `integrity`。

### Dashboard

- 只展示接口返回的节点和边。
- 对 canonical relation 做中文显示映射，未知 relation 安全降级。
- 继续以原始 audit `ref_id` 与时间线联动。
- 不通过 Mock 形态、节点顺序或 ID 前缀补造关系。

## 12. 后端验收矩阵

| 场景                    | Memory 与 PostgreSQL 共同验收                             |
| ----------------------- | --------------------------------------------------------- |
| 最小策略评估            | event/action、decision、audit 基础关系保持兼容            |
| 完整策略评估            | task 至 audit 的所有已有事实生成稳定 typed nodes          |
| 重复 evaluate           | 节点、边和审计链数量不增加；缺失 provenance 可修复        |
| 资源                    | 相同规范资源得到相同摘要；敏感目标不进入 ID               |
| 规则和策略              | 规则、风险和事件时策略与实际 decision 一致                |
| ask                     | approval 节点存在，但没有 outcome 时不推断执行结果        |
| approval resolve        | 更新同一 approval 节点，不创建第二个审批事实              |
| runtime success/failure | 通过稳定 links 连接 action、decision、approval 和 outcome |
| deny without receipt    | 保持运行时状态未知                                        |
| runtime observation     | 不生成新的策略 decision                                   |
| config audit            | typed config node 与 audit 节点正确关联                   |
| Action Critic           | review 节点通过 `reviewed_by` 连接实际 decision           |
| 缺失 links              | 保留真实节点，不创建猜测边或孤儿边                        |
| 冲突 ID                 | 返回受控错误，不覆盖另一 trace 或实体                     |
| 脱敏与边界              | 敏感 key、凭证、超长值和前端坐标不进入响应                |
| 查询                    | 排序稳定；未知 kind/relation 向前兼容                     |
| 历史 Trace              | 保持原有稀疏图，不自动回填或读取时合成                    |

## 13. 发布与回滚

推荐顺序：

1. 完成 AuditEvent 0.4、幂等、runtime outcome 和稳定 links。
2. 以
   [运行时安全主演示链 fixture](../../tests/fixtures/runtime_safety_trace_v04.json)
   为第一条共享基线，补充 Memory/PostgreSQL contract tests。
3. 先在测试环境启用 writer，比较 audit 数量、节点数、孤儿边和冲突数。
4. Dashboard 使用真实 API fixture 验证节点、关系、时间线联动和长文本布局。
5. 对新事件启用生产写入，不处理历史 Trace。
6. 观察受控冲突、writer 失败率、平均节点/边数量和 provenance 查询延迟。

回滚只停用丰富节点写入，保留基础 `event → decision → audit` 和已经持久化的数据。不得通过
回滚删除历史节点、重写审计链或把已有 typed node 降级为前端合成结果。

## 14. 完成定义

只有同时满足以下条件才能把 TODO 中的后端实现标记为完成：

- 冻结契约的节点、关系、ID、未知值和安全边界已实现。
- Memory / PostgreSQL 共享 contract tests 全部通过。
- evaluate、approval、runtime outcome、observation、config audit 和 critic 场景通过。
- 幂等重试能够修复部分写入且不重复审计。
- 查询不做读取时合成，历史 Trace 未被自动回填。
- Dashboard API 模式使用真实响应完成四档桌面视口验证。
- 当前接口、CLI 和旧消费者保持向后兼容。
