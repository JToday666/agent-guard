# Agent 运行时安全可观测与动态治理设计

> 状态：阶段 0 设计已冻结，代码实施尚未开始
>
> 冻结日期：2026-08-07
>
> 主演示运行时：LangGraph / AttackBench
>
> 适用组件：Dashboard、Guard API / Control Plane、AgentGuard Core、LangGraph Adapter、OpenClaw Plugin

## 1. 文档定位

本文冻结“执行轨迹、溯源关系、审计记录”三种视图的产品边界、事实来源、关联 ID、
真实演示链和动态刷新原则，作为后续分阶段实施的基线。

本阶段只完成设计和共享契约样例，不表示下列能力已经交付：

- Adapter 已写入完整 AuditEvent `0.4` 运行时回执；
- Adapter / Plugin 已持久化明确的 Trace start / terminal 生命周期 observation；
- Trace API 已支持条件请求；
- Provenance writer 已生成完整生命周期关系；
- Dashboard 已提供执行轨迹或动态刷新。

后续实现不得用静态页面、Mock 数据或前端推断替代这些真实能力。

## 2. 产品目标与非目标

本能力定位为“Agent 运行时安全可观测与动态治理”，服务三个用户问题：

1. **实时感知**：Agent 正在提出或执行什么动作。
2. **风险决策**：动作为什么被允许、要求审批或拒绝。
3. **人机协同**：审批如何影响后续执行，最终结果是否被运行时确认。

它不是 Agent 思维链、传统工作流进度条或通用流程编排器。

明确不做：

- 不展示或推断模型隐藏思维链。
- 不创建尚未发生的未来动作或百分比进度。
- 不把 Trace 内所有记录合并成一张持续重排的大图。
- 不新增一级导航或独立“执行监控”页面。
- 不把执行轨迹另存成新的后端事实模型。

## 3. 真实演示链选择

### 3.1 冻结结论

主演示链固定为：

```text
LangGraph / AttackBench
→ GuardedToolGateway
→ Guard API
→ Stateless Core
→ Approval
→ MockToolRegistry 隔离工具运行时
→ AuditEvent / Provenance
→ Dashboard
```

演示必须连接真实 Guard API，不能使用 Dashboard Mock、Fake Core Client 或手工注入的页面
状态代替链路事实。工具运行在受控本地演示环境，不访问真实秘密、生产数据或外部系统。
AttackBench 固定使用 `defense=on`、`fake_core=false`、`approval_mode=wait`；代码动作只进入
`MockToolRegistry.code_exec` 的 `safe_arithmetic` 分支。

OpenClaw 保留为跨运行时增强链，不作为本轮主演示链。只有在后续阶段通过稳定
`toolCallId` 关联、AuditEvent `0.4` 结果回执、审批释放和断线恢复验收后，才能升级为
等价演示链。

### 3.2 选择依据

| 维度         | LangGraph / AttackBench                               | OpenClaw                                        |
| ------------ | ----------------------------------------------------- | ----------------------------------------------- |
| 当前演示定位 | 已是 P0 主演示路径                                    | 当前演示脚本列为 P1                             |
| 动作事实     | `memory_read`、`code_exec` 已有明确工具名和 `call_id` | 工具 Hook 有 `toolCallId`                       |
| 资源事实     | Adapter 已能规范化 memory/code 资源                   | 依赖 Hook payload 和缓存恢复                    |
| 执行结果     | 已有 `ToolExecutionResult`，但尚未统一写入 0.4 回执   | 目前主要写 0.3 observation，稳定 links 仍需迁移 |
| 决赛风险     | 链路较短，行为和结果更容易确定性复现                  | Hook 版本和执行后语义带来额外联调面             |

选择 LangGraph 不代表 OpenClaw 能力被弱化，而是先保证一条可重复、可审计、可现场恢复的
真实闭环，再用 OpenClaw 证明跨运行时扩展性。

### 3.3 冻结场景

同一 `trace_id` 内演示两个真实动作：

1. `memory_read`
   - 每次演示前重置隔离 sandbox，并在 Trace 外预置一条 trusted 报告偏好；
   - 读取脱敏的本地偏好；
   - Core 返回 `allow`；
   - Adapter 实际执行并回写 `execution.status=executed`。
2. `code_exec`
   - 不可信上下文提出一个不属于原始任务的受控算术计算；该动作无网络和业务资源写入，
     只产生 sandbox 证据日志；
   - 隔离的演示策略把 `P108_agent_abuse` 从默认拒绝显式调整为高风险审批，
     `P004_task_mismatch` 继续要求审批；
   - Core 返回 `ask`、风险 72、严重性 high；
   - Dashboard 展示待审批；
   - 用户选择 `allow_once`；
   - Adapter 收到审批终态后显式上报 `tool_call_started`；
   - 受控工具执行成功并回写 `execution.status=executed`。

最终界面必须同时保留：

```text
ASK               原始策略决定
单次放行          人工审批结果
已执行            运行时确认结果
```

审批放行不能把原始 `ask` 改写成绿色 `allow`。

生产默认策略对未授权高影响代码动作保持 `deny`。演示策略是独立、版本化且带 digest 的
真实 PolicyBundle，只为展示人机协同闭环；不得隐藏该 override、修改生产默认策略或在
前端伪造 `ask`。

Trace 外的环境预置只用于确定性准备 sandbox，不得出现在执行轨迹中冒充 Agent 动作；其
来源和 trusted 标记仍由运行时数据记录。

当前 `P108_agent_abuse` 经 policy override 变为 `ask` 时，Core 生成的
`approval_intent.resource` 仍可能为空。主演示链进入实现前，Guard API 必须在创建审批时
使用服务端已规范化、已脱敏的首个 resource target 作为空值回退；不得由 Dashboard 从
原始命令补造。本 fixture 冻结的审批资源 `2 + 2` 是该目标形态，不是当前能力声明。

## 4. 冻结的架构决策

| 编号   | 冻结结论                                                                                                   |
| ------ | ---------------------------------------------------------------------------------------------------------- |
| RSO-01 | AuditEvent、Approval 和持久化 Provenance 是后端事实；执行轨迹是 Dashboard 投影。                           |
| RSO-02 | 不新增 `AgentActionEvent`、`RuntimeEvent` 或 `ExecutionNode` 后端模型。                                    |
| RSO-03 | 不新增 Dashboard 专用 trace events 或 runtime outcome 端点。                                               |
| RSO-04 | 继续复用 `GET /v1/traces/{trace_id}`、`GET /v1/traces/{trace_id}/provenance` 和 `POST /v1/audit/events`。  |
| RSO-05 | 不向 Trace JSON 增加含义不清的 `complete`；窗口未截断不等于 Agent 已结束。                                 |
| RSO-06 | 暂不增加 JSON `snapshot_version`；后续以 HTTP ETag 实现条件刷新。                                          |
| RSO-07 | Trace ETag 必须覆盖 audit events、approvals 及 Trace 响应中其他可变内容，不能只取最大审计 sequence。       |
| RSO-08 | Provenance 使用独立 ETag；Trace 和 Provenance 不共享隐含版本。                                             |
| RSO-09 | 后端 `execution.status` 保持 `not_invoked/executed/failed/unknown`，不为 UI 扩枚举。                       |
| RSO-10 | `decision`、`approval`、`execution` 三层事实分别展示，任何一层都不能覆盖另一层。                           |
| RSO-11 | “正在执行”只来自明确的 `tool_call_started` 或等价 observation；仅有 allow/审批放行时显示“等待运行时回执”。 |
| RSO-12 | 执行轨迹实时刷新；溯源关系保持稳定并按需更新，避免自动布局和视口持续跳动。                                 |
| RSO-13 | `memory_read` 只根据明确 action name 和规范资源映射，不做工具名模糊猜测。                                  |
| RSO-14 | 不补造未来动作、缺失关系、终态、成功、零副作用或未执行事实。                                               |
| RSO-15 | 历史 Trace 保持原状，不在读取时升级或合成新事实。                                                          |
| RSO-16 | 第一版不新增 SSE / WebSocket；条件轮询验收稳定后再单独评审推送能力。                                       |

这些决策若需变更，必须先同步本文、证据契约、UI 规范和共享 fixture，再进入代码实施。

## 5. 事实模型与责任边界

### 5.1 事实生产者

| 事实                          | 唯一或权威生产者     | Dashboard 行为                 |
| ----------------------------- | -------------------- | ------------------------------ |
| GuardEvent 与规范资源         | Adapter / Plugin     | 只读取脱敏投影                 |
| GuardDecision 与 rule hits    | Core                 | 不重新计算风险或决定           |
| policy evaluation AuditEvent  | Guard API            | 按 `record_type` 读取          |
| Approval 创建与终态           | Guard API / 人工审批 | 不根据按钮点击本地推断最终状态 |
| runtime observation / outcome | Adapter / Plugin     | 不根据 decision 推断执行       |
| Provenance 节点与边           | Guard API writer     | 不按时间邻近补边               |
| 执行动作卡片与阶段            | Dashboard projection | 可重建，不持久化为审计事实     |

Core 只回答“应该如何处理”；Adapter / Plugin 才能回答“后来是否开始、是否执行和结果如何”。

### 5.2 稳定关联 ID

| ID            | 语义                                       | 关联用途                     |
| ------------- | ------------------------------------------ | ---------------------------- |
| `trace_id`    | 一次 Agent 运行或调查链                    | 详情页、查询和刷新作用域     |
| `event_id`    | 一次 GuardEvent 或明确的运行时事件         | 策略输入和观察来源           |
| `action_id`   | 一次可执行动作；工具动作使用原始 `call_id` | 聚合策略、审批、结果和图节点 |
| `decision_id` | 一次 Core 决策                             | 关联策略判断与规则           |
| `approval_id` | 一次审批请求                               | 关联待审、终态和放行结果     |
| `audit_id`    | 一条持久化审计记录                         | 审计时间线和完整性           |

所有 ID 都是不透明字符串。消费者不得通过拆分前缀或内容推断事实。

### 5.3 Dashboard 投影

后续 Dashboard 以 `action_id` 聚合 AuditEvent 与 Approval，形成可重建的
`ExecutionActionViewModel`。它至少包含：

```text
actionId
actionName
resource summary
decision: allow | ask | deny | unknown
approval: not_required | pending | allowed_once | denied | expired | unknown
execution: not_invoked | executed | failed | unknown
phase: proposed | evaluated | waiting_approval | approval_released | waiting_receipt | terminal
policy checks
audit IDs
timestamps
provenance node ID
```

`phase` 是展示投影，不进入 AuditEvent。聚合必须支持同一动作多次策略检查，不能用
“最后一条记录覆盖前一条记录”。

投影的确定性规则：

- AuditEvent 按 `integrity.sequence`、`timestamp`、`audit_id` 排序；缺失 sequence 时不
  补造。
- 先按 `audit_id` 幂等合并；历史重复策略审计继续按稳定 `event_id + decision_id`
  识别逻辑重复并保留最早记录。
- `policyChecks[]` 保存动作的全部逻辑唯一策略判断。
- 卡片主决定优先使用 runtime outcome 的 `policy_audit_id` 所指策略审计；等待审批时使用
  Approval 关联的决定；其余情况才使用最近一次逻辑策略判断。
- links 缺失或互相冲突时，主决定保持 `unknown`，不得按时间邻近选择。
- 没有稳定 `action_id` 的记录只进入审计记录，不创建匿名动作卡片。
- 动作按首次已知事实排序；并列时使用不透明 `action_id` 保证顺序稳定。

### 5.4 生命周期投影规则

| 已持久化事实                    | 允许显示的 phase / 文案                      | 禁止推断                           |
| ------------------------------- | -------------------------------------------- | ---------------------------------- |
| 只有动作提议                    | `proposed` / 已提出动作                      | 已评估、正在执行                   |
| 已有 policy evaluation          | `evaluated` / 已完成安全判断，等待运行时回执 | 工具已开始                         |
| `ask` 且审批 pending            | `waiting_approval` / 等待审批                | 已拒绝、已执行                     |
| approval `allow_once`，无 start | `approval_released` / 已放行，等待运行       | 正在执行                           |
| 明确 `tool_call_started`        | `waiting_receipt` / 正在执行                 | 执行成功                           |
| runtime outcome `executed`      | `terminal` / 已执行                          | 副作用为零，除非另有 measured 事实 |
| runtime outcome `failed`        | `terminal` / 执行失败                        | 从错误推断策略拒绝                 |
| runtime outcome `not_invoked`   | `terminal` / 已确认未执行                    | 仅凭 deny/ask 得出未执行           |
| 无 outcome 且链路停止           | 保持 `unknown` / 未收到运行回执              | 自动改成失败或完成                 |

Trace 顶部的“运行中、等待审批、已结束”也只能由明确生命周期 observation 或当前已知
阻塞事实投影。若没有明确 `trace_completed/trace_failed/trace_cancelled`，统一使用
“实时观察中”，不声称 Trace 尚在运行或已经完成。

## 6. 页面结构与联动

不新增一级页面。`/evidence/:trace_id` 继续承担一次 Trace 的调查和治理上下文。

顶部保留 Trace 基本信息、最终安全结论、六维事实和紧凑阶段摘要；主体冻结为三个互补视图：

1. **执行轨迹**（默认）
   - 按动作而非按 AuditEvent 展示时间流卡片；
   - 决策颜色与运行状态图标分层编码；
   - 待审批动作提供“处理审批”；
   - 提供“查看安全依据”定位对应 Provenance action node。
2. **溯源关系**
   - 继续回答“为什么发生、依据是什么、事实如何关联”；
   - 进入视图或用户确认更新时获取最新图；
   - 新关系到达时提示数量，不自动复位筛选、折叠或视口；
   - Trace 明确终态后可执行一次最终布局。
3. **审计记录**
   - 按 AuditEvent 展示完整时间顺序；
   - 保留 integrity、原始 record type 和脱敏证据入口；
   - 与执行动作和溯源节点双向定位。

三种视图不会重复承担同一职责：

```text
执行轨迹：现在发生什么，以及人能做什么
溯源关系：为什么发生，以及事实如何关联
审计记录：系统实际记录了什么
```

组件迁移冻结为：

- 新增 `ExecutionTrace.vue`，只接收按 `action_id` 聚合的动作投影；
- 现有 `TraceTimeline.vue` 在迁移时重命名为 `AuditTimeline.vue`，继续按 AuditEvent 展示，
  不承担动作聚合；
- `EvidenceStageFlow.vue` 收敛为顶部紧凑阶段摘要；
- `ProvenanceGraph.vue` 保持溯源调查职责，不复制执行卡片；
- 不保留两套动作时间线，也不在一个组件内同时处理 action 和 audit event 语义。

视图与选择状态进入 URL query，保证刷新、分享和返回后可恢复：

```text
view=execution | provenance | audit
action_id=<raw action id>
node_id=<provenance node id>
event_id=<raw audit id>
```

默认 `view=execution`。旧的 `event_id` 深链继续有效，并打开审计记录或事件详情。点击“查看
安全依据”切换到 provenance，并按 `kind=action + ref_id=action_id` 精确查找节点；不得由
前端拼接 node ID。点击“处理审批”复用现有 `/approvals/{approval_id}`，不在证据链页复制
一套审批弹窗。

## 7. 动态刷新

### 7.1 Trace

后续实现采用约 2 秒的条件轮询作为第一阶段实时机制：

```text
GET /v1/traces/{trace_id}
If-None-Match: <trace-etag>
```

- `200`：按稳定 ID 合并完整响应并更新 ETag。
- `304`：保留当前投影，不重新布局或播报。
- 页面不可见时暂停，恢复可见后立即校准一次。
- 网络失败保留最后一次已确认事实，显示连接状态并采用有界退避。
- 审批提交得到服务端响应后立即刷新 Trace，不等待下一轮定时器。
- 有待审批动作时不得因为其他动作终态而停止刷新。
- 只有明确 Trace 终态且没有待审批、没有等待回执动作时才停止自动轮询。

响应使用私有、需重新验证的缓存语义，不能被共享缓存复用。ETag 的具体计算和路由实现属于
后续后端阶段，本阶段不修改接口。目标响应至少使用
`Cache-Control: private, no-cache` 和 `Vary: Cookie, Authorization`；ETag 保持不透明，
不得要求客户端解析 sequence 或状态。

### 7.2 Provenance

Provenance 使用独立条件请求和非对称刷新：

- 默认不跟随每次 Trace 轮询触发布局；
- 执行轨迹点击“查看安全依据”时刷新并定位；
- 已知有新关系时展示“有新证据”提示，由用户更新；
- Trace 终态后自动校准一次；
- 更新后保留用户筛选、折叠、选中节点和可恢复的视口锚点。

若后端尚不能廉价判断是否有新 Provenance，前端不得从 Trace 新增记录数伪造“新增节点数”。

## 8. 后续后端实施边界

本阶段不改后端。后续后端工作必须按以下顺序实施：

1. Guard API 唯一写入 AuditEvent `0.4` `policy_evaluation`，保留实际策略快照。
2. Guard API 为 `approval_intent.resource` 空值使用已规范化、已脱敏的资源目标回退，
   并以契约测试覆盖 policy override 后的 `ask`。
3. LangGraph Adapter 停止重复策略审计，并把成功、失败、未调用和审批释放结果写成
   `runtime_outcome`。
4. 仅在真实 start Hook 可观察时写 `tool_call_started` `runtime_observation`。
5. 使用稳定 `event_id/action_id/decision_id/approval_id/policy_audit_id` links。
6. Provenance writer 在写入时确定性物化动作、决策、审批、结果和审计关系。
7. 为 Trace 与 Provenance 分别实现完整响应 ETag 和 `304`。
8. Memory 与 PostgreSQL 运行同一套幂等、关联和条件请求 contract tests。

审批终态发生变化但 AuditEvent 未增加时，Trace ETag 也必须变化。禁止只使用最大
`integrity.sequence` 计算 Trace ETag。

## 9. 安全、故障与可恢复性

- 演示命令必须在受控工具中固定或严格 allowlist，不接触真实凭证、网络或持久化资源。
- 页面只展示服务端已脱敏、有界事实；不复制 approval nonce、token 或完整工具参数。
- `deny`、`ask`、断线或超时都不能单独证明 `not_invoked`。
- 条件轮询断线重连后以服务端完整快照校准，不依赖丢失期间的增量事件。
- 相同稳定 ID 内容冲突时进入受控错误，不采用 last-write-wins。
- 一条动作投影失败不能阻断审计记录查看；Provenance 失败不能清空已确认的执行轨迹。
- 现场演示必须保留一条预先验证的真实 Trace 作为只读恢复入口，但不得把它冒充正在运行。

## 10. 共享契约 fixture

[runtime_safety_trace_v04.json](../../tests/fixtures/runtime_safety_trace_v04.json)
冻结本场景的源事实、最终 Provenance 和分阶段投影断言。fixture 是目标契约样例，不代表
当前 Adapter、Guard API 或 Dashboard 已经端到端产出该结构。

后续跨组件测试必须至少验证：

- 两个 action 使用稳定且不同的 `action_id`；
- memory action 为 `allow + executed`；
- code action 保留 `ask + allow_once + executed`；
- 审批放行之前没有 `tool_call_started`；
- 只有 start observation 到达后才显示“正在执行”；
- runtime outcome 通过 `policy_audit_id` 回指唯一策略审计；
- 每条 Provenance 边的端点存在，action `ref_id` 使用原始 `action_id`；
- 执行轨迹、审计记录和 Provenance 可通过稳定 ID 双向定位；
- 不存在未来动作、前端坐标、敏感值或根据 ID 拆分得到的事实。

## 11. 阶段 0 完成定义

阶段 0 只有同时满足以下条件才算完成：

- 主演示运行时、动作顺序、安全决定和审批结果已唯一确定；
- 事实生产者、稳定 ID、未知值和状态投影规则已冻结；
- 页面位置、三视图职责和非对称刷新方案已冻结；
- 后端后续边界、ETag 覆盖范围和禁止推断项已记录；
- 共享 fixture 可通过 AuditEvent `0.4` Schema 和交叉引用检查；
- TODO 清楚区分“设计完成”“基础兼容已存在”和“端到端实现未开始”。

任何代码实现都从下一阶段开始，不得把本文的目标描述为当前已交付能力。
