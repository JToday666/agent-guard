# Agent 运行时安全可观测与动态治理设计

> 状态：设计与实施已完成；Memory/PostgreSQL 真实演示链和 Dashboard 读链验收通过
>
> 冻结日期：2026-08-07
>
> 实施更新：2026-08-08
>
> 主演示运行时：LangGraph / AttackBench
>
> 适用组件：Dashboard、Guard API / Control Plane、AgentGuard Core、LangGraph Adapter、OpenClaw Plugin

## 1. 文档定位

本文冻结“执行轨迹、溯源关系、审计记录”三种视图的产品边界、事实来源、关联 ID、
真实演示链和动态刷新原则，并记录当前实施与剩余验收边界。

截至 2026-08-08，以下代码能力已经交付：

- Guard API 唯一写入 AuditEvent `0.4` 策略记录，并统一幂等、脱敏和有界证据；
- LangGraph Adapter 写入运行时回执、`tool_call_started` 和 Trace 生命周期 observation；
- Trace 与 Provenance 使用独立 ETag 和 `304`，Trace 响应包含窗口完整性；
- Provenance writer 在写入时物化稳定节点与关系，并保护节点、边和审批状态冲突；
- Dashboard 已提供三视图、全 Guard 阶段的确定性步骤投影、约 2 秒条件轮询和按需溯源
  更新。
- 真实 LangGraph / AttackBench 主演示链已通过实际 Uvicorn HTTP 服务分别连接 Memory 与
  PostgreSQL，完成审批释放、受控执行、Trace、ETag 和 Provenance 验收；Dashboard 又通过
  真实 PostgreSQL API 读取同一代表性场景并验证动作投影和溯源定位；全 GuardEvent
  覆盖由共享矩阵回归验证，不以该场景的两个动作定义产品范围。

共享 fixture、单元测试和拦截式 API E2E 继续承担可重复的分层回归职责；真实链验收由
`tests/test_runtime_safety_e2e.py` 和本机浏览器只读核验独立证明，不用 TestClient 或页面
路由拦截冒充端到端结果。

## 2. 产品目标与非目标

本能力定位为“Agent 运行时安全可观测与动态治理”，服务三个用户问题：

1. **实时感知**：Agent 已经过哪些受控运行阶段，正在提出或执行什么动作。
2. **风险决策**：每个阶段或动作为什么被允许、要求审批或拒绝。
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

| 维度         | LangGraph / AttackBench                                           | OpenClaw                                                 |
| ------------ | ----------------------------------------------------------------- | -------------------------------------------------------- |
| 当前演示定位 | 已是 P0 主演示路径                                                | 当前演示脚本列为 P1                                      |
| 动作事实     | 回归场景中的 `memory_read`、`code_exec` 有明确工具名和 `call_id`  | 工具 Hook 有 `toolCallId`                                |
| 资源事实     | Adapter 已能规范化 memory/code 资源                               | 依赖 Hook payload 和缓存恢复                             |
| 执行结果     | 已统一写入 0.4 outcome 与生命周期 observation，真实链已跨存储验收 | 已覆盖最小 0.4 outcome；allow 后执行确证仍非本期完整范围 |
| 决赛风险     | 链路较短，行为和结果更容易确定性复现                              | Hook 版本和执行后语义带来额外联调面                      |

选择 LangGraph 不代表 OpenClaw 能力被弱化，而是先保证一条可重复、可审计、可现场恢复的
真实闭环，再用 OpenClaw 证明跨运行时扩展性。

### 3.3 代表性真实闭环场景

同一 `trace_id` 内使用两个真实动作演示最小完整治理闭环。它是稳定的答辩场景和跨存储
回归 fixture，不是 Dashboard 动作白名单，也不改变 Adapter / Plugin 原有审计范围。真实
Trace 中已持久化的其他工具、记忆、消息、模型输出和安全检查阶段必须按事实显示。

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

`P108_agent_abuse` 经 policy override 变为 `ask` 且 Core 的
`approval_intent.resource` 为空时，Guard API 现已使用服务端已规范化、已脱敏的首个
resource target 回退，并由共享存储契约测试覆盖。Dashboard 不从原始命令补造资源。

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
| 运行步骤、动作聚合与阶段      | Dashboard projection | 可重建，不持久化为审计事实     |

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

`event_id` 与 `action_id` 不可互换。常规 `context_assembled`、
`model_input_prepared` 可以显示为执行轨迹中的安全检查点，但不得仅因被 Guard 评估就
创建执行动作；`tool_result_produced` 复用来源工具的原始 `call_id`。需要审批的内部阶段可
使用稳定 `event_id` 作为受控审批主体，但这不改变其他同类记录的默认边界。

Provenance 策略节点使用 Trace 级内部键
`policy:{trace_id}:{bundle_id}:{revision-or-version}`，避免不同 Trace 复用同一策略快照时发生
节点归属冲突；`ref_id` 仍只保存原始 `bundle_id:revision-or-version`。该格式属于 writer
的确定性物化规则，前端不得拼接或解析它。

### 5.3 Dashboard 投影

Dashboard 先把逻辑唯一的 AuditEvent 投影为可重建的 `ExecutionStepViewModel`：有
`action_id` 时按动作聚合完整生命周期；没有 `action_id` 的 policy evaluation 按
`event_id` 形成独立安全检查点。它至少包含：

```text
stepId
kind: action | checkpoint
category
receiptExpectation
actionId | null
actionName
eventIds
resource summary
decision: allow | ask | deny | unknown
approval: not_required | pending | allowed_once | denied | expired | unknown
execution: not_invoked | executed | failed | unknown
phase: proposed | evaluated | checked | waiting_approval | approval_released | waiting_receipt | terminal
policy checks
step events
audit IDs
timestamps
```

`phase`、`kind` 和 `receiptExpectation` 都是展示投影，不进入 AuditEvent。同一动作可以有
多次策略检查、显式 start、工具结果检查和最终 outcome；这些记录在一个顶层动作步骤内按
时间展示，不能用“最后一条记录覆盖前一条记录”。

步骤投影不保存或拼接 Provenance node ID。加载独立溯源快照后，动作先以
`kind=action + ref_id=action_id` 定位；检查点再按事实类型和原始 `event_id` 查找
context、model intent 或 event 节点，最后才回退到 decision / audit 节点。

投影的确定性规则：

- AuditEvent 按 `integrity.sequence`、`timestamp`、`audit_id` 排序；缺失 sequence 时不
  补造。
- 先按 `audit_id` 幂等合并；历史重复策略审计继续按稳定 `event_id + decision_id`
  识别逻辑重复并保留最早记录。
- `policyChecks[]` 保存步骤的全部逻辑唯一策略判断。
- 步骤主决定优先使用 runtime outcome 的 `policy_audit_id` 所指策略审计；等待审批时使用
  Approval 关联的决定；其余情况才使用最近一次逻辑策略判断。
- links 缺失或互相冲突时，主决定保持 `unknown`，不得按时间邻近选择。
- policy evaluation 没有稳定 `action_id` 但有 `event_id` 时创建检查点，不复制
  `event_id` 冒充动作 ID。
- 当前支持的 `context_assembled`、`model_input_prepared`、`model_output_produced`、
  `tool_call_proposed`、`tool_result_produced`、`memory_write_proposed` 和
  `message_send_proposed` 都进入执行轨迹；未知的未来 policy event 也以检查点安全回退。
- Trace 生命周期 observation 只更新顶部状态，配置审计只进入审计 / Provenance；二者不
  冒充 Agent 步骤。
- 步骤按首次已知事实排序；工具结果和 runtime receipt 沿原始 `action_id` 并入既有动作，
  不额外产生重复顶层节点。

### 5.4 生命周期投影规则

| 已持久化事实                    | 允许显示的 phase / 文案                      | 禁止推断                           |
| ------------------------------- | -------------------------------------------- | ---------------------------------- |
| 只有动作提议                    | `proposed` / 已提出动作                      | 已评估、正在执行                   |
| 已有 policy evaluation          | `evaluated` / 已完成安全判断，等待运行时回执 | 工具已开始                         |
| 无需运行回执的安全检查点        | `checked` / 安全检查已完成                   | 外部动作已经执行                   |
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

顶部只保留 Trace 基本信息和当前已确认的安全结论；主体立即进入三个互补视图。六维事实和
紧凑阶段摘要位于工作区后的折叠“调查摘要”，需要时再展开：

1. **执行轨迹**（默认）
   - 默认按运行步骤展示确定性图形流，并提供信息等价的紧凑列表；动作生命周期聚合，
     非动作 Guard 阶段显示为检查点；
   - 图形流按智能体处理、受控动作、检查与结果划分泳道；边只表达“随后记录”的审计顺序，
     不把时间邻接冒充因果关系；
   - 决策颜色与运行状态图标分层编码；
   - 待审批动作提供“处理审批”；
   - 提供搜索和待审批、风险、失败等筛选；详情展开后仍可逐条查看该步骤的审计记录；
   - 提供“查看安全依据”定位对应 Provenance 事实节点。
2. **溯源关系**
   - 继续回答“为什么发生、依据是什么、事实如何关联”；
   - 进入视图或用户确认更新时获取最新图；
   - 更新后显示最新节点和关系数量，不自动复位筛选、折叠、选择或视口锚点；
   - Trace 明确终态后可执行一次最终布局。
3. **审计记录**
   - 按 AuditEvent 展示完整时间顺序；
   - 保留 integrity、原始 record type 和脱敏证据入口；
   - 与运行步骤和溯源节点双向定位。

三种视图不会重复承担同一职责：

```text
执行轨迹：现在发生什么，以及人能做什么
溯源关系：为什么发生，以及事实如何关联
审计记录：系统实际记录了什么
```

组件实现为：

- `ExecutionTrace.vue` 作为执行视图控制器，管理刷新状态、筛选、选择和图形/列表切换；
- `ExecutionFlowGraph.vue` 使用确定性泳道布局展示全部步骤，保留稳定位置、当前步骤聚焦、
  Minimap、适配和全屏能力；普通滚轮不被嵌入式画布劫持；
- `ExecutionTraceList.vue` 提供信息和键盘操作等价的紧凑列表回退；
- `ExecutionTraceToolbar.vue` 统一搜索、状态筛选与布局切换；
- `ExecutionStepInspector.vue` 统一解释安全判断、审批、运行结果和审计记录；
- `execution-flow-layout.ts` 只依据步骤顺序和类别生成可测试的确定性位置及审计顺序边；
- `AuditTimeline.vue` 继续按 AuditEvent 展示，不承担动作聚合；
- `EvidenceStageFlow.vue` 收敛为折叠调查摘要中的紧凑阶段说明；
- `ProvenanceGraph.vue` 保持溯源调查职责，不复制执行卡片；
- 不保留两套动作时间线；逐条 AuditEvent 的完整调查职责仍由审计记录视图承担。

视图与选择状态进入 URL query，保证刷新、分享和返回后可恢复：

```text
view=execution | provenance | audit
execution_layout=graph | list
action_id=<raw action id>
node_id=<provenance node id>
event_id=<raw audit id>
```

默认 `view=execution`。旧的 `event_id` 深链继续有效，并打开审计记录或事件详情。点击“查看
安全依据”切换到 provenance：动作按原始 `action_id` 查找 action 节点，检查点按原始
`event_id/decision_id/audit_id` 和事实类型查找 typed node；不得由前端拼接或拆分 node ID。
点击“处理审批”复用现有 `/approvals/{approval_id}`，不在证据链页复制一套审批弹窗。

## 7. 动态刷新

### 7.1 Trace

Dashboard 已采用约 2 秒的条件轮询作为第一阶段实时机制：

```text
GET /v1/traces/{trace_id}
If-None-Match: <trace-etag>
```

- `200`：按稳定 ID 合并完整响应并更新 ETag。
- `304`：保留当前投影，不重新布局或播报。
- 页面不可见时暂停，恢复可见后立即校准一次。
- 网络失败保留最后一次已确认事实，显示连接状态并采用有界退避。
- 审批提交得到服务端响应后立即刷新 Trace，不等待下一轮定时器。
- 普通新增或状态更新不抢夺用户滚动位置和焦点，只显示“查看最新”提示；待审批、拒绝、
  执行失败等优先变化才进入辅助技术播报。
- 图中既有节点的位置只由稳定步骤顺序和类别决定，状态更新或尾部追加不得让既有节点跳动；
  用户缩放、拖动画布或选择旧步骤后暂停自动跟随，只能由“查看最新”主动恢复并聚焦。
- 没有明确 Trace 终态时，即使当前已知动作都已结束也继续观察后续步骤；有待审批动作时
  不得因为其他动作终态停止刷新。
- 收到明确 `trace_completed/trace_failed/trace_cancelled` 后停止循环，随即强制读取一次
  完整 Trace 快照并校准一次 Provenance；终态时仍缺失的审批或回执保持“未确认”，不得
  为了继续等待而无限轮询，也不得补造结果。

响应使用私有、需重新验证的缓存语义，不能被共享缓存复用。Guard API 已返回
`Cache-Control: private, no-cache`、`Vary: Cookie, Authorization` 和不透明 ETag；
Dashboard 不解析 sequence 或状态来推断版本。

### 7.2 Provenance

Provenance 使用独立条件请求和非对称刷新：

- 默认不跟随每次 Trace 轮询触发布局；
- 执行轨迹点击“查看安全依据”时刷新并定位；
- 用户进入视图或主动更新后显示本次校准结果；
- Trace 终态后自动校准一次；
- 更新后保留用户筛选、折叠、选中节点和可恢复的视口锚点。

若后端尚不能廉价判断是否有新 Provenance，前端不得从 Trace 新增记录数伪造“新增节点数”。

## 8. 后端实施状态与剩余边界

下列代码步骤已经按顺序完成：

1. Guard API 唯一写入 AuditEvent `0.4` `policy_evaluation`，保留实际策略快照。
2. Guard API 为 `approval_intent.resource` 空值使用已规范化、已脱敏的资源目标回退，
   并以契约测试覆盖 policy override 后的 `ask`。
3. LangGraph Adapter 停止重复策略审计，并把成功、失败、未调用和审批释放结果写成
   `runtime_outcome`。
4. 仅在真实 start Hook 可观察时写 `tool_call_started` `runtime_observation`。
5. 使用稳定 `event_id/action_id/decision_id/approval_id/policy_audit_id` links。
6. Provenance writer 在写入时确定性物化动作、非动作 Guard 阶段、决策、审批、结果和审计
   关系；没有 `action_id` 的策略判断连接到 context、model intent 或 event 事实节点。
7. 为 Trace 与 Provenance 分别实现完整响应 ETag 和 `304`。
8. Memory 与 PostgreSQL 共用同一套幂等、关联和条件请求 contract tests。

Memory 与本机 PostgreSQL 已通过相同存储契约。`tests/test_runtime_safety_e2e.py` 使用实际
Uvicorn 回环 HTTP 服务运行 LangGraph / AttackBench 代表性主演示场景，并分别验证两种
存储中的审批、运行回执、Trace、独立 ETag 和 Provenance；本机只读浏览器核验又确认
Dashboard 可通过真实 PostgreSQL Guard API 显示代表性动作并定位代码动作的溯源节点。
全 Guard 阶段另由前端矩阵回归验证，不能把两动作场景解释为产品白名单。测试完成后专用
PostgreSQL 测试库恢复为空，不向开发库写入演示数据。

审批终态发生变化但 AuditEvent 未增加时，Trace ETag 也必须变化。禁止只使用最大
`integrity.sequence` 计算 Trace ETag。

## 9. 安全、故障与可恢复性

- 演示命令必须在受控工具中固定或严格 allowlist，不接触真实凭证、网络或持久化资源。
- 页面只展示服务端已脱敏、有界事实；不复制 token、CSRF 或完整工具参数。
- `deny`、`ask`、断线或超时都不能单独证明 `not_invoked`。
- 条件轮询断线重连后以服务端完整快照校准，不依赖丢失期间的增量事件。
- 相同稳定 ID 内容冲突时进入受控错误，不采用 last-write-wins。
- 一条步骤投影失败不能阻断审计记录查看；Provenance 失败不能清空已确认的执行轨迹。
- 现场演示必须保留一条预先验证的真实 Trace 作为只读恢复入口，但不得把它冒充正在运行。

## 10. 共享契约 fixture

[runtime_safety_trace_v04.json](../../tests/fixtures/runtime_safety_trace_v04.json)
冻结本场景的源事实、最终 Provenance 和分阶段投影断言。Schema、存储、Provenance writer
和 Dashboard 步骤投影均已复用该 fixture；它是代表性治理闭环样例而不是事件类型白名单。
真实 Adapter、Guard API 与两种数据库的端到端证据由
`tests/test_runtime_safety_e2e.py` 独立提供。

后续跨组件测试必须至少验证：

- 两个 action 使用稳定且不同的 `action_id`；
- memory action 为 `allow + executed`；
- code action 保留 `ask + allow_once + executed`；
- 审批放行之前没有 `tool_call_started`；
- 只有 start observation 到达后才显示“正在执行”；
- runtime outcome 通过 `policy_audit_id` 回指唯一策略审计；
- 每条 Provenance 边的端点存在，action `ref_id` 使用原始 `action_id`；
- 执行轨迹、审计记录和 Provenance 可通过稳定 ID 双向定位；
- 七类当前 GuardEvent 都恰好进入一个顶层步骤或一个动作的子记录，工具提议、工具结果和
  runtime receipt 通过同一 `action_id` 聚合；
- 未知未来 policy event 以 `event_id` 检查点回退，不因缺少 `action_id` 丢失；
- 不存在未来动作、前端坐标、敏感值或根据 ID 拆分得到的事实。

## 11. 阶段 0 完成定义

阶段 0 只有同时满足以下条件才算完成：

- 主演示运行时、动作顺序、安全决定和审批结果已唯一确定；
- 事实生产者、稳定 ID、未知值和状态投影规则已冻结；
- 页面位置、三视图职责和非对称刷新方案已冻结；
- 后端后续边界、ETag 覆盖范围和禁止推断项已记录；
- 共享 fixture 可通过 AuditEvent `0.4` Schema 和交叉引用检查；
- TODO 清楚区分“设计完成”“代码已实施”“真实端到端验收通过”和后续增强项。

上述定义继续作为实施约束。当前代码和验收状态以第 1、8 节为准；fixture、Mock 与拦截式
API E2E 仍不得单独描述为端到端交付证据。
