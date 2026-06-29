# AgentGuard Dashboard 完整设计方案

> 本文保留 Dashboard 的 P1/P2 目标设计。当前已落地的路由是 `/overview`、`/approvals/:approval_id?`、`/investigations`、`/evidence`、`/evidence/:trace_id`、`/evaluation` 和 `/system`；独立 Advanced 页仍是未来规划。证据链详情优先读取 `GET /v1/traces/{trace_id}`，接口失败时回退到已加载 AuditEvent 窗口中的同 `trace_id` 事件。

## 1. 产品定位

AgentGuard Dashboard 不是普通后台管理系统，也不是大屏展示页，而是 **Agent 运行时安全监督工作台**。

它要让用户清楚看到：

```text
Agent 正在执行什么任务
→ Agent 准备调用什么工具
→ 工具参数和目标资源是什么
→ 是否偏离用户原始任务
→ Core 为什么判定有风险
→ 决策是 allow / deny / ask
→ Adapter 是否真的阻断或暂停
→ 攻击链路能否还原
→ 防御效果能否量化
```

命题重点不是模型是否能安全聊天，而是模型接入工具后是否会产生真实系统行为风险；系统要展示工具调用、文件访问、API 调用、代码执行、长期记忆写入、任务一致性和实时拦截能力。

---

# 2. 目标页面结构

Dashboard 采用 **7 个主页面**：

```text
AgentGuard Dashboard
├── Events        实时事件，默认首页，核心工作台
├── Overview      态势总览，演示入口
├── Approvals     人工审批中心
├── Traces        攻击链路与 Provenance 图
├── Evaluation    AttackBench 与评测指标
├── System        系统状态与数据链路
└── Advanced      OpenClaw、Memory Guard、配置审计、审计完整性
```

默认进入：

```text
/ → /events
```

页面功能关系：

```text
Events 是中心
Overview 是入口
Approvals 是处理 ask 的地方
Traces 是解释攻击链路的地方
Evaluation 是证明防御有效的地方
System 是排查运行状态的地方
Advanced 是高级扩展能力的地方
```

---

## 2.1 阶段可用性

Dashboard 保留 7 个主页面作为目标态，但实现和验收必须按阶段收敛，不能把 P1/P2 能力写成 P0 必备功能。当前 P0 将 Events 和 Traces 的核心能力收敛为“调查”列表与详情，与总览、审批、评测和系统状态共同构成当前导航。

| 阶段 | 可用页面 / 能力                                                                               | 不在本阶段承诺                                                               |
| ---- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| P0   | Events、基础 Overview、最小 Approvals、Evaluation 基础指标、System 最小状态                   | Trace 查询、runtime metrics、复杂图谱、审计完整性                            |
| P1   | Traces、runtime metrics、FNR / Precision / Recall / Latency、OpenClaw Hook 状态、CLI 审批扩展 | Provenance Graph、Memory Guard、Config Audit、Audit Integrity、Action Critic |
| P2   | Provenance Graph、Memory Guard、Config Audit、Audit Integrity、Action Critic、消融实验        | 生产级多租户和复杂沙箱逃逸检测                                               |

P0 最小 Approvals 包括 `GET /v1/approvals/pending`、`POST /v1/approvals/{approval_id}/resolve` 和 `GET /v1/approvals/{approval_id}/wait`。P0 只支持 `allow_once` 和 `deny`，不做永久放行、多渠道审批、审批策略配置或 OpenClaw 社交审批。

# 3. 全局布局

所有页面共用同一个应用外壳，左侧导航和顶部栏始终固定。

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Top Bar                                                                      │
│ AgentGuard | Core Online | Runtime LangGraph | Mode enforce | Pending Ask 2  │
├───────────────┬──────────────────────────────────────────────┬───────────────┤
│ Sidebar       │ Main Workspace                               │ Right Drawer  │
│               │                                              │               │
│ Events        │ 当前主页面内容                                │ Event Detail  │
│ Overview      │ 表格 / 图表 / 时间线 / 图谱 / 审批队列         │ Approval      │
│ Approvals     │                                              │ Trace Node    │
│ Traces        │                                              │ Raw JSON      │
│ Evaluation    │                                              │               │
│ System        │                                              │               │
│ Advanced      │                                              │               │
└───────────────┴──────────────────────────────────────────────┴───────────────┘
```

响应式规则：

| 尺寸 | 布局策略                                                                         |
| ---- | -------------------------------------------------------------------------------- |
| 桌面 | 固定 Top Bar、Sidebar、Main Workspace 和右侧 Drawer                              |
| 平板 | Sidebar 可折叠，Drawer 占右侧较宽区域，主操作反馈保持可见                        |
| 手机 | Sidebar 变菜单，Drawer 变全屏详情或 bottom sheet，表格只保留核心列，图表纵向堆叠 |

右侧抽屉在小屏不作为窄栏挤压主内容。详情、审批和 Raw JSON 必须在全屏详情中保持可关闭、可返回和可恢复焦点。

## 3.1 顶部栏

顶部栏承担全局状态、全局筛选和即时审批提醒。

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ AgentGuard                                                                  │
│ Core: Online   Runtime: LangGraph   Mode: enforce   Time: Last 24h           │
│ Search trace / case / resource / rule                         Pending Ask 2  │
└──────────────────────────────────────────────────────────────────────────────┘
```

| 元素        | 展示形式                                     | 点击行为                 |
| ----------- | -------------------------------------------- | ------------------------ |
| Core 状态   | 状态点 + Online / Offline / Stale            | 进入 System              |
| Runtime     | badge：LangGraph / OpenClaw / Mixed          | Events 按 runtime 筛选   |
| Mode        | badge：shadow / enforce                      | 只展示，不在前端直接切换 |
| Time Range  | Last 15m / 1h / 24h / custom                 | 全局过滤                 |
| Search      | 搜索框                                       | 跳转 Events 并带搜索条件 |
| Pending Ask | 数字 badge，来自 `GET /v1/approvals/pending` | 打开右侧审批抽屉         |
| Last Sync   | 小字时间                                     | 数据过期时显示 warning   |

顶部栏始终存在。用户在任何页面都能看到系统是否在线、是否处于 enforce 模式、是否有待审批动作。

P0 中 Pending Ask 表示当前仍待处理的 pending approval 数。审批 resolve 使用 browser session、CSRF token 和 approval nonce；Adapter 通过 wait 接口获取 `allow_once` 或 `deny`。

---

## 3.2 左侧导航

左侧导航始终固定，任何页面都能直接跳转其他 6 个主页面。

```text
Monitor
  Events
  Overview
  Approvals
  Traces

Evaluation
  Evaluation

Operations
  System
  Advanced
```

当前页面高亮。带筛选状态时显示轻量提示：

```text
Events        filtered
Evaluation    case: PI-001
Approvals     2 pending
```

不会出现从 Events 进入 Trace、Approval 或 Evaluation 后“卡死出不来”的问题。因为主导航不消失，用户不依赖浏览器返回键。

---

## 3.3 右侧抽屉

右侧抽屉用于展示详情，不作为主页面跳转。

适合放：

```text
Event Detail
Approval Detail
Trace Node Detail
Rule Evidence
Resource Detail
Raw JSON
```

使用逻辑：

```text
点击表格行
→ 打开右侧抽屉
→ 查看详情
→ 关闭抽屉
→ 回到原页面原位置
```

这样避免用户每点一条事件就进入新页面，浏览体验更连续。

---

# 4. 目标路由与闭环跳转

## 4.1 目标主路由

```text
/events
/overview
/approvals
/approvals/:approval_id
/traces
/traces/:trace_id
/evaluation
/evaluation?case_id=PI-001
/system
/advanced
```

所有路由都在同一个全局外壳下渲染：

```text
App Shell
├── 固定 Top Bar
├── 固定 Sidebar
├── Main Workspace
└── 可关闭 Right Drawer
```

---

## 4.2 闭环跳转图

```text
Overview
  ├── 点击 High Risk / Deny / Blocked
  │     → Events 带筛选
  │
  ├── 点击 Pending Ask
  │     → Approvals
  │
  └── 点击 ASR / Block Rate / FPR
        → Evaluation


Events
  ├── 点击事件行
  │     → 打开 Event Detail Drawer
  │
  ├── 点击 trace_id
  │     → Traces / trace_id
  │
  ├── 点击 approval_id
  │     → Approvals / approval_id
  │
  ├── 点击 case_id
  │     → Evaluation?case_id=...
  │
  └── 点击 rule / resource / tool
        → 当前 Events 页应用筛选


Approvals
  ├── 点击 View Event
  │     → Events?event_id=...
  │
  ├── 点击 View Trace
  │     → Traces / trace_id
  │
  └── 审批完成
        → 留在审批详情，显示结果和后续入口


Traces
  ├── 点击 Audit Event
  │     → Events?event_id=...
  │
  ├── 点击 Approval 节点
  │     → Approvals / approval_id
  │
  ├── 点击 Case ID
  │     → Evaluation?case_id=...
  │
  └── 点击节点
        → 打开 Trace Node Drawer


Evaluation
  ├── 点击 case_id
  │     → 展开样本详情
  │
  ├── 点击 trace_id
  │     → Traces / trace_id
  │
  ├── 点击 event count
  │     → Events 带筛选
  │
  └── 点击 fail / false positive / false negative
        → Events 或 Case Result 表带筛选


System
  ├── 查看策略修订
  │     → System 内策略历史
  │
  └── 点击 stale runtime
        → Events?runtime=...


Advanced
  ├── 点击 OpenClaw event
  │     → Events?runtime=openclaw
  │
  ├── 点击 memory risk
  │     → Traces?event_type=memory_write
  │
  └── 点击 config risk
        → Advanced 内部详情
```

## 4.3 面包屑

面包屑只表达上下文，不替代主导航。

```text
Events / evt_001 / trace_001
Events / evt_002 / approval_009
Evaluation / PI-001 / trace_001
Advanced / OpenClaw Hooks / before_tool_call
```

Trace 详情页顶部提供明确返回：

```text
← 返回事件 evt_001
```

Approval 详情页审批后提供：

```text
[查看事件] [查看 Trace] [返回审批队列]
```

---

# 5. 页面一：Events 实时事件页

## 5.1 页面定位

Events 是默认首页和核心工作台。它承担三个任务：

```text
实时发现风险
解释单条事件
进入 Trace / Approval / Evaluation
```

P0 最重要的信息都要放在 Events 首屏：`time`、`decision`、`risk_score`、`severity`、`blocked`、`runtime`、`tool`、`resource_targets`、`reason`。

P0 默认表格只承诺展示 AuditEvent 字段。`trace_id`、`case_id` 可以展示和复制，当前可进入 `/evidence/:trace_id` 查看证据链详情；详情页优先读取证据链详情接口，失败时回退到已加载 AuditEvent 窗口。P1 扩展 stage 包括 `memory_write`、`message_sending`、`tool_result`、`context_build` 和 `model_call`。

Dashboard 文档要求实时事件页展示 AuditEvent 列表、决策、风险分数和阻断原因，并要求阻断记录显示工具名、参数、资源目标、命中规则和用户任务。仓库接口契约也把 AuditEvent 定义为 Dashboard、指标和答辩证据的共同输入。

## 5.2 布局

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Filter Bar                                                                   │
│ decision severity runtime tool resource search                               │
├──────────────────────────────────────────────────────────────────────────────┤
│ Quick Filters                                                                │
│ [Deny 12] [Ask 2] [High Risk 8] [Sensitive File 5] [External Send 3]          │
│ [Task Mismatch 6]                                                            │
├───────────────────────────────────────────────────────┬──────────────────────┤
│ Event Table                                           │ Event Detail Drawer  │
│                                                       │                      │
│ time decision score sev blocked runtime tool resource │ Risk Summary         │
│ 12:01 deny     92    high yes     lg      read token   │ AuditEvent           │
│ 12:03 ask      64    med  paused  lg      mail external│ Related IDs          │
│ 12:05 allow    12    low  no      lg      read README  │ Supplemental Evidence│
│                                                       │ Resources            │
│                                                       │ Related              │
│                                                       │ Raw JSON             │
└───────────────────────────────────────────────────────┴──────────────────────┘
```

## 5.3 表格字段

| 字段            | 展示形式                               | 优先级 |
| --------------- | -------------------------------------- | -----: |
| Time            | 相对时间 + hover 完整时间              |     P0 |
| Decision        | allow / deny / ask badge               |     P0 |
| Risk Score      | 数字 + 小进度条                        |     P0 |
| Severity        | critical / high / medium / low badge   |     P0 |
| Blocked         | true / false icon                      |     P0 |
| Runtime         | langgraph / openclaw badge             |     P0 |
| Stage           | before_tool_call tag                   |     P0 |
| Tool            | 等宽标签                               |     P0 |
| Resource Target | resource badge + copy                  |     P0 |
| Reason          | 单行摘要 + tooltip                     |     P0 |
| Trace ID        | 文本 + copy；P1 启用链接               |     P0 |
| Case ID         | 文本 + copy；Evaluation 可用时启用链接 |     P0 |
| Rule Hits       | rule tag；空间不足时进入抽屉           |     P0 |
| Attack Type     | tag                                    |  P0/P1 |
| Latency         | 小数字                                 |     P1 |

手机默认只保留 `time`、`decision`、`tool`、`resource`、`reason`，其他字段进入详情。

## 5.4 详情抽屉

```text
Event Detail
├── Risk Summary
│   decision: deny
│   risk_score: 92
│   severity: high
│   blocked: true
│   latency_ms: 18
│
├── AuditEvent Fields
│   audit_id: audit_001
│   trace_id: trace_001
│   stage: before_tool_call
│   event_type: tool_call
│   summary: Agent attempted to read /private/token.txt
│   resource_targets: /private/token.txt
│   rule_hits: P001_sensitive_file_access
│
├── Intent vs Action
│   user_task: 总结邮件内容
│   agent_action: read_file('/private/token.txt')
│   mismatch: true
│
├── Tool Call
│   tool.name: read_file
│   tool.category: file
│   arguments.path: /private/token.txt
│   pre_execution: true
│
├── Policy Decision
│   reason: 请求读取敏感文件，且与当前用户任务不一致
│   rule_hits:
│     P001_sensitive_file_access
│       evidence: target path contains token.txt
│     P004_task_mismatch
│
├── Resources
│   file / read / secret / local
│
├── Related
│   trace_id: trace_001
│   case_id: PI-001
│   approval_id: -
│
└── Raw JSON
    默认折叠
```

详情抽屉必须区分字段来源：AuditEvent P0 字段直接展示；ToolCallEvent、PolicyDecision、SecurityContext 等补充字段只有后端返回或可从已返回 payload 读取时展示。缺失字段显示为“未提供”，不能由 Dashboard 推断。

## 5.5 Events 页指标

| 指标              | 位置                | 形式          |
| ----------------- | ------------------- | ------------- |
| 当前事件数        | 表格左上角          | 小数字        |
| Deny 数           | Quick Filter        | chip badge    |
| Ask 数            | Quick Filter + 顶栏 | chip badge    |
| High Risk 数      | Quick Filter        | chip badge    |
| Sensitive File 数 | Quick Filter        | chip badge    |
| External Send 数  | Quick Filter        | chip badge    |
| Task Mismatch 数  | Quick Filter        | chip badge    |
| Memory Write 数   | P1 Quick Filter     | chip badge    |
| Code Exec 数      | P1 Quick Filter     | chip badge    |
| Risk Score        | 表格列 / 抽屉       | 数字 + 进度条 |
| Rule Hits         | 表格列 / 抽屉       | tag           |
| Resource Targets  | 表格列 / 抽屉       | badge + copy  |
| Blocked           | 表格列 / 抽屉       | icon          |
| Latency           | 抽屉                | 小号指标      |

---

# 6. 页面二：Overview 态势总览页

## 6.1 页面定位

Overview 用于演示和快速判断系统状态。它不是主要排查页，所有卡片和图表都应能下钻到 Events、Approvals 或 Evaluation。

Elastic Security 的仪表盘思路可以吸收：总览页负责聚合告警和案件态势，并支持进入告警或 Timeline 继续调查。Datadog 的全局筛选变量和 widget 化布局也适合用于 runtime、attack_type、decision、severity、time range 过滤。([Datadog 监控][1]) ([Datadog 监控][2])

## 6.2 布局

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ KPI Cards                                                                    │
│ Events | High Risk | Blocked | Pending Ask | ASR Before | ASR After | FPR     │
├───────────────────────────────┬──────────────────────────────────────────────┤
│ Decision Trend                │ Severity Distribution                        │
│ allow / ask / deny over time  │ critical / high / medium / low               │
├───────────────────────────────┼──────────────────────────────────────────────┤
│ Attack Type Coverage          │ Top Rule Hits                                │
│ injection / hijack / exfil    │ P001 / P004 / P005                           │
├───────────────────────────────┴──────────────────────────────────────────────┤
│ Latest High Risk Events                                                      │
├──────────────────────────────────────────────────────────────────────────────┤
│ Current Demo Chain                                                           │
│ PI-001 → read_file('/private/token.txt') → P001/P004 → deny → blocked        │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 6.3 KPI 卡片

| 卡片         | 形式                | 点击                          |
| ------------ | ------------------- | ----------------------------- |
| Total Events | 大数字 + 时间范围   | Events                        |
| High Risk    | 大数字 + 红橙强调   | Events?severity=high,critical |
| Blocked      | 大数字              | Events?blocked=true           |
| Pending Ask  | 大数字 + 警示 badge | Approvals                     |
| ASR Before   | 大数字              | Evaluation                    |
| ASR After    | 大数字              | Evaluation                    |
| Block Rate   | 大数字              | Evaluation                    |
| FPR          | 大数字              | Evaluation?subset=benign      |

## 6.4 图表

| 图表                    | 形式               | 点击                           |
| ----------------------- | ------------------ | ------------------------------ |
| Decision Trend          | 堆叠柱状图或折线图 | Events 带时间与 decision 筛选  |
| Severity Distribution   | 横向条形图         | Events 按 severity 筛选        |
| Attack Type Coverage    | 分组柱状图         | Evaluation 按 attack_type 筛选 |
| Top Rule Hits           | 横向条形图         | Events 按 rule_id 筛选         |
| Latest High Risk Events | 紧凑表格           | 打开 Event Detail              |
| Current Demo Chain      | 线性链路卡         | 进入 Trace                     |

---

# 7. 页面三：Approvals 审批中心

## 7.1 页面定位

Approvals 只处理 `ask`。`ask` 不是普通告警，而是 **动作已经暂停，等待用户确认**。Core 返回 `ask` 时 Adapter 必须暂停动作并等待审批；返回 `deny` 时 Adapter 必须阻断工具执行。审批界面必须解释风险，不能只给按钮。

阶段边界：

| 阶段 | 能力                                                     |
| ---- | -------------------------------------------------------- |
| P0   | pending 队列、审批详情、拒绝、允许一次、resolve 失败恢复 |
| P1   | CLI 审批、审批体验增强、跨页面通知优化                   |
| P2   | 多渠道审批、OpenClaw 社交审批、复杂审批策略              |

P0 最小审批闭环必须能让 Dashboard resolve `ask`，并让 Adapter wait 收到 `allow_once` 或 `deny`。P0 不做永久放行。

## 7.2 全局审批提醒

```text
Core 返回 ask
→ Adapter 暂停动作
→ Core 创建 pending approval
→ Top Bar Pending Ask +1
→ Toast 非阻塞提醒
→ 用户点击打开 Approval Drawer
→ 用户选择 拒绝 / 允许一次
→ Core 记录审批结果
→ Adapter 继续或取消
→ Events 与 Trace 更新
```

上述完整流程属于 P0 最小审批闭环。审批提交必须满足 browser session、CSRF ready 和 approval nonce 可用。

Toast：

```text
需要人工确认
Agent 请求 send_email 到 attacker@example.com
risk_score 64 · P005_non_whitelisted_email
[查看审批]
```

## 7.3 审批中心布局

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Approval Summary                                                             │
│ Pending 2 | High Risk 1 | Oldest Waiting 01:42 | Avg Score 63                │
├──────────────────────────────┬───────────────────────────────────────────────┤
│ Approval Queue               │ Approval Detail                               │
│                              │                                               │
│ ask_001 send_email 64        │ 需要确认的 Agent 动作                         │
│ ask_002 memory_write 58      │                                               │
│ ask_003 call_api 61          │ 动作: send_email                              │
│                              │ 目标: attacker@example.com                    │
│                              │ 用户任务: 总结邮件内容                         │
│                              │ Agent 行为: 发送总结到非白名单邮箱             │
│                              │ 风险原因: 可能造成数据外传                     │
│                              │ 命中规则: P005 / P004                         │
│                              │ 放行后果: 写入 mock_outbox                    │
│                              │                                               │
│                              │ Mini Trace                                    │
│                              │ untrusted email → model → send_email → ask    │
│                              │                                               │
│                              │ [拒绝]  [允许一次]  [查看 Trace]              │
└──────────────────────────────┴───────────────────────────────────────────────┘
```

## 7.4 审批详情字段

| 字段           | 展示形式                                   |
| -------------- | ------------------------------------------ |
| Approval 状态  | pending / allowed / denied / expired badge |
| 请求动作       | tool badge                                 |
| 目标对象       | resource badge                             |
| 用户原始任务   | 文本                                       |
| Agent 计划行为 | 文本                                       |
| 风险分数       | 数字 + 进度条                              |
| 严重性         | severity badge                             |
| 命中规则       | rule tags                                  |
| 解释原因       | 中文说明                                   |
| 放行后果       | 风险提示卡                                 |
| 参数           | key-value 表，敏感字段遮蔽                 |
| 相关事件       | event link                                 |
| 相关 Trace     | mini timeline                              |
| 操作按钮       | 拒绝 / 允许一次                            |

按钮顺序：

```text
[拒绝]    [允许一次]
```

本方案不做永久放行。`允许一次` 只对当前 `approval_id` 有效。

审批操作状态：

```text
pending → submitting → allowed / denied
pending → submitting → error
pending → expired
pending → forbidden
pending → csrf_not_ready
pending → nonce_missing
```

审批失败时保留当前详情和用户上下文，显示可重试动作。CSRF 未就绪、approval nonce 缺失或过期时不得提交请求。

---

# 8. 页面四：Traces 攻击链路页

## 8.1 页面定位

Traces 负责解释“为什么这条事件发生”。它把单条事件扩展成完整链路：

```text
用户任务 / 攻击样本
→ 不可信内容进入上下文
→ 模型产生工具调用意图
→ Adapter 构造事件
→ Core 判定风险
→ allow / deny / ask
→ 工具执行、阻断或等待审批
→ AuditEvent 写入
```

独立证据链列表和 Provenance 图是 P1 能力。当前已提供 `/evidence/:trace_id` 证据链详情，优先读取证据链详情接口生成同一 `trace_id` 的时间线；接口失败时回退到已加载 AuditEvent 窗口。

## 8.2 布局

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Trace Filters                                                                │
│ trace_id case_id attack_type runtime decision search                         │
├───────────────┬──────────────────────────────────────────────┬───────────────┤
│ Trace List    │ Trace Detail                                 │ Node Detail   │
│               │                                              │               │
│ trace_001     │ Tabs: Timeline | Events | JSON | Provenance   │ selected node │
│ trace_002     │                                              │ fields        │
│ trace_003     │ Timeline                                     │ evidence      │
│               │                                              │ related event │
│               │ User Input                                   │               │
│               │ ↓                                            │               │
│               │ Context Build                                │               │
│               │ ↓                                            │               │
│               │ Model Call                                   │               │
│               │ ↓                                            │               │
│               │ Tool Call                                    │               │
│               │ ↓                                            │               │
│               │ Policy Decision                              │               │
│               │ ↓                                            │               │
│               │ Tool Blocked / Approval                      │               │
└───────────────┴──────────────────────────────────────────────┴───────────────┘
```

## 8.3 Timeline 节点

| 节点             | 阶段 | 展示                                              |
| ---------------- | ---- | ------------------------------------------------- |
| User Input       | P0   | 用户任务、case_id、attack_type                    |
| Tool Call        | P0   | tool、arguments、resource_targets                 |
| Policy Decision  | P0   | decision、risk_score、rule_hits、reason           |
| Tool Enforcement | P0   | executed / blocked / paused                       |
| Audit Event      | P0   | audit_id、timestamp                               |
| Context Build    | P1   | source_type、source_trust、will_enter_context     |
| Model Call       | P1   | model_intent、输出摘要                            |
| Tool Result      | P1   | content_preview、will_enter_context、will_persist |
| Memory Write     | P1   | namespace、key、value_preview、will_persist       |
| Message Send     | P1   | channel、receiver、content summary                |
| Audit Integrity  | P2   | hash / tamper evidence                            |
| Provenance Graph | P2   | 因果图                                            |

## 8.4 Provenance 图

Provenance 图是 P2 tab，用于展示风险因果链。P1 Trace 默认只承诺 Timeline、Events 和 JSON；不在 P1 路径中承诺复杂图谱。P2 默认展示关键路径，不超过 15 个节点。

```text
┌────────────────┐       entered_context       ┌────────────────┐
│ Untrusted Email│ ──────────────────────────► │ Context Chunk  │
└────────────────┘                              └───────┬────────┘
                                                        │ influenced
                                                        ▼
                                                ┌────────────────┐
                                                │ Model Call     │
                                                └───────┬────────┘
                                                        │ requested
                                                        ▼
                                                ┌────────────────┐
                                                │ read_file      │
                                                │ path=/private  │
                                                └───────┬────────┘
                                                        │ accesses
                                                        ▼
                                                ┌────────────────┐
                                                │ token.txt      │
                                                │ secret file    │
                                                └───────┬────────┘
                                                        │ triggered
                                                        ▼
                                                ┌────────────────┐
                                                │ P001 / P004    │
                                                └───────┬────────┘
                                                        │ decided
                                                        ▼
                                                ┌────────────────┐
                                                │ deny / blocked │
                                                └────────────────┘
```

图节点：

```text
Source
Context
Model Call
Tool Call
Resource
Rule Hit
Decision
Approval
Tool Result
Memory Write
Audit Event
```

图交互：

```text
点击 Source        → 显示来源、信任级别、是否包含指令型文本
点击 Tool Call     → 显示工具参数和 pre_execution
点击 Resource      → 显示资源类型、方向、敏感级别
点击 Rule Hit      → 显示规则证据
点击 Decision      → 显示 reason、risk_score、safe_message
点击 Approval      → 跳 Approvals
点击 Audit Event   → 跳 Events
```

---

# 9. 页面五：Evaluation 评测页

## 9.1 页面定位

Evaluation 合并 AttackBench 样本结果与指标评测。它证明系统不是单个 demo，而是能批量复现、对比和量化。

AttackBench 负责攻击样本、正常样本、攻击脚本、批量执行、成功条件判断和评测指标；runner 流程包括无防御运行、开启 AgentGuard 重放、判断阻断并汇总 ASR、Block Rate、FPR、FNR、Latency。

评测结果必须来自 AttackBench 报告或 Core metrics API。Dashboard 只展示和下钻结果，不根据前端事件自行推断 ground truth、攻击成功与否或误报/漏报分类。

## 9.2 布局

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Evaluation Filters                                                           │
│ run_id attack_type runtime dataset decision result case search               │
├──────────────────────────────────────────────────────────────────────────────┤
│ Metric Cards                                                                 │
│ ASR Before | ASR After | ASR Reduction | Block Rate | FPR                   │
├───────────────────────────────┬──────────────────────────────────────────────┤
│ Before / After ASR            │ Expected vs Actual Decision Matrix           │
├───────────────────────────────┼──────────────────────────────────────────────┤
│ Block Rate by Attack Type     │ FPR / FNR Samples                            │
├───────────────────────────────┴──────────────────────────────────────────────┤
│ Case Result Table                                                            │
│ case_id attack_type expected actual before_success after_success trace       │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 9.3 指标卡

| 指标              | 形式              | 阶段 |
| ----------------- | ----------------- | ---- |
| ASR Before        | 大数字            | P0   |
| ASR After         | 大数字            | P0   |
| ASR Reduction     | 大数字 + 下降箭头 | P0   |
| Block Rate        | 大数字            | P0   |
| FPR               | 大数字            | P0   |
| FNR               | 大数字            | P1   |
| Precision         | 大数字            | P1   |
| Recall            | 大数字            | P1   |
| F1                | 大数字            | P1   |
| Latency P50 / P95 | 分位数卡片        | P1   |

## 9.4 图表

| 图表                        | 形式       | 用途                    |
| --------------------------- | ---------- | ----------------------- |
| Before / After ASR          | 对比柱状图 | 防御前后攻击成功率对比  |
| Block Rate by Attack Type   | 分组柱状图 | 各攻击类型阻断效果      |
| Expected vs Actual Decision | 混淆矩阵   | P1 判断误报、漏报、偏差 |
| Latency Trend               | 折线图     | P1 策略判断开销         |
| FPR / FNR Samples           | 表格       | P1 定位误报和漏报样本   |
| Case Result Table           | 高密度表格 | 下钻到样本、事件、Trace |

混淆矩阵：

```text
                 Actual
              allow  ask  deny
Expected allow   42    2    1
Expected ask      3   18    4
Expected deny     1    5   37
```

## 9.5 Case Result 表字段

| 字段              | 展示                  |
| ----------------- | --------------------- |
| case_id           | 链接                  |
| attack_type       | tag                   |
| is_malicious      | badge                 |
| source_type       | email / file / api    |
| source_trust      | trusted / untrusted   |
| target_tool       | tool badge            |
| target_resource   | resource badge        |
| expected_decision | badge                 |
| actual_decision   | badge                 |
| before_success    | true / false          |
| after_success     | true / false          |
| result            | pass / fail / partial |
| trace_id          | 链接                  |
| event_count       | 点击跳 Events         |

---

# 10. 页面六：System 系统状态页

## 10.1 页面定位

System 用于确认数据链路是否正常。演示时如果调查列表没有数据，用户能快速判断是 Guard API 离线、session 失效、轮询中断、Adapter 未上报，还是指标尚未生成。

阶段边界：

| 阶段 | System 能力                                                                 |
| ---- | --------------------------------------------------------------------------- |
| P0   | Guard API 状态、browser session 状态、最近 AuditEvent 时间、数据 stale 提示 |
| P1   | runtime metrics、SSE / polling 连接状态、Adapter errors、schema version     |
| P2   | Audit Integrity、hash chain、missing events、tamper evidence                |

## 10.2 布局

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Runtime Health                                                               │
│ Guard API Online | Browser Session Valid | CSRF Ready                        │
├──────────────────────────────────────────────────────────────────────────────┤
│ Data Pipeline                                                                │
│ Adapter → Core → Audit Log → Dashboard                                       │
├──────────────────────────────────────────────────────────────────────────────┤
│ Runtime Metrics (P1)                                                         │
│ Last Event Time | Ingestion Delay | Adapter Errors | Schema Version          │
├──────────────────────────────────────────────────────────────────────────────┤
│ Audit Integrity (P2)                                                         │
│ Hash Chain Valid | Missing Events 0 | Schema Mismatch 0                      │
├──────────────────────────────────────────────────────────────────────────────┤
│ Diagnostics                                                                  │
│ recent errors / stale modules / retry actions                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 10.3 展示字段

| 信息                  | 形式                           |
| --------------------- | ------------------------------ |
| Guard API 状态        | status card                    |
| browser session 状态  | status card                    |
| CSRF 状态             | status card，不显示 token 原文 |
| SSE / polling 状态    | P1 status card                 |
| Last Event Time       | 时间文本                       |
| Event Ingestion Delay | P1 小折线图                    |
| Adapter Error Count   | P1 KPI + 错误表                |
| Schema Version        | P1 badge                       |
| Audit Integrity       | P2 pass / fail                 |
| Missing Events        | P2 数字                        |
| Stale Data            | warning banner                 |

---

# 11. 页面七：Advanced 高级审计页

## 11.1 页面定位

Advanced 集中放 P1/P2 高级能力，避免干扰 P0 主流程。P0 可以显示入口，但不把 Advanced 内部能力作为验收项。

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Tabs                                                                         │
│ OpenClaw Hooks | Config Audit | Memory Guard | Audit Integrity | Experiments │
├──────────────────────────────────────────────────────────────────────────────┤
│ OpenClaw Hooks (P1)                                                          │
│ before_tool_call       待验证 / 已验证 / 不支持 / 降级实现                    │
│ message_sending        待验证                                                │
│ before_prompt_build    待验证                                                │
├──────────────────────────────────────────────────────────────────────────────┤
│ Config Audit (P2)                                                            │
│ dmPolicy=open        high       建议关闭开放 DM                               │
│ allowFrom=*          high       建议改为白名单                                │
│ sandbox.mode=off     critical   建议开启 sandbox                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ Memory Guard (P2)                                                            │
│ memory write attempts / poisoned rule / rollback                             │
├──────────────────────────────────────────────────────────────────────────────┤
│ Audit Integrity (P2)                                                         │
│ hash chain / missing events / schema mismatch                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 11.2 OpenClaw Hooks

| Hook                   | 展示字段                                             |
| ---------------------- | ---------------------------------------------------- |
| before_tool_call       | 状态、可用字段、是否能 block、是否能 requireApproval |
| message_sending        | 状态、receiver、channel、是否能 cancel               |
| before_prompt_build    | 状态、是否能读取上下文来源                           |
| after_tool_call        | 状态、是否能读取工具结果                             |
| tool_result_persist    | 状态、是否能改写或阻止持久化                         |
| llm_input / llm_output | P2 状态                                              |

状态枚举：

```text
待验证
已验证
不支持
降级实现
```

## 11.3 Config Audit

Config Audit 是 P2 能力。

展示 OpenClaw 高风险配置：

```text
dmPolicy = open
allowFrom = *
sandbox.mode = off
tools.deny 缺失
Gateway 暴露
插件上下文权限过大
```

形式：

```text
配置项 | 当前值 | 风险等级 | 风险说明 | 修复建议
```

## 11.4 Memory Guard

Memory Guard 是 P2 能力。

展示记忆写入风险：

```text
memory namespace
key
value_preview
source_trust
will_persist
requires_approval
rollback status
```

形式：

```text
记忆写入时间线
+ value diff
+ rollback 按钮状态
```

---

# 12. 全局状态、鉴权与敏感信息

## 12.1 页面状态

每个页面和主要模块都必须覆盖以下状态：

```text
loading
empty
error
forbidden
stale
partial
not-found
disabled
offline
timeout
```

状态规则：

| 场景                   | 展示策略                                                    |
| ---------------------- | ----------------------------------------------------------- |
| API 未实现或阶段未启用 | 显示能力未启用状态，不写 Mock / Coming Soon                 |
| 权限不足               | 显示 forbidden 和可执行下一步                               |
| 数据未生成             | empty 说明数据来源，例如等待 AuditEvent 或 AttackBench 报告 |
| 数据过期               | stale banner 显示 Last Sync 和刷新动作                      |
| 局部失败               | partial 状态保留其他可用模块                                |
| 详情不存在             | not-found 保留返回列表入口                                  |

## 12.2 鉴权与初始化

Dashboard 不做用户登录，不生成 launch code，不保存长期 token。启动链接由 CLI / Launcher 和 Core 生成，前端只负责用 launch code 换 browser session。

初始化状态：

```text
booting
launch_code_exchange
session_restoring
session_valid
csrf_ready
session_expired
forbidden
offline
```

展示规则：

| 状态                 | UI 行为                                          |
| -------------------- | ------------------------------------------------ |
| launch_code_exchange | 显示正在初始化，不展示 launch code 原文          |
| session_restoring    | 恢复 browser session，失败后显示重新打开启动链接 |
| csrf_ready           | 状态改变请求可提交，不展示 CSRF token 原文       |
| session_expired      | 清空内存状态，提示重新通过 Launcher 打开         |
| forbidden            | 说明当前 browser session 权限不足                |

审批 resolve 必须同时满足 browser session、CSRF ready 和 approval nonce 可用。任一条件缺失时，审批按钮不可提交并解释原因。

## 12.3 敏感信息展示

参数、资源、日志和 Raw JSON 默认按文本渲染。Raw JSON 默认折叠，复制前仍使用脱敏版本。

默认不展示：

```text
AGENTGUARD_CONTROL_TOKEN
AGENTGUARD_ADAPTER_TOKEN
Authorization Bearer token
launch code 原文
CSRF token 原文
approval nonce 原文
未脱敏 secret / token / key
完整系统提示词
真实邮箱正文
真实 API 响应正文
真实敏感文件内容
runtime 内部私有状态
AttackBench ground truth 的前端推断结果
```

脱敏示例：

```text
token = sk-****a91
secret.key = ****
Authorization = Bearer ****
email = a****@example.com
```

Dashboard 不直接读取 LangGraph、OpenClaw、沙箱工具或 AttackBench runner 的内部状态，不根据前端事件自行判断攻击是否成功。

---

# 13. 指标落点总表

| 指标                        | 主展示页            | 辅助位置              | 形式                  |
| --------------------------- | ------------------- | --------------------- | --------------------- |
| Total Events                | Overview            | Events                | KPI + 表格总数        |
| High Risk Events            | Overview            | Events                | KPI + quick filter    |
| Blocked Events              | Overview            | Events                | KPI + blocked filter  |
| Pending Approvals           | Top Bar / Approvals | Overview              | badge + KPI           |
| Decision Distribution       | Overview            | Events                | 堆叠柱状图            |
| Severity Distribution       | Overview            | Events                | 横向条形图            |
| Risk Score                  | Events              | Traces / Approvals    | 数字 + 进度条         |
| Rule Hits                   | Events              | Overview / Evaluation | tag + 横向条形图      |
| Top Risk Tools              | Overview            | Events                | 条形图 + 表格         |
| Top Resource Targets        | Overview            | Events                | 表格 + resource badge |
| Sensitive File Access Count | Overview            | Events                | KPI / filter chip     |
| External Send Count         | Overview            | Approvals             | KPI / filter chip     |
| Task Mismatch Count         | Overview            | Events                | KPI / filter chip     |
| Memory Write Risk Count     | Advanced            | Traces                | KPI + diff            |
| ASR Before                  | Evaluation          | Overview              | KPI + 对比柱状图      |
| ASR After                   | Evaluation          | Overview              | KPI + 对比柱状图      |
| ASR Reduction               | Evaluation          | Overview              | KPI                   |
| Block Rate                  | Evaluation          | Overview              | KPI + 分组柱状图      |
| FPR                         | Evaluation          | Overview              | KPI + benign 样本表   |
| FNR                         | Evaluation          | -                     | KPI + 漏报表          |
| Precision                   | Evaluation          | -                     | KPI                   |
| Recall                      | Evaluation          | -                     | KPI                   |
| F1                          | Evaluation          | -                     | KPI                   |
| Latency P50 / P95           | Evaluation / System | Overview              | 分位数卡 + 折线图     |
| Expected vs Actual          | Evaluation          | -                     | 混淆矩阵              |
| Case Pass Rate              | Evaluation          | Overview              | KPI + 表格            |
| Hook Verified Count         | Advanced            | System                | KPI + 矩阵            |
| Config Risk Count           | Advanced            | Overview              | KPI + 风险清单        |
| Audit Integrity Status      | System / Advanced   | -                     | P2 pass / fail 卡     |
| Event Ingestion Delay       | System              | Overview              | 小折线图              |
| Adapter Error Count         | System              | -                     | KPI + 错误表          |

---

# 14. 信息展示边界

## 14.1 P0 必须展示

```text
AuditEvent
decision
risk_score
severity
blocked
reason
rule_hits
resource_targets
trace_id
case_id
runtime
attack_type
approval status
ASR before
ASR after
Block Rate
FPR
```

ToolCallEvent、PolicyDecision、SecurityContext 中的 `tool arguments`、`user_task`、`agent_action`、rule evidence 等补充证据在后端返回时展示；缺失时显示“未提供”，不能由 Dashboard 推断。

## 14.2 P1/P2 展示

```text
ContextBuildEvent
ToolResultEvent
MemoryEvent
message_sending
FNR
Precision
Recall
F1
Latency
OpenClaw Hook 状态
Config Audit
Audit Integrity
Provenance Graph
Memory rollback
消融实验
```

## 14.3 不展示或默认隐藏

```text
AGENTGUARD_CONTROL_TOKEN
AGENTGUARD_ADAPTER_TOKEN
Authorization Bearer token
CSRF token 原文
approval nonce 原文
launch code
未脱敏 secret / token / key
完整系统提示词
真实邮箱数据
真实 API 数据
真实敏感文件内容
runtime 内部私有状态
AttackBench ground truth 的前端推断结果
```

敏感内容展示方式：

```text
token = sk-****a91
secret.key = ****
Authorization = Bearer ****
```

---

# 15. 外部产品可吸收的设计优点

| 产品                       | 可吸收优点                                       |
| -------------------------- | ------------------------------------------------ |
| Elastic Security           | 总览态势、告警下钻、Timeline 调查路径            |
| Splunk Enterprise Security | Analyst Queue 式集中事件排查队列                 |
| Datadog                    | 全局筛选变量、widget 化指标布局、saved view 思路 |
| Sentry                     | 事件详情层级：摘要优先、证据展开、原始 JSON 折叠 |

Sentry Issue Details 的页面结构强调通过详情页辅助 triage，并在顶部放置高层信息；这适合 Event Detail Drawer 的结构。([Sentry 文档][3])

---

# 16. 视觉与交互风格

## 16.1 视觉方向

```text
整体风格：现代、安全、专业、轻量
背景：浅灰蓝
卡片：白底、细边框、轻阴影
主色：冷蓝 / 靛蓝
allow：绿色
deny：红色
ask：琥珀色或紫色
critical / high：红橙
medium：黄色
low：蓝灰
字体：系统字体或 Inter 风格
密度：中高密度
```

不要做深色大屏、赛博朋克或过度玻璃拟态。安全工作台的重点是可信、清楚、可解释。

## 16.2 交互原则

```text
表格优先
详情抽屉辅助
时间线解释过程
图谱解释因果
指标证明效果
审批只处理 ask
所有关键对象可复制
所有图表可下钻
所有主页面可直接跳转
```

---

# 17. P0 / P1 / P2 页面落地顺序

## P0

```text
Events
  AuditEvent 表格
  Event Detail Drawer
  deny / ask / allow 展示
  reason、rule_hits、resource_targets 展示

Overview
  基础 KPI
  最新高风险事件
  防御前后核心指标入口

Approvals
  pending 队列
  风险说明
  拒绝 / 允许一次
  resolve 失败恢复

Evaluation
  ASR before
  ASR after
  Block Rate
  FPR

System
  Core 状态
  session 状态
  最近事件时间
  stale 状态
```

## P1

```text
Traces
  Trace Timeline
  ContextBuildEvent
  ToolResultEvent
  MemoryEvent
  message_sending

Evaluation
  FNR
  Precision
  Recall
  F1
  Latency

Advanced
  OpenClaw Hook 验证状态

```

## P2

```text
Provenance Graph
Memory Guard
OpenClaw Config Audit
Audit Integrity
Action Critic
消融实验
跨 runtime 对比
```

---

# 18. 最终页面关系

```text
┌────────────┐
│ Overview   │
│ 态势入口    │
└─────┬──────┘
      │ 下钻
      ▼
┌────────────┐       trace_id        ┌────────────┐
│ Events     │ ───────────────────► │ Traces     │
│ 主工作台    │ ◄─────────────────── │ 链路解释    │
└─────┬──────┘      audit_event      └─────┬──────┘
      │ ask                                │ case_id
      ▼                                    ▼
┌────────────┐                       ┌────────────┐
│ Approvals  │                       │ Evaluation │
│ 人工确认    │                       │ 效果证明    │
└─────┬──────┘                       └─────┬──────┘
      │ status / error                     │ metrics
      ▼                                    ▼
┌────────────┐                       ┌────────────┐
│ System     │ ◄─────────────────── │ Advanced   │
│ 运行状态    │                       │ 高级审计    │
└────────────┘                       └────────────┘
```

最显眼的位置分配：

```text
顶部栏：
Core 状态、runtime、mode、pending approvals

默认页 Events：
decision、risk_score、tool、resource、reason、blocked

详情抽屉：
用户任务 vs Agent 行为、命中规则、风险解释、原始 JSON

审批页：
风险说明、放行后果、拒绝 / 允许一次

Trace 页：
时间线优先，Provenance 图增强

Evaluation 页：
Block Rate、FPR、FNR、Latency 优先；ASR before / after 仅在数据存在时展示

System / Advanced：
运行可信度和高级扩展能力
```

这个结构形成完整闭环：

```text
攻击样本或用户任务
→ Agent 产生工具调用
→ Core 判定 allow / deny / ask
→ Events 展示审计证据
→ Approvals 处理人工确认
→ Traces 解释攻击链路
→ Evaluation 证明防御效果
→ System / Advanced 证明工程可信度和扩展能力
```
