# Core V2.1 official 双运行时接入

本计划承接 `dev@94047b7`，目标是固定候选上的真实 LangGraph / OpenClaw
Product Active 闭环。所有适用判定必须满足 `source=v21`、`mode=active`、
`selection_basis=profile_all`；shadow、旧 current 和测试夹具不构成最终验收。

## 范围与约定

- LangGraph `1.2.7`；OpenClaw `2026.7.1-2`；真实 Guard API 与独立 PostgreSQL 测试库。
- 采用隔离 profile：`read`、`write`、`edit`、`exec`、`process`、`message`、
  `agentguard_memory_read`、`agentguard_memory_write`。记忆使用隔离 SQLite，
  消息仅进入本机测试收件端；不修改个人 Gateway。
- 全任务最多 120 次真实 Qwen 请求，包含预检、失败和重试；受控响应单独标识。
- 保留冻结的 OpenClaw restricted allow_once、五项 residual boundaries、
  `C3=false` 与 `CF-13=NOT_SUPPORTED`；restricted 不表示 shadow。
- 不包含 24 小时验证、完整 Internal RC、正式发布、350-run、Memory 回滚或
  OpenClaw Strong Binding。`internal_rc_canary` 是冻结签署范围，不能扩大为通过声明。

## 顺序 PR DAG

每批都从前一批实际 squash 后的新 `origin/dev` 创建独立 `codex/*` 分支。
完成独立审查和全部 required checks 后合入，才能开始下一批。

| 批次 | 可独立验收的结果 | 完成依赖 |
| --- | --- | --- |
| 01 | 隔离工具与真实 Host descriptor/schema/来源清单、fixture 映射 | #213 |
| 02 | LangGraph 严格配置、heartbeat、ACK 会话和历史 carrier | 01 |
| 03 | OpenClaw 可信 handshake、ACK 会话和历史 carrier | 02 |
| 04 | LangGraph 加密持久回执、结构化状态、恢复与熔断 | 03 |
| 05 | OpenClaw required 持久回执、拒绝隔离与熔断 | 04 |
| 06a | 独立契约修正：可信工具语义、模型数据承诺与控制影响分离 | 05 |
| 06 | LangGraph 统一执行模板、原生 StateGraph 和七事件链 | 06a |
| 07 | OpenClaw tool/memory/message 的 official 动作链 | 06 |
| 08 | OpenClaw context/model/result 的 official 内容链 | 07 |
| 09 | 完整组合检查与显式启用，默认关闭 | 08 |
| 10 | 候选版本、制品身份、admission/activation 校验与签署工具 | 09 |
| 11 | 真实宿主预激活基线和确定性 conformance 报告 | 10 |
| 12 | 双运行时 Product Active、真实 Qwen 与浏览器审批验收 | 11 |

实现中保留未接完产品链的注册限制。LangGraph 和 OpenClaw 的 ACK 更新不能
替换在途动作的快照；无 lease 回执绑定 evaluate ACK，有 lease 回执绑定 consume ACK。
开始确认失败不得调用工具，终态失败不得重新执行；持久回执补投只重发证据。

两侧正式工厂、受保护清单与启动检查见
[Product Active 完整启动入口](../03_adapters/product_runtime_startup.md)。

2026-09-08 用户明确授权增加 06a：真实模型驱动的 `write/exec` 暴露出
旧契约把模型控制影响的 `possible` 等同于实际参数数据缺证的问题。
修正范围见[产品数据与控制影响契约](../AgentGuard_Core_V2.1_Final_Contract_Freeze/11_Product数据与控制影响修正.md)。
该授权来自本次隔离验收任务，不代表人工审查已完成或生产风险接受；
LangGraph strong binding、OpenClaw restricted allow_once 及全部残余边界不变。

## 最终验收

1. 所有批次合入后固定最终 `dev` SHA，构建并干净安装实际候选制品。
2. 执行预激活宿主基线和确定性 conformance，明确标注其非 Active 证据来源。
3. 校验真实报告与摘要后签署 admission、限定验收环境的 residual acceptance 和 activation。
4. 两个真实 runtime 完成 heartbeat/ACK 后，运行 official V2.1 失败矩阵与
   两 runtime × 文件/命令/记忆/消息 × allow/deny/ask 的 24 个 Qwen 场景。
5. 通过真实浏览器 session/CSRF 审批入口验证 allow_once，核对数据库的
   policy → approval → lease → receipt 关联及实际副作用。

必需用例全部 PASS、真实副作用符合预期、回执闭环且无 current/shadow 回退才返回 0；
失败返回 1，环境、预算或证据不足返回 2。最终报告记录准确源码 SHA、制品摘要、
Host/工具清单、模型请求数和证据来源；任何新增提交都要求重新固定候选并验证。

本页描述实施约定，不预先声明任何批次或最终验收完成。批次结果以对应 PR、
托管检查和最终独立报告为准。
