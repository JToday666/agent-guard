# 项目状态与后续边界

## 文档用途

本文只记录当前已落地边界、明确冻结项和仍需单独决策的真实后续工作。已经完成的
迁移过程、旧接口和阶段性兼容方案不再作为待办长期保留。详细契约以
[文档地图](README.md) 中列出的稳定文档为准。

## 当前已落地

- `agentguard-core` 是无状态安全核心：接收 `GuardEvent`，执行现有检测器、规则匹配、
  风险评分和三态判定，返回 `GuardDecision`；不访问数据库、网络或审批状态。
- Guard API 是唯一 Control Plane：负责运行时身份鉴权、策略快照、原子审批状态机、
  审计哈希链、证据与 provenance、指标和 Dashboard 查询。
- 审计读取只保留 `GET /v1/audit/window`；响应以固定 sequence 快照原子返回 scope、
  events 和 policy metrics，cursor 自包含过滤条件、页大小、位置和统计时点。
- 历史策略指标只保留有明确时间范围的
  `GET /v1/metrics/policy-evaluations`；按发生时间建立 cohort，按入链时间执行
  `outcomes_as_of` 截止，并通过 keyset 分页完整聚合。
- PostgreSQL 中完整 AuditEvent JSON 与哈希链是权威证据；typed 时间和高频查询列只是
  可重建投影。Memory/PostgreSQL 使用同一存储契约测试。
- AuditEvent 与策略摘要统一使用 RFC 8785 JCS 规范化；生产部署必须把 HMAC 签名审计检查点写入 PostgreSQL 之外的受保护追加日志，Dashboard 分别显示链有效性和锚定覆盖。
- Dashboard API 模式直接消费原子审计窗口，不从旧 500 条事件数组重算后端指标；
  Mock 与 API 共用领域类型，但 API 失败不回退到 Mock。
- 审批只允许未过期 pending 状态原子转换一次；runtime credential 与
  `runtime + agent_id` 绑定，浏览器只持有 session、CSRF token 和 approval nonce。
- OpenClaw 插件使用一套配置解析与 23 个受支持 hook；关键安全 gate 缺失、Guard API
  不可达或响应无效时按配置的强制 fail-closed 路径处理。
- Python 发布入口收敛为 `aegis-agentguard-core`、`aegis-agentguard-api` 和
  `aegis-agentguard-cli`；Core 只维护 `agentguard_core` 公共导入面。

## 评测门禁基线（PR-1）

- 门禁脚本为 `scripts/core-metrics-gate.py`，评估保留集
  `tests/fixtures/eval_gate/`（保留集不参与任何词表调优）；口径与
  `scripts/core-rule-matrix.py` 对齐：`deny`/`ask` 视为拦截，攻击用例被拦截计为
  拦截成功，benign 用例被拦截计为误报。
- 基线（2026-08-13，dev @ 9883771 派生分支 feat/eval-regression-gate）：
  攻击变形 30 例、benign 13 例；Recall=0.9667（29/30），FNR=0.0333，FPR=0.0（0/13）。
- 已知漏拦：EG-AA-004（defamation 语义变形邮件未被拦截）。
- 门禁默认阈值：`--min-recall 0.90`、`--max-fpr 0.05`，相对当前基线留有余量。

## 本轮明确冻结

以下内容不在当前优化范围内，不应通过邻接重构间接改变：

- 正式 LangGraph SDK 及靶场中的答案生成、兼容和评测逻辑；
- LLM 审批、LLM 检测器或 LLM 作为最终违规裁决者的职责设计；
- 记忆生命周期与长期污染恢复机制；
- 新增 `ActionContext` 持久化模型或 Core 公共模型。Core 继续以 `GuardEvent` 为中心。

## 需要另行决策的后续工作

### 动作终态与执行覆盖指标

只有稳定 `action_id`、审批终态和 runtime receipt 覆盖达到可解释门槛后，才在现有
`/v1/audit/window` 与 `/v1/metrics/policy-evaluations` 响应中增加同快照的
`action_metrics`。`deny` 或审批拒绝本身不能冒充“工具确认未调用”；必须同时展示
执行回执覆盖率。定义见
[Dashboard 指标作用域与审计窗口 API 契约](08_api/dashboard_metrics_api_contract.md)。

### 风险分解

是否在 `GuardDecision` 与 `AuditEvent` 增加同构 `risk_breakdown` 会改变 Core 输出契约，
必须在明确评分解释模型、聚合不变量和迁移边界后单独确认，不能仅为 Dashboard 展示
临时拼装。

### 结构化上下文来源

`context_sources` 若从摘要升级为结构化来源对象，需要先冻结生产者字段、信任语义、
脱敏规则和跨 runtime 映射，再同步 Core schema、writers、Dashboard 与证据测试。

### 发布与供应链

基础 GitHub CI 已覆盖 Python 静态检查、类型检查、PostgreSQL migration/测试，以及 Dashboard、OpenClaw 插件和本地工具检查。容器公开发布、SBOM、制品签名、构建 provenance、可信发布和部署自动化仍需作为独立交付任务实施和验收，不能从基础 CI 通过反推为已具备。

## 维护原则

- 不恢复已删除的旧审计读取接口、feature flag、客户端聚合回退或平行 Python 门面。
- 新查询投影必须可从审计链重建，不成为第二个裁决或证据事实源。
- 任何会改变检测器、规则、评分、阈值、决策或 Core 公共模型的工作必须单独确认。
- 完成一项后更新稳定契约和验收证据，不再在本文保留已失效的迁移步骤。
