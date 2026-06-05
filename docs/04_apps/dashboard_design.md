# Dashboard 与审批流

## 1. 文档定位

Dashboard 是 AgentGuard 的监督端。它只读取 Core API，用于展示实时事件、告警、阻断记录、审批、攻击链路和评测指标。

Dashboard 前端采用 Vue 3 + TypeScript + Sass + Pinia，使用 pnpm 管理依赖。

关联入口：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [系统总体架构](../01_overview/architecture.md)
- [演示脚本](../06_delivery/demo_script.md)

## 2. 模块职责

| 模块                 | 职责                                    |
| -------------------- | --------------------------------------- |
| Event List           | 展示 AuditEvent 列表和阻断状态          |
| Trace Timeline       | 按 `trace_id` 展示攻击链路              |
| Approval Center      | 处理 `ask` 决策                         |
| Metrics View         | 展示 ASR、Block Rate、FPR、FNR、Latency |
| Config Audit View    | 展示 OpenClaw 配置风险                  |
| Audit Integrity View | 展示 hash chain 或审计完整性检查        |

## 3. 数据来源

```text
GET  /v1/audit/events
GET  /v1/audit/traces/{trace_id}
GET  /v1/metrics/runtime
GET  /v1/metrics/eval
GET  /v1/approvals/pending
POST /v1/approvals/{id}/resolve
```

Dashboard 不直接读取 LangGraph、OpenClaw、Mock Tools 或 redteam runner 的内部状态。

## 4. 页面优先级

| 页面       | 阶段  | 内容                                      |
| ---------- | ----- | ----------------------------------------- |
| 实时事件   | P0    | AuditEvent 列表、决策、风险分数、阻断原因 |
| 总览       | P0    | 事件数、风险数、阻断数、ASR、FPR          |
| 审批中心   | P0-P1 | pending approval、allow_once、deny        |
| 攻击链路   | P1    | trace_id 时间线                           |
| 指标评测   | P1    | ASR、Block Rate、FPR、FNR、Latency        |
| 配置审计   | P2    | OpenClaw 配置风险                         |
| 审计完整性 | P2    | hash chain 验证                           |

## 5. 展示原则

- 每个告警必须展示原因，不只显示“危险”。
- 阻断记录必须显示工具名、参数、资源目标、命中规则和用户任务。
- 指标页必须区分 defense before / after。
- 审批页必须说明放行风险，避免只提供按钮。

## 6. P0/P1/P2 开发边界

| 阶段 | 交付                                                |
| ---- | --------------------------------------------------- |
| P0   | AuditEvent 列表、阻断记录、基础总览、Dashboard 审批 |
| P1   | trace 时间线、指标评测、CLI 审批                    |
| P2   | OpenClaw 社交审批、配置审计、审计完整性             |

## 7. 验收证据

1. `deny` 事件能出现在实时事件页。
2. 阻断记录显示 `reason`、`rule_hits`、`resource_targets`。
3. `ask` 事件能进入审批中心。
4. 指标页能展示 AttackBench 结果。
5. Dashboard 不直接访问 runtime 内部数据。
