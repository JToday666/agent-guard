# 实施路线与验收标准

## 1. 文档定位

本文面向开发执行，定义 AgentGuard 的 P0/P1/P2 模块边界和验收标准。P0 最小闭环、P1 核心路径和部分 P2 能力已经实现；下文明确区分当前能力、剩余能力和仅供路线参考的历史阶段。

关联入口：

- [系统总体架构](../01_overview/architecture.md)
- [接口契约与事件模型](../02_core/interface_contract.md)
- [AttackBench 攻击样本与评测](../05_redteam/attackbench.md)
- [演示脚本](demo_script.md)

## 2. 阶段目标

| 阶段 | 目标                | 验收口径                                                                       |
| ---- | ------------------- | ------------------------------------------------------------------------------ |
| P0   | LangGraph 保底闭环  | 攻击样本能触发危险工具调用，Guard API 调用 Core 得到阻断决策，Dashboard 能展示 |
| P1   | 完整可解释链路      | 上下文、模型、工具结果、记忆和消息链路可追踪，可计算 FPR/FNR                   |
| P2   | OpenClaw 与冲奖增强 | OpenClaw 接入、Memory Guard、Action Critic、Provenance Graph、消融实验         |

## 3. P0 当前实现

P0 闭环的 Guard API / Control Plane、schemas、Core 策略、LangGraph wrapper、Mock Tools、AttackBench runner 和 Dashboard 均已有可运行实现。下列顺序表示运行链路和模块依赖，不再表示待实现任务。

1. Guard API / Control Plane event flow
   - 实现 `GuardEvent`、`GuardDecision`、`AuditEvent`。
   - 实现统一判定入口 `POST /v1/guard/evaluate`。
   - Guard API 负责鉴权、加载策略快照、调用 `agentguard-core.evaluate(event, policies)`。
   - Core 返回 `allow`、`deny`、`ask` 三类 P0 决策，不创建审批记录。
   - Guard API 实现最小 approvals API：`GET /v1/approvals/pending`、`POST /v1/approvals/{approval_id}/resolve`、`GET /v1/approvals/{approval_id}/wait`。
   - P0 审批动作只支持 `allow_once` 和 `deny`。

2. Schemas and contract tests
   - 落地 `guard_event.schema.json`。
   - 落地 `guard_decision.schema.json`。
   - 落地 `audit_event.schema.json`。
   - 落地 `attack_case.schema.json`。
   - 用 schema 校验 P0 样本、Guard API 响应和 Core 判定输出。

3. Core 基础策略
   - 敏感文件检测。
   - 工具调用劫持检测。
   - 用户任务与工具动作一致性检测。
   - 非白名单外发检测。

4. LangGraph wrapper
   - 在 ToolNode 执行前构造 `GuardEvent`，其中 `ToolCallEvent` 作为 P0 payload。
   - 调用 Guard API，并按 `GuardDecision` 执行、阻断或暂停。
   - 记录 trace_id、case_id、runtime。

5. Mock Tools
   - `read_file`
   - `write_file`
   - `send_email`
   - `call_api`
   - 副作用只写入沙箱或 mock outbox。

6. AttackBench runner
   - 读取 AttackCase JSONL。
   - 支持 defense before / after 重放。
   - 统计 ASR before、ASR after、Block Rate、FPR。

7. Dashboard
   - 使用 Vue 3 + TypeScript + Sass + Pinia。
   - 在总览、调查、调查详情、审批、评测和系统状态页消费 Guard API 数据。
   - 展示阻断原因、命中规则、风险分数、资源目标。
   - 展示 pending approval，并支持 `allow_once` / `deny`。
   - 审批 resolve 使用 browser session、CSRF token 和服务端原子状态转换。

## 4. P1 已完成 / 部分完成项

- `GET /v1/traces/{trace_id}` 已接入，证据链页展示 Trace 时间线与详情。
- `GET /v1/traces/{trace_id}/provenance` 已接入，证据链页展示溯源图，时间线与节点联动。
- `GET /v1/audit/integrity` 已接入，系统状态页与安全总览展示审计链完整性。
- `ContextBuildEvent`、`ToolResultEvent`、`MemoryEvent`、`MessageSendEvent` 已进入 `GuardEvent` 契约、schema 校验和 Core/API 测试路径。
- `message_send_proposed` 已支持消息外发 DLP、`ask` 审批与 OpenClaw `message_sending` 映射。
- `memory_write_proposed` 已有契约、Core 检测、Guard API 评估联动和基础后端变更记录；真实 runtime memory/store wrapper 仍需后续补齐。
- FPR、FNR、Block Rate、Latency 已在安全评测页展示；混淆矩阵由 `is_malicious + blocked` 派生。
- 评测结果导入与读取后端接口已实现：`POST /v1/evaluations`、`GET /v1/evaluations`、`GET /v1/evaluations/datasets`、`GET /v1/evaluations/latest`、`GET /v1/evaluations/{run_id}`；run 支持 dataset digest、版本锁定、per-case provenance 和 regression gate 摘要。
- `GET /v1/metrics/runtime` 已提供最小运行时监控聚合：审计事件计数、阻断率、hook 活跃度和 adapter status。
- OpenClaw `before_agent_run` 已作为模型读取前的正式输入阻断面；`before_prompt_build`、`llm_input`、`llm_output` 保持观察型，输出策略评估由 `before_agent_finalize` 承接 revise，最终外发由 `message_sending` 裁决；`tool_result_persist` 同步执行本地净化、异步上报远端评估，工具消息在下一次 `before_agent_run` 再接受阻断裁决。
- LangGraph demo graph 已在 planner 前接入 `context_assembled` / `model_input_prepared` 阻断，并在 tool calls 落地前接入 `model_output_produced` 阻断。
- Dashboard 运行时延迟对比（LangGraph / OpenClaw）由 `latency_ms` 字段前端派生。

## 5. P1 剩余能力

- 长期记忆真实 runtime/store wrapper 写入前拦截与回滚链路。
- 更完整的上下文隔离执行策略，包括 sanitize、降权、工具最小权限和下游审计联动。

## 6. P2 已完成 / 部分完成项

- Provenance Graph（前端接入）。
- Tamper-Evident Audit / 审计完整性（前端接入）。
- OpenClaw Config Audit 后端评估与 findings 查询接口已实现；前端摘要可基于 `event_type=config_audit` 派生。
- 运行时适配器活动（LangGraph / OpenClaw 审计统计）。
- Dashboard 规则命中 TopN。
- Memory Guard 已有后端基础变更流：propose、commit、rollback。
- Action Critic 已有确定性 review 与可选 provider 扩展点。
- OpenClaw verify / E2E / reliability 最近状态摘要写入与读取接口已实现：`PUT /v1/adapters/openclaw/status`、`GET /v1/adapters/openclaw/status`。
- 安全评测 ASR before/after 后端导入、latest 查询和 dataset registry 汇总已实现，统一走 `/v1/evaluations` 系列接口；独立 dataset 资源表、样本版本锁文件和跨 run regression gate 发布门禁仍需后续补齐。

## 7. P2 剩余能力

- Memory Guard 策略深化、真实 runtime memory 接入和审批/回滚语义完善。
- Action Critic 从确定性 review 扩展到可评测、可消融的 LLM-as-Judge / rule hybrid 方案。
- 多渠道审批。
- 消融实验。
- OpenClaw verify / E2E / reliability 报告已能写入 adapter status；后续需接入 CI 或发布脚本作为强制门禁。
- 当前已落地边界、明确冻结项和需要另行决策的后续工作统一记录在
  [`docs/TODO.md`](../TODO.md)；本文件只保留阶段路线和验收口径。

## 8. 分工建议

| 成员 | 负责                                                      |
| ---- | --------------------------------------------------------- |
| A    | 无状态 Core、Guard API、schemas、policies、contract tests |
| B    | LangGraph、沙箱工具、AttackBench runner                   |
| C    | Dashboard、OpenClaw Plugin、文档、Demo                    |

## 9. P0 验收标准

P0 完成必须同时满足：

1. 至少 3 类攻击样本和 benign 样本可运行。
2. 无防御时至少一个样本能触发危险工具调用。
3. 有防御时 Guard API 在工具执行前返回 `deny` 或 `ask`。
4. 被拒绝的工具没有执行副作用。
5. `ask` 决策能由 Guard API 创建 pending approval。
6. Dashboard resolve 后，Adapter wait 能返回 `allow_once` 或 `deny`。
7. 审批 resolve 使用 browser session、CSRF token，并拒绝重复或过期转换。
8. AuditEvent 被 Dashboard 展示。
9. runner 输出 ASR before、ASR after、Block Rate、FPR。
10. `schemas/` 中至少存在 `guard_event.schema.json`、`guard_decision.schema.json`、`audit_event.schema.json`、`attack_case.schema.json`。
11. `git diff --check`、契约测试、runner smoke test 通过。
