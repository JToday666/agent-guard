# 实施路线与验收标准

## 1. 文档定位

本文面向开发执行，定义 AgentGuard 的 P0/P1/P2 模块边界和验收标准。P0 最小闭环已有可运行实现；P1/P2 开发项与优先级保持不变。

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
   - 审批 resolve 使用 browser session、CSRF token 和 approval nonce。

## 4. P1 开发项

- `ContextBuildEvent`、`ToolResultEvent`、`MemoryEvent`。
- `pre_model_hook`、`post_model_hook`。
- 消息外发和记忆写入审计。
- 攻击链路页。
- FPR、FNR、Precision、Recall、Latency。
- OpenClaw `before_tool_call` 和 `message_sending` Hook 验证。

## 5. P2 增强项

- Provenance Graph。
- Memory Guard。
- Action Critic。
- Tamper-Evident Audit。
- OpenClaw Config Audit。
- 多渠道审批。
- 消融实验。

## 6. 分工建议

| 成员 | 负责                                                      |
| ---- | --------------------------------------------------------- |
| A    | 无状态 Core、Guard API、schemas、policies、contract tests |
| B    | LangGraph、沙箱工具、AttackBench runner                   |
| C    | Dashboard、OpenClaw Plugin、文档、Demo                    |

## 7. P0 验收标准

P0 完成必须同时满足：

1. 至少 3 类攻击样本和 benign 样本可运行。
2. 无防御时至少一个样本能触发危险工具调用。
3. 有防御时 Guard API 在工具执行前返回 `deny` 或 `ask`。
4. 被拒绝的工具没有执行副作用。
5. `ask` 决策能由 Guard API 创建 pending approval。
6. Dashboard resolve 后，Adapter wait 能返回 `allow_once` 或 `deny`。
7. 审批 resolve 使用 browser session、CSRF token 和 approval nonce。
8. AuditEvent 被 Dashboard 展示。
9. runner 输出 ASR before、ASR after、Block Rate、FPR。
10. `schemas/` 中至少存在 `guard_event.schema.json`、`guard_decision.schema.json`、`audit_event.schema.json`、`attack_case.schema.json`。
11. `git diff --check`、契约测试、runner smoke test 通过。
