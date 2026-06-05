# 实施路线与验收标准

## 1. 文档定位

本文面向开发执行，定义 AgentGuard 的 P0/P1/P2 开发顺序、模块边界和验收标准。实现时优先完成 P0 最小闭环，不提前实现 P2 亮点。

关联入口：

- [系统总体架构](../01_overview/architecture.md)
- [接口契约与事件模型](../02_core/interface_contract.md)
- [AttackBench 攻击样本与评测](../05_redteam/attackbench.md)
- [演示脚本](demo_script.md)

## 2. 阶段目标

| 阶段 | 目标                | 验收口径                                                               |
| ---- | ------------------- | ---------------------------------------------------------------------- |
| P0   | LangGraph 保底闭环  | 攻击样本能触发危险工具调用，Core 能阻断，Dashboard 能展示              |
| P1   | 完整可解释链路      | 上下文、模型、工具结果、记忆和消息链路可追踪，可计算 FPR/FNR           |
| P2   | OpenClaw 与冲奖增强 | OpenClaw 接入、Memory Guard、Action Critic、Provenance Graph、消融实验 |

## 3. P0 最小实现顺序

必须按以下顺序推进，避免先做 UI 或增强项导致闭环不稳。

1. Core event/decision
   - 实现 `ToolCallEvent`、`PolicyDecision`、`AuditEvent`。
   - 实现 `POST /v1/evaluate/tool-call`。
   - 实现 `allow`、`deny`、`ask` 三类决策。

2. Schemas and contract tests
   - 落地 `tool_call_event.schema.json`。
   - 落地 `policy_decision.schema.json`。
   - 落地 `audit_event.schema.json`。
   - 落地 `attack_case.schema.json`。
   - 用 schema 校验 P0 样本和 Core 响应。

3. Core 基础策略
   - 敏感文件检测。
   - 工具调用劫持检测。
   - 用户任务与工具动作一致性检测。
   - 非白名单外发检测。

4. LangGraph wrapper
   - 在 ToolNode 执行前构造 ToolCallEvent。
   - 按 Core 决策执行、阻断或暂停。
   - 记录 trace_id、case_id、runtime。

5. Mock Tools
   - `read_file`
   - `write_file`
   - `send_email`
   - `call_api`
   - 副作用只写入沙箱或 mock outbox。

6. Redteam runner
   - 读取 AttackCase JSONL。
   - 支持 defense before / after 重放。
   - 统计 ASR before、ASR after、Block Rate、FPR。

7. Dashboard event page
   - 使用 Vue 3 + TypeScript + Sass + Pinia 初始化前端工程。
   - 展示 AuditEvent。
   - 展示阻断原因、命中规则、风险分数、资源目标。
   - 支持 `ask` 审批入口。

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

| 成员 | 负责                                    |
| ---- | --------------------------------------- |
| A    | Core、schemas、policies、contract tests |
| B    | LangGraph、Mock Tools、Redteam runner   |
| C    | Dashboard、OpenClaw Plugin、文档、Demo  |

## 7. P0 验收标准

P0 完成必须同时满足：

1. 至少 3 类攻击样本和 benign 样本可运行。
2. 无防御时至少一个样本能触发危险工具调用。
3. 有防御时 Core 在工具执行前返回 `deny` 或 `ask`。
4. 被拒绝的工具没有执行副作用。
5. AuditEvent 被 Dashboard 展示。
6. runner 输出 ASR before、ASR after、Block Rate、FPR。
7. `schemas/` 中至少存在 `tool_call_event.schema.json`、`policy_decision.schema.json`、`audit_event.schema.json`、`attack_case.schema.json`。
8. `git diff --check`、契约测试、runner smoke test 通过。
