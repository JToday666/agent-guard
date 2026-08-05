# 演示脚本

## 1. 文档定位

本文定义答辩和开发验收使用的演示顺序。演示必须展示防御前后对比、阻断证据和指标结果，避免只展示静态页面。

关联入口：

- [实施路线与验收标准](implementation_plan.md)
- [AttackBench 攻击样本与评测](../05_redteam/attackbench.md)
- [Dashboard 与审批流](../04_apps/dashboard_design.md)
- [命题要求追踪矩阵](../00_requirements/requirement_traceability_matrix.md)

## 2. Demo 1：LangGraph 文件泄露攻击

目标：证明 AgentGuard 能在文件读取前阻断敏感资源访问。

步骤：

1. 运行无防御 Agent。
2. 输入恶意邮件样本。
3. Agent 尝试读取 `/private/token.txt`。
4. 展示无防御攻击成功或危险工具意图。
5. 开启 AgentGuard。
6. 重放相同样本。
7. Guard API 调用无状态 Core 并返回 `deny`。
8. Mock Tool 未执行。
9. Dashboard 显示阻断原因、命中规则和 trace。

关键证据：

- AttackCase ID。
- GuardEvent / ToolCallEvent payload。
- GuardDecision。
- AuditEvent。
- Dashboard 截图。

## 3. Demo 2：工具调用劫持与外发泄露

目标：证明系统能识别用户任务和工具动作不一致。

步骤：

1. 用户任务是总结邮件。
2. 恶意上下文诱导调用 `send_email(attacker@example.com)`。
3. Guard API 调用 Core 判断任务不一致和外发风险。
4. 返回 `ask` 或 `deny`。
5. Dashboard 显示审批或阻断记录。

关键证据：

- 非白名单收件人。
- 用户任务与工具动作不一致说明。
- 审批或阻断记录。

## 4. Demo 3：AttackBench 指标对比

目标：证明系统不是单点演示，而是可批量评测。

展示：

- ASR before。
- ASR after。
- Block Rate。
- FPR。
- Latency。

步骤：

1. 批量运行 P0 攻击样本和 benign 样本。
2. 生成 defense before / after 对比结果。
3. Dashboard 或报告展示指标。

## 5. Demo 4：OpenClaw 真实接入

目标：证明方案可接入开源智能化应用。

P1 后展示：

1. 启动 OpenClaw。
2. 安装 AgentGuard Security Plugin。
3. 发送恶意消息。
4. 触发 `before_tool_call`。
5. Guard API 返回 `deny`。
6. Dashboard 显示 `runtime=openclaw` 事件。

## 6. 演示顺序建议

正式答辩优先顺序：

1. 用命题矩阵说明覆盖范围。
2. 展示四层目标架构，并说明 LangGraph / OpenClaw 是运行时接入与演示场景。
3. 跑 Demo 1，证明实时阻断。
4. 跑 Demo 2，证明任务一致性和外发控制。
5. 展示 Demo 3 指标。
6. 若 P1 完成，再展示 Demo 4。
