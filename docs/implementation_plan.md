# 实施路线与验收标准

## 1. 阶段

```text
P0：LangGraph 保底闭环
P1：完整可解释链路
P2：OpenClaw 与冲奖增强
```

## 2. P0

目标：

```text
攻击样本 → LangGraph → Core → deny → Dashboard
```

必做：

- Core API；
- ToolCallEvent；
- PolicyDecision；
- AuditEvent；
- LangGraph ToolNode wrapper；
- read_file / send_email / call_api；
- Dashboard 事件页；
- 3 类攻击样本。

## 3. P1

必做：

- ContextBuildEvent；
- ToolResultEvent；
- pre_model_hook；
- post_model_hook；
- MemoryEvent；
- OpenClaw before_tool_call；
- message_sending；
- 攻击链路页；
- FPR 指标。

## 4. P2

增强：

- Provenance Graph；
- Memory Guard；
- Action Critic；
- Tamper-Evident Audit；
- OpenClaw Config Audit；
- 多渠道审批；
- 消融实验。

## 5. 分工

| 成员 | 负责 |
|---|---|
| A | Core、schemas、policies、contract tests |
| B | LangGraph、Mock Tools、Redteam runner |
| C | OpenClaw Plugin、Dashboard、文档、Demo |
