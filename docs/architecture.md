# 系统总体架构

## 1. 架构概述

AgentGuard 采用一核两壳架构：

```text
Agent Security Core
├── LangGraph + LangChain Core + Mock Tools
└── OpenClaw + Security Plugin
```

## 2. 总体框架图

```mermaid
flowchart TB
    R["Redteam<br/>攻击样本与评测"]
    L["LangGraph Shell<br/>评测靶场"]
    O["OpenClaw Shell<br/>真实应用接入"]
    C["Agent Security Core<br/>检测 策略 审计 审批 指标"]
    D["Dashboard<br/>告警 阻断 审批 指标"]

    R --> L
    R --> O
    L --> C
    O --> C
    C --> D
```

## 3. 核心链路

```text
输入 / 外部内容
→ 上下文拼接审计
→ 模型输入输出审计
→ 工具调用前拦截
→ 文件/API/代码/消息/记忆审计
→ 策略决策
→ allow / deny / ask
→ 审计日志
→ Dashboard 展示
→ Metrics 评测
```

## 4. 模块职责

| 模块 | 职责 |
|---|---|
| Agent Security Core | 风险判断、策略、审批、审计、指标 |
| LangGraph Shell | 可控评测、Mock Tools、批量攻击样本 |
| OpenClaw Shell | 真实应用插件接入、Hook、配置审计 |
| Dashboard | 可视化、审批、攻击链路、指标 |
| Redteam | 攻击样本、攻击脚本、成功条件 |

## 5. 亮点

- 一核两壳；
- 运行时工具调用拦截；
- 上下文拼接审计；
- 工具结果回流审计；
- Memory Guard；
- Provenance Graph；
- OpenClaw Config Audit；
- Tamper-Evident Audit；
- Continuous Red Team Loop。
