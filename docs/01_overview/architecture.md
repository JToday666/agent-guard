# 系统总体架构

## 1. 文档定位

本文是 AgentGuard 的架构入口，面向开发者说明系统分层、模块职责、事件流和阶段边界。实现时优先保证 P0 最小闭环，再扩展 OpenClaw、上下文审计、记忆审计和高级评测。

关联入口：

- [接口契约与事件模型](../02_core/interface_contract.md)
- [Agent Security Core 设计](../02_core/core_design.md)
- [实施路线与验收标准](../06_delivery/implementation_plan.md)

## 2. 架构概述

AgentGuard 采用 **一核两壳**：

```text
Agent Security Core
├── LangGraph + LangChain Core + Mock Tools
└── OpenClaw + Security Plugin
```

| 层级 | 职责 | 开发优先级 |
|---|---|---|
| Agent Security Core | 统一事件模型、风险检测、策略决策、审批、审计、指标 | P0 |
| LangGraph Shell | 可控评测靶场、Mock Tools、批量攻击样本重放 | P0 |
| Dashboard | AuditEvent 展示、阻断记录、审批、指标 | P0-P1 |
| OpenClaw Shell | 开源智能化应用接入、Hook 映射、配置审计 | P1-P2 |
| Redteam / AttackBench | 攻击样本、正常样本、runner、成功条件和指标 | P0-P1 |

## 3. 核心数据流

```text
AttackCase / 用户任务
→ Agent Runtime
→ Adapter Mapping
→ AgentGuard Event
→ Agent Security Core
→ PolicyDecision
→ Adapter Enforcement
→ AuditEvent
→ Dashboard / Metrics
```

关键约束：

- Core 只做安全判断，不执行工具。
- Adapter 只做运行时映射和执行控制，不内置核心规则。
- Dashboard 只读 Core API，不直接连接 Agent runtime。
- Redteam 提供 ground truth，评测结果不能由 Dashboard 推断。

## 4. P0/P1/P2 开发边界

| 阶段 | 必须实现的架构能力 | 不做或延后 |
|---|---|---|
| P0 | LangGraph 靶场、ToolCallEvent、PolicyDecision、AuditEvent、Mock Tools、Dashboard 事件页、AttackBench 基础 runner | OpenClaw 完整接入、多渠道审批、复杂模型检测 |
| P1 | ContextBuildEvent、ToolResultEvent、MemoryEvent、输入输出过滤、攻击链路页、FPR/FNR 指标 | Tamper-Evident Audit、复杂 provenance 图 |
| P2 | OpenClaw Config Audit、Memory Guard、Action Critic、Provenance Graph、消融实验 | 生产级多租户、安全沙箱逃逸检测 |

## 5. 验收证据

P0 架构验收必须能展示：

1. 同一攻击样本在无防御模式下触发危险工具调用。
2. 开启 Core 后，Adapter 在工具执行前收到 `deny` 或 `ask`。
3. 危险工具未执行，AuditEvent 写入审计日志。
4. Dashboard 展示 trace、风险分数、命中规则和阻断原因。
5. AttackBench 输出 ASR before、ASR after、Block Rate、FPR。
