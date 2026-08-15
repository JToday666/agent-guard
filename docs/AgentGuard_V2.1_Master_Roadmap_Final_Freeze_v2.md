# AgentGuard V2.1 三轨实施总路线图（Master Roadmap v2，Implementation Freeze Candidate）

## Document Status

  项目       内容
  ---------- --------------------------------------------------
  文档类型   Master Roadmap / Implementation Freeze Candidate
  目标       统一 CORE / CT / RTE 三轨实施路线
  优先级     低于三套正式冻结分册（CORE / CT / RTE）
  当前状态   Implementation Freeze Candidate（非正式冻结产物）

本文件为 Implementation Freeze Candidate，非正式冻结产物，不含
FREEZE_METADATA / SHA256SUMS / 签字锚点；其效力低于三套正式冻结分册
（CORE / CT / RTE），与冻结分册冲突时以冻结分册为准。

------------------------------------------------------------------------

# 1. 文档定位与原则

本文档是 AgentGuard V2.1 从当前基线到最终 E2E Security Closure
的统一实施路线。

三条 Track：

  Track   全称                                 核心职责
  ------- ------------------------------------ --------------------
  CT      Context Isolation / Taint Tracking   可信安全事实生产
  CORE    Core V2.1 Decision Engine            安全判定与策略融合
  RTE     Runtime Enforcement                  执行控制与结果证明

核心原则：

> Data may influence reasoning, but only authenticated authority may
> authorize side effects.

含义：

-   不可信数据可以影响 Agent 推理；
-   不可信数据不能产生 Authority；
-   LLM 不是可信边界；
-   LLM 不是 Sanitizer；
-   Decision 与 Execution 必须分离。

------------------------------------------------------------------------

# 2. 当前基线（Baseline）

当前状态：

  Track   已完成
  ------- ---------------------------------------
  CORE    V21-08 完成
  CT      CT-PR-00 Contract Freeze 完成
  CT      CT-PR-01 Fact Authority Matrix 已完成
  CT      CT-PR-02a 已合入 dev（PR #145，无接线）
  CT      CT-PR-02b 已合入 dev（PR #148，写侧三事件，无接线）
  CT      CT-PR-03a 已合入 dev（PR #149，纯函数内核，无接线）
  CT      CT-PR-03b 已合入 dev（PR #150，接线与 DoD 状态投影，flag 门控默认关）
  RTE     RTE-01 \~ RTE-04 完成
  RTE     RTE-05 Freeze Gate 核对通过（PR #144 已合入 dev）

近期动态（以 dev 实时状态为准，状态词随项目推进更新）：

-   PR #144（RTE-05 Freeze Gate 八项核对）已合入：判定 RTE-05
    可开工；唯一未实现项为 consume endpoint，归属 RTE-05 本体（见 §7）；
-   PR #145（CT-PR-02a，Verified Fact Producer 读路径，无接线）已合入 dev；
-   PR #148（CT-PR-02b，Verified Fact Producer 写侧三事件，无接线）已合入 dev；
-   PR #149（CT-PR-03a，Committed Delta Builder 纯函数内核，无接线）已合入 dev；
-   PR #150（CT-PR-03b，CT 事实投影接线与 DoD 状态投影，flag 门控默认关）已合入 dev；
-   feat/v21-09-assess-finalize 分支开发中（assess/finalize
    正式入口等），尚未合入。

因此当前起点：

    CORE:
        V21-09（进行中）

    CT:
        CT-PR-03 已完成（03a/03b 已合入 dev），下一步 CT-PR-04

    RTE:
        RTE-05（开工条件已具备）

------------------------------------------------------------------------

# 3. 三轨总体依赖图

``` mermaid
flowchart TB

START["CURRENT BASELINE<br/><br/>CORE V21-08 ✅<br/>CT-PR-00 ✅<br/>CT-PR-01 ✅<br/>CT-PR-02a ✅<br/>RTE-01~04 ✅<br/>RTE-05 Freeze Gate ✅"]


subgraph CORE["🔵 CORE Track"]

C09["CORE V21-09<br/>Assessment Finalization<br/>CAS/Digest Revalidation"]

C10["CORE V21-10<br/>Receipt & Evaluation<br/>Pre-enable Gate"]

C11["CORE V21-11<br/>Limited Enable"]

C12["CORE V21-12<br/>Attack Chain Modernization"]

C13["CORE V21-13<br/>Semantic Shadow"]

C14["CORE V21-14<br/>Semantic Upgrade"]

C09 --> C10
C10 --> C11 --> C12
C10 --> C13 --> C14

end


subgraph CT["🟢 CT Track"]

CT02["CT-PR-02<br/>Verified Fact Producer"]

CT03["CT-PR-03<br/>Committed Delta Builder<br/>State Wiring"]

CT04["CT-PR-04<br/>Context Builder"]

CT05["CT-PR-05<br/>Memory Bridge"]

CT06["CT-PR-06<br/>Declassification Evidence"]

INT01["INT-PR-01<br/>Fact → Snapshot → Shadow Fusion"]

INT02["INT-PR-02<br/>Decision → Runtime"]

INT03["INT-PR-03<br/>Cross Session Memory E2E"]

INT04["INT-PR-04<br/>Shadow → Limited Enable"]

CT02 --> CT03

CT03 --> INT01

CT03 --> CT04
CT03 --> CT05

CT04 --> CT06
CT05 --> CT06

CT04 --> INT03
CT05 --> INT03

CT04 --> INT04

end


subgraph RTE["🟣 RTE Track"]

R05P["RTE-05 Preparation<br/>Lease / Binding Contract"]

R05["RTE-05 Integration<br/>Strong Approval Binding"]

R06["RTE-06<br/>Evidence Hardening"]

R07["RTE-07<br/>Reliability Evidence"]

R05P --> R05
R05 --> R06
R05 --> R07

end


GA{{"GATE A<br/><br/>CT Facts enter CORE"}}

GB{{"GATE B<br/><br/>CORE Decision controls Runtime"}}


START --> C09
START --> CT02
START --> R05P


CT03 --> INT01
C09 --> GA
INT01 --> GA


GA --> C10


C10 --> INT02
R05 --> INT02


C10 --> GB
R05 --> GB
INT02 --> GB


GB --> C11
GB --> C13

GB --> INT03
GB --> INT04

GB --> R06
GB --> R07


FINAL["FINAL SYSTEM ACCEPTANCE"]

CT06 --> FINAL
C12 --> FINAL
C14 --> FINAL
INT03 --> FINAL
INT04 --> FINAL
R06 --> FINAL
R07 --> FINAL
```

图注：CT-PR-06（Declassification Evidence）按 §10 最终验收要求归入
FINAL 前置，故出边指向 FINAL；其不阻塞 Gate A（见 §4 Gate A 非必需条件）。

------------------------------------------------------------------------

# 4. Gate 定义

------------------------------------------------------------------------

# Gate A：CT → CORE Integration Gate

## 定义

证明：

    Runtime Event

    ↓

    Verified Fact Producer

    ↓

    SecurityStateDelta

    ↓

    Projection

    ↓

    Snapshot

    ↓

    CORE Assessment

    ↓

    Decision

完整闭环。

注：Gate A 为本路线图设置的三轨项目级叠加门槛；冻结 CORE 04 §5 DAG
本身为 V21-09 → V21-10 直连，不含该门槛。

------------------------------------------------------------------------

## Gate A 必需条件

必须：

-   SourceFact 可生成；
-   FlowFact 可生成；
-   Context Taint 可进入 Snapshot；
-   CORE 可以消费真实 Snapshot；
-   Shadow Fusion 可以运行。

------------------------------------------------------------------------

## Gate A 非必需条件

不阻塞：

-   Memory Bridge；
-   Cross Session Memory E2E；
-   Declassification 完整能力。

原因：

这些属于长期状态增强，不属于最小 Decision 闭环。

------------------------------------------------------------------------

# Gate B：CORE → RTE Integration Gate

## 定义

证明：

    GuardDecision

    ↓

    EnforcementBinding

    ↓

    ExecutionLease（如需要）

    ↓

    Runtime Enforcement

    ↓

    RuntimeOutcomeReceipt

成立。

注：对照冻结 CT 00 §9，EnforcementBinding 为必需绑定层；
ExecutionLease 按需（"如需要"）签发。

------------------------------------------------------------------------

## Gate B 必需条件

-   action_id 精确绑定；
-   authorization fingerprint 一致；
-   EnforcementBinding 完成；
-   deny 可以证明未执行；
-   allow_once 可以证明完整执行链。

------------------------------------------------------------------------

## Gate B 顺序裁决说明

本路线图采用 RTE-05 → Gate B 方向（RTE-05 Strong Binding 不以等待
Gate B 为前置）。

依据（冻结文本层）：

-   CT 分册 08 §12：Strong Binding 仅要求 ActionIR production、
    authorization_fingerprint、ExecutionLease endpoint 就绪，
    未要求等待 Gate B；
-   RTE 分册 06 §11：R5（Strong Binding）仅依赖 C4 + R4。

冻结 CT 分册 08 §1 的粗粒度 mermaid（G2 → R3）与此方向不一致，
属粗图示意误差；本候选稿不修改冻结分册，口径以冻结文本层为准。

------------------------------------------------------------------------

# 5. CT Track 实施计划

------------------------------------------------------------------------

## CT-PR-02 Verified Fact Producer

目标：

建立：

    Runtime Event

    ↓

    Verified Fact

    ↓

    SourceFact / FlowFact / MemoryFact

解决当前最大断点：

Runtime 到安全事实之间缺失。

------------------------------------------------------------------------

## CT-PR-03 Committed Delta Builder

目标：

建立：

    Verified Fact

    ↓

    SecurityStateDelta

    ↓

    Projector

    ↓

    OnlineSecurityState

要求：

-   Adapter 不产生 Delta；
-   Server 侧派生；
-   Commit 后 Projection；
-   Replay 一致。

------------------------------------------------------------------------

## CT-PR-04 Context Builder

目标：

实现：

-   ContextChunk；
-   compartment；
-   quarantine。

注意：

Context Isolation 是软隔离。

最终安全边界：

Capability + CORE + RTE。

------------------------------------------------------------------------

## CT-PR-05 Memory Bridge

目标：

防御 Memory Poisoning。

流程：

    Session A

    ↓

    Tainted Memory

    ↓

    Commit

    ↓

    Restart

    ↓

    Session B

    ↓

    Sticky Taint

原则：

ALLOW != TRUST。

------------------------------------------------------------------------

## CT-PR-06 Declassification Evidence

要求：

不能通过：

    sanitized=true

解除污染。

必须：

    trusted_declassifier

    +

    proof

    +

    evidence

------------------------------------------------------------------------

# 6. CORE Track 实施计划

------------------------------------------------------------------------

# CORE V21-09

目标：

完成：

-   assess；
-   finalize；
-   CAS revalidation；
-   state digest validation。

------------------------------------------------------------------------

# CORE V21-10

目标：

进入 Enable 前状态。

验收：

-   Receipt Coverage；
-   Shadow divergence；
-   Rollback；
-   Performance。

------------------------------------------------------------------------

# CORE V21-11

Limited Enable。

------------------------------------------------------------------------

# CORE V21-12

攻击链现代化：

-   Prompt Injection；
-   Agent Abuse（对照冻结 CORE 04 §18 三类攻击链口径）；
-   Memory Poisoning。

------------------------------------------------------------------------

# CORE V21-13 / V21-14

Semantic Shadow 分支。

不阻塞 Deterministic 主线。

------------------------------------------------------------------------

# 7. RTE Track 实施计划

------------------------------------------------------------------------

# RTE-05 Preparation

提前完成：

-   ExecutionLease contract；
-   Binding contract；
-   Runtime adapter准备。

------------------------------------------------------------------------

# RTE-05 Integration

目标：

完成：

    Decision

    ↓

    ExecutionLease

    ↓

    Runtime Action

交付含 consume endpoint（归属 RTE-05 本体，对照 RTE 分册 06 §7
"已冻结，实施需完成"与 §8 交付口径）：

    POST /v1/approvals/{id}/execution-leases/consume

------------------------------------------------------------------------

# RTE-06 Evidence Hardening

包括：

-   result persistence；
-   correlation；
-   evidence completeness。

------------------------------------------------------------------------

# RTE-07 Reliability Evidence

验证：

-   API unavailable；
-   duplicate receipt；
-   late approval；
-   restart/drain。

------------------------------------------------------------------------

# 8. 串并行关系

## Gate A 前

并行：

    CORE V21-09

    ||

    CT-PR-02
     ↓
    CT-PR-03

    ||

    RTE-05 Preparation

------------------------------------------------------------------------

## Gate A 后

并行：

    CORE V21-10

    ||

    CT-PR-04
    ||
    CT-PR-05

    ||

    RTE-05 Integration

------------------------------------------------------------------------

## Gate B 后

最大并行区域：

CORE：

    V21-11 → V21-12

    并行

    V21-13 → V21-14

CT：

    INT-PR-03

    并行

    INT-PR-04

RTE：

    RTE-06

    并行

    RTE-07

------------------------------------------------------------------------

# 9. 阻塞项管理

  阻塞项                        影响
  ----------------------------- ---------------------
  CT-PR-03 未完成               Gate A 无法通过
  CORE V21-09 未完成            无法进入真实 Fusion
  ExecutionLease consume 缺失   RTE-05 交付阻塞
  OpenClaw Adapter C2 未证明    RTE 集成风险
  CT 编号未统一                 文档维护风险

------------------------------------------------------------------------

# 10. 最终验收

Final Acceptance 必须同时满足：

## CT

-   Context Isolation；
-   Stateful Taint；
-   Memory E2E；
-   Declassification。

## CORE

-   Decision Evidence；
-   Fusion；
-   Limited Enable；
-   AttackBench。

## RTE

-   Strong Binding；
-   Runtime Receipt；
-   Reliability Evidence。

最终闭环：

    Source

    ↓

    Fact

    ↓

    Flow

    ↓

    Decision

    ↓

    Runtime

    ↓

    Receipt

------------------------------------------------------------------------

# 11. 最终项目定位

AgentGuard 不是单纯 Prompt Injection Detector。

它是：

> 面向 Agent Runtime 的安全参考监视器，通过 Context Isolation、Stateful
> Taint Tracking、Core V2.1 Decision Fusion 与 Runtime
> Enforcement，控制不可信信息对 Agent
> 高影响行为的传播，并提供可验证执行闭环。
