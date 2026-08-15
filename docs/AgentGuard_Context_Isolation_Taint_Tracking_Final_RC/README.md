# AgentGuard Context Isolation / Taint Tracking — Design & Implementation Package

> **状态**：Contract Frozen（2026-08-15，`ct-1.0`；签字见 `CT_FREEZE_METADATA.yaml`）  
> **仓库**：`JToday666/agent-guard`  
> **代码基线**：`dev@f3f650a54921408d4cee3ed2a4a6b3932a040c5f`（PR #133 合并后）  
> **日期**：2026-08-15  
> **定位**：在不推翻 AgentGuard Core V2.1 与 Runtime Enforcement Contract 的前提下，补齐 Context Isolation / Stateful Taint Tracking 的生产闭环。  
> **术语纪律**：`CURRENT` 表示当前代码事实；`TARGET-FROZEN` 表示本设计建议冻结的新增契约；目标能力不能写成当前实测能力。

## 1. 一句话结论

AgentGuard 当前已经具备较完整的 `SourceFact / FlowFact / MemoryFact / DeclassificationFact / StickyTaintSummary`、Taint 传播、11 路 typed projection、Coverage、Authority/Capability、B1-B6 与 Runtime Receipt 基础。真正缺口不是“再设计一套污点模型”，而是两条生产链：

```text
Runtime / GuardEvent
→ Verified Facts
→ committed SecurityStateDeltaV21
→ OnlineSecurityState
→ SecuritySnapshot
```

以及：

```text
SecuritySnapshot + Current Event
→ Core V2.1 Fusion
→ GuardDecision
→ RTE
→ RuntimeOutcomeReceipt
```

本方案因此坚持：

> **停止扩张安全状态模型，优先打通事实生成、上下文隔离、Fusion 消费和真实执行闭环。**

## 2. 当前能力与缺口

### CURRENT — 已具备

- 五类 TaintLabel：`UNTRUSTED / EXTERNAL_INSTRUCTION / SENSITIVE / CREDENTIAL / PERSISTENT_UNTRUSTED`
- `FlowStrength = exact / strong / possible`
- `SourceFact / FlowFact / MemoryFact / DeclassificationFact / StickyTaintSummary`
- `SecurityStateDeltaV21`
- 11 个 typed upsert handler 已静态装配
- `OnlineSecurityState`、CAS、Replay、Rebuild、Coverage
- bounded provenance lookup
- Authority/Capability 与 ExecutionLease 基础设施
- B1-B6 behavior matcher，且严格 signal-only
- OpenClaw `before_agent_run` 输入检测/阻断
- RuntimeOutcomeReceipt 0.4 生产审计入口

### CURRENT — 仍未生产闭合

- `SecurityStateService` 尚未接入 production evaluation
- `EvaluationService` 仍调用 legacy `core_evaluate(event, bundle)`
- 生产 `GuardEvent → Verified typed facts → SecurityStateDeltaV21` 生成链缺失
- V2 Fusion 仍是冻结契约/机器矩阵，未成为 production GuardDecision 主链
- `MemoryGuardChange ↔ MemoryFact` 尚未闭合
- `SecuritySnapshot.declassifications` 当前构建为空
- structured Context Compartmentalization 尚未形成统一生产实现
- OpenClaw frozen pin 的 C2 execution-closure 仍需按 RTE 合同继续收口

## 3. 文档目录

1. `00_总体架构与边界冻结.md` — 总体架构、威胁模型、双平面、三轨、Integration Gate。
2. `01_字段与契约冻结.md` — 当前字段复用、新增内部 DTO、ID/digest/ref、ContextChunk、TransientSecurityFacts。
3. `02_Fact_Authority与Verified_Fact_Producer.md` — Fact Authority Matrix、Runtime Event→Fact、当前事实与历史事实。
4. `03_Context_Isolation与Context_Builder.md` — Context Compartment、Builder、OpenClaw/LangGraph Profile。
5. `04_Taint_Provenance_Memory_Declassification.md` — Taint/Flow、LLM black-box、Sticky、Memory、Declassification。
6. `05_Core_V2.1_Fusion接线.md` — FlowVerdict、Coverage、B1-B6、Fusion、Semantic、Shadow→Active。
7. `06_RTE接线与端到端攻击链.md` — Decision→Lease→Runtime→Receipt 与重点攻击链。
8. `07_测试_评测_性能_可信验收.md` — Unit/Property/Replay/E2E/AttackBench/SLO。
9. `08_实施拆PR与三轨并行计划.md` — PR 设计、依赖、DoD、回滚和集成节点。
10. `09_风险_决策记录_冻结清单.md` — 风险、冻结决策、禁止事项、checklist。
11. `10_竞赛映射_创新点与演示方案.md` — 命题映射、创新点和主 Demo。
12. `11_代码基线与改造映射.md` — 代码基线与改造映射。
13. `12_未决问题处置与决策记录.md` — Freeze Review Questions 处置记录（18 问）与冻结接口映射。
14. `context_taint_contract_freeze.yaml` — 机器可读冻结契约（`ct-1.0`，严格 JSON 兼容）。
15. `context_taint_contract_freeze.schema.json` — 冻结契约 JSON Schema（Draft 2020-12）。
16. `CT_FREEZE_METADATA.yaml` — 冻结元数据与签字记录。
17. `AgentGuard_Context_Isolation_Taint_Tracking_完整方案.md` — 自动合并版（信息性聚合，不作为校验源）。
18. `SHA256SUMS.md` — 文件摘要。

> **校验纪律**：机器校验源为分册 + `context_taint_contract_freeze.yaml` + `CT_FREEZE_METADATA.yaml`；`完整方案.md` 仅为信息性聚合，校验工具不读取它。

## 4. 核心冻结不变量

```text
CT-F0-01  Data / Flow never creates Authority.
CT-F0-02  LLM is neither sanitizer nor authority issuer.
CT-F0-03  ALLOW does not imply TRUST.
CT-F0-04  Decision does not prove Execution; Runtime Receipt does.
CT-F0-05  Missing required fact is not equivalent to Safe.
CT-F0-06  Taint does not decay by hop count or by crossing an LLM.
CT-F0-07  Adapter claims cannot self-elevate trust or remove taint.
CT-F0-08  No committed authoritative record → no historical state mutation.
CT-F0-09  Current-event facts affect current decision only as transient evidence before commit.
CT-F0-10  B1-B6 are signals, not standalone decision engines.
CT-F0-11  Context compartments are soft defenses; Capability/RTE is the hard backstop.
CT-F0-12  Context/Taint consumes the single Core V2.1 Fusion; no second PDP.
```

## 5. 推荐实施顺序

```text
CT-00 Contract Freeze
        ↓
CT-01 Fact Authority Matrix
        ↓
CT-02 Verified Fact Producer ───────┐
                                    │
Core V21-08 Fusion ─────────────────┼─ Integration Gate A
                                    │
CT-03 Context Builder ──────────────┤
CT-04 Memory / Declassification ────┘

RTE Track ───────────────────────────── Integration Gate B
```

关键纪律：

- **Fact Authority Contract 先于 Fact Producer**；
- Fact Producer、Core Fusion、RTE 可并行；
- Context Builder/Memory Bridge 可与 Fusion 并行；
- 最终在 `Fact→Snapshot→Fusion` 与 `Decision→Execution→Receipt` 两个 Gate 汇合。

## 6. 第一版明确不做

- token-level taint；
- 全局无限 provenance graph 热路径；
- LLM 内部精确因果追踪；
- 第二 Decision Engine / 第二 OnlineSecurityState；
- 所有 `UNTRUSTED` 一律 DENY；
- `sanitized=True` 清除 taint；
- LLM summary 作为 declassification；
- Prompt delimiter 作为硬安全边界；
- 将 PR #133 regression 数字当 Context/Taint E2E 效果；
- 没有 Receipt 就宣称 `not_invoked`；
- Runtime capability 未被版本化实证时夸大支持。

## 7. 仓库位置

本设计包位于：

```text
docs/AgentGuard_Context_Isolation_Taint_Tracking_Final_RC/
```

本包已于 CT-PR-00 入库，并作为机器校验源（`scripts/ct-contract-tools.py` + `tests/test_ct_contract_freeze.py`）。

> **维护注记**：本特性分支（`feat/ct-pr-00-contract-freeze`）在隔离 worktree `.tmp/ct-worktree` 中开发；合入 dev 后须执行 `git worktree remove .tmp/ct-worktree` 并删除本特性分支。
