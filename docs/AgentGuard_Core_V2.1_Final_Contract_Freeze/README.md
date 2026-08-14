# AgentGuard Core V2.1-Final — Contract Freeze

> 状态：**Final Design / Contract Freeze Candidate**  
> 适用范围：AgentGuard 竞赛版 Minimal V2.1 + 后续生产级扩展  
> 当前远端 `dev` 冻结检查点：`69efe2f027d9a4ba9c18623838e84f6ce30ffa62`  
> 核心功能设计基线：其父提交 `1d9fb7ffd6fbb94dc228143c19793e0f7fe20642`；`69efe2f` 仅为 CI 修复，不改变 Core 判定设计前提。

## 1. 文档定位

本目录是此前 V2、V2.1、Deep Research 与多轮评审意见的唯一候选收敛版本。自动校验与人工签字完成前保持 `candidate-for-freeze`。自正式冻结起：

- 不再维护平行的 V2.1 判定方案；
- 新实现若偏离 F0/F1 契约，必须先修改本文档并经过安全评审；
- 竞赛实现采用 **Minimal V2.1-Final**，生产级多 worker、共享状态和更广泛 Semantic de-escalation 明确后置；
- “高召回、低误报、实时、可解释、高可信”是本架构支持的**目标**，不是文档本身已证明的结果；必须由最终 benchmark、消融实验、真实 Runtime Receipt 和可复现性能测试验证。

Candidate 转为 Frozen 必须同时满足：机器契约通过 Schema 校验、分册与聚合文档一致、V21-00 基线证据完整、冻结清单中的设计签字项通过，并由评审者明确确认。实现期测试项不冒充设计签字项。

## 2. 核心结论

Core 最终采用六层混合判定架构：

1. **L1 Event & Action Normalization**：统一不同 Runtime/Tool 的动作语义；
2. **L2 Deterministic Policy / Resource / Content**：确定性规则、硬安全策略、资源约束；
3. **L3 Behavior & Sequence**：跨事件行为、预算、序列与状态异常；
4. **L4 Provenance / Taint + Authority**：数据流/影响流与授权链严格分离；
5. **L5 Selective Semantic Analysis**：仅处理 `DEFER` 中可被语义消歧的灰区；
6. **L6 Evidence Correlation & Decision**：证据相关性去重、事实优先级与三态快速裁决。

对外仍输出：

```text
ALLOW / ASK / DENY
```

Core 内部快速态为：

```text
CLEAR_ALLOW / CLEAR_DENY / DEFER
```

## 3. 关键设计原则

- **规则不是唯一检测器**：纯静态 detector 对开放世界语义改写、多步链路与长期记忆污染不足；
- **LLM 不是最终裁决者**：LLM 仅做受限语义判断，不能创造 Authority、不能覆盖硬拒绝；
- **Data Reachability ≠ Authorization**：有数据/影响路径不代表用户授权；
- **Missing Fact ≠ Safe Fact**：缺失必需事实时禁止 `CLEAR_ALLOW`；
- **Taint 不因 hop 自动衰减**：只有可信、策略注册、可审计的 declassification 才能改变标签；
- **Taint label 与 flow strength 分离**：LLM 看过凭据不等于输出必然泄露凭据；
- **Decision ≠ Enforcement**：`DENY` 不是“确认未执行”，Runtime Receipt 才是执行事实；
- **Uncommitted fact 不能成为历史安全状态**：Projector 只消费 committed authoritative record；
- **Snapshot 必须有域级 coverage**：状态质量按 task/source/capability/behavior/dataflow/memory/runtime_outcome 分域；
- **Semantic timeout / invalid / stale 不产生 ALLOW**；
- **Required component failure 不允许 fail-open**；
- **allow_once 必须绑定内部授权指纹并只能消费一次**。

## 4. 文档地图

| 文档 | 内容 |
|---|---|
| `00_最终架构与冻结边界.md` | 六层架构、事实平面、冻结级别、竞赛/生产范围 |
| `01_F1字段与契约冻结.md` | 全部 P0/F1 数据类型与字段，消除未定义类型 |
| `02_状态投影_Provenance_Authority.md` | Authoritative Record、StateDelta、Projector、Coverage、Taint、Authority |
| `03_判定融合与Semantic契约.md` | CLEAR_ALLOW/DENY/DEFER、冻结矩阵、Semantic 路由与重验证 |
| `04_兼容迁移与实施计划.md` | Legacy/V2 共存、15 Phase DAG、回滚和启用顺序 |
| `05_评测_性能_可信验收.md` | Recall/FPR/ASK/ASR/Receipt/Latency、CI 与统计门禁 |
| `06_创新点与命题映射.md` | 竞赛命题覆盖、创新点、答辩口径 |
| `07_当前代码改造映射.md` | 当前 dev 文件级改造范围、模块落点 |
| `08_参考研究与证据要求.md` | 研究依据、代码事实引用规范、答辩证据格式 |
| `AgentGuard_Core_V2.1_Final_完整方案.md` | 上述分册聚合版 |
| `contract_freeze.yaml` / `contract_freeze.schema.json` | JSON-compatible YAML 总冻结清单及机器校验 |
| `fusion_matrix.yaml` / `fusion_matrix.schema.json` | 可执行 Fusion 规则及 selector/disposition Schema |
| `baseline/` | V21-00 环境清单、机器报告、可读摘要与 freeze-readiness |

## 5. 冻结级别

### F0 — System Security Invariants

不可被普通配置、Tenant Policy、Semantic Judgment 或 Adapter claim 改写。

### F1 — Internal Security Contracts

Minimal V2.1 实施期间稳定。字段语义、digest 口径、Projector 顺序、Fusion Matrix 等属于 F1。

### F2 — Public Compatibility Contracts

`GuardEvent`、公开 `GuardDecision`、现有 Audit/Receipt API 等默认向后兼容；必要 breaking change 必须单独版本化。

### F3 — Tunable Policy / Operational Parameters

阈值、窗口大小、Semantic deadline、具体 Tenant Hard Policy 等可配置，但必须版本化、审计、可回滚，且不能违反 F0。

## 6. 本版明确不做

Minimal 竞赛版不把以下内容作为前置：

- Neo4j/完整在线图数据库；
- 任意深度跨全局 Session 图查询；
- Vector Clock；
- 多 worker 分布式强一致状态；
- Semantic 自动 `ASK/DEFER → ALLOW`；
- Embedding/NLI 大规模常驻推断层；
- LLM 因果关系作为单独 hard deny 证据；
- 重写整个公开 GuardDecision Schema；
- 第二套 Approval/Grant 状态机。
