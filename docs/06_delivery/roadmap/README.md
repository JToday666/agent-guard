# AgentGuard 全轨实施路线图

本目录是 AgentGuard 的实施控制面：机器源记录原子任务、验收项、真实依赖和 Git
证据；工具从机器源计算可启动节点并生成可阅读路线图。它不是对冻结文档的复制，也不能
反向修改冻结契约。

## 1. 制品和真值边界

```text
schema/                    JSON Schema 2020-12
source/roadmap.json        目录、泳道、颜色、共享资源和文档效力
source/nodes/*.json        一个文件一个文档明确任务/Gate/Stage/验收项
source/edges/*.json        一条文件一条具有语义的依赖关系
source/decisions/*.json    文档冲突和项目级叠加门槛的显式裁决
source/evidence/<node>/    Git、测试、CI、文档和 worktree 证据
generated/                 由工具确定性生成，禁止手工修改
```

完整构建生成：

- `generated/roadmap.normalized.json`：供 CI、Agent 和其他工具读取；
- `generated/roadmap.md`：GitHub Mermaid 总览与无脚本表格；
- `generated/index.html`：无 CDN 的交互泳道 DAG。

文档效力从高到低：CORE/CT/RTE 正式冻结分册、Console S0–S6 当前计划、Master
Roadmap candidate、Git 历史。前三者决定合同依赖，Git 只决定实施状态和真实观察顺序；
没有合同依据的提交先后只能标为 `observed_sequence`。

## 2. 状态和可启动性

| 状态          | 颜色             | 含义                                          |
| ------------- | ---------------- | --------------------------------------------- |
| `completed`   | 绿色 `#1F9D63`   | 完成提交进入 `origin/dev` 且出口证据齐全      |
| `in_progress` | 琥珀色 `#D99000` | 已 claim，或分支已实现但尚未进入基线          |
| `ready`       | 蓝色 `#2774D8`   | 未开始、所有 start 阻断已满足且无共享资源冲突 |
| `not_ready`   | 灰色 `#7B8494`   | 未开始但仍有 start 阻断或资源冲突             |

`ready` 是生成值，不能写入节点 JSON。正式可 claim 的蓝色节点必须满足：

```text
kind == task
lifecycle == not_started
all start/hard predecessors completed
blocked == false and hold == false
not deferred/not_applicable
no active exclusive-surface conflict
```

红色外框是 `blocked`，虚线外框是 optional，警告徽标是 evidence gap。已满足
start 条件但仍有 activation/exit 门槛时，蓝色节点带锁徽标；这表示“可以开发”，不表示
“可以启用或宣称完成”。

截至 2026-08-24，代码基线为 `origin/dev@5986538`（PR #188）；Productization Alpha
状态为 **in progress**，最终集成 SHA 和门禁结果以
[`productization_alpha_status.md`](../productization_alpha_status.md) 为准。

PR #188 已把 LGV2 Core selector、Guard API 接线、competition runner 和 Dashboard
只读报告的大批实现表面合入 `origin/dev`，但它跨越多个路线图节点。当前机器源仍将
LGV2-C/LGV2-B 标为 `in_progress`，LGV2-I/LGV2-FE 标为 `not_started`；在逐节点核对
acceptance、commit、CI 和真实评测证据前，不得仅按代码存在批量改为 completed。

正式 `R05` 继续保持 blocked；S2、Gate B、正式 S4、正式 S5-C 及后续门槛仍未完成。
Operational MVP、competition profile、shadow 或演示证据不得解释为这些 Stage/Gate 已通过。

R05 implementation 已在 `67ad24d` 合入并登记 commit/test/review/E2E 证据，但
OpenClaw 2026.7.1-2 仍缺 atomic replace-and-seal 和 authoritative invocation-start hook，
因此 R05 保持 blocked，CF-13/C3、Gate B 与正式 S4 均不能关闭。
`D-OPERATIONAL-MVP-LANGGRAPH-SCOPE` 已将验证完成的 LangGraph、Context Builder 和
display-safe evidence 开发表面与该宿主缺口解耦；这允许 C10、CT04/CT04M、FE08/FE10A
和 I02A 正式完成，但不改变 R05 或跨 runtime 的正式结论。

`D-COMPETITION-LANGGRAPH-V2-ACTIVE` 另行登记了受冻结 activation manifest
限定的 `competition-langgraph-v2` 专项路线。LGV2-C 和 LGV2-B 可独立
claim；LGV2-I 在 Core selector 完成后接线 Guard API/RTE，LGV2-FE 再做只读
展示。该专项不更改 C11/I02B/I04/ROL1、R05、Gate B 或正式 S5-O。真实外部
Provider 的固定 A0–A4、70 例、`70×5=350` qualifying matrix 尚未完成；
contracts/demo/stub 运行不能替代正式效果证据。

S2-L 的 typed Provenance writer、FE-RSC-06/07、Memory/PostgreSQL live path 与 parity 已在
`b814a67` 合入；`RSC-CTPROV`、FE06 和 FE07 现已按正式 claim/evidence/close 生命周期完成
reconciliation。该收口只完成三个原子任务，S2 仍有未完成验收项，不能据此宣称 Stage 绿色。

## 3. 节点和边契约

节点保存明确原文标题、类型、角色、泳道、生命周期、revision、可选/阻塞标志、共享
修改表面、文档定位和证据引用。验收节点通过 `acceptance_parent` 归属于一个 Gate、Stage
或 Final；正文中的每个验收清单项各占一个节点。

边必须声明：

| `constraint` | 视觉         | 语义                                     |
| ------------ | ------------ | ---------------------------------------- |
| `start`      | 粗实线       | 前置不绿则不能 claim 后继任务            |
| `activate`   | 实线加锁     | 可开发，但不能进入 production activation |
| `exit`       | 细实线/汇合  | 可并行开发，但不能通过 Gate/Stage/Final  |
| `none`       | 点线或覆盖层 | 不参与阻断计算                           |

`hard_dependency`、`required_input` 和 `join` 表示真实依赖；`optional`、`fallback`、
`non_blocking` 分别使用虚线、点划线、点线。每条边必须有 rationale、provenance 和
source ref；纯 Git 顺序只能使用 `observed_sequence`。

关键裁决位于 `source/decisions/`：RTE-05 在 Gate B 前；RTE-06/07 并行；CT04 有
Gate A 项目级叠加门槛；S5-C/S5-O 独立后汇合；Competition S6 与 Full Master Final
不得混称。`D-OPERATIONAL-MVP-LANGGRAPH-SCOPE` 进一步冻结 reference profile 边界：
OpenClaw host 缺口继续阻塞 R05/Gate B/正式 S4，但不再占用已验证 LangGraph、Context
Builder 和 display-safe evidence 的开发表面。

## 4. 强制维护流程

主工作区只做读取和调度。实现前：

```bash
git fetch origin
uv run python scripts/roadmap-tools.py validate
uv run python scripts/roadmap-tools.py ready
uv run python scripts/roadmap-tools.py explain NODE
uv run python scripts/roadmap-tools.py claim NODE \
  --branch codex/NODE-slug --owner OWNER --worktree-slug NODE \
  --base-sha SHA --expected-revision N
```

claim 更新必须先从独立 allocation worktree 合入 `dev`，然后才创建功能 worktree：

```bash
git worktree add ../agent-guard-worktrees/NODE \
  -b codex/NODE-slug ALLOCATION_SHA
```

实施中只为所 claim 节点追加 evidence。实现、测试、CI、真实 E2E、回滚证据和 feature
提交全部进入 `origin/dev` 后，立即在新的状态 worktree 执行：

```bash
uv run python scripts/roadmap-tools.py add-evidence NODE \
  --kind commit --ref SHA --summary "merged into dev" --status verified
uv run python scripts/roadmap-tools.py close NODE \
  --commit SHA --expected-revision N
uv run python scripts/roadmap-tools.py build
uv run python scripts/roadmap-tools.py check
```

`add-evidence` 只追加本节点证据，不改节点或 `generated/`；`close` 由 integration owner
把已核验 commit evidence 引用进节点并原子重建图。阻塞和恢复命令为：

```bash
uv run python scripts/roadmap-tools.py block NODE \
  --reason "REASON" --expected-revision N
uv run python scripts/roadmap-tools.py resume NODE --expected-revision N
uv run python scripts/roadmap-tools.py check-diff \
  --base-ref BASE --head-ref HEAD
```

不删除历史证据。功能 worktree 不得修改其他节点状态，不得手改 `generated/`。关闭节点后
由生成器重新计算 Ready Queue，下游只能在更新后的蓝色状态进入 `dev` 后 claim。

独立基准工具例外：Claude Code/AttackBench 基准运行器、MCP bridge、紧凑报告和 smoke
维护不代表产品 runtime activation，因此不要求伪造或借用路线图 claim。`check-diff` 仅在
实现差异同时满足以下条件时适用该例外：包含
`agentguard_langgraph_bench/adapters/claude_code/**` 或 `scripts/claude_code_smoke.py`
这一 canonical marker；所有实现路径均位于 `agentguard_langgraph_bench/**`、
`benchmarks/claude-code-mcp-bridge/**` 或 `scripts/claude_code_smoke.py`；并且没有产品
代码、Guard API、策略或路线图节点变更。任何不满足这些条件的差异仍遵守完整 claim、surface
和 evidence 门禁。

## 5. 最快并行路线

1. Operational MVP 已完成 C10、CT04/CT04M、FE08/FE10A 与 reference-profile I02A；
   current official 保持权威，V2 保持 shadow，LangGraph 强绑定与 Context required 链已闭合。
2. PR #159 的 `RSC-CTPROV`、FE06、FE07 已完成正式 reconciliation；S2 的其他验收项继续
   按节点推进，不因这三个任务绿色而整体关闭。
3. 先完成 PR #188 与 LGV2-C/I/B/FE 的逐节点 reconciliation，再以生成后的 Ready Queue
   为准；当前文字摘要不替代机器源、claim、worktree 与独占修改表面规则。
4. R05 只保留 OpenClaw host capability 缺口并保持 blocked；它继续阻塞 Gate B 与正式 S4，
   不回退已验证的 LangGraph Operational MVP。
5. 正式 S5-C、S2 和后续 Stage/Gate 仅在各自剩余验收与证据满足后关闭；当前不作绿色声明。

任何路线变化都必须先修改机器源和 decision，再重新生成并通过校验；不能只改图形位置或
文字说明来绕开真实依赖。
