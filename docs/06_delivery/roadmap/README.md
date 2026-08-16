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

当前 `origin/dev@f435bff` 快照：

- 绿色：B0、CORE C00–C09、CT00/01/02A/02B/03A/03B、RTE01–04、R05P、
  Native-ID/C2/R05 Freeze Gates、FE00–FE04、S0、S1；
- 琥珀色：`I01`（`codex/gate-a-int-pr-01`）、正式 `R05`
  （`codex/rte-05-integration`）以及控制面 bootstrap `RM-00`
  （`codex/roadmap-control`）；
- 蓝色：`RSC-CT01`、`CT05`、可选 `CT03R`；
- 灰色：Gate A、CT04、C10、S2 及其后续。

I01 与 R05 的独立代码可并行，但两者声明的 evaluation/production activation 共享表面
必须由 integration owner 串行收口；Gate A、RTE-05 Integration 和 Gate B 均未因此通过。
需要关闭其中一个节点时，integration owner 先 `block` 暂停另一个并释放共享表面，完成
串行合入和 `close` 后再 `resume`；不得绕过资源冲突直接宣称完成。

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
不得混称。

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

## 5. 最快并行路线

1. S1 已进入基线；并行推进 I01、R05P，并 claim RSC-CT01、CT05；有资源时做 CT03R。
2. RSC-CT01 后分成 `RSC-CTPROV→FE06/07→S2` 与 `I01→Gate A` 两支；R05、CT05
   同时继续。
3. Gate A 后 C10、CT04、S3 并行；C10+R05 后立即 I02A→Gate B。
4. Gate B 后最大并行 C11/C12、CT04M/S5-C、CT06、I03、R06、R07、I04、I02B
   和 FE08/S4；共享 activation 仍串行集成。
5. S5 与 Stateful Rollout Gate 汇合 Competition S6；C13→Semantic Gate→C14 单独汇合
   Full Master Final，不拖慢 Competition 关键路径。

任何路线变化都必须先修改机器源和 decision，再重新生成并通过校验；不能只改图形位置或
文字说明来绕开真实依赖。
