# AgentGuard 仓库治理收口记录

- 收口日期：2026-08-28
- Roadmap 重建提交：`892b4a485211092dfe9f88cfb1594aa21e6f5f53`
- 外部恢复包：`/home/today/dev/agent-guard-governance-archive/2026-08-28-892b4a4/`
- 状态：历史分支、worktree 与未提交工作已完成可恢复保全及清理；历史文档已归档或移除，现行文档入口已收敛。功能冻结解除评审仍按 [`CONTRIBUTING.md`](../../CONTRIBUTING.md) 执行。

## 范围与结论

本次收口处理 Roadmap 重建前遗留的历史分支、linked worktree、stash、诊断产物及远端分支。恢复副本存放在仓库外，当前 Git 树中不保留归档副本、兼容 stub 或恢复制品。

收口后的活动 Git 表面为：

- 本地分支只保留 `main`、`dev`。
- linked worktree 只保留主工作树 `/home/today/dev/agent-guard`。
- stash 为空。
- 远端保留 `main`、`dev`，以及受 GitHub repository ruleset `21281596` 保护的只读历史分支 `codex/archive-competition-2026`。
- `origin/HEAD` 继续指向 `origin/dev`。

只读历史分支是平台规则保护下的明确例外，不是活动开发分支、Roadmap 状态来源或发布输入。除该例外外，16 个历史远端分支已删除。

本记录只证明仓库历史工作可恢复和 Git 表面已经收敛，不代表：

- 功能冻结已经解除；
- 产品运行时、安全语义或公共契约发生变化；
- LangGraph 正式全量评测、OpenClaw Strong Binding 或生产发布已经完成；
- 最终候选 SHA 已通过托管 CI 和独立解除冻结评审。

## 恢复制品

| 制品 | SHA-256 | 内容与恢复基线 |
| --- | --- | --- |
| `agent-guard-history.bundle` | `3ce34b521f58f8167a7adef82cc494469d6cd1328e69a4047171d7f8c87c1689` | 51 个 refs；包含清理前的本地分支、远端跟踪 refs、tags、`refs/stash` 与完整可达历史 |
| `LGV2-I-uncommitted.patch` | `03c59179cd17dba1e40181353440f4ea88b0db8f00e51b3e10326a6bfa4d315d` | `codex/LGV2-I-output-observation` 未提交修改；精确基线 `7065ec5a818259fbd10f760053330844f865a9be` |
| `pre-CT05-allocation-stash.patch` | `3137a01cb1b00989f056f1b390d944d07130a91df46002d03ac143237136f8a6` | 原 stash `4f2b545f7cc68f44f1981bedbbab6563a4f6ea43` 的旧 Roadmap claim 修改 |
| `I02A-diagnostic-run_20260817T150852229674Z.tar.gz` | `b8018ea6f20c92c4f6b076aafea2685d9373d33338ec72d9e3f049c4e0386909` | I02A worktree 中被 Git 忽略的 16 个诊断文件；解压目录内容摘要见下文 |

LGV2-I patch 覆盖 6 个已跟踪文件；归档时没有暂存文件或未跟踪文件。它属于历史 competition/evaluation 工作，不应直接应用到当前 `dev`；需要恢复时必须先检出上述精确基线，再进行独立评审。

I02A 诊断目录内容摘要为：

```text
9a85360cb50a8b026010f21816fbdd58e525d3693022d94eef13182f77158f35
```

该摘要不是 tar 文件摘要。它在解压后的 `run_20260817T150852229674Z` 根目录内按下列方式计算，只覆盖普通文件内容及其以 `./` 开头的相对路径：

```bash
export LC_ALL=C.UTF-8
find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum
```

该目录是单例诊断记录：`run_valid=true`、`run_status=blocked`、`llm_request_count=0`，不能作为正式全量评测证据。

## 恢复验证

恢复包在清理前完成以下验证：

1. 四个制品均计算并记录 SHA-256。
2. `git bundle verify agent-guard-history.bundle` 通过，bundle 报告 51 个 refs、完整历史及 `sha1` 对象格式。
3. 从 bundle 创建临时 clone 成功。
4. 临时 clone 中的 refs 与 bundle 清单可回读，`git fsck --full` 通过。
5. LGV2-I patch 的基线提交存在于 bundle；patch 内容使用 binary/full-index 格式保全。
6. I02A tar 可列出和解压，解压后的 16 个普通文件得到上述目录摘要。

恢复前应先验证制品本身：

```bash
cd /home/today/dev/agent-guard-governance-archive/2026-08-28-892b4a4
sha256sum agent-guard-history.bundle \
  LGV2-I-uncommitted.patch \
  pre-CT05-allocation-stash.patch \
  I02A-diagnostic-run_20260817T150852229674Z.tar.gz
git bundle verify agent-guard-history.bundle
git bundle list-heads agent-guard-history.bundle
```

恢复 LGV2-I 未提交工作时，应在隔离 clone 中执行：

```bash
git checkout --detach 7065ec5a818259fbd10f760053330844f865a9be
git apply --check /home/today/dev/agent-guard-governance-archive/2026-08-28-892b4a4/LGV2-I-uncommitted.patch
git apply /home/today/dev/agent-guard-governance-archive/2026-08-28-892b4a4/LGV2-I-uncommitted.patch
```

不得把恢复成功解释为内容适合重新合并；恢复后的工作仍需依据当前契约、测试和产品/评测边界重新评审。

## 清理记录

### Worktree

以下 7 个 linked worktree 在对应 refs 和非 Git 产物完成保全后移除：

- `I02A-full-corpus-fix`
- `LGV2-ASK-E2E`
- `LGV2-B`
- `LGV2-C-output-observation`
- `LGV2-I`
- `LGV2-I-scope-audit`
- `llm-semantic`

其中 LGV2-I 的未提交修改由独立 patch 保留；I02A 的有效 ignored 诊断目录由独立 tar 保留。其余 ignored 内容仅为 `.venv`、`node_modules`、Python cache 和测试缓存，不进入恢复包。

### 本地分支与 stash

- 清理前 28 个本地分支全部进入 bundle。
- 删除 26 个历史本地分支，只保留 `main`、`dev`。
- 原 stash 同时进入 bundle 并导出独立 patch，验证后从活动仓库删除。
- 由于历史 PR 广泛使用 squash，清理没有把 `git branch --merged` 当作充分证据，而是结合 tip、tree 等价、patch 等价、worktree 状态和外部恢复验证决定处置。

清理前的精确分支名、tip SHA 与远端跟踪 refs 可通过以下命令回读，不在当前仓库重复维护第二份清单：

```bash
git bundle list-heads \
  /home/today/dev/agent-guard-governance-archive/2026-08-28-892b4a4/agent-guard-history.bundle
```

### 远端分支

已删除 16 个历史远端分支；其 tip 均已由 bundle 保全。远端最终保留：

- `main`
- `dev`
- `codex/archive-competition-2026`：受 ruleset `21281596` 保护的只读例外

保留的 archive 分支不得继续承载开发提交。若未来平台治理允许删除，必须先复验外部 bundle 仍可读取、摘要一致且恢复演练通过，再以独立治理变更删除并更新本记录。

## 后续边界

- [`ROADMAP.md`](../../ROADMAP.md) 只管理能力节点、状态和硬依赖，不记录本次 Git 清理为能力节点。
- [`docs/TODO.md`](../TODO.md) 不再保留已经完成的分支、worktree、bundle 和 stash 清理 checklist。
- 长期结构债务和已立项能力的细粒度实施项继续由 TODO 跟踪。
- 功能冻结是否解除只由贡献规范、状态页、最终托管 CI 和独立维护者评审共同决定；本记录不自动改变治理状态。
