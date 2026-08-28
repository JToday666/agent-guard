# Contributing to AgentGuard

感谢你参与 AgentGuard。当前主线以可维护、可验证的产品化能力为目标；历史竞赛材料不是新功能的默认设计依据。

## 开始之前

1. 阅读[产品化架构与目录职责](docs/01_overview/productization_architecture.md)和[兼容矩阵](docs/06_delivery/compatibility_matrix.md)。
2. 使用 Python 3.12、Node.js 24.18.0、pnpm 11.9.0；涉及持久化时使用 PostgreSQL 16 独立测试库。
3. 从仓库根目录安装锁定依赖：

   ```bash
   uv sync --locked --all-groups
   pnpm install --frozen-lockfile
   ```

4. 不提交 `.env`、token、数据库口令、真实用户数据、浏览器会话、临时目录或未脱敏的运行报告。

## 变更边界

产品化收口与冻结评审期间继续冻结新功能。只接受缺陷、安全边界、契约兼容、结构治理、迁移、可观测性、测试、文档和发布工程；仓库继续采用 monorepo，本阶段不拆分多仓库、不发布新版本、不推送制品，也不修改 `main`。

- `packages/agentguard-core` 保持无状态，不访问数据库、网络或 Dashboard。
- Runtime Adapter 只负责事件映射和执行前控制，不复制 Core 策略。
- Guard API 是审批、审计、身份和持久化的唯一 Control Plane。
- Dashboard 只消费 Guard API，不从展示数据反推官方判定。
- `schemas/`、Pydantic 模型、writer 和消费者必须在同一个契约变更中同步。
- `docs/archive/` 只保存历史材料；不得把其中依赖 ignored 文件或临时目录的步骤重新作为产品入口。

开发方向和当前焦点见根目录 [`ROADMAP.md`](ROADMAP.md)，细粒度技术待办见 [`docs/TODO.md`](docs/TODO.md)。Roadmap 是人维护的能力路线，通过状态变更记录轻量能力认领，但不负责 owner、worktree 分配、修改锁、evidence 字段或 PR 准入；普通变更按本文和对应契约执行。

解除功能冻结必须同时满足：

1. 历史分支和 worktree 已完成可恢复归档、恢复验证与清理；
2. Roadmap、状态页、TODO 和文档入口已形成一致真值；
3. 产品与 benchmark 边界完成收敛，受支持的 benchmark 测试基线已经明确；
4. workspace、CI 和版本映射在最终候选 SHA 的托管 CI 上通过；
5. 维护者完成独立评审，并同步更新本文和状态页；只有解除冻结同时改变能力路线、优先级或节点范围时，才更新 Roadmap 及其调整记录。

满足技术条件不会自动解除冻结，必须保留上述显式评审记录。

## 轻量能力工作流

Roadmap 的能力节点只记录方向、状态和硬依赖，不代替 Issue、TODO、PR 或维护者判断。节点处于 `可认领` 也不自动授权新功能；任何工作仍须符合上文的变更边界和冻结规则。

当变更对应 Roadmap 中的能力节点时，按以下方式人工维护：

1. **开始实施**：确认节点处于 `可认领`，复核并补齐 [`docs/TODO.md`](docs/TODO.md) 同 ID 小节中的可验证执行项；实际开发开始时将节点改为 `进行中`。
2. **持续实施**：通过普通分支和 PR 交付；一个节点可以由多个独立 PR 完成。每次只勾选已经进入 `dev` 且通过相关检查的 TODO，不把未合并工作写成已有能力。
3. **进入验证**：节点定义的能力结果已经落地、仅剩目标 SHA 上的测试或人工核对时，将状态改为 `验证中`。仍有实现缺口时保持 `进行中`。
4. **完成能力**：相关检查在目标 SHA 上通过后，人工将节点改为 `已完成` 并按 Roadmap 约定移入历史，同时从 TODO 移除已完成清单。状态不会由依赖或 CI 自动推进。

未完成的多 PR 工作宜使用 Draft PR，或在标题、说明中清楚标记 WIP；这类 PR 本身不作为能力完成依据。若中间变更可以独立保持兼容、通过测试且不扩大能力声明，可以作为普通 PR 分批合并，但节点在整体结果完成前保持 `进行中`，不得为展示进度提前进入 `验证中` 或 `已完成`。

为保持 WIP 可读，通常同时处于 `进行中` 或 `验证中` 的能力节点不超过 3 个，短期例外也不得超过 5 个；达到上限时应先收口、暂停或重新排序现有节点。该约定由维护者人工执行，不由脚本或 CI 强制。

缺陷修复、安全修补、依赖更新、文档、测试、CI、兼容迁移和不改变能力路线的内部重构，可以直接通过 TODO 的“不进入能力 DAG 的仓库维护”小节、Issue 或 PR 处理，不必创建能力节点或改变 Roadmap 状态。这个维护旁路只免除 Roadmap 状态流，不免除功能冻结、契约同步、测试和评审要求。

Roadmap 不保存 owner、修改锁、evidence 字段或 Gate；并行协作、验证输出和变更讨论分别留在 PR、CI、状态页或对应契约中。只有能力被新增、拆分、合并、取消、改序，或硬依赖发生变化时，才需要同步修改 Roadmap 路线和调整记录。

## 测试分层

Pytest 使用以下互斥分类：

| Marker | 范围 | 默认 CI |
| --- | --- | --- |
| `unit` | 单模块、无进程/网络/数据库依赖 | 是 |
| `contract` | Schema、冻结契约、跨实现公共行为 | 是 |
| `integration` | 多组件内联集成，不依赖 PostgreSQL 或外部宿主 | 是 |
| `postgres` | 需要 `AGENTGUARD_TEST_DATABASE_URL` 的 migration/存储测试 | 是，独立 PostgreSQL 16 job |
| `e2e` | 本机跨进程或完整应用链路，不访问真实外部 Provider | 是 |
| `live` | 真实宿主、真实 Provider 或显式 opt-in 链路 | 否，仅手动触发 |

现有测试由根 `conftest.py` 兼容归类；新增测试应优先显式声明模块级 marker，例如：

```python
import pytest

pytestmark = pytest.mark.contract
```

模块级 marker 只适用于依赖层级一致的文件。混合 memory/PostgreSQL 参数化测试必须对 PostgreSQL 参数使用 `pytest.param(..., marks=pytest.mark.postgres)`，或拆成独立 PostgreSQL 测试；collection 会拒绝把带 PostgreSQL 参数/fixture 的用例显式标成其他层。本机跨进程用例属于 `e2e`，不能标成 `unit`。

默认 `testpaths` 目前只包含根 `tests/` 与 `packages/agentguard-langgraph-adapter/tests/`。`agentguard_langgraph_bench/bench/tests/` 的旧测试混有浏览器、本地 socket、已移除 fixture 和外部数据依赖，尚未完成六层分类，因而不在自动 Python 矩阵内。任何门禁结果都必须写明这一范围；不得把默认 pytest 结果描述为全仓 benchmark 覆盖。

不得用 `live` 测试结果替代可重复的 unit/contract/integration 覆盖，也不得在自动 CI 中读取开发者本地 `.env`。

常用命令：

```bash
uv run pytest -q -m unit
uv run pytest -q -m contract
uv run pytest -q -m integration
uv run pytest -q -m e2e
uv run python scripts/release/check_markdown_links.py
AGENTGUARD_TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:5432/agent_guard_test \
  uv run pytest -q -m postgres
```

Dashboard 与 Node 工作区：

```bash
pnpm --filter @agentguard/dashboard check
pnpm --filter @agentguard/dashboard test:e2e
pnpm --filter @agentguard/dashboard test:e2e:api
pnpm --filter @agentguard-ai/openclaw-plugin test
pnpm --filter @agentguard/openclaw-bench-tools test
pnpm openclaw:bench-shim:test
```

## Pull request 检查清单

- 变更范围单一，兼容性或迁移影响已写明。
- 新行为有对应测试；失败路径和 fail-closed 路径有覆盖。
- 文档描述的是已验证事实，尚未运行的门禁标为待验证。
- 没有把 Mock、stub、shadow 或沙箱副作用描述成真实生产效果。
- `git diff --check`、相关测试和 Markdown 相对链接检查通过。
- 没有提交生成缓存、浏览器产物、临时报告或秘密。

仅当 PR 对应 Roadmap 能力节点时，还应确认：

- 节点状态与实际进展一致，同 ID 的 TODO 已同步本次可执行项和完成项。
- 未完成的跨 PR 工作保持 `进行中`，并在需要时将 PR 标记为 Draft 或 WIP。
- 只有实现结果已经落地才进入 `验证中`，只有目标 SHA 的相关检查通过才进入 `已完成`。
- 若 PR 改变能力范围、拆分、合并、顺序或硬依赖，Roadmap 和调整记录已在同一变更中更新；否则不必修改 Roadmap。

提交信息建议使用 `type(scope): summary`，例如 `fix(api): reject expired approval replay`。合并、发布和推送由维护者完成。
