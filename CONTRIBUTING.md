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

Productization Alpha 严格冻结新功能。只接受缺陷、安全边界、契约兼容、结构治理、迁移、可观测性、文档和发布工程；恢复功能开发必须在 Alpha 出口后单独评审。仓库继续采用 monorepo，本阶段不拆分多仓库、不发布新版本、不推送制品，也不修改 `main`。

- `packages/agentguard-core` 保持无状态，不访问数据库、网络或 Dashboard。
- Runtime Adapter 只负责事件映射和执行前控制，不复制 Core 策略。
- Guard API 是审批、审计、身份和持久化的唯一 Control Plane。
- Dashboard 只消费 Guard API，不从展示数据反推官方判定。
- `schemas/`、Pydantic 模型、writer 和消费者必须在同一个契约变更中同步。
- `docs/archive/` 只保存历史材料；不得把其中依赖 ignored 文件或临时目录的步骤重新作为产品入口。

涉及路线图节点、冻结契约或独占修改表面的工作，还必须遵守[路线图维护流程](docs/06_delivery/roadmap/README.md)。

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
- `git diff --check`、相关测试、Markdown 相对链接和路线图检查通过。
- 没有提交生成缓存、浏览器产物、临时报告或秘密。

提交信息建议使用 `type(scope): summary`，例如 `fix(api): reject expired approval replay`。合并、发布和推送由维护者完成。
