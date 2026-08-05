# AgentGuard 0.1.0 Beta 1 预发布说明

## 发布物与版本

本次 Beta 固定使用以下映射：

```text
Git tag:                 v0.1.0-beta.1
Python:                  0.1.0b1
npm / OpenClaw:          0.1.0-beta.1
GHCR（延期）:            0.1.0-beta.1
```

公开安装入口：

```bash
pip install --pre aegis-agentguard
pip install "aegis-agentguard[api]==0.1.0b1"
pip install "aegis-agentguard[cli]==0.1.0b1"
pip install "aegis-agentguard[all]==0.1.0b1"

pip install aegis-agentguard-core==0.1.0b1
pip install aegis-agentguard-api==0.1.0b1
pip install aegis-agentguard-cli==0.1.0b1

npm install @agentguard-ai/openclaw-plugin@beta
openclaw plugins install @agentguard-ai/openclaw-plugin@beta
```

`aegis-agentguard` 是安装入口包，默认只依赖 `aegis-agentguard-core`，并提供稳定门面：

```python
from aegis_agentguard import GuardDecision, GuardEngine, GuardEvent, PolicyBundle, evaluate
```

为避免与第三方项目冲突，本项目不提供顶层 `agentguard` Python 模块。组件级 import 保持为：

```python
import agentguard_core
import guard_api
import agentguard_cli
```

## 当前阶段边界

仓库当前不配置 CI/CD，也不在 PR、push 或 tag 时自动检查或发布。所有验证均由
发布负责人在本地执行并保存结果；实际 PyPI、npm 上传和最终 tag 不属于
本次预发布前置工作。

Docker 构建与 GHCR 发布本轮明确延期，不作为 Python/npm Beta 发布的前置条件。

可信发布绑定、自动制品构建、SBOM、provenance 和远端审批门禁推迟到恢复自动化
发布时再配置。任何 registry 凭证、token、`.env` 或本地测试结果都不得提交。

## 本地预发布检查

先安装冻结依赖并验证版本映射：

```bash
uv sync --frozen
pnpm install --frozen-lockfile
uv run python scripts/check-release-versions.py
uv run python scripts/check-release-versions.py --tag v0.1.0-beta.1
```

运行发布范围的静态检查和测试：

```bash
uv run ruff check apps/cli apps/guard-api packages/agentguard-core packages/agentguard-meta scripts/check-release-artifacts.py scripts/check-release-versions.py scripts/verify-wheel-install.py tests/test_agentguard_cli.py tests/test_core_engine.py tests/test_core_extended_capabilities.py tests/test_core_rule_matrix.py tests/test_guard_api.py tests/test_guard_api_extended_capabilities.py tests/test_openclaw_plugin_contract.py tests/test_package_facade.py tests/test_release_versions.py tests/test_schemas.py
uv run black --check apps/cli/agentguard_cli apps/guard-api/guard_api packages/agentguard-core/agentguard_core packages/agentguard-meta/aegis_agentguard scripts/check-release-artifacts.py scripts/check-release-versions.py scripts/verify-wheel-install.py tests/test_agentguard_cli.py tests/test_core_rule_matrix.py tests/test_openclaw_plugin_contract.py tests/test_package_facade.py tests/test_release_versions.py
uv run pyright apps/cli/agentguard_cli apps/guard-api/guard_api packages/agentguard-core/agentguard_core packages/agentguard-meta/aegis_agentguard
uv run pytest tests/test_core_engine.py tests/test_core_extended_capabilities.py tests/test_core_rule_matrix.py tests/test_guard_api.py tests/test_guard_api_dashboard_capabilities.py tests/test_guard_api_extended_capabilities.py tests/test_agentguard_cli.py tests/test_schemas.py tests/test_package_facade.py tests/test_release_versions.py tests/test_openclaw_plugin_contract.py
pnpm --filter @agentguard-ai/openclaw-plugin build
pnpm --filter @agentguard-ai/openclaw-plugin test
```

PostgreSQL 持久化验证需要将 `AGENTGUARD_TEST_DATABASE_URL` 指向独立测试库；库名
必须为 `agent_guard_test` 或以 `_test` 结尾：

```bash
uv run pytest tests/test_postgres_test_utils.py tests/test_guard_api_postgres.py
```

## 本地制品验证

构建四个 Python 包：

```bash
uv build packages/agentguard-core --out-dir release-dist/aegis-agentguard-core
uv build apps/guard-api --out-dir release-dist/aegis-agentguard-api
uv build apps/cli --out-dir release-dist/aegis-agentguard-cli
uv build packages/agentguard-meta --out-dir release-dist/aegis-agentguard
uvx twine check release-dist/*/*
uv run python scripts/verify-wheel-install.py release-dist
```

构建并验证 OpenClaw npm tarball：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin pack --pack-destination release-dist/npm
node scripts/verify-npm-tarball.mjs
uv run python scripts/check-release-artifacts.py release-dist
```

检查结果必须满足：

- 四个 Python wheel 和 sdist 都能通过 metadata 检查并从空环境安装。
- `aegis-agentguard` 提供 `aegis_agentguard` 稳定门面，但不提供顶层 `agentguard` import package。
- npm tarball 可在空目录安装并加载插件。
- 制品不包含 `.env`、凭证、Dashboard、LangGraph、benchmark、测试结果或本地路径。

## Guard API 容器延期

本轮不构建或发布 Guard API 镜像，也不把 Docker/GHCR 验证作为 Python/npm Beta 的
阻塞条件。现有 Dockerfile 仅同步新的 Python 分发名，容器 healthcheck、PostgreSQL
迁移和 GHCR 发布在后续容器交付任务中单独验证。

## 首次发布准备

发布顺序固定为 Core → API → CLI → 主包 → npm。开始上传前必须确认：

- PyPI 上 `aegis-agentguard-core`、`aegis-agentguard-api`、`aegis-agentguard-cli` 和 `aegis-agentguard` 当前均返回 404。
- npm scope 管理员已启用 2FA，并确认 `@agentguard-ai/openclaw-plugin` 所有权。
- 所有本地检查均通过，制品摘要已由团队成员复核。
- 发布凭证只存在于本机凭证存储或进程环境中，不写入仓库。

PyPI 的 404 不能证明名称一定通过相似项目校验。首次发布必须先只上传
`aegis-agentguard-core` wheel；成功后再上传其 sdist，然后依次发布 API、CLI 和主包。
任一首次上传被拒绝时立即停止，不混用旧分发名。若统一前缀仍被拒绝，整组改用
`aegis-team-agentguard-*` 后重新构建和验证。

当前阶段不创建 `v0.1.0-beta.1` tag，也不上传任何 registry。后续即使推送该 tag，
也只会形成 Git 引用，不会自动发布制品。
