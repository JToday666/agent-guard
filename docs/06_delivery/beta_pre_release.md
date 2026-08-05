# AgentGuard 0.1.0 Beta 1 预发布说明

## 发布物与版本

本次 Beta 固定使用以下映射：

```text
Git tag:                 v0.1.0-beta.1
Python:                  0.1.0b1
npm / OpenClaw / GHCR:   0.1.0-beta.1
```

公开安装入口：

```bash
pip install --pre agentguard
pip install agentguardctl==0.1.0b1
pip install "agentguard[api]==0.1.0b1"
pip install "agentguard[cli]==0.1.0b1"
pip install "agentguard[all]==0.1.0b1"

npm install @agentguard-ai/openclaw-plugin@beta
openclaw plugins install @agentguard-ai/openclaw-plugin@beta

docker pull ghcr.io/jtoday666/agentguard-api:0.1.0-beta.1
```

`agentguard` 是安装入口元包，默认只依赖 `agentguard-core`。它不提供顶层
`agentguard` Python 模块；公开 import 仍为：

```python
import agentguard_core
import guard_api
import agentguard_cli
```

## 当前阶段边界

仓库当前不配置 CI/CD，也不在 PR、push 或 tag 时自动检查或发布。所有验证均由
发布负责人在本地执行并保存结果；实际 PyPI、npm、GHCR 上传和最终 tag 不属于
本次预发布前置工作。

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
uv run ruff check apps/cli apps/guard-api packages/agentguard-core packages/agentguard-meta scripts/check-release-artifacts.py scripts/check-release-versions.py scripts/verify-wheel-install.py tests/test_agentguard_cli.py tests/test_core_engine.py tests/test_core_extended_capabilities.py tests/test_core_rule_matrix.py tests/test_guard_api.py tests/test_guard_api_extended_capabilities.py tests/test_openclaw_plugin_contract.py tests/test_release_versions.py tests/test_schemas.py
uv run black --check apps/cli/agentguard_cli apps/guard-api/guard_api packages/agentguard-core/agentguard_core scripts/check-release-artifacts.py scripts/check-release-versions.py scripts/verify-wheel-install.py tests/test_agentguard_cli.py tests/test_core_rule_matrix.py tests/test_openclaw_plugin_contract.py tests/test_release_versions.py
uv run pyright apps/cli/agentguard_cli apps/guard-api/guard_api packages/agentguard-core/agentguard_core
uv run pytest tests/test_core_engine.py tests/test_core_extended_capabilities.py tests/test_core_rule_matrix.py tests/test_guard_api.py tests/test_guard_api_dashboard_capabilities.py tests/test_guard_api_extended_capabilities.py tests/test_agentguard_cli.py tests/test_schemas.py tests/test_release_versions.py tests/test_openclaw_plugin_contract.py
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
uv build packages/agentguard-core --out-dir release-dist/agentguard-core
uv build apps/guard-api --out-dir release-dist/agentguard-api
uv build apps/cli --out-dir release-dist/agentguardctl
uv build packages/agentguard-meta --out-dir release-dist/agentguard
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
- `agentguard` 元包不提供顶层 `agentguard` import package。
- npm tarball 可在空目录安装并加载插件。
- 制品不包含 `.env`、凭证、Dashboard、LangGraph、benchmark、测试结果或本地路径。

## Guard API 容器验证

Python wheel 构建完成后创建本地镜像：

```bash
docker build -f apps/guard-api/Dockerfile -t agentguard-api:0.1.0-beta.1 .
docker image inspect agentguard-api:0.1.0-beta.1 --format "{{.Config.User}}"
docker run --rm -e AGENTGUARD_STORAGE_BACKEND=memory -p 8088:8088 agentguard-api:0.1.0-beta.1
```

镜像用户应为 `agentguard:agentguard`，启动后 `/health` 应返回正常状态。正式发布前
还需使用独立 PostgreSQL 测试库验证迁移和 `/health?check_db=true`。

## 首次发布准备

发布顺序固定为 Core → API → CLI → meta → npm → GHCR。开始上传前必须确认：

- PyPI 上 `agentguard-core`、`agentguard-api`、`agentguardctl` 和 `agentguard` 名称可用。
- npm scope 管理员已启用 2FA，并确认 `@agentguard-ai/openclaw-plugin` 所有权。
- 所有本地检查均通过，制品摘要已由团队成员复核。
- 发布凭证只存在于本机凭证存储或进程环境中，不写入仓库。

当前阶段不创建 `v0.1.0-beta.1` tag，也不上传任何 registry。后续即使推送该 tag，
也只会形成 Git 引用，不会自动发布制品。
