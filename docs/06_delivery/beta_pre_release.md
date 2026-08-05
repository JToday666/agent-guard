# AgentGuard 0.1.0 Beta 1 发布记录与复现说明

> 发布状态：PyPI、npm 与 Git tag 已发布；Guard API 容器与 GHCR 延期
> 发布日期：2026-08-05
> 许可证：MIT

## 发布物与版本

本次 Beta 已按以下版本映射发布：

```text
Git tag:                 v0.1.0-beta.1（已发布）
Python:                  0.1.0b1（已发布）
npm / OpenClaw:          0.1.0-beta.1（已发布）
GHCR:                    未发布
```

公开注册表中的发布物：

| 注册表 | 包 | 版本 | 状态 |
| ------ | -- | ---- | ---- |
| PyPI | [`aegis-agentguard`](https://pypi.org/project/aegis-agentguard/)、[`aegis-agentguard-core`](https://pypi.org/project/aegis-agentguard-core/)、[`aegis-agentguard-api`](https://pypi.org/project/aegis-agentguard-api/)、[`aegis-agentguard-cli`](https://pypi.org/project/aegis-agentguard-cli/) | `0.1.0b1` | 2026-08-05 已发布；每个项目均包含 wheel 和 sdist |
| npm | [`@agentguard-ai/openclaw-plugin`](https://www.npmjs.com/package/@agentguard-ai/openclaw-plugin) | `0.1.0-beta.1` | 2026-08-05 已发布；`latest` 与 `beta` 均指向该版本 |

上述日期使用注册表记录的 UTC 上传日期，不记录容易产生时区歧义的本地时刻。

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

## 当前发布边界

截至 2026-08-05，仓库没有配置 CI/CD，也不会在 PR、push 或 tag 时自动检查或
发布。本次 PyPI、npm 和 Git tag 由发布负责人在本地完成；以下命令用于复现构建和
验证，不代表仓库已经具备自动发布能力。

Guard API 镜像构建和 GHCR 发布仍未完成，不属于本次 Python/npm Beta 发布物。

Trusted Publishing、自动制品构建、SBOM、provenance 和远端审批门禁均未配置，
不能作为当前发布的已有保障。任何 registry 凭证、token、`.env` 或本地测试结果
都不得提交。

## 本地发布复现检查

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

## Guard API 容器与 GHCR 延期

本轮没有发布 Guard API 镜像，也不把 Docker/GHCR 验证追溯为 Python/npm Beta 的
既有保障。仓库已经提供使用发布 wheel 的多阶段 Dockerfile、非 root 运行配置和
healthcheck，但完整镜像构建、PostgreSQL 迁移、公开 manifest 读取和 GHCR 发布仍需
在后续容器交付任务中单独验证。

## 已完成发布记录与后续要求

本次发布已按 Core → API → CLI → 主包 → npm 的顺序完成：

- PyPI 四个项目均已存在，版本为 `0.1.0b1`。
- npm 包已存在，版本为 `0.1.0-beta.1`。
- Git tag `v0.1.0-beta.1` 已存在并指向本次 Beta 源码。

后续发布继续要求所有本地检查通过、制品摘要经复核，且发布凭证只存在于本机凭证
存储或进程环境中。不得根据本次手工发布推断自动发布、供应链签名或远端审批已经
配置完成。

当前 tag 只形成 Git 引用；仓库没有 tag 触发的自动发布流程。创建后续 tag 前必须
重新完成版本、制品和注册表检查。
