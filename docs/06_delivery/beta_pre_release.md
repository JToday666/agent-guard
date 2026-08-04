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

## 本地预发布检查

先验证版本映射：

```bash
uv run python scripts/check-release-versions.py
uv run python scripts/check-release-versions.py --tag v0.1.0-beta.1
```

构建 Python 制品：

```bash
uv build packages/agentguard-core --out-dir release-dist/agentguard-core
uv build apps/guard-api --out-dir release-dist/agentguard-api
uv build apps/cli --out-dir release-dist/agentguard-cli
uv build packages/agentguard-meta --out-dir release-dist/agentguard
uvx twine check release-dist/*/*
uv run python scripts/verify-wheel-install.py release-dist
uv run python scripts/check-release-artifacts.py release-dist
```

构建 npm tarball 和容器：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin test
pnpm --filter @agentguard-ai/openclaw-plugin pack --pack-destination release-dist/npm
node scripts/verify-npm-tarball.mjs
docker build -f apps/guard-api/Dockerfile -t agentguard-api:0.1.0-beta.1 .
```

`.github/workflows/pre-release-check.yml` 只做验证，不上传任何制品。它覆盖
Windows、Ubuntu、Python 3.12、Node 24.18、pnpm 11.9、PostgreSQL、Python
制品、npm tarball和容器构建。

## PyPI 首次发布配置

四个项目都可使用 [PyPI Pending Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
完成首次创建。每个项目分别
填写：

```text
Owner:            JToday666
Repository:       agent-guard
Workflow:         publish-beta.yml
Environment:      pypi
```

项目名依次为 `agentguard-core`、`agentguard-api`、`agentguard-cli`、
`agentguard`。Pending Publisher 只允许指定工作流通过 OIDC 创建项目；它不会在
第一次发布前保留名称，因此打 tag 前仍需再次检查名称可用性。TestPyPI 与 PyPI
相互独立，也不能代替正式名称占用。

GitHub 中建立受保护 Environment `pypi`，配置 required reviewers。工作流按
Core → API → CLI → meta 顺序进入同一个审批环境并发布，不需要长期 PyPI token。

## npm 首次发布配置

[npm Trusted Publisher](https://docs.npmjs.com/trusted-publishers/) 只能绑定已经存在的包。因此
`@agentguard-ai/openclaw-plugin@0.1.0-beta.1` 第一次发布必须由 scope 管理员在
本地完成，启用 npm 2FA，并先检查 tarball：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin pack --pack-destination release-dist/npm
npm publish release-dist/npm/agentguard-ai-openclaw-plugin-0.1.0-beta.1.tgz --access public --tag beta
```

首次发布成功后，在 npm 包设置中绑定 GitHub Actions Trusted Publisher：

```text
Owner:            JToday666
Repository:       agent-guard
Workflow:         publish-beta.yml
Environment:      npm
```

随后建立受保护 Environment `npm`，配置 required reviewers，并设置仓库变量
`NPM_TRUSTED_PUBLISHING_READY=true`。在此变量就绪前，发布工作流会明确跳过 npm
步骤，不会尝试使用临时 token。OIDC 发布使用 Node 24 自带的 npm CLI 11.5.1+
执行 `npm publish`；pnpm 继续负责依赖、构建、测试和打包。绑定成功后撤销所有
临时发布凭证。

## GHCR 与最终触发

按 [GitHub deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
建立受保护 Environment `ghcr` 并配置 required reviewers。GHCR 使用最小权限
`GITHUB_TOKEN`，发布 `0.1.0-beta.1` 与不可变的 `sha-<commit>` 标签，同时生成
SBOM 和 provenance；不需要单独的 registry 密钥。

所有权、Pending Publisher、npm 首次发布和三个 Environment 审批都确认后，才
创建并推送最终 tag：

```bash
git tag -a v0.1.0-beta.1 -m "AgentGuard 0.1.0 Beta 1"
git push origin v0.1.0-beta.1
```

推送该 tag 会触发 `.github/workflows/publish-beta.yml`。本次前置实施不创建 tag，
也不执行 PyPI、npm 或 GHCR 上传。
