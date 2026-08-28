# 安装、升级和故障排查

本文是产品化入口页。完整环境变量和部署细节见[部署、安装与使用说明](deployment_install_usage.md)，支持版本见[兼容矩阵](compatibility_matrix.md)。

## 1. 干净 clone 开发安装

```bash
git clone https://github.com/JToday666/agent-guard.git
cd agent-guard
uv sync --locked --all-groups
pnpm install --frozen-lockfile
cp .env.example .env
```

先运行不需要数据库或外部服务的最小示例：

```bash
uv run python examples/evaluate_events.py examples/events/benign-read.json
uv run python examples/evaluate_events.py examples/events/blocked-sensitive-read.json
```

两条命令分别应输出 `allow` 和 `deny`。示例不访问网络、不写副作用、不依赖 `.openclaw-dev` 或系统临时目录。

## 2. 本地 Control Plane

创建独立 PostgreSQL 数据库并在 `.env` 配置：

```dotenv
AGENTGUARD_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard
AGENTGUARD_TEST_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard_test
AGENTGUARD_CONTROL_TOKEN=<本地非默认强随机值>
AGENTGUARD_EVIDENCE_CONTENT_PREVIEW_ENABLED=false
```

输出证据预览默认关闭。只有完成数据分级和访问范围评审后才应显式启用；启用后服务端也只
投影脱敏、限长的模型输出/待发送消息预览，模型输入永不投影。Dashboard 轮询可用
`VITE_EVIDENCE_POLL_INTERVAL_MS` 配置，默认 10 秒、下限 2 秒，并在页面隐藏或 Trace
进入明确终态时停止。

终端 A 加载配置并启动 Guard API（前台进程）：

```bash
set -a
. ./.env
set +a
pnpm guard-api:dev
```

终端 B 同样加载配置，再启动 Dashboard：

```bash
set -a
. ./.env
set +a
pnpm dashboard:dev
```

终端 C 加载 `.env`，检查数据库并生成一次性 Dashboard 登录地址：

```bash
set -a
. ./.env
set +a
uv run agentguardctl health --check-db
uv run agentguardctl launch
```

## 3. 升级

升级前：

1. 阅读 [`CHANGELOG.md`](../../CHANGELOG.md) 的 breaking change、known limitation 和 migration 说明。
2. 备份 PostgreSQL，并保留数据库外审计检查点。
3. 停止 Guard API 与 runtime 写入；不要让新旧版本并行写入。
4. 在隔离测试库先运行 migration 和 PostgreSQL 测试。

源码安装升级。分支和 tag 不能使用同一条 switch 命令；根据目标二选一：

```bash
git fetch --prune origin
git fetch --tags origin
# 已有本地分支：
git switch <目标分支>
git merge --ff-only origin/<目标分支>
# 或已发布 tag（保持 detached HEAD）：
git switch --detach <目标标签>
uv sync --locked --all-groups
pnpm install --frozen-lockfile
```

随后在已加载 `.env` 的终端只启动一个 Guard API 实例，使其执行当前 migration。再在另一个已加载 `.env` 的终端执行以下检查；确认通过后才恢复其他实例和 runtime：

```bash
set -a
. ./.env
set +a
uv run agentguardctl health --check-db
curl --fail --silent http://127.0.0.1:8088/v1/audit/integrity \
  -H "Authorization: Bearer ${AGENTGUARD_CONTROL_TOKEN}"
```

若 migration 或审计完整性失败，保持停写，使用备份恢复并记录错误；不要手工修改 `alembic_version` 或重算证据来绕过失败。

## 4. 测试入口

```bash
uv run pytest -q -m unit
uv run pytest -q -m contract
uv run pytest -q -m integration
uv run pytest -q -m e2e
AGENTGUARD_TEST_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard_test \
  uv run pytest -q -m postgres
pnpm --filter @agentguard/dashboard build
pnpm --filter @agentguard/dashboard test:e2e
```

`live` 测试只允许显式手动运行；它可能需要已构建插件、真实宿主或 Provider 凭据，不能作为普通 PR 的隐式依赖。

## 5. 常见故障

### `uv sync --locked` 报锁文件变化

确认 Python/uv 版本和工作区文件未被局部工具改写。普通安装不要使用会更新 lockfile 的命令；依赖变更应单独提交并说明根 `uv.lock` 与 `apps/guard-api/uv.lock` 两个 Python lockfile 的影响。

### PostgreSQL 测试被跳过

设置 `AGENTGUARD_TEST_DATABASE_URL`，并确保数据库名为 `agent_guard_test` 或以 `_test` 结尾。测试会清理 schema，绝不能指向开发库或生产库。

### migration 失败

确认连接账号拥有目标 schema 的迁移权限、没有旧实例继续写入，并检查 `/v1/audit/integrity`。审计链迁移发现已有损坏时会拒绝继续，这是预期的 fail-closed 行为。

### Dashboard 无法登录或 `401/403`

`agentguardctl launch` 只生成一次性地址，不启动 Dashboard。先运行 `pnpm dashboard:dev`。CLI 使用 control token；Adapter 使用绑定 runtime/agent 的 adapter credential，不可混用。

### Playwright 找不到 Chromium

```bash
pnpm --filter @agentguard/dashboard exec playwright install chromium
```

Linux CI/容器还可能需要：

```bash
pnpm --filter @agentguard/dashboard exec playwright install-deps chromium
```

### OpenClaw hook 数量不一致

先区分制品和源码基线：公开 `v0.1.0-beta.1` 是 22 个 hook 名；23-hook 只存在于历史中间
源码/证据；当前未发布源码契约要求 24 个唯一 hook 名。插件入口实际注册 25 个 handler，
因为 `after_tool_call` 同时注册通用 observation 和 terminal closure handler。先构建并运行
插件测试，再执行 verify：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin build
pnpm --filter @agentguard-ai/openclaw-plugin test
pnpm openclaw:plugin:verify
```

OC-02 的宿主能力限制不会因 24 个 hook 名/25 个 handler 已注册而解除：当前宿主仍缺少
原子 replace-and-seal 与权威 invocation-start。详见
[Productization Alpha Status](productization_alpha_status.md)。
