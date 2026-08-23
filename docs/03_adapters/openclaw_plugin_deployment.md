# OpenClaw 插件部署、安装与配置

## 1. 文档定位

本文记录 AgentGuard OpenClaw 插件的本机开发安装、配置、验证、卸载和故障排查流程。插件设计、Hook 映射和事件语义见 [OpenClaw Security Plugin](openclaw_plugin.md)。

当前流程不依赖 Dashboard；OpenClaw 插件通过 Guard API adapter token 调用后端，审计、完整性和 provenance 由 Guard API 查询验证。

## 2. 前置条件

本机开发安装默认使用以下组件：

- OpenClaw `2026.7.1-2` 是当前语义证据 pin；`2026.6.6` 仅为历史 23-hook 基线，不满足当前 24-hook 验收。插件 peer range 为 `>=2026.6.6 <2027.0.0`，但允许安装不等于逐版本、逐平台实测。Gateway 默认监听 `127.0.0.1:18789`。
- 仓库根目录可运行 `pnpm` 和 `uv`。
- Guard API 可连接 PostgreSQL，并通过 `/health?check_db=true` 检查数据库。
- OpenClaw 本机 profile 允许执行插件安装、config patch、persisted plugin registry refresh 和 Gateway safe restart。

基础检查：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
openclaw gateway status
```

## 3. `.env` 配置

仓库根目录 `.env` 提供 Guard API 和 OpenClaw 插件安装所需配置。`.env` 已被 `.gitignore` 忽略，不应提交。

最小配置：

```dotenv
AGENTGUARD_DATABASE_URL=postgresql+psycopg://postgres:<password>@127.0.0.1:5432/agent_guard
AGENTGUARD_ADAPTER_TOKEN=agt_xxx
AGENTGUARD_CONTROL_TOKEN=ag_control_xxx
AGENTGUARD_HOST=127.0.0.1
AGENTGUARD_PORT=8088
```

OpenClaw 插件安装脚本读取：

- `AGENTGUARD_ADAPTER_TOKEN`：必填。缺失或为空时安装失败，避免向 OpenClaw profile 写入空 token。
- `AGENTGUARD_HOST`：可选，默认 `127.0.0.1`。
- `AGENTGUARD_PORT`：可选，默认 `8088`。

安装脚本把 `AGENTGUARD_ADAPTER_TOKEN` 写入 `.openclaw-dev/secrets/openclaw-adapter-token`，目录权限为 `0700`、文件权限为 `0600`；OpenClaw 主配置只保存 file SecretRef 和 provider 路径。token 用于插件调用 Guard API 的 `Authorization: Bearer <token>` header，不写入仓库、OpenClaw 主配置、审计事件、metadata、错误消息或日志。

Windows 上凭证策略不同：OpenClaw 的 file secret provider 在无法可靠校验文件 ACL 时会 fail-closed 拒绝加载（Windows 没有 POSIX 0600 权限语义），因此安装脚本改用 env provider：token 写入 OpenClaw state 目录下的 `.env`（键 `AGENTGUARD_OPENCLAW_ADAPTER_TOKEN`），`secrets.providers` 配置 `source: "env"` 且 allowlist 只含该键。这是明文保管的折中方案，不宣称加密保管；该 state `.env` 应视为敏感文件，卸载时会删除该键。后续可接入 DPAPI 或 Windows Credential Manager 的 exec provider 替换，SecretRef 接口契约不变。

## 4. Guard API 启动与检查

启动 Guard API：

```bash
pnpm guard-api:dev
```

首次安装前，在另一个已加载 `.env` 的终端为 OpenClaw `main` agent 签发凭证，并把只显示一次的 `agt_...` token 写入本机 `.env`：

```bash
uv run agentguardctl credential issue --runtime openclaw --agent-id main
```

Guard API 只保存 token hash；不要复用 LangGraph 或其他 OpenClaw agent 的 token。

或直接运行：

```bash
set -a
. ./.env
set +a
uv run uvicorn guard_api.main:app --host 127.0.0.1 --port 8088
```

检查 API 和数据库：

```bash
curl -s "http://127.0.0.1:8088/health?check_db=true"
```

预期结果应显示服务健康，并且数据库检查正常。若使用非默认 host 或 port，以 `.env` 中的 `AGENTGUARD_HOST`、`AGENTGUARD_PORT` 为准。

## 5. 开发安装

正式开发安装使用 repo-local ignored staging：

```text
.openclaw-dev/agentguard-security
```

安装命令：

```bash
pnpm openclaw:plugin:install
```

该命令会执行（事务化流程，任一步失败按基线整体回滚）：

1. 预检：token 非空，`pnpm` 与 `openclaw` 可解析。
2. 备份当前 OpenClaw config 到 `.openclaw-dev/backups/`，记录基线。
3. `pnpm --filter @agentguard-ai/openclaw-plugin build`。
4. 在临时目录构建校验完整后，原子切换 `.openclaw-dev/agentguard-security`（只含 `dist/`、`openclaw.plugin.json`、`package.json`、`README.md`）。
5. 凭证准备：POSIX 写 `0600` secret 文件；Windows 写 state 目录 `.env`（见第 3 节）。
6. 单一 config patch：先 `openclaw config patch --file <patch> --dry-run --json` 校验，成功后才写入；patch 覆盖 secrets provider、`plugins.load.paths`、插件 entry（enabled、Guard API URL、SecretRef、`hooks.allowConversationAccess=true`），不触碰无关配置。
7. `openclaw plugins registry --refresh`。
8. 仅在显式隔离 profile 且未指定 `--no-restart` 时执行 `openclaw gateway restart --safe` 并轮询健康；否则提示用户自行重启。
9. 成功后清理保留的旧 staging。

流程不再使用 `openclaw plugins install -l` / `--link`（插件通过 `plugins.load.paths` + registry 加载）；失败回滚时恢复基线 config 与旧 staging，并报告原始错误与回滚结果。

安装器的配置策略与插件 manifest 的无配置 fallback 必须区分：

- 新 profile 由安装器写入 `requestTimeoutMs=60000`、`approvalTimeoutMs=600000` 和
  `hooks.timeoutMs=600000`；插件文档中的 5,000/25,000 ms 是未经过安装器接线时的
  runtime fallback，不是产品安装默认值。
- 重装采用 merge：保留已有的 runtime、hooks 和无关配置，只刷新 AgentGuard 的
  staging/load path、SecretRef、Guard API URL、enabled/enforcement 等接线键；不会用新安装
  默认值静默覆盖维护者已有超时。
- `verify` 要求 `hooks.timeoutMs >= approvalTimeoutMs`。已有配置不满足时明确失败并要求
  维护者修正，不在验证阶段修改配置。

不要直接从 `packages/agentguard-openclaw-plugin` 安装。pnpm workspace 包目录可能包含 `node_modules` symlink，会被 OpenClaw local install safety scan 拦截。

## 6. 验证

首选通过 AgentGuard CLI 验证：

```bash
uv run agentguardctl openclaw verify
```

该命令只封装现有 OpenClaw 插件验证脚本，不重写 runtime 检查逻辑，不负责安装或卸载插件。

等价底层命令：

```bash
pnpm openclaw:plugin:verify
```

该命令会执行 `openclaw plugins inspect agentguard-security --runtime --json` 并采用多证据口径。除下述受限回退外，任一证据缺失即失败：

- 证据 1：`plugin.status=loaded`、`plugin.hookCount=24`、24 hooks 集合完整、`plugin.source` 或 `plugin.rootDir` 指向 `.openclaw-dev/agentguard-security`、diagnostics 不包含 `allowConversationAccess=true` 缺失导致的 hook block。
- 证据 2：`openclaw gateway status` 的 `Connectivity probe: ok`（Runtime 允许 unknown，如 Windows 任务计划不可查询；仅 stopped/failed 等明确异常态才失败）。
- 证据 3：Guard API 收到新鲜 heartbeat（晚于本次验证开始时刻）。
- 证据 4：插件 entry `enforcementMode=enforce`，且 `openclaw --version` 解析的版本落在插件 peer range 内。

隔离 Gateway 尚未触发 hook 时，宿主 inspect 可能暂时返回 `hookCount=0`。此时 verify 只允许用本次启动后收到的、scope 匹配的新鲜 heartbeat 补足 hook 集合证据，并在结果中标记 `hook_evidence_source=heartbeat-fallback`；该回退是插件自报证据，不等同于宿主 inspect 实证，也不能掩盖其他失败。

必须存在的 hooks：

```text
before_tool_call
after_tool_call
message_sending
before_install
message_received
before_prompt_build
before_agent_run
llm_input
llm_output
tool_result_persist
before_message_write
before_agent_finalize
gateway_start
gateway_stop
session_start
session_end
before_compaction
after_compaction
subagent_spawned
subagent_ended
model_call_started
model_call_ended
cron_changed
resolve_exec_env
```

需要人工复查时可直接运行：

```bash
uv run agentguardctl openclaw verify
openclaw plugins inspect agentguard-security --runtime --json
openclaw gateway status
```

## 7. E2E 验收

Guard API 和插件安装验证通过后，运行 repo 内确定性 E2E runner：

```bash
pnpm openclaw:plugin:e2e
```

该命令会构建插件并执行 `scripts/openclaw-e2e-runner.mjs`。runner 自动读取根 `.env`，要求 `AGENTGUARD_ADAPTER_TOKEN` 和 `AGENTGUARD_CONTROL_TOKEN` 可用，并默认连接 `http://${AGENTGUARD_HOST:-127.0.0.1}:${AGENTGUARD_PORT:-8088}`。

覆盖 hooks：

- `before_tool_call`
- `message_sending`
- `before_prompt_build`
- `before_agent_run`
- `llm_input`
- `llm_output`
- `before_agent_finalize`
- `before_install`
- `tool_result_persist`
- `session_start`

输出文件：

```text
<系统临时目录>/agentguard-openclaw-e2e-report.json
<系统临时目录>/agentguard-openclaw-e2e-acceptance-report.md
```

验收重点：

- `ok=true`
- OpenClaw audit events 包含 `tool_call_proposed`、`context_assembled`、`model_input_prepared`、`model_output_produced`、`message_send_proposed`、`config_audit`、`tool_result_produced` 和 `runtime_observation`
- audit integrity `valid=true`
- provenance 至少包含 `event`、`decision` 和 `audit` 节点

全 Hook 可靠性验收使用独立测试库，要求 `.env` 中存在
`AGENTGUARD_TEST_DATABASE_URL`，且数据库名为 `agent_guard_test` 或以
`_test` 结尾：

```bash
pnpm openclaw:plugin:reliability
```

该命令会构建插件、重置测试库控制平面表、启动指向测试库的 Guard
API、复核 OpenClaw runtime 插件加载状态，并触发 24 个 hook 各 50 次，
共 1,200 条预期主审计事件；干预回执 `runtime_outcome` 单独存在，不冒充或覆盖每个 hook 的主事件。若 `127.0.0.1:8088` 已有 Guard API 监听，runner 会直接停止，避免误写开发库。

输出文件：

```text
<系统临时目录>/agentguard-openclaw-reliability-report.json
<系统临时目录>/agentguard-openclaw-reliability-acceptance-report.md
```

验收重点：

- `ok=true`
- `missing_traces=[]`、`duplicate_trace_ids=[]`、`non_openclaw_count=0`
- 主审计事件计数符合 `tool_call_proposed=50`、
  `model_input_prepared=50`、`model_output_produced=50`、
  `message_send_proposed=50`、`config_audit=50`、
  `tool_result_produced=50`、`runtime_observation=900`
- adapter status 显示 `loaded=true`、`hook_count=24`、
  `expected_hook_count=24`
- audit integrity `valid=true`
- 阻断型 hook：`before_tool_call` 返回 `block=true`，
  `message_sending` 返回 `cancel=true`，`before_install` 返回 `block=true`，
  `before_agent_run` 返回 `decision.outcome=block`

`openclaw:plugin:e2e` 和 `openclaw:plugin:reliability` 会把摘要写入
`/v1/adapters/openclaw/status` 的 `capabilities.release_gates`，用于后续发布前查询。

## 8. 卸载与回滚

卸载开发安装：

```bash
pnpm openclaw:plugin:uninstall
```

该命令会：

- 备份当前 OpenClaw config 到 `.openclaw-dev/backups/`
- 通过单一 config patch（dry-run 先行）只移除 AgentGuard 自有引用：删除 `plugins.entries.agentguard-security`、删除 `secrets.providers.agentguard_adapter`、从 `plugins.load.paths` 移除 AgentGuard staging 路径与旧临时路径；不触碰无关配置，不再执行 `openclaw plugins uninstall --force`
- 删除本地 adapter token：POSIX 删 `0600` secret 文件；Windows 删 state 目录 `.env` 中的 `AGENTGUARD_OPENCLAW_ADAPTER_TOKEN` 键
- 刷新 OpenClaw persisted plugin registry
- 仅在显式隔离 profile 且未指定 `--no-restart` 时重启 Gateway 并等待健康

默认保留 `.openclaw-dev/agentguard-security`，便于复查和快速重装。需要同时删除 staging：

```bash
pnpm openclaw:plugin:uninstall -- --clean-staging
```

卸载后再运行：

```bash
pnpm openclaw:plugin:verify
```

预期应失败并提示 `Plugin not found: agentguard-security` 或插件未加载。

## 9. 真实运行时兼容验收（当前手动）

当前 `.github/workflows/ci.yml` 运行插件单元测试和跨语言契约测试，但**没有** `openclaw-runtime-smoke` job，也没有 ubuntu/windows × OpenClaw 版本矩阵。以下脚本是维护者在隔离环境中手动执行的真实运行时验收；未保存对应版本、平台和提交的报告前，不得把它表述为自动 CI 覆盖：

1. 在工作区外的临时目录安装指定版本 OpenClaw（`npm install --prefix <ephemeral-run-dir>/openclaw-<version>`）；缓存策略由执行环境自行管理，不作为验收证据。
2. 由操作者提供隔离 PostgreSQL `agent_guard_test` 测试库；Guard API 使用随机端口前台启动，adapter 凭证由 control token 现签发。
3. `scripts/openclaw-runtime-smoke.mjs` 驱动：隔离 profile（临时目录，禁止指向真实 `~/.openclaw`）→ 事务化安装 → 随机端口真实前台 Gateway（持久化随机 auth token 供 CLI RPC）→ 新鲜 heartbeat（loaded、24 hooks，由 Guard API 实证）→ 安装器 verify 多证据口径 → uninstall 与残留检查（config fragment 清空、staging 删除、state `.env` token 键删除）。
4. 隔离 Gateway 中 `plugins inspect` 的 hookCount 需 hooks 被 agent runtime 实际触发后才上报；若暂时为 0，smoke 可回退到 Guard API 收到的 scope-matched 新鲜 heartbeat（loaded、hook_count=24）。这是插件自报的补充证据，不等同于宿主 inspect 实证；其余 verify 失败仍为硬门禁，回退会如实记录在报告 `installer-verify` 阶段中。
5. 输出脱敏 JSON 报告与 Gateway 日志；报告由执行者人工归档，当前 workflow 不会自动上传。

本机隔离干跑（不触碰真实 profile 与用户真实 Gateway）：

```bash
node scripts/openclaw-runtime-smoke.mjs --openclaw-root <工作区外的 openclaw 安装根目录> --expect-version 2026.7.1-2
```

可用 `AGENTGUARD_OPENCLAW_ROOT` 环境变量代替 `--openclaw-root`；`scripts/openclaw-e2e-runner.mjs` 的插件加载也支持同一覆盖，并对 `dist/plugins/hook-runner-global.js` 做存在性探测，缺失时明确报错。本机无 Guard API 测试库时可用 `--skip-guard-api` 只验证到隔离 Gateway 中插件 loaded/24 hooks。

脚本包含 Windows 与 POSIX 差异处理：`.cmd` shim 解析为 `node + 入口 JS`（不走 shell）、env provider 凭证策略、全局 prefix 安装时 shim 位于 prefix 根目录的 bin 探测。只有在对应平台实际执行并归档成功报告后，才可声明该平台已覆盖。

## 10. 故障排查

### runtime 仍指向旧临时 staging

OpenClaw 2026.6.6 会优先使用 persisted plugin registry。若旧 registry 仍记录 `<ephemeral-run-dir>/agentguard-openclaw-plugin-install-p2*`，同 ID 插件可能覆盖 `.openclaw-dev/agentguard-security`。

处理方式：

```bash
openclaw plugins registry --refresh
pnpm openclaw:plugin:verify
```

正常状态下，`plugin.source` 应指向：

```text
<repo>/.openclaw-dev/agentguard-security/dist/index.js
```

### conversation hooks 被 runtime 拦截

`before_agent_run`、`llm_input`、`llm_output` 和 `before_agent_finalize` 读取 conversation 内容。非 bundled 插件必须在 OpenClaw config 里显式配置：

```json
{
  "plugins": {
    "entries": {
      "agentguard-security": {
        "hooks": {
          "allowConversationAccess": true
        }
      }
    }
  }
}
```

`pnpm openclaw:plugin:install` 会自动写入该配置。若 `pnpm openclaw:plugin:verify`
仍显示缺少上述 hooks，先运行安装脚本刷新配置和 registry，再复查
`openclaw plugins inspect agentguard-security --runtime --json` 里的 diagnostics。

### install safety scan 拦截

不要安装 workspace 包目录：

```bash
openclaw plugins install -l packages/agentguard-openclaw-plugin
```

应使用：

```bash
pnpm openclaw:plugin:install
```

### `openclaw plugins validate` 报 metadata 缺失

OpenClaw 2026.6.6 的 `openclaw plugins validate --root ... --entry ...` 面向 `defineToolPlugin` simple tool plugin。当前 AgentGuard 插件是 hook-only `definePluginEntry`，因此可能返回：

```text
plugin entry does not expose defineToolPlugin metadata
```

这不是当前插件的失败标准。hook-only 插件以 runtime inspect、Gateway status 和 hook runner/E2E 验收作为真实验证依据。

### Gateway restart 短暂 1006

`openclaw gateway restart --safe` 过程中可能短暂返回 `gateway closed (1006 abnormal closure)`。安装脚本会继续轮询 `openclaw gateway status`，只要最终 `Runtime: running` 且 `Connectivity probe: ok` 即可。

## 11. E2E 复查入口

手动 E2E runner 会在系统临时目录生成瞬时报告：

```text
<系统临时目录>/agentguard-openclaw-e2e-acceptance-report.md
```

该文件只代表当次本机运行，未绑定 commit SHA、OpenClaw 版本、平台和校验值时不能称为“最近一次真实证据”。当前语义证据 pin 为 OpenClaw `2026.7.1-2`；要形成可引用证据，必须在隔离环境重跑，并连同 commit、平台、配置边界和报告校验值归档。runner 覆盖 `before_tool_call`、`message_sending`、`before_agent_run`、`before_agent_finalize`、`before_install`、`tool_result_persist`、观察型 hooks、audit integrity 和 provenance。
