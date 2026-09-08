# AgentGuard OpenClaw Plugin

`@agentguard-ai/openclaw-plugin` 是 AgentGuard 的 OpenClaw runtime security plugin。它是 hook-only `definePluginEntry` 插件，不提供业务工具本身；插件负责在 OpenClaw 关键 hook 中构造 GuardEvent、调用 Guard API，并把 `allow`、`deny`、`ask` 映射为运行时控制结果。

## Hook 覆盖

默认启用 24 个 hook（RTE-03 新增 `after_tool_call`）：

```text
before_tool_call
after_tool_call
message_sending
before_install
before_agent_run
before_prompt_build
llm_input
llm_output
tool_result_persist
message_received
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

固定执行且宿主 runner fail-closed 的阶段（heartbeat 只声明这些阶段）：

```text
before_tool_call
before_install
before_agent_run
before_agent_finalize
tool_result_persist
before_message_write
```

`before_agent_run` 是 OpenClaw 正式支持的模型输入 gate；`before_prompt_build`、`llm_input` 和 `llm_output` 是观察 hook，不再返回 SDK 不支持的伪 `block`。`before_agent_finalize` 可要求安全重写，最终外发仍由 `message_sending` 取消。插件在 `message_sending` 内把 Guard API 的 bounded 错误捕获为明确 `cancel`，但 OpenClaw 对未被插件捕获的 handler 异常/宿主 timeout 采用 fail-open，因此 heartbeat 不把该阶段声明为宿主 fail-closed。`tool_result_persist` 和 `before_message_write` 是同步 hook，只执行本地脱敏、清洗或隔离；远端结果评估异步写入证据，不伪装成同步远端裁决。工具消息在进入下一次模型调用前，会在 `before_agent_run` 作为不可信上下文再次评估。

RTE-03 terminal outcome closure：`before_tool_call` 在返回前同步写入 GateState 与 policy linkage；`after_tool_call`（观察型，不进 fail-closed 清单）对已放行调用产 `execution_completed/failed` runtime_outcome 回执。两条硬安全约束：blocked/timed_out/binding_failed gate 下 after hook 到达只记诊断、绝不派生 terminal fact（pin `openclaw@2026.7.1-2` 已证明 blocked 调用也会触发 after hook，Q9）；成败只能用非空 `error` 字符串判定，不得依赖 result/error 字段存在性（falsy 成功两者皆无，Q5）。回执中 `tool_result_entered_context/persisted` 保持 null，`side_effects` 一律 not_measured。

其他生命周期观察 hook 只记录审计；Guard API 不可用时不阻断 OpenClaw 基础生命周期。

## 配置

OpenClaw plugin config 示例：

```json
{
  "guardApiBaseUrl": "http://127.0.0.1:8088",
  "adapterToken": {
    "source": "file",
    "provider": "agentguard_adapter",
    "id": "value"
  },
  "agentId": "main",
  "enforcementMode": "enforce",
  "requestTimeoutMs": 60000,
  "approvalPollIntervalMs": 1000,
  "approvalTimeoutMs": 600000,
  "strongApprovalBindingEnabled": false,
  "runtimeBindingId": "binding:cred_openclaw_main",
  "diagnosticLogging": false
}
```

`adapterToken` 只接受 OpenClaw SecretRef，OpenClaw 在插件注册前把它解析为字符串；明文 token 和插件内环境变量回退均不再支持。SecretRef provider 需在 OpenClaw 的 `secrets.providers` 中配置。仓库开发安装脚本会把根 `.env` 中的 token 写入权限为 `0600` 的 `.openclaw-dev/secrets/openclaw-adapter-token`，并配置 file SecretRef，token 不进入 OpenClaw 主配置。

`agentId` 必须与 `agentguardctl credential issue --runtime openclaw --agent-id <id>` 签发时绑定的 agent 一致。`runtimeBindingId` 是与该 credential principal 一起可信下发的 `binding:<principal_id>`，不得从 evaluate 响应或工具参数学习；服务端一旦声明 execution lease，缺失或不匹配会在等待/consume 前 fail closed。`strongApprovalBindingEnabled` 已弃用，保留旧配置兼容，默认 `false`；它仅启用历史 canary 处理，不代表 Strong Binding。当前 OpenClaw hook API 无法在最终调用边界原子地 replace-and-seal 参数/消息，因此 heartbeat 的 C3 始终保持 false。插件会在 consume 前后复验完整 action snapshot，在成功时返回批准内容的深拷贝，并以最低安全整数优先级尽量成为最后修改 hook；同优先级或更低优先级的其他插件仍是明确的残余信任边界。`approvalTimeoutMs` 是审批等待与 consume 重试共享的唯一 deadline；每个 Guard API 请求的 `requestTimeoutMs` 同时覆盖 headers 和有界 body 读取/解析，JSON 响应最大 1 MiB，停滞、超限或无效响应均在插件内安全分类。409/410 不重试，网络、429、5xx/503 仅以完全相同请求在 deadline 内有界重试。插件只保留 lease/consumption ID，明文 lease token 在响应解析栈内验证后丢弃。读取对话内容的 hook 需要 `hooks.allowConversationAccess=true`，开发安装脚本会写入该设置。

### V2.1 Product ACK 传输（产品启动仍关闭）

已接入受保护本地清单、Product heartbeat、ACK 会话、evaluate/consume 请求头和历史 receipt carrier。传输只接受 `source=v21 / mode=active / selection_basis=profile_all`；响应身份来自本地清单的预期值，不从服务端输出反推。显式配置 official profile 仍在插件注册前拒绝，直到七事件消费者、加密持久投递和熔断完整接通。当前实际包仍是 `0.1.0-beta.1`，真实版本检查会在 HTTP 前拒绝 Product 握手。

| 字段 | 默认与约束 |
| --- | --- |
| `officialProfileId` | 未配置为空；仅接受 `agentguard-openclaw-v2-restricted`，当前注册限制保留 |
| `officialProfileDigest` | 与 profile ID 成对配置，小写 `sha256:` + 64 位摘要 |
| `productManifestPath` | 显式提供绝对路径；规范 JSON、文件 `0600`、父目录 `0700`，校验所有者、链接和变更 |
| `productReceiptDirectory` | Product 回执必需的绝对路径；独立 `0700` 加密队列 |
| `productReceiptKeyPath` | 与队列路径成对提供；队列之外的独立 `0600` 密钥，父目录 `0700` |
| `restrictedAskReleaseEnabled` | 默认 `false`；当前配置 `true` 直接拒绝插件注册 |
| `activationAckMaxAgeMs` | 默认 `120000`；`1..120000` 的整数，服务端更短 expiry 优先 |

profile 还要求可信非空 `runtimeBindingId`、`agentId` 和 `enforcementMode=enforce`。旧 `strongApprovalBindingEnabled` 与任一新字段同时显式出现都会失败，包括显式 `false`。迁移字段不设置 Host schema defaults，避免注入虚假的配置冲突。

`GuardApiClient.startProductSession(observe)` 从本地清单加载身份和四类 inventory 预期，独立 observer 提供实际安装版本、能力和清单观察值；使用既有 heartbeat 接口。默认每 30 秒刷新，单次并发请求，ACK 最长 120 秒。`refreshProductAck`、`snapshotProductAck`、`closeProductSession` 管理会话；身份、版本、清单或 activation 漂移后阻断新动作。

`evaluateProductEvent` 保存不可变 ACK；审批后的 `consumeProductExecutionLease` 刷新一次并固定请求体和 ACK，重复调用保留原消费结果。历史回执使用 evaluate 或 consume 当时的 ACK，关闭/刷新会话后仍通过原传输发送；普通 JSON、日志和 correlation state 不带 ACK token，只有显式 `runtimeOutcomeToWire` 才生成完整传输载体。旧明文 spool 明确拒绝 Product 回执。Product 的 `submitRuntimeOutcome` 已接入独立加密队列，缺少路径或写盘失败会返回失败，不会直接发送。

Node 与真实 Guard API 的 HTTP 契约测试使用实际构建的 SDK 和 pinned Host 包，测试专用副本采用合成 RC metadata；不修改生产版本检查，不构成候选签署、真实宿主副作用或 Product Active 验收。OpenClaw 保持 restricted allow_once、五项残余边界、`C3=false` 和 `CF-13=NOT_SUPPORTED`。

### Product 加密持久回执

`GuardApiClient.openProductDelivery()` 从受保护清单读取稳定的 runtime、agent、principal 和 binding 身份，打开独立队列并启动补投。`submitProductReceipt(receipt)` 返回明确的投递状态；兼容的 `submitRuntimeOutcome(receipt)` 只有在 `recorded` 时返回 `ok:true`，并附带 `delivery_status`。原始 payload 在异步初始化之前固定，后续调用者修改对象不会改变已提交证据。

| 状态 | 含义与动作边界 |
| --- | --- |
| `recorded` | 服务端返回 `ok:true` 且 audit ID 精确匹配 |
| `queued_durable` | 原字节已持久化，网络、408/429/5xx 按有界退避补投；不等于服务端确认 |
| `permanent_rejected` | 包括 409/422 的永久拒绝保留原记录，并打开 breaker |
| `failed` | 写盘、解密、内容冲突、格式或确认错误；阻断新动作 |

`delivery.status()` 仅返回计数和固定错误码；`delivery.drain()` 尝试已到重试时刻的记录。ACK 会话关闭不影响历史补投；结束队列时另外调用 `closeProductDelivery()`。每次 HTTP 尝试使用原 endpoint、token 和原 wire，禁止重定向，不添加当前 ACK header，也不重建实时授权 handle。历史 reader 检查原 ACK 的结构与发行窗口；HMAC、原 policy/lease 的时间和授权归属仍由既有 Guard API 校验，不能因为当前过期而丢弃。

存储使用 Node 内置 [AES-GCM](https://nodejs.org/docs/latest-v24.x/api/crypto.html#class-cipheriv)：32-byte 独立密钥、每次写入随机 12-byte nonce、完整认证标签、绑定稳定身份和记录 revision 的 AAD。加密 envelope 为 `0600`，写入和原子替换均 fsync；密钥不在队列目录内。回执、动作、breaker 和完成 tombstone 共同计入 10,000 条、单条 512 KiB、总计 64 MiB，大小按实际编码文件计算，并预留一条最大 envelope 的原子替换空间。完成 tombstone 不自动清理，避免重复动作重新获得权限；不声称抵抗整个受保护目录的跨进程回滚。

本轮存储针对 Linux 固定隔离 profile，使用 [抽象 Unix socket](https://nodejs.org/docs/latest-v24.x/api/net.html#ipc-support) 保证单进程所有权，并将 boot ID、network namespace 和队列 inode 固定在私有 owner anchor 中。进程退出后内核释放锁，同一 boot/namespace 的进程重启可以补投。主机重启、切换 namespace 或复制队列到其他 inode 会拒绝自动恢复；禁止删除、改写 anchor 或抢占已有锁来绕过此约束。其他平台不能启用这个 Product 存储。

`prepareAction` / `releaseAction` 只持久记录 gate 与交回宿主的许可，不生成 invocation-start HTTP。`finishAction` 接收实际 after hook 的终态并先持久化；终态未确认期间不能释放下个动作。没有 after 的记录在重启后保持 unknown 并打开 breaker，恢复不生成 ticket、不重新执行工具。真实 hook 接线属于后续动作链批次，当前插件注册仍关闭。

旧 `RuntimeOutcomeDelivery` 已修复负确认或错误 audit ID 导致删除的问题，永久失败会保留并停止自动重试。旧 hook 的写盘回退和 `receiptQueued` 状态还不具备 Product 保证，将在动作链接线时处理；Product 回执不能进入旧队列。

## Windows 支持

Windows 上安装脚本使用 env provider 而非 file provider：OpenClaw 的 file secret provider 在无法可靠校验文件 ACL 时会 fail-closed 拒绝加载（Windows 没有 POSIX 0600 权限语义），导致插件无法注册。作为折中，安装脚本把 adapter token 写入 OpenClaw state 目录下的 `.env`（键 `AGENTGUARD_OPENCLAW_ADAPTER_TOKEN`），并在 `secrets.providers` 中配置 `source: "env"` 且 allowlist 只含该键。

必须明确的边界：

- 这是明文保管的折中方案，仅缓解「token 进入 OpenClaw 主配置 / 审计事件 / 日志」的问题，不宣称加密保管。
- state `.env` 与仓库根 `.env` 一样应被视为敏感文件；卸载时会删除该键。
- 后续可接入 DPAPI 或 Windows Credential Manager 的 exec provider 替换 env provider，接口契约（SecretRef）不变。

安装、卸载与 verify 的口径与 POSIX 一致：config patch dry-run 先行、失败按基线整体回滚、卸载只移除 AgentGuard 自有引用；不再使用 `openclaw plugins install --link`。当前 CI 没有真实 OpenClaw runtime 的 ubuntu/windows 矩阵；跨平台验收仍需按下文脚本在隔离环境中手动执行并归档报告。

## 运行时版本兼容

`package.json` 的 peer range 为 `openclaw >=2026.6.6 <2027.0.0`，这是允许安装的声明范围，不表示范围内每个版本都已实测。开发/证据 pin 自 PR-RTE-02 rev5 起为 `2026.7.1-2`（C2 Gate PASS 的证据版本）。当前版本证据边界为：

- `2026.6.6`：历史 23-hook 基线，不满足当前 24-hook 验收要求，也不是 RTE-03 的证据锚点。
- `2026.7.1-2`：`after_tool_call` 语义和 24-hook 实现的当前证据 pin；真实 runtime 报告仍按具体提交和平台单独记录。

`.github/workflows/ci.yml` 目前只自动执行插件测试和契约检查，不代表上述 peer range 已逐版本、逐平台实测。新增兼容版本时必须更新证据 pin、隔离 runtime 报告和本文档；恢复自动 smoke 矩阵前不得宣称该矩阵已覆盖。

## 验证

在仓库根目录运行：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin build
pnpm --filter @agentguard-ai/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
```

开发安装、验证、E2E、reliability 和卸载：

```bash
pnpm openclaw:plugin:install
pnpm openclaw:plugin:verify
pnpm openclaw:plugin:e2e
pnpm openclaw:plugin:reliability
pnpm openclaw:plugin:uninstall
```

`pnpm openclaw:plugin:verify` 采用多证据口径：`plugins inspect`（loaded、24 hooks、staging 指向）、Gateway RPC 连通、Guard API 新鲜 heartbeat、enforce 模式与版本范围一致性。唯一受限例外是隔离 Gateway 尚未触发 hook 时，inspect 的空 hook 集可由本次启动后、scope 匹配的新鲜 heartbeat 补足，并显式标记 `hook_evidence_source=heartbeat-fallback`；这是插件自报证据，不等同于宿主 inspect 实证，其他失败仍会 fail closed。

真实运行时兼容验收由 `scripts/openclaw-runtime-smoke.mjs` 驱动：工作区外安装指定版本 OpenClaw → 隔离 profile 事务化安装 → 随机端口真实前台 Gateway → 新鲜 heartbeat（loaded、24 hooks）→ 安装器 verify → 卸载与残留检查，输出脱敏 JSON 报告。该脚本当前不是 CI job；本机隔离干跑示例：

```bash
node scripts/openclaw-runtime-smoke.mjs --openclaw-root <工作区外的 openclaw 安装根目录> --expect-version 2026.7.1-2
```

干跑只使用临时目录中的隔离 profile 与 `_test` 库，严禁指向真实 `~/.openclaw` profile 或用户正在运行的 Gateway。

`pnpm openclaw:plugin:e2e` 会读取根 `.env`，触发关键 hook，并在系统临时目录输出 `agentguard-openclaw-e2e-report.json` 和 `agentguard-openclaw-e2e-acceptance-report.md`。

`pnpm openclaw:plugin:reliability` 会对注册 hook 做重复触发，使用隔离 PostgreSQL 测试库，并在系统临时目录输出 `agentguard-openclaw-reliability-report.json` 和 `agentguard-openclaw-reliability-acceptance-report.md`。

## 验收口径

`openclaw plugins validate` 主要验证 simple tool plugin metadata。当前包是 hook-only plugin，如果该命令提示缺少 tool-plugin metadata，不应单独判定为失败。有效验收应以以下证据为准：

- `pnpm openclaw:plugin:verify` 成功。
- OpenClaw runtime inspect 能看到 `agentguard-security` 已加载。
- Guard API 收到 heartbeat、审计事件和 runtime adapter 状态。
- `before_tool_call`、`message_sending`、`before_install` 和 `before_agent_run` 能返回 SDK 正式支持的阻断结果。
- `before_agent_finalize` 在策略拒绝或 Guard API 不可用时请求一次安全重写，`message_sending` 作为最终外发阻断面。
- 同步持久化 hook 能完成本地脱敏/隔离，工具结果远端评估及下一次模型输入 gate 均有审计证据。
- Dashboard 或 CLI 能查询到 OpenClaw 相关 audit、trace 和 provenance 数据。

## 边界

- 插件不保存 Dashboard browser session。
- 插件使用 adapter token，不使用 control token。
- 插件不修改 AgentGuard Core 规则，不直接写数据库。
- 插件不替代 OpenClaw 自身权限、沙箱、配置审计和安全扫描。
