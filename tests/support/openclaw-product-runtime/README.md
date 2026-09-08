# 隔离 Product runtime 验收支持

此目录包含真实 SQLite 记忆工具、本机 HTTP 消息渠道及 OpenClaw 工具清单预检。
它是验收支持代码，不进入 AgentGuard 产品包，也不导入 benchmark。

## 清单预检

先构建插件，再显式指定已安装的 OpenClaw `2026.7.1-2` package 根目录或 npm prefix：

```bash
pnpm --filter @agentguard-ai/openclaw-plugin build
node scripts/product-runtime-inventory.mjs \
  --openclaw-root /absolute/path/to/openclaw \
  --output /absolute/path/to/new-inventory-report.json
```

预检创建独立状态和 workspace，启动仅监听 `127.0.0.1` 的受控模型端点，
通过真实 `openclaw agent --local` 第一轮请求捕获模型可见工具 schema。
它与 pinned SDK 工具 descriptor 和原生 `tools.effective` handler 的投影交叉核对，
再用冻结契约生成四项 inventory digest。`tools.effective` 当前在进程内调用，
不能声称验证了 Gateway RPC 传输。

八个工具必须与 [fixtures.json](fixtures.json) 精确匹配，参数必须符合真实 schema。
预检不执行 fixture 动作、不调用外部 Provider，也不连接 Guard API。
命令工具在该阶段被 Host 配置为 deny；受控 completion 只返回文本。
报告和私密诊断文件使用 `0600`，临时 profile 在退出时删除，已有输出不会覆盖。

此处 `PASS` 只证明清单前置成立；不是 V2.1 official 激活、执行回执、
Gateway wire、真实 Qwen、canary 或 Internal RC 的通过证据。整体执行约定见
[双运行时实施计划](../../../docs/06_delivery/product_runtime_implementation_plan.md)。

## Product 消息渠道的可信装配入口

默认导出的插件仍是 B01 非 Product 清单/本机工具 fixture。Product 装配必须从受保护的
Host 插件入口模块导入 `createFixturePlugin` 和 `createMessagePermitBridge`，将同一个
bridge 对象同时交给动作 coordinator 与 `createFixturePlugin({ productMode: true,
messagePermitBridge: bridge })`。该 factory 返回真实 Host loader 所需的 `register(api)`
插件对象；缺少真实 bridge 会在注册任何工具或渠道前失败。`productMode` 和 bridge
不属于插件 JSON 配置，也不能由模型参数或全局 Symbol 注入。

coordinator 在动作门禁释放后调用 `bridge.authorize(released)`；released 必须包含实际
`runId/toolCallId/sessionKey/toolName/argumentsJson/actionId`，以及实时的 `assertCanSend`、
异步核验当前会话观察的 `assertReadyToSend` 和只记录关联的 `onMessageDelivered`。
渠道的 `actions.prepareSendPayload` 核对 pinned
Host 自动生成的 idempotency key、完整文本与固定目标，生成进程内一次性 nonce。
`outbound.sendPayload` 在实际 loopback HTTP 发送前消耗 nonce，并重新核对 coordinator
状态与当前 ACK 观察。dispatch 回调前后均重新核验；Product 的 `sendText` 入口始终拒绝。
改写、异会话、重启或 Host 队列重放不能恢复许可。
实际 HTTP 发送使用校验时冻结的完整文本和目标。

渠道返回的 messageId 仅用于关联，不能代替真实 `after_tool_call` 终态，也不声明 C3。
B07 的 SDK factory/渠道测试不等于模型 agent loop、官方激活或最终候选资格；完整可信装配
和原生模型链仍由后续批次验证。

## 独立验证

```bash
pnpm product-runtime:test
node packages/agentguard-openclaw-plugin/test/product-inventory.test.mjs
```

SQLite/HTTP 测试使用真实本地存储和 loopback 连接；不会读取 `.env`、个人 OpenClaw
配置或向真实收件人发送消息。Host discovery 只应实例化工具，不写入记忆或发信。
