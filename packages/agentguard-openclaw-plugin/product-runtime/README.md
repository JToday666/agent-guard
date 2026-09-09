# 隔离 Product 运行资产

此目录随 `@agentguard-ai/openclaw-plugin` 的 tgz 交付。测试与 inventory collector
也使用这些工具、SQLite 和 loopback channel；生产代码不导入 `tests/support`。

`profile.mjs` 的 `createProductRuntimeProfile` 创建全新的私有 Host 状态目录。
输入为 `root`、`inboxUrl`、`provider` 和未来的 `runManifestPath`。Provider 固定
`id=agentguard-acceptance`、`api=openai-completions`，凭据采用
`{source:"env",provider:"default",id:"ENV_NAME"}`。Gateway token 使用
`AGENTGUARD_PRODUCT_GATEWAY_TOKEN` 环境引用。工厂不读取这些凭据、不请求模型，
也不签发 ACK。`loadProductRuntimeProfileSync` 可在实际插件注册时重新读取 profile；
启动身份和签署清单由完整 Product 组合核验。

`factory.mjs` 的 `createProductFixturePlugin({profile,messagePermitBridge})`
接收同一组合创建的许可桥，返回真实工具/channel 插件及 full registration witness。
工具描述和执行函数保存在冻结蓝本中；稳定工厂每次返回新的浅拷贝，供真实 Host
安装执行 scope wrapper。注册见证仍绑定原工厂、schema 和执行函数。
实际安全组合位于 `product/`；默认插件及 `baseline/` 保留非 Product 行为。
只创建这些资源不能取得 Product 执行许可。

Product SQLite 读返回完整 `{key,value}`，缺失键固定失败；写仅允许新增键，
事务内拒绝覆盖。内容来源、信任和隔离仍由原 ACK/回执与服务端 MemoryFact 决定。
明确的 baseline 继续使用原 `found` 读结果和 UPSERT，双方共享存储实现和工具 schema。

真实 Host exec 仅预配置 `node marker.mjs` 的 exact-command 允许规则，使用公开 SDK
写入该 profile 的 `exec-approvals.json`。不存在 Node 通配授权。Node 和 `/bin/sh`
解析后的路径、完整文件摘要、包内 marker、受保护配置和命令策略都绑定到资产见证。
`assertProductRuntimeAssets(profile)` 在 release 前复核；只允许 Host 的合法
`lastUsedAt`、原命令 `lastUsedCommand`、真实 Node `lastResolvedPath` 及原子文件替换，
不忽略策略变化。实际会话还须核对完整 `profile.env`，拒绝代码注入环境变量。

消息仅送到字面 loopback HTTP inbox；一次许可绑定真实会话、run/toolCall ID、
完整原参数、目标和正文。dispatch 前后复核同一许可及当前会话。Release 不证明
invocation-start，未知结果不得重执行，OpenClaw 的 C3 残余边界保持不变。
