# Product Active 的完整启动入口

该入口用于固定隔离 profile 的 Core V2.1 official 执行。适用判定必须是
`source=v21 / mode=active / selection_basis=profile_all`。启动成功表示本地组合与
服务端 ACK 已就绪，最终闭环验收仍须执行
[双运行时验收计划](../06_delivery/product_runtime_implementation_plan.md)。

默认配置不启用 Product 执行。候选身份要求 Python `0.1.0rc1` 和 OpenClaw
`0.1.0-rc.1`；旧 beta 制品、editable 安装以及测试的 synthetic
admission 不构成正式候选证据。候选必须由最终固定 `dev` SHA 构建并干净安装。

## LangGraph

使用独立 `native` extra 的真实 StateGraph 入口：

```python
import os

from agentguard_langgraph_adapter import AgentGuardLangGraphConfig, LangGraphAdapter
from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph

config = AgentGuardLangGraphConfig(
    core_base_url=guard_api_url,
    token=os.environ["AGENTGUARD_LANGGRAPH_TOKEN"],
    agent_id=agent_id,
    runtime_binding_id=runtime_binding_id,
    api_mode="guard-api-v0.3",
    context_isolation_mode="required",
    runtime_receipt_mode="required",
    product_execution_enabled=True,
    product_manifest_path=activation_manifest_path,
    product_adapter_wheel_path=adapter_wheel_path,
    product_receipt_directory=receipt_directory,
    product_receipt_key_path=receipt_key_path,
)
adapter = LangGraphAdapter(config=config)
graph = build_native_product_graph(
    adapter=adapter,
    model=model,
    tools=isolated_tools,
    provider=provider_id,
    model_name=model_id,
)
try:
    graph.start()
    status = graph.snapshot()
    result = graph.invoke(sources=sources, security=security, trace_id=trace_id)
finally:
    graph.close()
```

`adapter` 的配置必须显式设置 `product_execution_enabled=True`，并提供
`product_manifest_path`、`product_adapter_wheel_path`、
`product_receipt_directory`、`product_receipt_key_path` 及已绑定身份的真实 Guard API
连接。wheel 保存于受保护目录，摘要必须与 activation 清单一致；实际安装文件、
RECORD、加载来源和七类消费者也要通过检查。

使用 pip 安装时设置 `--no-compile`；uv 安装保持 `UV_COMPILE_BYTECODE=0`，
运行进程设置 `PYTHONDONTWRITEBYTECODE=1`。候选包目录内的
旧 bytecode 不满足源码执行验证要求。完整入口独占对应 ACK 会话和执行权限；已有的
transport 会话、任意 callback 或仅设置配置标志不能获得副作用执行权限。

## OpenClaw

发布包内的 `product-runtime/profile.mjs` 提供 `createProductRuntimeProfile`。
创建参数为独立的 `root`、本机 `inboxUrl`、Provider 配置和未来的
`runManifestPath`。Provider 凭据采用环境变量 SecretRef。profile 工厂创建受保护的目录、
配置和唯一允许的命令 `node marker.mjs`；实际插件工厂注册 SQLite 工具和本机消息渠道。
命令脚本、运行目录和执行文件均受完整性检查。

`root` 必须是当前用户拥有的独立绝对路径，目录权限为 `0700`；`inboxUrl` 指向已启动的
本机测试收件端。Provider 参数形状如下，`baseUrl` 在正式验收时指向统一计数出口：

```javascript
const provider = {
  id: "agentguard-acceptance",
  modelId: "qwen3.7-plus",
  baseUrl: budgetGatewayUrl,
  apiKey: { source: "env", provider: "default", id: "AGENTGUARD_MODEL_TOKEN" },
};
```

Product 消息仅接受 `fixture-inbox@agentguard.invalid`，由本机渠道投递到固定的
loopback `inboxUrl`，没有邮件或 DNS 投递。工具语义为 `isolated-product-tools-2`；
旧目标和旧语义清单均不能用于 Product 启动。策略允许 `agentguard.invalid` 域时，
Core 可直接 ALLOW；默认外发策略要求 ASK；明确的拒绝策略返回 DENY。三者均由
签署前固定的真实 PolicyBundle 决定，不能通过更换 ACK 或运行中改策略绕过审批。

调用 `start()` 前，专用运行进程必须提供三项环境凭据：profile 中
`provider.apiKey.id` 指定的模型凭据、run manifest 中 `adapterTokenRef.id`
指定的适配器凭据，以及固定名称 `AGENTGUARD_PRODUCT_GATEWAY_TOKEN` 对应的
隔离运行 token。缺失凭据会阻断启动；profile 创建和 `inspect` 阶段不读取它们。

`start()` 在本地解析模型与 Gateway 的 env SecretRef，仅写入公开 SDK 的内存
runtime snapshot。受保护配置文件仍保留 SecretRef，凭据正文不写回文件或日志；
该流程不连接默认个人 Gateway，也不要求先启动 Gateway 服务。

正式启动使用已安装包的公开入口：

```javascript
import { createOpenClawProductRuntime } from "@agentguard-ai/openclaw-plugin/dist/runtime/product-composition.js";

const runtime = await createOpenClawProductRuntime({ runManifestPath });
try {
  await runtime.start();
  const status = runtime.snapshot();
  await runtime.run();
} finally {
  await runtime.close();
}
```

run manifest 是权限为 `0600`、父目录为 `0700` 的规范 JSON 文件，使用以下字段：

| 字段                                               | 作用                                                |
| -------------------------------------------------- | --------------------------------------------------- |
| `schemaVersion`                                    | 固定为 `1`                                          |
| `activationManifestPath`                           | 受保护的 activation 身份与预期摘要清单              |
| `candidateTgzPath`                                 | 实际已安装候选的原始 tgz，权限 `0600`               |
| `profileConfigPath`                                | 隔离 profile 的 OpenClaw 配置路径                   |
| `guardApiBaseUrl`                                  | 真实 Guard API 地址                                 |
| `adapterTokenRef`                                  | `{source:"env", provider:"default", id:"ENV_NAME"}` |
| `taskId`、`scopeDigest`、`taskText`、`traceId`     | 真实任务及 scope 的绑定信息                         |
| `productReceiptDirectory`、`productReceiptKeyPath` | 独立持久队列与分离密钥路径                          |

完整工厂复用 OpenClaw `2026.7.1-2` 自身的完整 registry 加载入口，在模型请求前核验
实际插件、来源、hook、middleware、消息桥、工具清单和 tgz 安装字节，然后取得 ACK。
该加载入口属于 pinned Host 的内部接口，使用固定版本、安装来源和入口文件摘要校验；
升级 Host 必须重新核验这一绑定，不能静默选择其他入口。真实工具工厂和 schema
采集继续使用公开 SDK。
`run()` 经过真实 `agentCommand`，单次顺序执行。直接运行旧插件或复制 Product JSON
标志不能替代完整工厂。

`inspectOpenClawProductRuntime({profileConfigPath, candidateTgzPath})` 用于签署前采集
实际安装和宿主材料。其报告固定 `active=false`，不发行 ACK、不调用模型；存在已启动
的 Product 会话时拒绝再次 `inspect` 或 `create`。完成 `close()` 后须关闭该专用进程，
再启动新的专用进程重新采集；同进程的 Host registry 会保留已关闭的组合实例。
签署时必须同时验证 conformance 和其他候选证据。`snapshot().modelAttempts` 是进入本地模型
边界的次数；外部 Provider 请求预算必须在 HTTP 出口另外统计，包含所有重试。

## 就绪和恢复

两个真实运行时均完成 `start()` 和 ACK 检查后才开始双运行时验收。工具、能力、身份、
activation 或本地安装漂移都会阻断新动作。LangGraph 所需的 invocation-start 回执、
OpenClaw ASK 所需的 approval-release 回执，分别必须获得服务端确认后才能执行。
终态回执没有确认时阻断后续副作用，重启后只补投保存的原始 payload 和历史 ACK。
永久拒绝的记录须使用[回执定向补投](product_runtime_receipt_recovery.md)显式选择，
完成确认后仍保留动作熔断。

模型生成的记忆不会因一次审批或写入成功而成为可信内容；控制面保留 unknown 或
quarantined 状态。继承工具输出污点的记忆写入按冻结覆盖规则阻断；读取受限记忆时，
原始内容仍须经过隔离检查，不能以宿主读取成功作为允许进入模型的依据。

OpenClaw 保持 restricted allow_once、`C3=false`、`CF-13=NOT_SUPPORTED` 和五项残余
边界。gate/release 记录不冒充权威 invocation-start；实际 after/middleware 回调才提供
宿主终态证据。执行中断而结果未知时保留未知状态，不自动重执行工具。
