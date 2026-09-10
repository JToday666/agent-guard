# Product 回执的定向补投

恢复入口只读取已有加密队列，向原 Guard API 补投原始回执。它不启动 LangGraph、
OpenClaw、heartbeat、审批或工具，也不取得新的 ACK。回执中的历史 ACK、payload、
`audit_id` 和发送字节保持不变；服务端仍按既有历史发行窗口校验。

该入口用于已修复传输拒绝原因的 409/422 记录。永久拒绝不能自动重试，不能通过编辑
payload 或替换 ACK 消除。服务端继续拒绝时保留原记录并报告失败。
这项恢复能力不等于[双运行时 Product Active 验收](../06_delivery/product_runtime_implementation_plan.md)完成。

## 选择记录与确认结果

每次定向补投必须同时提供原 `audit_id` 和原 HTTP body 的 SHA-256：64 位小写十六进制，
不带 `sha256:` 前缀。摘要来自产生该回执时保留的证据，不是重新序列化后的对象摘要。
选择不存在、摘要不同、记录有冲突或不具备永久拒绝补投条件时，在 HTTP 之前拒绝。

每个选中项目先在加密 journal 中记录本次尝试，再进行一次 HTTP 请求。最多保留 32 次
显式尝试；达到上限后拒绝继续发送。准备记录写盘失败时不发送。网络中断或结果不确定时，
下一次尝试仍需显式选择同一项目，不会转为后台自动重试。成功必须同时满足服务端
`ok:true`、同一 `audit_id`、非 skipped，以及本地确认状态持久化成功。

服务端已保存、客户端确认写盘失败时，记录仍待确认。再次发送原字节，由既有接口处理
同一 `audit_id` 的幂等性；不能根据“可能已送达”删除本地记录。已完成定向补投的项目
再次选择只返回已有确认事实，不再发送 HTTP。

`selected_confirmed` 只说明选中的一条已确认。LangGraph 动作的 start 与 terminal 是
两个项目：先显式确认 start，再显式确认已经存在的 terminal。确认 start 不能被解释为
终态已确认。OpenClaw 不生成无宿主证据的权威 invocation-start；若进程中断且没有观察
到终态，未知动作仍保留，恢复入口不能编造结果或重新执行来补齐证据。

## 原端点与队列所有权

新队列将以下内容的规范 JSON 摘要同时持久化到控制记录及动作、回执和确认记录中：

- 固定 schema `agentguard-product-receipt-transport/1` 与 `guard-api-v0.3`。
- 该 SDK 实际校验并固定的 Guard API base URL。
- `runtime`、`agent_id`、`principal_id` 和 `runtime_binding_id`。

凭据正文、当前 ACK 和 activation 时间不参与该摘要；同一身份的凭据轮换无需改写历史
回执。更换 API 地址或身份会拒绝恢复。该绑定证明本地发送目的地一致，不代替独立
PostgreSQL 的回执关联核验，也不证明网络后的数据库身份。

旧版未绑定队列继续遵守原投递行为，但不能进入定向补投。恢复工具不会给旧记录追认
端点，不会创建缺失队列或密钥，也不会修复混用格式、损坏密文或冲突记录。

先停止原生产者，再打开独立恢复进程。队列目录为 `0700`，分离的密钥文件为 `0600`，
两者由当前用户拥有。恢复期间继续独占原队列。在途 HTTP 尚未结束时，`close` 不会提前
交出所有权；LangGraph 用 `closing` 表示，OpenClaw 的有界关闭返回 pending/ownerHeld。
进程崩溃可能留下结果不确定的旧 HTTP 请求，不能据此声称全局只有一次 HTTP；恢复保证
仍是同一回执的幂等补投，且不会增加工具副作用。

成功确认后保留加密的确认记录及尝试历史。动作熔断继续生效，重启仍会读取该事实；
本入口不提供解除熔断或继续执行任务的方法。

## LangGraph 命令

使用已安装候选 SDK 的 Python 环境。`--config-file` 指向当前用户拥有的 `0600` JSON，
其父目录必须是 `0700`。格式如下；`config` 使用实际生产者的配置及原队列路径，
`product_execution_enabled` 必须显式为 `false`：

```json
{
  "schema_version": "agentguard-product-receipt-recovery/1",
  "runtime": "langgraph",
  "config": {
    "core_base_url": "http://127.0.0.1:8088",
    "token": "<保存在受保护文件中的适配器凭据>",
    "runtime": "langgraph",
    "agent_id": "<原 agent_id>",
    "runtime_binding_id": "<原 runtime_binding_id>",
    "api_mode": "guard-api-v0.3",
    "fail_closed": true,
    "defense_enabled": true,
    "context_isolation_mode": "required",
    "runtime_receipt_mode": "required",
    "product_manifest_path": "/absolute/private/activation-manifest.json",
    "product_receipt_directory": "/absolute/receipts",
    "product_receipt_key_path": "/absolute/keys/receipt.key",
    "product_execution_enabled": false
  }
}
```

```bash
python scripts/product-runtime-receipts.py status --config-file "$RECOVERY_CONFIG"
python scripts/product-runtime-receipts.py drain --config-file "$RECOVERY_CONFIG"
python scripts/product-runtime-receipts.py reconcile \
  --config-file "$RECOVERY_CONFIG" \
  --audit-id "$RECEIPT_AUDIT_ID" --expected-wire-digest "$RECEIPT_WIRE_SHA256"
```

`status` 只读。`drain` 只处理原有的普通网络待投项目，不能处理永久拒绝。空队列的
`drain` 不会宣称已确认任何回执。SDK 入口为
`open_product_receipt_recovery(config)`，返回的对象只提供状态、投递、定向补投和关闭。
普通 Adapter 的 `close_product_delivery()` 也返回关闭状态；`closing=true` 表示原发送
尚未结束，未配置产品队列时返回 `None`。

## OpenClaw 命令

使用已安装候选包内的 `product-runtime/receipt-recovery.mjs`。受保护 JSON 配置包含
`guardApiBaseUrl`、`agentId`、`principalId`、`runtimeBindingId`、
`productReceiptDirectory`、`productReceiptKeyPath`，以及凭据环境变量名
`adapterTokenEnv`；可选 `requestTimeoutMs`。配置文件为 `0600`，父目录为 `0700`。
不要在命令行或报告中传入凭据正文。

```bash
node scripts/product-runtime-reconcile-openclaw.mjs \
  --package-root "$INSTALLED_PLUGIN_ROOT" \
  --config "$RECOVERY_CONFIG" \
  --audit-id "$RECEIPT_AUDIT_ID" \
  --expected-wire-digest "$RECEIPT_WIRE_SHA256" \
  --report "$PRIVATE_REPORT_PATH"
```

报告路径须为尚不存在的文件，父目录为当前用户拥有的 `0700` 目录。命令使用原队列的
同一身份，不加载 Host registry 或模型配置。SDK 的
`openOpenClawProductReceiptRecovery(config)` 接收内存中的 `adapterToken`，提供
`status()`、`drain()`、`reconcileRejectedReceipt()`、`close()` 和 `closeWithin()`。

## 退出码与证据

| 退出码 | 含义 |
| --- | --- |
| `0` | 所选回执确认成功；LangGraph `status` 则仅表示状态读取成功，`drain` 要求已有回执全部确认 |
| `1` | 确定的选择、绑定或契约拒绝，或服务端再次永久拒绝 |
| `2` | 网络、存储、关闭未完成或环境/证据不足，不能声明成功 |

输出只有固定错误码、摘要、投递状态和计数，不包含 ACK token 或原始 payload。最终
验收仍需在独立 PostgreSQL 查询原 policy、approval、consume、lease 和回执，核验每个
必需 `audit_id`、历史 ACK 关联及真实副作用数量。普通投递的 `queued_durable` 只表示
本地已持久化，不能替代数据库确认。
