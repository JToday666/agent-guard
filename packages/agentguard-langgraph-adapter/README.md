# AgentGuard LangGraph Adapter SDK

`agentguard-langgraph-adapter` 是 AgentGuard 面向 LangGraph 风格工具执行的 Python SDK。它把工具调用映射为 GuardEvent，调用 Guard API 或测试 Core client，并在工具真正执行前应用 `allow`、`deny`、`ask` 决策。

## 暴露能力

- `LangGraphAdapter`：将 LangGraph 工具调用和运行上下文映射为 AgentGuard 事件与决策。
- `SecureToolNode` / `GuardedToolNode`：可插入 LangGraph graph 的受保护工具节点。
- `create_guarded_tool_node`：便于接入现有工具集合的工厂函数。
- `GuardedToolGateway`：与 LangGraph 解耦的通用工具调用网关。
- `AgentGuardCoreClient`：访问 Guard API 的 HTTP client。
- fake core clients：用于单元测试、离线靶场和演示。

## 使用边界

- SDK 不实现检测规则；检测和策略由 Guard API 后的 `agentguard-core` 负责。
- SDK 不直接写数据库、不管理 Dashboard session、不保存 control token。
- SDK 只负责事件映射、执行前控制和审计字段补齐。
- benchmark 包仍保留 `agentguard_langgraph_bench.adapter` 兼容导入路径；新集成建议直接使用 `agentguard_langgraph_adapter`。

## Guard API 协议迁移

适配器默认连接 `http://127.0.0.1:8088`，并使用当前 Guard API `v0.3` 协议：

- 事件评估：`POST /v1/guard/evaluate`
- 审批等待：`GET /v1/approvals/{approval_id}/wait`
- 强绑定 lease：`POST /v1/approvals/{approval_id}/execution-leases/consume`

策略审计（`policy_evaluation`）由 Guard API 在 `POST /v1/guard/evaluate` 内部唯一
写入，适配器在该模式下不再经 `POST /v1/audit/events` 重复提交（契约 §12.1/§22.1）。

旧 Core 仍可通过 `api_mode="legacy"` 显式启用。该模式仅依赖
`/v1/evaluate/tool-call` 和 `/v1/audit/event`，不提供 P1 运行时事件或审批等待能力，
并会发出弃用提示。未知的 `api_mode` 会直接报错，不会回退到 legacy。

## RTE-05 Strong Approval Binding

Guard API 返回 `requires_execution_lease=true` 时，SDK 只接受与本次 action ID
以及本地可信配置完全一致的 runtime binding；`runtime_binding_id` 应与 credential
principal 一起带外配置，例如：

```python
AgentGuardLangGraphConfig(
    core_base_url="http://127.0.0.1:8088",
    token="...",
    runtime_binding_id="binding:cred_langgraph_main",
)
```

缺少 binding 的旧响应继续保持 C1 行为；一旦服务端声明 strong binding，配置缺失、
action/runtime mismatch、非人工 `allow_once`、409/410、非法响应或超时都会
fail closed 且不调用工具。网络、429、5xx/503 只在原审批 deadline 内以完全相同
请求有界重试。SDK 不本地重算 authorization fingerprint，明文 lease token 仅在
consume 响应解析栈内验证后丢弃，结果与回执只携带 lease/consumption ID。

## Required runtime receipts

`runtime_receipt_mode="best_effort"` 为兼容默认值；需要强制回执的产品 gateway
可显式配置 `runtime_receipt_mode="required"`。Product V2 Active 的 `profile_all`
响应或 `required_durable` directive 也会强制 required，不能由本地默认值降级。

required 模式会在审批/lease 前检查回执入口和 policy parent；未启用、缺少
submitter 或 policy audit ID 时不调用工具。start 回执必须收到包含精确 audit ID
的肯定响应后才能执行。terminal 回执失败保留已经执行的事实，不重试工具，
并在 `ToolExecutionResult.runtime_receipt_status` 中返回 `failed`。

新 API `submit_runtime_receipt_result()` 明确返回 `recorded | disabled | failed`；
旧 `submit_runtime_receipt()` 保留 `str | None` 兼容投影，二者使用同一发送路径。
required 调用方和验收脚本必须检查结构化状态，不能把 `disabled` 当作成功。
`recorded` 只说明服务端确认了该回执，不是持久性或 Host exactly-once 的独立证明。

## Product official ACK 传输

`product_manifest_path` 显式选择 Product official 传输；它要求 v0.3、
`defense_enabled=True`、`fail_closed=True`、`context_isolation_mode="required"`
和 `runtime_receipt_mode="required"`。配置或运行清单发生变化后，不再发起新动作。
官方响应必须同时具有 `source=v21 / mode=active / selection_basis=profile_all`、
匹配的 activation/capability 和严格 release directive；current、shadow 或缺字段
均返回 fail-closed 结果，不使用兼容放行分支。

`ProductActivationManifest.from_file()` 读取独立可信期望值。清单必须是当前用户拥有的
规范绝对路径，父目录 `0700`、文件 `0600`，不得使用符号链接、硬链接、重复 JSON
字段或超大文件。清单包含 runtime/profile/binding/principal、候选制品、capability
和 host/tool inventory 摘要，不能从 heartbeat 或 evaluate 响应反推这些期望值。
`ProductRuntimeObservation` 则来自实际运行时注册和工具清单采集；会话比较两者，
并独立读取已安装的 LangGraph `1.2.7` 与 Adapter `0.1.0rc1` metadata。
当前包版本尚未对齐候选时，真实 handshake 会拒绝，不谎报 RC 版本。

`adapter.start_product_session(observe=...)` 首次成功 heartbeat 后启动每 30 秒刷新。
`adapter.refresh_product_ack()` 提供 single-flight 刷新，
`adapter.core_client.snapshot_product_ack()` 取得不可变快照而不发送新请求，
`adapter.close_product_session()` 关闭会话。ACK 最长 120 秒，服务端更短期限和本地
更短 `activation_ack_max_age_seconds` 优先。刷新失败阻断新动作；身份、版本、
清单或 capability 漂移锁死当前会话。

evaluate 与 consume 通过 `X-AgentGuard-Activation-Ack` 发送 token。每个 decision
私下保留 evaluate ACK；ASK 人工等待结束后刷新一次，并为该次 consume 固定 ACK
与请求体进行有界重试。消费结果不确定且 ACK 过期时停止，不换 ACK 重试。
无 lease 的终态保留 evaluate ACK；已有 lease/consumption 的终态保留 consume ACK。
过期后的历史补投仍使用原始完整 ACK，由服务端按历史窗口验证。

ACK 的普通 dump/repr 隐藏 token，只有 `ActivationAckV1.to_wire()`、
`header_value()` 和 `RuntimeOutcomeReceipt.to_wire()` 显式输出传输材料。
`adapter.submit_audit_event(receipt)` 使用该专用 wire 投影；不要用普通日志或通用
state dump 保存历史凭据。start observation 的私有加密 envelope 保留原始 ACK；其
通用 HTTP observation payload 不增加公开 ACK 字段，也不据此扩大服务端
invocation-start 验证声明。

当前 `GuardedToolGateway` 继续拒绝 Product 配置：统一执行模板和原生七事件消费者
尚未接齐。ACK 传输、持久队列和受控合同测试不构成真实 Product Active、
双 canary 或 Internal RC 资格。完整顺序见
[双运行时实施约定](../../docs/06_delivery/product_runtime_implementation_plan.md)。

## Product 加密持久投递

Product 回执要求显式配置 `product_receipt_directory` 与
`product_receipt_key_path`，两者均为绝对路径，密钥位于队列目录外。仅测试 ACK
传输时可省略两者；省略后提交 Product 回执会失败，不能直接发送以绕过持久化。
配置两者后，adapter 固定原始 namespace、HTTP endpoint 和凭据并启动补投线程。
关闭 ACK 会话后仍可补投历史回执；退出时另调用 `close_product_delivery()` 释放
队列锁。`drain_product_receipts()` 尝试已到重试时刻的待投记录，`product_delivery_status()`
只返回计数和固定错误码，不显示 payload 或 token。

每条 envelope 使用 [PyCA AESGCM](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
实现 AES-256-GCM，使用独立随机 32 字节密钥和每次写入新生成的 12 字节 nonce。
队列目录为 `0700`、文件及分离密钥为 `0600`，校验所有者、单链接、无符号链接，
并以进程锁和原子 replace/fsync 保证单写者及持久确认。AAD 绑定稳定的 runtime、
agent、principal、binding 和记录身份，不绑定当前 activation，历史 ACK 不会因
候选更新或当前过期而被替换、丢弃。

`adapter.submit_product_receipt()` 返回 `ProductReceiptDeliveryResult`：

| 状态 | 事实 |
| --- | --- |
| `recorded` | 服务端明确返回 `ok=true` 且 audit ID 精确匹配 |
| `queued_durable` | 已加密落盘，网络故障后等待有界退避补投，尚未确认入库 |
| `permanent_rejected` | 永久 HTTP 拒绝，保留原记录并熔断 |
| `failed` | 写盘、解密、内容冲突或无效确认等失败；阻断新副作用 |

原 `submit_audit_event()`、`submit_runtime_receipt_result()` 和
`submit_runtime_receipt()` 保留兼容返回；排队不会投影成成功。补投固定原始字节，
不会刷新 ACK，也不会执行工具。永久失败和损坏记录不自动删除或降级直接发送。

`ProductActionBarrier.begin_action()` 原子写入动作意图并确认开始回执后才返回
不透明 ticket。开始确认失败时没有 ticket；进程重启后遇到未完成意图，保留
执行结果未知并阻断，不能推测为未执行。`finish_action()` 先持久化终态再投递；
终态未确认期间阻断后续副作用，重启只补投已保存的终态。完成记录转换为加密
去重 tombstone，拒绝相同动作再次执行。该 primitive 尚未接入原生工具执行入口。

所有记录（含 tombstone、永久失败和熔断记录）统一计入 10,000 条、单条 envelope
512 KiB、总计 64 MiB 的限制；总容量预留一条最大 envelope 的原子替换空间。
本批不自动清理去重记录，不宣称可以抵抗外部对整个队列目录的回滚。

## 验证

在仓库根目录执行：

```bash
uv run pytest packages/agentguard-langgraph-adapter/tests -q
uv run pytest packages/agentguard-langgraph-adapter/tests/test_required_runtime_receipts.py -q
uv run pytest tests/test_openclaw_plugin_contract.py -q
uv run pytest tests/test_langgraph_product_activation_http.py -q
uv run pytest tests/test_langgraph_product_delivery_http.py -q
```

靶场侧兼容性可通过：

```bash
uv run pytest agentguard_langgraph_bench/bench/tests/test_langgraph_adapter.py agentguard_langgraph_bench/bench/tests/test_core_client.py -q
```
