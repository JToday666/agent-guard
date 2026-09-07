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

本批不提供 ACK handshake/历史 ACK carrier，不开启 Product Active runtime 开关，
也不构成原生 StateGraph、双 canary 或 Internal RC 资格。后续小批次依次接通
ACK 客户端与历史 carrier、统一执行模板、原生 LangGraph runtime；每批从前一批
实际合入后的 `dev` SHA 开始。OpenClaw 配置/契约读取层单独交付，不混入本批。

## 验证

在仓库根目录执行：

```bash
uv run pytest packages/agentguard-langgraph-adapter/tests -q
uv run pytest packages/agentguard-langgraph-adapter/tests/test_required_runtime_receipts.py -q
uv run pytest tests/test_openclaw_plugin_contract.py -q
```

靶场侧兼容性可通过：

```bash
uv run pytest agentguard_langgraph_bench/bench/tests/test_langgraph_adapter.py agentguard_langgraph_bench/bench/tests/test_core_client.py -q
```
