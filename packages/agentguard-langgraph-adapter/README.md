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

## 验证

在仓库根目录执行：

```bash
uv run pytest packages/agentguard-langgraph-adapter/tests -q
uv run pytest tests/test_openclaw_plugin_contract.py -q
```

靶场侧兼容性可通过：

```bash
uv run pytest agentguard_langgraph_bench/bench/tests/test_langgraph_adapter.py agentguard_langgraph_bench/bench/tests/test_core_client.py -q
```
