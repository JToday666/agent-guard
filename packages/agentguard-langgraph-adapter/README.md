# AgentGuard LangGraph Adapter SDK

Standalone Python SDK for guarding LangGraph-style tool execution with
AgentGuard.

The package exposes:

- `LangGraphAdapter` for mapping tool calls to AgentGuard events and decisions.
- `SecureToolNode` for inserting a guarded tool node into a LangGraph graph or
  a compatible state-machine runner.
- `GuardedToolGateway` for generic guarded tool invocation.
- `AgentGuardCoreClient` and fake core clients for HTTP integration and tests.

The benchmark package keeps `agentguard_langgraph_bench.adapter` as a
compatibility import path, but new integrations should import from
`agentguard_langgraph_adapter`.
