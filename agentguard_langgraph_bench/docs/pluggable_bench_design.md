# Pluggable Bench Design

`agentguard_langgraph_bench/bench/` is now the stable evaluation kernel. It owns AttackCase loading, sandbox tool runtime, Guard/Core audit flow, row normalization, scoring, metrics, and result output. Concrete agents run behind `AgentAdapterProtocol`.

## Runtime Protocol

The runner depends on:

- `bench/runtime/agent_protocol.py`
  - `AgentAdapterProtocol`
  - `CaseContext`
  - `CaseRunResult`
- `bench/runtime/adapter_loader.py`
- `bench/runtime/tool_gateway.py`
- `bench/runtime/tool_runtime.py`
- `bench/runtime/row_normalizer.py`

Adapters return `CaseRunResult`; they do not compute `attack_success`. Scoring stays in the bench layer through `success_for_case` and the existing metrics modules.

## Tool Execution

All benchmark tools execute through `GuardedToolGateway`. The gateway:

1. builds a ToolCallEvent via the guard adapter;
2. calls AgentGuard Core or a fake core;
3. submits an AuditEvent;
4. enforces `allow`, `deny`, and `ask`;
5. invokes the sandbox tool runtime only after `allow`;
6. returns `ToolExecutionResult` evidence.

`SecureToolNode` is now only the LangGraph state wrapper and no longer scans or writes sandbox state directly.

## Tool Runtime

`MockToolRegistry` now implements the generic tool runtime shape:

- `invoke`
- `list_tools`
- `snapshot`
- `diff`
- `close`

`SandboxToolRuntime = MockToolRegistry` is retained as a compatibility alias.

## Default Behavior

The old default path remains equivalent to:

```bash
--agent-adapter langgraph-demo --tool-server-mode inprocess
```

`bench/runner.py` no longer imports `demo_agent.graph` or calls `run_demo_case`.

## Runtime Targets

`AttackCase.runtime_targets` defaults to `["any"]`. A case supports a runtime when `runtime_targets` contains `any` or the selected adapter runtime. `--strict-runtime-targets` converts skipped cases into an error.
