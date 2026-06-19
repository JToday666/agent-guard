# Adapter Contract

Adapters live under `agentguard_langgraph_bench/adapters/` or are loaded through `--agent-adapter python --adapter-entrypoint module:function`.

## Required Interface

```python
class AgentAdapterProtocol(Protocol):
    name: str
    runtime: str

    def setup(self, context: dict[str, Any]) -> None: ...
    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult: ...
    def teardown(self) -> None: ...
```

## CaseContext

`CaseContext` contains the case, trace id, sandbox/results paths, security metadata, `tool_gateway`, `tool_runtime`, config, and optional `tool_server`.

Adapters must not expose scoring-only fields to the tested agent, including:

- `success_condition`
- `expected_decision`
- `normal_oracle`
- `attack_oracle`
- `task_oracle`
- `safety_oracle`
- `sequence_oracle`
- `permission_oracle`
- `response_oracle`
- `incorrect_answer`
- `target_incorrect_answer`

## CaseRunResult

Adapters return execution evidence only:

- `tool_calls`
- `behavior_events`
- `final_answer`
- `blocked`
- `executed`
- `side_effects`
- `raw_state`
- `raw_logs`
- `error`

Adapters must not set or calculate `attack_success`.

## Tool Calls

In-process adapters should call:

```python
context.tool_gateway.invoke_tool(...)
```

External agents should call the benchmark HTTP Tool Server. Tool evidence must come from `ToolExecutionResult`, Tool Server events, sandbox evidence, browser/MCP/RAG/memory logs, or equivalent runtime evidence. Agent self-reported tool calls are not trusted as scoring evidence.
