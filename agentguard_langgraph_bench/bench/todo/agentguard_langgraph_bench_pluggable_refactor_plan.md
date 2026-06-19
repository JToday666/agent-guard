# agentguard_langgraph_bench 可插拔靶场改造方案

## 0. 文档用途

本文档用于指导 Codex 对 `agentguard_langgraph_bench` 靶场进行系统性改造，使其从当前偏向 LangGraph demo agent 的评测靶场，升级为一个通用、可插拔、可复用的 Agent 安全评测靶场。

改造目标是：

> 不论被测 Agent 是 LangGraph、OpenClaw、HTTP Agent、Subprocess Agent，还是未来新增的任意 Agent 框架，只要实现靶场定义的 adapter 协议，就能直接复用同一套 AttackCase、sandbox、Mock/Sandbox Tools、Guard/Core 审计链路、成功判定、metrics 和结果输出。

本文档是给 Codex 执行的工程任务书。Codex 修改代码时应严格遵守本文档中的目录边界、协议定义、实施顺序和验收标准，不能为了快速通过测试而把某个 Agent 框架再次硬编码进 runner。

---

## 1. 当前仓库状态与主要问题

### 1.1 当前已有的优点

当前 `agentguard_langgraph_bench` 已经有初步分层：

```text
agentguard_langgraph_bench/
  bench/
  adapter/
  demo_agent/
  docs/
```

各目录当前职责大致如下：

```text
bench/
  AttackCase 加载
  runner
  metrics
  success checker
  MockToolRegistry
  browser/MCP/RAG/memory sandbox runtime
  dataset
  sandbox
  results
  tests

adapter/
  LangGraphAdapter
  SecureToolNode / GuardedToolNode
  Core client
  ToolCallEvent / AuditEvent / PolicyDecision / ToolExecutionResult
  resource mapper
  audit mapper
  fake core

demo_agent/
  LangGraph demo agent
  LangGraph state
  planner
  LLM planner
  lifecycle capture
```

这些结构说明当前靶场已经具备“可插拔雏形”，但还没有达到“任意 Agent 只需写 adapter 即可接入”的程度。

### 1.2 当前最关键的问题

当前靶场的核心执行链路仍然绑定 LangGraph demo agent。

`bench/runner.py` 中存在类似结构：

```python
from ..adapter import LangGraphAdapter
from ..demo_agent.graph import run_demo_case

...

state = run_demo_case(case, adapter, tools)
```

这意味着 runner 只能运行内置 LangGraph demo agent。即使后续写了 OpenClaw adapter，也无法不改 runner 就直接接入。

### 1.3 AttackCase 强绑定 LangGraph

当前 `bench/models.py` 中：

```python
runtime_targets: list[str] = Field(default_factory=lambda: ["langgraph"])

@field_validator("runtime_targets")
@classmethod
def must_target_langgraph(cls, value: list[str]) -> list[str]:
    if "langgraph" not in value:
        raise ValueError("runtime_targets must include langgraph")
    return value
```

这会阻止 OpenClaw、HTTP Agent、Subprocess Agent 或其他框架作为同级 runtime 接入。

### 1.4 ToolNode 与 MockToolRegistry 耦合

当前 `SecureToolNode` 直接：

```python
self.tool_registry.invoke(...)
self.tool_registry.sandbox_dir
```

这使它更像是 `MockToolRegistry` 的专用包装器，而不是通用工具网关。OpenClaw 这类外部 Agent 无法直接复用 LangGraph ToolNode，需要一个独立的 `GuardedToolGateway` 和可选 HTTP Tool Server。

### 1.5 Adapter 层命名和职责不清

当前 `LangGraphAdapter` 实际承担的是通用 Guard 能力：

```text
构造 ToolCallEvent
调用 Core
处理 fail-closed
构造 AuditEvent
提交 AuditEvent
```

这些能力并不是 LangGraph 专属。应将其泛化为 `GuardAdapter`，再让 LangGraph / OpenClaw adapter 复用。

### 1.6 Core API 契约需要兼容升级

当前 `AgentGuardCoreClient` 使用：

```text
POST /v1/evaluate/tool-call
POST /v1/audit/event
```

但平台统一契约目标更接近：

```text
POST /v1/guard/evaluate
POST /v1/audit/events
```

改造时应支持 legacy 与新契约双模式，避免一次性破坏当前 fake core 和测试。

---

## 2. 总体改造目标

改造完成后的靶场应支持如下命令形式：

```bash
# 默认运行 LangGraph demo adapter
python -m agentguard_langgraph_bench.bench.cli \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --agent-adapter langgraph-demo \
  --defense off
```

```bash
# 运行 OpenClaw adapter
python -m agentguard_langgraph_bench.bench.cli \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --agent-adapter openclaw \
  --adapter-config agentguard_langgraph_bench/adapters/openclaw/config.example.toml \
  --tool-server-mode http \
  --defense on \
  --core-url http://localhost:8000
```

```bash
# 运行自定义 Python adapter
python -m agentguard_langgraph_bench.bench.cli \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --agent-adapter python \
  --adapter-entrypoint my_agent_adapter:create_adapter \
  --defense off
```

```bash
# 运行 HTTP Agent
python -m agentguard_langgraph_bench.bench.cli \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --agent-adapter http \
  --agent-endpoint http://127.0.0.1:19000/run-case \
  --tool-server-mode http \
  --defense on
```

核心要求：

```text
bench/runner.py 不再关心具体 Agent 框架。
LangGraph 只是一个 adapter。
OpenClaw 只是一个 adapter。
外部 HTTP/Subprocess Agent 也是 adapter。
所有 adapter 输出统一 CaseRunResult。
所有评分仍由 bench 统一完成。
所有工具调用必须经过 GuardedToolGateway 或 HTTP Tool Server。
```

---

## 3. 改造后的推荐目录结构

建议将目录逐步改造为如下结构：

```text
agentguard_langgraph_bench/
  bench/
    __init__.py
    cli.py
    runner.py
    config.py
    models.py
    dataset_loader.py
    tools.py
    browser_runtime.py
    environment.py
    mcpsafety.py
    mcpsafety_evaluator.py
    poisonedrag_context.py
    poisonedrag_data.py
    poisonedrag_metrics.py
    poisonedrag_service.py
    memory_poisoning_metrics.py
    metrics.py

    runtime/
      __init__.py
      agent_protocol.py
      adapter_loader.py
      tool_runtime.py
      tool_gateway.py
      tool_server.py
      side_effects.py
      row_normalizer.py

    scoring/
      __init__.py
      success.py
      tool_hijacking.py
      memory_poisoning.py
      poisonedrag.py

    datasets/
      attack_cases/
      instrumentation/
      poisonedrag/

    sandbox/
    results/
    scripts/
    tests/

  guard/
    __init__.py
    config.py
    core_client.py
    event_models.py
    guard_adapter.py
    resource_mapper.py
    event_mapper.py
    audit_mapper.py
    fake_core.py

  adapter/
    __init__.py
    core_client.py
    event_models.py
    langgraph_adapter.py
    secure_tool_node.py
    resource_mapper.py
    event_mapper.py
    audit_mapper.py
    fake_core.py

  adapters/
    __init__.py

    langgraph_demo/
      __init__.py
      adapter.py
      graph.py
      state.py
      planner.py
      llm_planner.py
      instrumentation_planner.py
      lifecycle.py

    openclaw/
      __init__.py
      adapter.py
      tool_manifest.py
      config.example.toml
      README.md

    http_agent/
      __init__.py
      adapter.py

    subprocess_agent/
      __init__.py
      adapter.py

  demo_agent/
    __init__.py
    graph.py
    state.py
    planner.py
    llm_planner.py
    instrumentation_planner.py
    lifecycle.py

  docs/
    README.md
    integration_notes.md
    dataset_mapping.md
    evaluation_audit.md
    requirements_trace.md
    pluggable_bench_design.md
    adapter_contract.md
    openclaw_adapter_guide.md
```

### 3.1 关于兼容目录

为了降低改造风险，可以保留当前 `adapter/` 和 `demo_agent/` 目录作为兼容层：

```text
adapter/
  兼容旧导入路径
  内部转发到 guard/ 或 runtime/

demo_agent/
  兼容旧导入路径
  内部转发到 adapters/langgraph_demo/
```

不要一次性删除旧路径。Codex 应优先保证现有测试和旧命令仍能运行。

---

## 4. 新增核心协议

## 4.1 AgentAdapterProtocol

新增文件：

```text
agentguard_langgraph_bench/bench/runtime/agent_protocol.py
```

建议内容：

```python
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from agentguard_langgraph_bench.bench.models import AttackCase


@dataclass(slots=True)
class CaseContext:
    case: AttackCase
    trace_id: str
    runtime: str
    adapter_name: str
    sandbox_dir: Path
    results_dir: Path
    security: dict[str, Any]
    tool_gateway: Any
    tool_runtime: Any
    config: Any


@dataclass(slots=True)
class CaseRunResult:
    case_id: str
    trace_id: str
    runtime: str
    adapter_name: str

    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    behavior_events: list[dict[str, Any]] = field(default_factory=list)
    final_answer: str = ""

    blocked: bool = False
    executed: bool = False
    side_effects: list[dict[str, Any]] = field(default_factory=list)

    raw_state: dict[str, Any] = field(default_factory=dict)
    raw_logs: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


class AgentAdapterProtocol(Protocol):
    name: str
    runtime: str

    def setup(self, context: dict[str, Any]) -> None:
        ...

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        ...

    def teardown(self) -> None:
        ...
```

### 4.1.1 协议语义

`AgentAdapterProtocol` 是可插拔靶场的核心。runner 只依赖它，不依赖 LangGraph、OpenClaw 或任何具体 Agent 框架。

各 adapter 的职责：

```text
LangGraphDemoAdapter:
  AttackCase -> LangGraph State
  GuardedToolGateway -> LangGraph SecureToolNode
  LangGraph Final State -> CaseRunResult

OpenClawAdapter:
  AttackCase -> OpenClaw Task
  Benchmark Tool Server -> OpenClaw Tool Manifest
  OpenClaw logs + Tool Server evidence -> CaseRunResult

HttpAgentAdapter:
  AttackCase -> HTTP request
  Agent response + Tool Server evidence -> CaseRunResult

SubprocessAgentAdapter:
  AttackCase -> stdin/temp JSON
  subprocess stdout/logs + Tool Server evidence -> CaseRunResult
```

---

## 4.2 ToolRuntimeProtocol

新增文件：

```text
agentguard_langgraph_bench/bench/runtime/tool_runtime.py
```

建议内容：

```python
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ToolRuntimeProtocol(Protocol):
    sandbox_dir: Path

    def invoke(self, name: str, arguments: dict[str, Any]) -> Any:
        ...

    def list_tools(self) -> dict[str, dict[str, Any]]:
        ...

    def snapshot(self) -> dict[str, tuple[int, int]]:
        ...

    def diff(self, before: dict[str, tuple[int, int]]) -> list[dict[str, Any]]:
        ...

    def close(self) -> None:
        ...
```

### 4.2.1 对当前 MockToolRegistry 的要求

当前 `MockToolRegistry` 已经具有：

```text
invoke()
functions
langchain_tools()
close()
browser_recordings()
finalize_browser_session()
```

需要补充：

```python
def list_tools(self) -> dict[str, dict[str, Any]]:
    ...

def snapshot(self) -> dict[str, tuple[int, int]]:
    ...

def diff(self, before: dict[str, tuple[int, int]]) -> list[dict[str, Any]]:
    ...
```

并建议新增：

```python
SandboxToolRuntime = MockToolRegistry
```

或者反过来：

```python
class SandboxToolRuntime:
    ...

MockToolRegistry = SandboxToolRuntime
```

保留 `MockToolRegistry` 名字是为了兼容当前测试和旧导入。

---

## 4.3 GuardedToolGateway

新增文件：

```text
agentguard_langgraph_bench/bench/runtime/tool_gateway.py
```

职责：

```text
统一接收工具调用意图
构造 ToolCallEvent
调用 AgentGuard Core 或 fake Core
处理 allow / deny / ask
执行 sandbox tool runtime
记录 side effects
返回统一 ToolExecutionResult
```

建议内容：

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentguard_langgraph_bench.adapter.event_models import ToolExecutionResult, new_id
from agentguard_langgraph_bench.adapter.langgraph_adapter import blocked_result


@dataclass(slots=True)
class GuardedToolGateway:
    guard_adapter: Any
    tool_runtime: Any

    def invoke_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        security: dict[str, Any],
        trace_id: str,
        call_id: str | None = None,
    ) -> ToolExecutionResult:
        call_id = call_id or new_id("call")

        event, decision = self.guard_adapter.evaluate_before_tool(
            tool_name=tool_name,
            arguments=arguments,
            security=security,
            trace_id=trace_id,
            call_id=call_id,
        )

        audit_event = self.guard_adapter.build_audit_event(event, decision)
        self.guard_adapter.submit_audit_event(audit_event)

        if decision.decision in {"deny", "ask"}:
            return blocked_result(
                tool_name=tool_name,
                call_id=call_id,
                event=event,
                decision=decision,
                audit_event=audit_event,
            )

        before = self.tool_runtime.snapshot()

        try:
            result = self.tool_runtime.invoke(tool_name, arguments)
            return ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=True,
                blocked=False,
                decision=decision.decision,
                status="executed",
                result=result,
                safe_message=None,
                side_effects=self.tool_runtime.diff(before),
                event=event.model_dump(),
                audit_event=audit_event.model_dump(),
                error=None,
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name=tool_name,
                call_id=call_id,
                executed=True,
                blocked=False,
                decision=decision.decision,
                status="error",
                result=None,
                safe_message=None,
                side_effects=self.tool_runtime.diff(before),
                event=event.model_dump(),
                audit_event=audit_event.model_dump(),
                error=str(exc),
            )
```

### 4.3.1 重要约束

所有 Agent adapter 的工具调用都必须经过 `GuardedToolGateway`。

禁止：

```text
OpenClaw adapter 直接写 sandbox 文件
OpenClaw adapter 直接调用 MockToolRegistry.invoke()
HTTP agent adapter 直接伪造 tool_calls
Subprocess adapter 直接根据 stdout 生成攻击成功结果
```

允许：

```text
adapter 调用 GuardedToolGateway.invoke_tool()
adapter 调用 HTTP Tool Server，由 Tool Server 内部调用 GuardedToolGateway
```

---

## 5. HTTP Tool Server 设计

## 5.1 为什么必须有 HTTP Tool Server

LangGraph 可以通过 Python 对象调用工具，但 OpenClaw、外部 HTTP Agent、Subprocess Agent 不一定能直接访问 Python 对象。

因此需要一个 HTTP Tool Server，把靶场工具暴露成本地 HTTP API。外部 Agent 只调用 HTTP 工具接口，实际执行仍然由 `GuardedToolGateway` 完成。

## 5.2 新增文件

```text
agentguard_langgraph_bench/bench/runtime/tool_server.py
```

## 5.3 API 设计

### `GET /health`

响应：

```json
{
  "ok": true,
  "service": "agentguard-benchmark-tool-server"
}
```

### `GET /tools`

返回可用工具：

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read a sandbox file.",
      "input_schema": {
        "type": "object",
        "properties": {
          "path": {"type": "string"}
        },
        "required": ["path"]
      }
    }
  ]
}
```

### `POST /tools/{tool_name}`

请求体：

```json
{
  "trace_id": "trace_x",
  "case_id": "PI-001",
  "call_id": "call_x",
  "arguments": {
    "path": "/private/token.txt"
  },
  "security": {
    "user_task": "...",
    "source_type": "web",
    "source_trust": "untrusted",
    "metadata": {}
  }
}
```

响应体必须是 `ToolExecutionResult` 的 `model_dump()`：

```json
{
  "tool_name": "read_file",
  "call_id": "call_x",
  "executed": false,
  "blocked": true,
  "decision": "deny",
  "status": "blocked",
  "result": null,
  "safe_message": "The tool call was blocked by AgentGuard.",
  "side_effects": [],
  "event": {},
  "audit_event": {},
  "error": null
}
```

### `GET /events`

返回当前 case 或当前 run 中通过 Tool Server 执行的工具调用结果。供 HTTP/OpenClaw/Subprocess adapter 在执行结束后回收 evidence。

```json
{
  "tool_results": [
    {
      "tool_name": "mcp_call",
      "executed": true,
      "blocked": false,
      "status": "executed",
      "result": {}
    }
  ]
}
```

### `POST /reset-case`

可选。用于 runner 在每个 case 开始前清空 Tool Server 内存中的临时工具调用记录，但不要清空 sandbox。sandbox 重置仍由 runner/environment 负责。

---

## 6. Guard 层重构

## 6.1 将 LangGraphAdapter 泛化为 GuardAdapter

当前 `LangGraphAdapter` 的实际职责是通用 Guard 逻辑，不是 LangGraph 专属。建议新增：

```text
agentguard_langgraph_bench/guard/guard_adapter.py
```

定义：

```python
@dataclass(slots=True)
class GuardAdapter:
    config: GuardConfig
    core_client: CoreClientProtocol | None = None

    def evaluate_before_tool(...):
        ...

    def build_tool_call_event(...):
        ...

    def build_audit_event(...):
        ...

    def submit_audit_event(...):
        ...
```

然后保留兼容：

```python
# agentguard_langgraph_bench/adapter/langgraph_adapter.py
from agentguard_langgraph_bench.guard.guard_adapter import GuardAdapter as LangGraphAdapter
```

或者：

```python
class LangGraphAdapter(GuardAdapter):
    pass
```

## 6.2 新增 GuardConfig

新增文件：

```text
agentguard_langgraph_bench/guard/config.py
```

建议内容：

```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class GuardConfig:
    core_base_url: str = "http://localhost:8000"
    token: str = "demo-token"
    timeout: float = 5.0
    fail_closed: bool = True
    defense_enabled: bool = True

    runtime: str = "unknown"
    agent_id: str = "unknown_agent"

    schema_version: str = "0.3"
    event_type: str = "tool_call_proposed"

    api_mode: str = "legacy"
```

`BenchConfig` 可以生成 `GuardConfig`：

```python
def to_guard_config(self, *, runtime: str, agent_id: str) -> GuardConfig:
    return GuardConfig(
        core_base_url=self.core_base_url,
        token=self.token,
        timeout=self.timeout,
        fail_closed=self.fail_closed,
        defense_enabled=self.defense_enabled,
        runtime=runtime,
        agent_id=agent_id,
        api_mode=self.core_api_mode,
    )
```

## 6.3 Core API 双模式

当前路径：

```text
/v1/evaluate/tool-call
/v1/audit/event
```

新增支持：

```text
/v1/guard/evaluate
/v1/audit/events
```

建议在 `AgentGuardCoreClient` 中：

```python
def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
    if self.config.api_mode == "guard-api-v0.3":
        return self._post_json("/v1/guard/evaluate", to_guard_event_payload(event))
    return self._post_json("/v1/evaluate/tool-call", event)

def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
    if self.config.api_mode == "guard-api-v0.3":
        return self._post_json("/v1/audit/events", event)
    return self._post_json("/v1/audit/event", event)
```

同时修改 fake core，使它同时支持：

```text
POST /v1/evaluate/tool-call
POST /v1/audit/event
POST /v1/guard/evaluate
POST /v1/audit/events
```

---

## 7. BenchConfig 改造

当前 `BenchConfig` 已经包含：

```text
core_base_url
token
timeout
fail_closed
defense_enabled
runtime
sandbox_dir
results_dir
llm_enabled
llm_provider
llm_model
llm_api_key
browser_mode
browser_engine
tool_hijacking_mode
tool_catalog_view
```

建议新增：

```python
agent_adapter: str = "langgraph-demo"
adapter_entrypoint: str = ""
adapter_config: str = ""
agent_endpoint: str = ""
agent_command: str = ""
tool_server_mode: str = "inprocess"
tool_server_host: str = "127.0.0.1"
tool_server_port: int = 18090
core_api_mode: str = "legacy"
strict_runtime_targets: bool = False
```

`from_values()` 也要接收这些字段，并从环境变量读取默认值：

```text
AGENTGUARD_BENCH_AGENT_ADAPTER
AGENTGUARD_BENCH_ADAPTER_ENTRYPOINT
AGENTGUARD_BENCH_ADAPTER_CONFIG
AGENTGUARD_BENCH_AGENT_ENDPOINT
AGENTGUARD_BENCH_AGENT_COMMAND
AGENTGUARD_BENCH_TOOL_SERVER_MODE
AGENTGUARD_BENCH_TOOL_SERVER_HOST
AGENTGUARD_BENCH_TOOL_SERVER_PORT
AGENTGUARD_CORE_API_MODE
```

---

## 8. CLI 改造

在 `bench/runner.py` 或 `bench/cli.py` 的 parser 中新增：

```python
parser.add_argument(
    "--agent-adapter",
    choices=["langgraph-demo", "openclaw", "http", "subprocess", "python"],
    default="langgraph-demo",
    help="Agent adapter used by the benchmark runner.",
)

parser.add_argument(
    "--adapter-entrypoint",
    default="",
    help="Python entrypoint for --agent-adapter python, e.g. my_pkg.my_adapter:create_adapter.",
)

parser.add_argument(
    "--adapter-config",
    default="",
    help="Adapter-specific config file path.",
)

parser.add_argument(
    "--agent-endpoint",
    default="",
    help="HTTP endpoint for http/openclaw adapter.",
)

parser.add_argument(
    "--agent-command",
    default="",
    help="Subprocess command for subprocess adapter.",
)

parser.add_argument(
    "--tool-server-mode",
    choices=["inprocess", "http"],
    default="inprocess",
    help="Use in-process tool gateway or expose local HTTP tool server.",
)

parser.add_argument("--tool-server-host", default="127.0.0.1")
parser.add_argument("--tool-server-port", type=int, default=18090)

parser.add_argument(
    "--runtime",
    default="",
    help="Runtime label. Defaults to adapter runtime.",
)

parser.add_argument(
    "--core-api-mode",
    choices=["legacy", "guard-api-v0.3"],
    default="legacy",
)

parser.add_argument(
    "--strict-runtime-targets",
    action="store_true",
    help="Fail instead of skipping cases whose runtime_targets do not include the selected runtime.",
)
```

---

## 9. Adapter Loader 设计

新增文件：

```text
agentguard_langgraph_bench/bench/runtime/adapter_loader.py
```

建议内容：

```python
from __future__ import annotations

import importlib
from typing import Any

from .agent_protocol import AgentAdapterProtocol


def load_agent_adapter(config: Any) -> AgentAdapterProtocol:
    name = config.agent_adapter

    if name == "langgraph-demo":
        from agentguard_langgraph_bench.adapters.langgraph_demo.adapter import create_adapter
        return create_adapter(config)

    if name == "openclaw":
        from agentguard_langgraph_bench.adapters.openclaw.adapter import create_adapter
        return create_adapter(config)

    if name == "http":
        from agentguard_langgraph_bench.adapters.http_agent.adapter import create_adapter
        return create_adapter(config)

    if name == "subprocess":
        from agentguard_langgraph_bench.adapters.subprocess_agent.adapter import create_adapter
        return create_adapter(config)

    if name == "python":
        return load_python_entrypoint(config.adapter_entrypoint, config)

    raise ValueError(f"Unknown agent adapter: {name}")


def load_python_entrypoint(entrypoint: str, config: Any) -> AgentAdapterProtocol:
    if not entrypoint or ":" not in entrypoint:
        raise ValueError("--adapter-entrypoint must be module:function")
    module_name, factory_name = entrypoint.split(":", 1)
    module = importlib.import_module(module_name)
    factory = getattr(module, factory_name)
    adapter = factory(config)
    return adapter
```

---

## 10. runner.py 改造细节

## 10.1 修改 run_cases 签名

当前：

```python
def run_cases(
    cases: list[AttackCase],
    *,
    config: BenchConfig,
    fake_core: bool = False,
    fake_core_decision: str = "deny",
    reset_environment: bool = True,
    scenario_stateful: bool = False,
    isolate_scenarios: bool = True,
) -> list[dict[str, Any]]:
```

建议改为：

```python
def run_cases(
    cases: list[AttackCase],
    *,
    config: BenchConfig,
    agent_adapter: AgentAdapterProtocol | None = None,
    fake_core: bool = False,
    fake_core_decision: str = "deny",
    reset_environment: bool = True,
    scenario_stateful: bool = False,
    isolate_scenarios: bool = True,
) -> list[dict[str, Any]]:
```

如果 `agent_adapter is None`：

```python
agent_adapter = load_agent_adapter(config)
```

## 10.2 构建运行组件

新增 helper：

```python
def build_runtime_components(config, agent_adapter, fake_core, fake_core_decision):
    tool_runtime = build_mock_tools(
        config.sandbox_dir,
        browser_mode=config.browser_mode,
        browser_engine=config.browser_engine,
    )

    core_client = None
    if fake_core:
        core_client = FakeAllowCoreClient() if fake_core_decision == "allow" else FakeDenyCoreClient()

    guard_config = config.to_guard_config(
        runtime=agent_adapter.runtime,
        agent_id=agent_adapter.name,
    )

    guard_adapter = GuardAdapter(config=guard_config, core_client=core_client)

    gateway = GuardedToolGateway(
        guard_adapter=guard_adapter,
        tool_runtime=tool_runtime,
    )

    return tool_runtime, guard_adapter, gateway
```

## 10.3 构建 CaseContext

新增：

```python
def build_case_context(case, config, agent_adapter, tool_runtime, tool_gateway):
    trace_id = new_id("trace")
    security = {
        "case_id": case.case_id,
        "trace_id": trace_id,
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "source_type": case.input.source_type,
        "source_trust": case.input.source_trust,
        "user_task": case.input.payload,
        "payload": case.input.payload,
        "metadata": case.metadata,
        "agent_id": agent_adapter.name,
        "runtime": agent_adapter.runtime,
    }

    return CaseContext(
        case=case,
        trace_id=trace_id,
        runtime=agent_adapter.runtime,
        adapter_name=agent_adapter.name,
        sandbox_dir=config.sandbox_dir,
        results_dir=config.results_dir,
        security=security,
        tool_gateway=tool_gateway,
        tool_runtime=tool_runtime,
        config=config,
    )
```

## 10.4 新 `_run_single_case`

替换当前 `_run_single_case()` 中的硬编码：

```python
state = run_demo_case(case, adapter, tools)
```

改成：

```python
def _run_single_case(
    case: AttackCase,
    agent_adapter: AgentAdapterProtocol,
    tool_runtime: ToolRuntimeProtocol,
    tool_gateway: GuardedToolGateway,
    config: BenchConfig,
) -> dict[str, Any]:
    context = build_case_context(
        case=case,
        config=config,
        agent_adapter=agent_adapter,
        tool_runtime=tool_runtime,
        tool_gateway=tool_gateway,
    )

    result = agent_adapter.run_case(case, context)

    row = normalize_case_result(
        case=case,
        result=result,
        config=config,
        tool_runtime=tool_runtime,
    )

    row = attach_tool_hijacking_report_if_needed(case, row, config)
    row = attach_mcpsafety_report_if_needed(case, row)
    row["attack_success"] = success_for_case(case, row)

    return row
```

## 10.5 结果 row 标准化

新增文件：

```text
bench/runtime/row_normalizer.py
```

必须输出统一字段：

```python
def normalize_case_result(case, result, config, tool_runtime) -> dict[str, Any]:
    tool_results = list(result.tool_calls or [])
    decisions = [item.get("decision") for item in tool_results if item.get("decision")]
    side_effects = result.side_effects or [
        effect
        for item in tool_results
        for effect in item.get("side_effects", [])
    ]

    blocked = result.blocked or any(item.get("blocked") for item in tool_results)
    executed = result.executed or any(item.get("executed") for item in tool_results)

    return {
        "case_id": case.case_id,
        "trace_id": result.trace_id,
        "runtime": result.runtime,
        "adapter_name": result.adapter_name,
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "case_schema_version": getattr(case, "case_schema_version", None),
        "scenario_id": case.metadata.get("scenario_id"),
        "phase": case.metadata.get("phase"),
        "scenario_order": case.metadata.get("scenario_order"),
        "metadata": case.metadata,
        "tool_hijacking_mode": config.tool_hijacking_mode if case.attack_type == "tool_hijacking" else None,
        "tool_catalog_view": config.tool_catalog_view if case.attack_type == "tool_hijacking" else None,
        "planning_source": result.raw_state.get("planning_source") or result.adapter_name,
        "defense_enabled": config.defense_enabled,
        "expected_decision": case.expected_decision,
        "tool_calls": tool_results,
        "behavior_events": list(result.behavior_events or []),
        "behavior_event_types": [item.get("event_type") for item in result.behavior_events or []],
        "browser_recordings": collect_browser_recordings(case, tool_runtime),
        "decisions": decisions,
        "blocked": blocked,
        "executed": executed,
        "side_effects": side_effects,
        "final_answer": result.final_answer or final_answer_from_tool_results(tool_results),
        "adapter_error": result.error,
        "raw_logs": result.raw_logs,
    }
```

---

## 11. AttackCase 模型改造

## 11.1 删除 LangGraph 强制校验

当前：

```python
runtime_targets: list[str] = Field(default_factory=lambda: ["langgraph"])
```

改为：

```python
runtime_targets: list[str] = Field(default_factory=lambda: ["any"])
adapter_hints: dict[str, Any] = Field(default_factory=dict)
```

当前校验器改为：

```python
@field_validator("runtime_targets")
@classmethod
def normalize_runtime_targets(cls, value: list[str]) -> list[str]:
    cleaned = [str(item).strip().lower() for item in value if str(item).strip()]
    return cleaned or ["any"]
```

新增 helper：

```python
def supports_runtime(case: AttackCase, runtime: str) -> bool:
    targets = {item.lower() for item in case.runtime_targets or ["any"]}
    return "any" in targets or runtime.lower() in targets
```

## 11.2 runner 中按 runtime 过滤 case

在 `main()` 加载 cases 后：

```python
adapter = load_agent_adapter(config)
runtime = args.runtime or adapter.runtime

supported = []
skipped = []

for case in cases:
    if supports_runtime(case, runtime):
        supported.append(case)
    else:
        skipped.append(case)

if skipped and args.strict_runtime_targets:
    raise SystemExit(
        "Cases do not support selected runtime: "
        + ", ".join(case.case_id for case in skipped)
    )

cases = supported
```

可选：summary 中记录 skipped case 数量：

```json
{
  "skipped_runtime_mismatch": 3
}
```

---

## 12. LangGraph demo adapter 迁移

## 12.1 新增目录

```text
agentguard_langgraph_bench/adapters/langgraph_demo/
```

将当前 `demo_agent/graph.py` 的主要逻辑迁移到：

```text
adapters/langgraph_demo/graph.py
adapters/langgraph_demo/adapter.py
adapters/langgraph_demo/lifecycle.py
adapters/langgraph_demo/planner.py
adapters/langgraph_demo/llm_planner.py
adapters/langgraph_demo/instrumentation_planner.py
```

不要一次性删除 `demo_agent/graph.py`。旧文件可以改成兼容转发：

```python
from agentguard_langgraph_bench.adapters.langgraph_demo.graph import *
```

## 12.2 LangGraphDemoAdapter

新增：

```python
from __future__ import annotations

from typing import Any

from agentguard_langgraph_bench.bench.runtime.agent_protocol import CaseContext, CaseRunResult
from agentguard_langgraph_bench.bench.models import AttackCase
from .graph import build_demo_graph, initial_state_from_case


class LangGraphDemoAdapter:
    name = "langgraph-demo"
    runtime = "langgraph"

    def __init__(self, config: Any | None = None) -> None:
        self.config = config

    def setup(self, context: dict[str, Any]) -> None:
        return None

    def run_case(self, case: AttackCase, context: CaseContext) -> CaseRunResult:
        state = initial_state_from_case(case, trace_id=context.trace_id, security=context.security)
        graph = build_demo_graph(context.tool_gateway, context.tool_runtime, context.config)

        final_state = graph.invoke(state) if hasattr(graph, "invoke") else graph(state)

        tool_results = list(final_state.get("tool_results") or [])
        behavior_events = list(final_state.get("behavior_events") or [])

        return CaseRunResult(
            case_id=case.case_id,
            trace_id=final_state.get("trace_id") or context.trace_id,
            runtime=self.runtime,
            adapter_name=self.name,
            tool_calls=tool_results,
            behavior_events=behavior_events,
            final_answer=_final_answer_from_state(final_state),
            blocked=any(item.get("blocked") for item in tool_results),
            executed=any(item.get("executed") for item in tool_results),
            raw_state=final_state,
        )

    def teardown(self) -> None:
        return None


def create_adapter(config: Any | None = None) -> LangGraphDemoAdapter:
    return LangGraphDemoAdapter(config)
```

## 12.3 SecureToolNode 改造

当前 `SecureToolNode` 同时承担：

```text
LangGraph state wrapper
Guard/Core 调用
tool runtime 执行
side effect diff
RAG retrieve/answer dependency handling
```

改造后：

```text
Guard/Core 调用 -> GuardedToolGateway
tool runtime 执行 -> GuardedToolGateway
side effect diff -> ToolRuntime
LangGraph state wrapper -> SecureToolNode
RAG dependency handling -> 可以暂时保留在 SecureToolNode，后续再迁移
```

新版 `SecureToolNode` 应只负责：

```python
class SecureToolNode:
    def __init__(self, gateway: GuardedToolGateway):
        self.gateway = gateway

    def __call__(self, state):
        for call in state["tool_calls"]:
            result = self.gateway.invoke_tool(...)
            results.append(result.model_dump())
        return updated_state
```

保留兼容构造：

```python
def create_guarded_tool_node(adapter_or_gateway, tool_registry=None):
    if isinstance(adapter_or_gateway, GuardedToolGateway):
        return SecureToolNode(adapter_or_gateway)

    gateway = GuardedToolGateway(
        guard_adapter=adapter_or_gateway,
        tool_runtime=tool_registry,
    )
    return SecureToolNode(gateway)
```

---

## 13. OpenClaw adapter 设计

## 13.1 目标

OpenClaw adapter 的目标不是把 OpenClaw 写进 runner，而是让 OpenClaw 作为一个独立 adapter 接入靶场：

```text
bench runner
  -> OpenClawAdapter
  -> OpenClaw runtime
  -> Benchmark HTTP Tool Server
  -> GuardedToolGateway
  -> SandboxToolRuntime
  -> CaseRunResult
  -> bench scoring
```

## 13.2 新增文件

```text
agentguard_langgraph_bench/adapters/openclaw/
  __init__.py
  adapter.py
  tool_manifest.py
  config.example.toml
  README.md
```

## 13.3 config.example.toml

```toml
mode = "http"
endpoint = "http://127.0.0.1:19000/run"
timeout = 120

[tool_server]
mode = "http"
host = "127.0.0.1"
port = 18090

[task]
include_attackcase_metadata = true
include_tool_plan_as_hint = true
include_oracle = false
```

注意：

```text
include_oracle 必须默认 false。
adapter 不能把 success_condition、normal_oracle、attack_oracle 等评分答案直接暴露给被测 Agent。
```

## 13.4 OpenClawAdapter 协议

```python
class OpenClawAdapter:
    name = "openclaw"
    runtime = "openclaw"

    def __init__(self, config):
        self.config = config
        self.adapter_config = load_openclaw_config(config.adapter_config)

    def setup(self, context):
        # 如果使用 HTTP Tool Server，确认 server 已启动
        # 如果需要生成 tool manifest，在此生成
        ...

    def run_case(self, case, context):
        task_payload = build_openclaw_task(case, context)
        response = call_openclaw(task_payload)
        tool_results = collect_tool_server_results(context.trace_id)

        return CaseRunResult(
            case_id=case.case_id,
            trace_id=context.trace_id,
            runtime=self.runtime,
            adapter_name=self.name,
            tool_calls=tool_results,
            behavior_events=build_behavior_events(response),
            final_answer=extract_final_answer(response),
            raw_logs=extract_logs(response),
            raw_state={"openclaw_response": response},
        )

    def teardown(self):
        ...
```

## 13.5 OpenClaw task payload

传给 OpenClaw 的任务输入建议：

```json
{
  "case_id": "PI-001",
  "trace_id": "trace_x",
  "user_task": "用户任务内容",
  "source_type": "web",
  "source_trust": "untrusted",
  "tool_manifest_url": "http://127.0.0.1:18090/tools",
  "tool_invocation_base_url": "http://127.0.0.1:18090/tools",
  "metadata": {
    "attack_type": "prompt_injection",
    "scenario_id": "..."
  },
  "hints": {
    "tool_plan": [
      {
        "tool": "browser_start",
        "arguments": {}
      }
    ]
  }
}
```

禁止传给被测 Agent：

```text
expected_decision
success_condition
normal_oracle
attack_oracle
safety_oracle
sequence_oracle
permission_oracle
response_oracle
incorrect_answer
target_incorrect_answer
```

除非某些字段本身就是 agent-facing case 输入的一部分。

## 13.6 OpenClaw Tool Manifest

`tool_manifest.py` 应根据 `ToolRuntime.list_tools()` 生成：

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read a sandbox file.",
      "input_schema": {
        "type": "object",
        "properties": {
          "path": {"type": "string"}
        },
        "required": ["path"]
      },
      "endpoint": "http://127.0.0.1:18090/tools/read_file"
    }
  ]
}
```

必须包含当前所有工具：

```text
read_file
write_file
send_email
call_api
code_exec
memory_write
memory_read
memory_search
browser_start
browser_navigate
browser_input
browser_click
browser_extract_text
mcp_call
rag_retrieve
rag_answer
```

---

## 14. HTTP Agent adapter 设计

新增：

```text
agentguard_langgraph_bench/adapters/http_agent/adapter.py
```

作用：接入任意外部 HTTP Agent。

请求体：

```json
{
  "case_id": "PI-001",
  "trace_id": "trace_x",
  "input": {
    "source_type": "web",
    "source_trust": "untrusted",
    "payload": "..."
  },
  "metadata": {},
  "tool_manifest_url": "http://127.0.0.1:18090/tools"
}
```

外部 Agent 响应：

```json
{
  "final_answer": "...",
  "logs": [],
  "metadata": {}
}
```

真正的工具调用仍然通过 Tool Server 回收，不信任 HTTP Agent 自报的 tool_calls。

---

## 15. Subprocess Agent adapter 设计

新增：

```text
agentguard_langgraph_bench/adapters/subprocess_agent/adapter.py
```

运行方式：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter subprocess \
  --agent-command "python my_agent.py --input {input_json} --output {output_json}" \
  --tool-server-mode http
```

adapter 流程：

```text
1. 为 case 写入 input_json
2. input_json 中包含 tool_manifest_url 和 trace_id
3. 启动 subprocess
4. 等待输出 output_json
5. 从 output_json 读取 final_answer/logs
6. 从 Tool Server 读取 tool_calls
7. 返回 CaseRunResult
```

必须设置 timeout，避免被测 Agent 卡死。

---

## 16. Scoring 拆分

## 16.1 拆出 success_for_case

当前 `success_for_case()` 在 `runner.py`，建议迁移到：

```text
bench/scoring/success.py
```

保留兼容：

```python
# bench/checkers.py
from .scoring.success import success_for_case
```

## 16.2 拆出工具劫持 report 附加逻辑

当前 `build_tool_hijacking_report()` 在 `runner.py`，建议迁移到：

```text
bench/scoring/tool_hijacking.py
```

导出：

```python
def attach_tool_hijacking_report(case, row, config) -> dict:
    ...
```

## 16.3 保留 MCPSafety evidence-based 评分原则

`mcpsafety.py` 中已经以执行证据评分，不信任 agent 自报。该原则必须保持。

所有 adapter 最终必须输出统一 `tool_calls`，使 `normalize_tool_calls()` 可处理。

## 16.4 Memory poisoning 评分保持不变

`memory_poisoning_metrics.py` 的指标逻辑保留，但数据来源变为所有 adapter 的统一 row。

---

## 17. 结果格式标准

每个 case 的 row 至少包含：

```json
{
  "case_id": "PI-001",
  "trace_id": "trace_x",
  "runtime": "langgraph",
  "adapter_name": "langgraph-demo",
  "attack_type": "prompt_injection",
  "is_malicious": true,
  "case_schema_version": null,
  "scenario_id": null,
  "phase": null,
  "scenario_order": null,
  "metadata": {},
  "defense_enabled": false,
  "expected_decision": "deny",
  "tool_calls": [],
  "behavior_events": [],
  "behavior_event_types": [],
  "browser_recordings": [],
  "decisions": [],
  "blocked": false,
  "executed": true,
  "side_effects": [],
  "final_answer": "",
  "attack_success": false,
  "task_success": null,
  "safe_completion": null,
  "overblocked": null,
  "adapter_error": null,
  "raw_logs": []
}
```

工具劫持 case 额外包含：

```json
{
  "hijacking_report": {},
  "hijacking_mode": "tool_shadowing",
  "target_tool": "search",
  "hijacked_tool": "Google_Search",
  "resisted": true,
  "resistance_score": 1.0,
  "evidence_status": "tool_evidence",
  "task_success": true,
  "safe_completion": true,
  "overblocked": false,
  "resisted_but_task_failed": false,
  "oracle_evidence": {},
  "descriptor_evidence": [],
  "descriptor_diff": []
}
```

Memory poisoning summary 继续包含：

```json
{
  "memory_poisoning": {
    "memory_contamination_rate": 0.0,
    "delayed_attack_success_rate": 0.0,
    "conflict_detection_rate": 0.0,
    "untrusted_memory_rejection_rate": 0.0,
    "benign_memory_fpr": 0.0,
    "counts": {},
    "by_scenario": {}
  }
}
```

---

## 18. 分阶段实施计划

## 阶段 1：新增协议层，不改变默认行为

新增文件：

```text
bench/runtime/agent_protocol.py
bench/runtime/tool_runtime.py
bench/runtime/tool_gateway.py
bench/runtime/adapter_loader.py
bench/runtime/row_normalizer.py
bench/runtime/side_effects.py
```

此阶段不要删除旧代码。目标是先建立抽象。

验收：

```bash
pytest -q agentguard_langgraph_bench/bench/tests
```

---

## 阶段 2：实现 LangGraphDemoAdapter

新增：

```text
adapters/langgraph_demo/adapter.py
```

第一版可以内部调用当前 `demo_agent.graph.run_demo_case()`，只要输出 `CaseRunResult`。

验收：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter langgraph-demo \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/benign.jsonl \
  --defense off
```

---

## 阶段 3：runner 接入 AgentAdapterProtocol

修改 `runner.py`：

```text
删除直接 import run_demo_case
删除 runner 对 demo_agent 的硬编码
新增 load_agent_adapter
新增 CaseContext 构建
新增 CaseRunResult -> row 规范化
```

验收：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter langgraph-demo \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --defense off
```

应能得到与旧行为基本一致的 summary。

---

## 阶段 4：抽出 GuardedToolGateway

将 `SecureToolNode.invoke_tool()` 中的 Guard 调用、工具执行、副作用 diff 迁移到 `GuardedToolGateway`。

`SecureToolNode` 只保留 LangGraph state 包装逻辑。

验收：

```bash
pytest -q agentguard_langgraph_bench/bench/tests/test_tool_call_event.py
pytest -q agentguard_langgraph_bench/bench/tests/test_audit_event.py
pytest -q agentguard_langgraph_bench/bench/tests/test_mock_tools.py
```

---

## 阶段 5：ToolRuntime 协议化

将 `MockToolRegistry` 补充为 `ToolRuntimeProtocol` 实现：

```text
invoke
list_tools
snapshot
diff
close
```

并确保 `SecureToolNode` 不再直接访问 `tool_registry.sandbox_dir`。

验收：

```bash
pytest -q agentguard_langgraph_bench/bench/tests/test_mock_tools.py
```

---

## 阶段 6：AttackCase runtime_targets 泛化

修改 `bench/models.py`：

```text
runtime_targets 默认 ["any"]
删除 must_target_langgraph
新增 adapter_hints
新增 supports_runtime helper
```

runner 中按当前 adapter runtime 过滤或报错。

验收：

```bash
pytest -q agentguard_langgraph_bench/bench/tests
```

新增测试：

```text
test_runtime_targets_any_supports_langgraph
test_runtime_targets_openclaw_supports_openclaw
test_runtime_targets_langgraph_skips_openclaw
```

---

## 阶段 7：新增 HTTP Tool Server

实现：

```text
bench/runtime/tool_server.py
```

支持：

```text
GET /health
GET /tools
POST /tools/{tool_name}
GET /events
POST /reset-case
```

验收：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter langgraph-demo \
  --tool-server-mode http \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/benign.jsonl \
  --defense off
```

即使 LangGraph 默认可以 inprocess，也要保证 http 模式不破坏结果。

---

## 阶段 8：实现 HTTP Agent adapter

新增：

```text
adapters/http_agent/adapter.py
```

用 fake HTTP Agent server 做测试。

验收：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter http \
  --agent-endpoint http://127.0.0.1:19000/run-case \
  --tool-server-mode http \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/benign.jsonl \
  --defense off
```

---

## 阶段 9：实现 OpenClaw adapter

新增：

```text
adapters/openclaw/
```

第一版使用 fake OpenClaw server 验证协议，不要求真实 OpenClaw 已安装。

验收：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter openclaw \
  --adapter-config agentguard_langgraph_bench/adapters/openclaw/config.example.toml \
  --tool-server-mode http \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/tool_hijacking.jsonl \
  --defense off
```

---

## 阶段 10：Guard/Core API 双模式

新增 `GuardConfig`，修改 CoreClient 支持：

```text
legacy
guard-api-v0.3
```

fake core 同时支持新旧 endpoint。

验收：

```bash
python -m agentguard_langgraph_bench.adapter.fake_core
```

然后分别用：

```bash
--core-api-mode legacy
--core-api-mode guard-api-v0.3
```

运行 smoke test。

---

## 阶段 11：文档和测试补齐

新增文档：

```text
docs/pluggable_bench_design.md
docs/adapter_contract.md
docs/openclaw_adapter_guide.md
```

新增测试：

```text
bench/tests/test_agent_adapter_protocol.py
bench/tests/test_runner_adapter_loading.py
bench/tests/test_tool_gateway.py
bench/tests/test_tool_server.py
bench/tests/test_runtime_targets.py
bench/tests/test_langgraph_demo_adapter_compat.py
bench/tests/test_http_agent_adapter.py
bench/tests/test_openclaw_adapter_contract.py
```

---

## 19. 必须新增的测试用例

### 19.1 runner 不再 import demo_agent

```python
def test_runner_does_not_import_demo_agent():
    source = Path("agentguard_langgraph_bench/bench/runner.py").read_text(encoding="utf-8")
    assert "demo_agent.graph" not in source
    assert "run_demo_case" not in source
```

### 19.2 dummy adapter 可运行

创建测试 adapter：

```python
class EchoAdapter:
    name = "echo"
    runtime = "test"

    def setup(self, context):
        pass

    def run_case(self, case, context):
        result = context.tool_gateway.invoke_tool(
            tool_name="write_file",
            arguments={
                "path": "/reports/echo.txt",
                "content": case.input.payload,
            },
            security=context.security,
            trace_id=context.trace_id,
        )
        return CaseRunResult(
            case_id=case.case_id,
            trace_id=context.trace_id,
            runtime=self.runtime,
            adapter_name=self.name,
            tool_calls=[result.model_dump()],
            final_answer="done",
        )

    def teardown(self):
        pass


def create_adapter(config):
    return EchoAdapter()
```

验收：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter python \
  --adapter-entrypoint tests.fixtures.echo_adapter:create_adapter \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/benign.jsonl \
  --defense off
```

### 19.3 Tool Server 必须经过 Guard

用 fake deny core：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter http \
  --tool-server-mode http \
  --defense on \
  --fake-core \
  --fake-core-decision deny
```

断言：

```text
tool_calls 中 blocked=true
sandbox 没有产生对应副作用
audit_event 存在
decision=deny
```

### 19.4 scenario-stateful 保持有效

使用 memory poisoning delayed 数据集：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter langgraph-demo \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/memory_poisoning_delayed.jsonl \
  --scenario-stateful \
  --defense off
```

再用 dummy/http/openclaw fake adapter 跑同一流程，确保 summary 中仍有：

```text
memory_contamination_rate
delayed_attack_success_rate
conflict_detection_rate
untrusted_memory_rejection_rate
benign_memory_fpr
```

---

## 20. 禁止事项

Codex 改造时严禁做以下事情：

1. **禁止把 OpenClaw 写死进 `bench/runner.py`。**

   错误示例：

   ```python
   if args.agent_adapter == "openclaw":
       run_openclaw_case(...)
   else:
       run_demo_case(...)
   ```

   正确做法：

   ```python
   agent_adapter = load_agent_adapter(config)
   result = agent_adapter.run_case(case, context)
   ```

2. **禁止让 adapter 自己计算 attack_success。**

   adapter 只能返回 `CaseRunResult`。攻击成功与否必须由 `bench/scoring` 判断。

3. **禁止让外部 Agent 直接操作 sandbox。**

   所有工具调用必须经过 `GuardedToolGateway` 或 HTTP Tool Server。

4. **禁止信任 Agent 自报工具调用。**

   工具调用证据必须来自：

   ```text
   ToolExecutionResult
   Tool Server events
   sandbox evidence
   browser/mcp/rag/memory logs
   ```

5. **禁止把安全策略写入 adapter。**

   adapter 不判断安全与否。安全判断由 AgentGuard Core 或 fake core 返回。

6. **禁止破坏旧命令。**

   旧命令应默认等价于：

   ```bash
   --agent-adapter langgraph-demo
   --tool-server-mode inprocess
   ```

7. **禁止删除旧导入路径。**

   `LangGraphAdapter`、`SecureToolNode`、`MockToolRegistry` 等应保留兼容 alias 或 wrapper。

8. **禁止把 oracle 泄露给被测 Agent。**

   包括：

   ```text
   success_condition
   expected_decision
   normal_oracle
   attack_oracle
   task_oracle
   safety_oracle
   sequence_oracle
   permission_oracle
   response_oracle
   incorrect_answer
   target_incorrect_answer
   ```

   除非这些字段原本就是 agent-facing 输入的一部分。

---

## 21. 最终验收标准

### 21.1 架构验收

必须满足：

```text
bench/runner.py 不 import demo_agent
bench/runner.py 不 import adapters/langgraph_demo
bench/runner.py 不 import adapters/openclaw
AttackCase 不强制 runtime_targets 包含 langgraph
GuardAdapter 不依赖完整 BenchConfig
SecureToolNode 不直接访问 tool_registry.sandbox_dir
Tool Server 调用必须经过 GuardedToolGateway
OpenClaw adapter 位于 adapters/openclaw/
LangGraph demo 位于 adapters/langgraph_demo/
```

### 21.2 功能验收

必须通过：

```bash
pytest -q agentguard_langgraph_bench/bench/tests
```

必须能运行：

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter langgraph-demo \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --defense off
```

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter langgraph-demo \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --defense on \
  --fake-core
```

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter python \
  --adapter-entrypoint tests.fixtures.echo_adapter:create_adapter \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/benign.jsonl \
  --defense off
```

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter openclaw \
  --adapter-config agentguard_langgraph_bench/adapters/openclaw/config.example.toml \
  --tool-server-mode http \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/tool_hijacking.jsonl \
  --defense off
```

### 21.3 结果验收

每次运行必须生成：

```text
bench/results/run_<timestamp>.json
bench/results/run_<timestamp>.csv
bench/results/summary_<timestamp>.json
bench/results/sandbox_artifacts/sandbox_<timestamp>/manifest.json
```

### 21.4 指标验收

summary 必须保留：

```text
case_count
malicious_count
benign_count
asr_before
asr_after
block_rate
fpr
benign_fpr
task_success_rate
safe_completion_rate
overblock_rate
per_attack
per_hijacking_mode
per_mcpsafety_evaluator
memory_poisoning
poisonedrag
```

具体字段根据数据集是否包含相关类型可以为 `None` 或缺省，但原有指标不能被无故删除。

---

## 22. Codex 推荐执行顺序

Codex 应按以下顺序提交修改，避免大爆炸式重构：

```text
1. 新增 runtime 协议文件，不改旧逻辑。
2. 新增 LangGraphDemoAdapter，内部暂时调用旧 run_demo_case。
3. 修改 runner 使用 AgentAdapterProtocol，但默认仍走 langgraph-demo。
4. 抽出 GuardedToolGateway，SecureToolNode 改成薄包装。
5. MockToolRegistry 补齐 ToolRuntimeProtocol。
6. AttackCase runtime_targets 泛化。
7. 新增 HTTP Tool Server。
8. 新增 HTTP Agent adapter。
9. 新增 OpenClaw adapter。
10. Core API 双模式。
11. 拆分 scoring。
12. 补测试和 docs。
```

每一步都必须运行相关测试，不能在未验证的情况下继续大规模修改。

---

## 23. 最终目标形态

改造完成后，整体架构应为：

```text
AttackCase JSONL
    ↓
Bench Runner
    ↓
AgentAdapterProtocol
    ├── LangGraphDemoAdapter
    ├── OpenClawAdapter
    ├── HttpAgentAdapter
    ├── SubprocessAgentAdapter
    └── CustomPythonAdapter
    ↓
GuardedToolGateway
    ↓
AgentGuard Core / Fake Core
    ↓
SandboxToolRuntime / HTTP Tool Server
    ↓
ToolExecutionResult + sandbox evidence
    ↓
统一 scoring
    ↓
run_json / run_csv / summary_json / sandbox_artifacts
```

最终效果：

> `bench/` 是稳定评测内核；`adapters/` 是唯一需要针对 Agent 框架编写的部分。LangGraph、OpenClaw 或任何新 Agent，只要实现 `AgentAdapterProtocol`，并让工具调用经过 `GuardedToolGateway` 或 HTTP Tool Server，就能直接复用同一套 AttackCase、sandbox、checker、metrics 和结果输出进行评测。
