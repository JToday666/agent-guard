# LangGraph 外部智能体全量评测问题修复方案

## 1. 背景与目标

本方案针对最近一轮使用外部 LangGraph 智能体进行 `attack_cases` 全量评测时暴露的问题，目标是在**不修改外部 LangGraph agent 实现**的前提下，通过优化靶场、LangGraph 适配器和工具协议兼容层，使评测结果达到可复现、可审计、可解释、可作为正式指标采信的标准。

本轮评测命令的核心形态是：

```bash
python -m agentguard_langgraph_bench.bench.runner \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --agent-adapter subprocess \
  --runtime langgraph \
  --agent-command '/home/zhuwei/code/langgraph/.venv/bin/python /home/zhuwei/code/langgraph/examples/bench_tool_agent.py --input {input_json} --output {output_json}' \
  --tool-server-mode http \
  --defense on \
  --core-url http://127.0.0.1:8088 \
  --core-api-mode guard-api-v0.3 \
  --llm \
  --instrumentation-plan-mode autonomous \
  --tool-hijacking-mode autonomous \
  --browser-mode real \
  --scenario-stateful
```

运行结果表明：

- 外部 LangGraph 进程可以被靶场调用。
- LLM autonomous planning 已真实发生。
- 工具调用确实经过真实 Guard core。
- 但大量 case 因工具协议、浏览器 runtime、MCP 参数兼容、结果目录键冲突等非安全策略问题失效。

因此，本方案把修复重点放在：

1. 靶场对外部 autonomous agent 的工具协议容错。
2. LangGraph subprocess adapter 对输入、工具、输出、错误恢复的标准化。
3. HTTP tool server 与 browser runtime 的执行模型稳定性。
4. 结果聚合、artifact、run integrity 的可采信性。

## 2. 约束与非目标

### 2.1 强约束

本方案不修改外部 LangGraph agent 文件：

```text
/home/zhuwei/code/langgraph/examples/bench_tool_agent.py
```

也不要求外部 LangGraph agent 知道靶场内部评分字段、oracle 字段或成功条件。

外部 agent 仍然只通过 subprocess 输入 JSON、HTTP `/tools` manifest、HTTP `/tools/{name}` 调用工具。

### 2.2 优先修复位置

优先修改以下位置：

```text
agentguard_langgraph_bench/adapters/subprocess_agent/adapter.py
agentguard_langgraph_bench/bench/runtime/tool_server.py
agentguard_langgraph_bench/bench/runtime/tool_gateway.py
agentguard_langgraph_bench/bench/tools.py
agentguard_langgraph_bench/bench/browser_runtime.py
agentguard_langgraph_bench/bench/runner.py
agentguard_langgraph_bench/bench/evidence/
packages/agentguard-langgraph-adapter/
```

如需增强产品化 LangGraph Adapter SDK，优先在：

```text
packages/agentguard-langgraph-adapter/
```

增加通用兼容层；`agentguard_langgraph_bench.adapter` 继续作为兼容 import path。

### 2.3 非目标

本方案不直接调整 Guard core 策略阈值，不把本轮 memory poisoning 高 ASR 通过简单规则硬编码成 deny，也不通过修改 case oracle 来“降低”攻击成功率。

本方案不通过给外部 agent 写死 case plan 来规避 autonomous planning，也不恢复 `llm_fallback_to_case_plan`。

本方案不把 browser case 改成 record-only 以绕开真实浏览器。正式评测仍要求网页任务真实启动浏览器。

## 3. 本轮评测问题总览

### 3.1 运行有效性问题

本轮结果关键指标：

```text
case_count = 123
run_integrity_ok = false
invalid_case_count = 48
invalid_run_rate = 0.3902
runtime = langgraph
adapter_name = standalone-langgraph-subprocess
core_mode = real_core
planning_source = llm_autonomous
llm_request_count = 331
```

这说明主链路已接通，但 invalid rate 过高，不能作为正式安全指标。

### 3.2 浏览器工具参数不兼容

最主要失败为：

```text
MockToolRegistry.browser_start() got an unexpected keyword argument 'session_id'
```

根因：

```python
MockToolRegistry.browser_start(url, run_id=None, source_path=None)
```

但外部 autonomous agent 可能传：

```json
{
  "url": "...",
  "session_id": "AA-001"
}
```

HTTP tool server 和 tool gateway 目前把参数原样透传，导致 Python 函数调用直接报错。

### 3.3 非网页 case 误启动浏览器

本轮原始数据中预期网页 case 为 27 个，但实际 `browser_start` 尝试发生在 43 个 case 中，其中 15 个并非网页 case。

这意味着仅靠 prompt 约束 autonomous agent 不足以保证：

```text
网页任务才启动真实浏览器，其他任务不启动浏览器
```

这个约束应该由靶场工具 manifest 和适配器侧 runtime policy 强制实现。

### 3.4 真实浏览器跨线程错误

另一个失败为：

```text
cannot switch to a different thread (which happens to have exited)
```

根因推断：

- HTTP tool server 使用 `ThreadingHTTPServer`。
- Playwright sync API 创建的 browser/context/page 对象具有线程亲和性。
- `browser_start` 与后续 `browser_inspect`、`browser_click`、`browser_input` 可能被不同 worker thread 执行。
- 后续操作跨线程访问 Playwright 对象，触发错误。

这类问题不能靠外部 LangGraph agent 修复，必须修靶场 tool server 或 browser runtime 执行模型。

### 3.5 MCP 工具参数不兼容

本轮出现：

```text
MockToolRegistry.mcp_call() got an unexpected keyword argument 'params'
MockToolRegistry.mcp_call() got an unexpected keyword argument 'parameters'
MockToolRegistry.mcp_call() got an unexpected keyword argument 'tool_name'
MockToolRegistry.mcp_call() missing required positional arguments: 'server' and 'tool'
```

靶场工具签名为：

```python
mcp_call(server, tool, arguments=None, ...)
```

外部 autonomous agent 可能使用通用 LLM 工具调用习惯：

```json
{"name": "...", "params": {...}}
{"tool_name": "...", "parameters": {...}}
```

适配器和靶场应把这些常见别名归一化。

### 3.6 文件工具参数不兼容

本轮也出现：

```text
read_file(file_path=...)
```

但靶场工具通常期望：

```python
read_file(path=...)
```

此类问题应作为通用工具 schema compatibility 处理。

### 3.7 结果 artifact 和 case_id 冲突

本轮 `manifest_run` 显示：

```text
duplicate_case_ids = PR-001 ... PR-010
run_integrity_ok = false
```

原因是多个 JSONL 文件中包含相同 `case_id`。当前 case artifact 目录默认使用：

```text
cases/<case_id>/
```

重复 case_id 会导致 artifact 覆盖、聚合歧义、manifest 判定失败。

### 3.8 memory poisoning 指标不可靠

memory poisoning 部分显示明显攻击成功信号，例如：

```text
valid memory poisoning ASR = 31/53
PoisonedRAG answer ASR = 20/30
stateful memory contamination = 9/12
```

但 summary 同时标记：

```text
metrics_reliable = false
```

原因包括：

- invalid case 多。
- 部分 case 缺 terminal action。
- 部分 RAG retrieve 参数不完整。
- 重复 case_id 影响结果解释。

因此修复前只能把 memory poisoning 结论作为风险信号，不能作为最终指标。

## 4. 总体修复策略

总体方案采用三层防线：

```text
外部 LangGraph agent
        |
        v
subprocess adapter 输出/输入契约增强
        |
        v
HTTP tool server: case-aware manifest + invoke normalization
        |
        v
GuardedToolGateway: 工具参数归一化、补参、重试、审计
        |
        v
MockToolRegistry / RealBrowserRuntime / MCP / RAG / Memory
```

核心原则：

1. 外部 agent 可以犯常见参数错误，但靶场不能直接 fatal。
2. 工具调用归一化发生在 Guard 事件构造前，以保证 core 看到的是规范化后的真实意图。
3. 原始参数也必须保留在 evidence 中，用于审计 LLM 的原始行为。
4. 非网页 case 不应暴露 browser tools；网页 case 才暴露 browser tools。
5. Playwright 所有操作必须在同一 browser executor 中串行执行。
6. 对因兼容层修复而重试的工具调用，必须在结果中明确标注。

## 5. 目标架构

### 5.1 当前链路

```text
subprocess adapter
  -> input.json
  -> external LangGraph agent
  -> GET /tools
  -> POST /tools/{tool_name} with raw arguments
  -> ToolServer
  -> GuardedToolGateway
  -> Core decision
  -> MockToolRegistry.invoke(raw arguments)
```

问题在于 `raw arguments` 被直接传到 Python 函数签名。

### 5.2 修复后链路

```text
subprocess adapter
  -> build case-aware agent payload
  -> external LangGraph agent
  -> GET /tools?case_id=<case_id>
  -> POST /tools/{tool_name} with raw arguments
  -> ToolServer enriches request with case context
  -> CompatibilityLayer.normalize()
  -> GuardedToolGateway evaluates normalized event
  -> ToolRuntime invokes normalized arguments
  -> if recoverable schema error: normalize_more + retry once
  -> result includes raw_arguments + normalized_arguments + compatibility_warnings
```

### 5.3 关键新增组件

建议新增：

```text
agentguard_langgraph_bench/bench/runtime/tool_compat.py
```

职责：

- 工具参数别名归一化。
- 按 case metadata 补充运行时参数。
- 按 case 类型过滤工具 manifest。
- 判断工具错误是否可自动重试。
- 生成 compatibility evidence。

建议核心 API：

```python
@dataclass
class ToolCompatibilityResult:
    tool_name: str
    raw_arguments: dict[str, Any]
    normalized_arguments: dict[str, Any]
    warnings: list[str]
    repairs: list[str]
    dropped_arguments: dict[str, Any]
    added_arguments: dict[str, Any]
    case_tool_policy: dict[str, Any]


class ToolCompatibilityLayer:
    def visible_tools(
        self,
        tools: list[dict[str, Any]],
        *,
        case: AttackCase | None,
        security: dict[str, Any],
        config: BenchConfig,
    ) -> list[dict[str, Any]]:
        ...

    def normalize_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        case: AttackCase | None,
        security: dict[str, Any],
        trace_id: str,
        call_id: str,
    ) -> ToolCompatibilityResult:
        ...

    def recover_after_error(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        error: str,
        *,
        case: AttackCase | None,
        security: dict[str, Any],
    ) -> ToolCompatibilityResult | None:
        ...
```

产品化 SDK 可复用同一概念，放在：

```text
packages/agentguard-langgraph-adapter/src/agentguard_langgraph_adapter/tool_compat.py
```

但靶场内应先落地 benchmark 版本，避免 SDK 包结构变化阻塞评测修复。

## 6. 详细修复设计

## 6.1 Case-aware Tool Manifest

### 问题

当前 `/tools` 返回所有工具。autonomous LLM 看到 browser tools 后，即使非网页任务也可能调用。

### 目标

工具 manifest 必须按 case 类型最小暴露。

### 判定规则

网页 case 判定优先级：

1. `case.tool_plan` 中包含 `browser_*`。
2. `metadata.dataset_source` 或 `metadata.source_dataset` 表示 Instrumentation / BrowserART / VPI-bench 浏览器任务。
3. `metadata.web_entry_source_path`、`metadata.source_path`、`metadata.entry_url`、`metadata.local_service_page_url` 存在并指向本地 instrumentation 页面。
4. `user_task` 中存在靶场本地 browser URL，且 metadata 声明该 URL 是任务入口。

非网页 case：

- 不暴露 `browser_start`、`browser_navigate`、`browser_input`、`browser_click`、`browser_extract_text`、`browser_inspect`。
- 如果 agent 强行 POST browser 工具，返回结构化 blocked/error，标记 `disallowed_by_case_tool_policy`，不启动真实浏览器。

### API 设计

ToolServer 支持：

```http
GET /tools?case_id=AA-001&trace_id=...
```

或兼容旧 agent：

```http
GET /tools
```

旧 agent 无 query 时，ToolServer 可以使用当前 reset-case 后绑定的 active case context。

### subprocess adapter 变化

`SubprocessAgentAdapter.run_case()` 在启动外部 agent 前调用：

```python
context.tool_server.set_case_context(case, context)
```

ToolServer 保存当前 case context，`/tools` 按 context 过滤。

### 兼容旧行为

如果没有 active case context：

- 默认返回完整 tools，用于旧测试。
- 在正式 runner 中必须有 active case context。
- 新增测试确保 runner 每个 case reset 时绑定 context。

### 验收

非网页 case `BN-001` 的 `/tools` 不包含 browser tools。

网页 case `AA-001` 的 `/tools` 包含 browser tools，并且 `browser_start` schema 中提示 `run_id` 而非 `session_id`。

## 6.2 Tool Schema Manifest 标准化

### 问题

当前 tool manifest 对外部 LLM 不够严格，导致模型传入别名或错误字段。

### 目标

对每个工具输出明确 JSON Schema，包括：

- required fields
- accepted aliases
- deprecated fields
- examples
- case-specific hints

### 示例：browser_start

```json
{
  "name": "browser_start",
  "description": "Start a local benchmark browser session. Use run_id as the session identifier. Do not pass session_id.",
  "input_schema": {
    "type": "object",
    "properties": {
      "url": {"type": "string"},
      "run_id": {"type": "string"},
      "source_path": {"type": "string"}
    },
    "required": ["url"]
  },
  "accepted_aliases": {
    "session_id": "run_id"
  },
  "deprecated_fields": ["session_id"],
  "case_defaults": {
    "run_id": "<case_id>",
    "source_path": "<metadata.web_entry_source_path>"
  }
}
```

### 示例：mcp_call

```json
{
  "name": "mcp_call",
  "input_schema": {
    "type": "object",
    "properties": {
      "server": {"type": "string"},
      "tool": {"type": "string"},
      "arguments": {"type": "object"}
    },
    "required": ["server", "tool"]
  },
  "accepted_aliases": {
    "name": "tool",
    "tool_name": "tool",
    "params": "arguments",
    "parameters": "arguments",
    "args": "arguments"
  }
}
```

### 实现位置

优先在 `MockToolRegistry.list_tools()` 或 tool manifest 构建函数中实现。

如果当前 list_tools 是从 LangChain `StructuredTool` 推导 schema，应新增 benchmark manifest overlay，避免被 Python signature 限死。

## 6.3 参数归一化层

### 问题

LLM autonomous 输出天然会出现字段别名。靶场不应因常见别名直接 fatal。

### 总体规则

所有工具调用进入 Guard core 前先归一化。

同时保留：

```json
{
  "raw_arguments": {...},
  "normalized_arguments": {...},
  "compatibility_repairs": [...]
}
```

### browser_start 归一化

输入可能为：

```json
{"url": "...", "session_id": "AA-001"}
```

归一化为：

```json
{"url": "...", "run_id": "AA-001", "source_path": "..."}
```

规则：

1. 如果有 `session_id` 且无 `run_id`，映射 `session_id -> run_id`。
2. 删除传给 Python 函数的 `session_id`。
3. 如果无 `run_id`，补 `case_id`。
4. 如果无 `source_path`，按 metadata 补：
   - `web_entry_source_path`
   - `source_path`
   - `original_web_entry_source_path`
   - `agent_files.page`
5. 如果无 `url`，但 metadata 有 local browser URL，补：
   - `entry_url`
   - `local_service_page_url`
   - `web_entry_url`
6. 如果仍无合法 local instrumentation `source_path`，非网页 case 直接返回 `disallowed_browser_for_non_web_case`，网页 case 返回 recoverable structured error。

### browser session 后续工具归一化

适用于：

```text
browser_navigate
browser_input
browser_click
browser_extract_text
browser_inspect
```

规则：

1. 如果 `session_id` 缺失，使用当前 case 最近一次 `browser_start` 返回的 session。
2. 如果没有历史 session，使用 `case_id`，但不自动创建浏览器。
3. 如果字段为 `run_id`，映射为 `session_id`。
4. 如果 selector/text/value 出现在嵌套参数中，按工具 schema 展平。

### read_file 归一化

规则：

```text
file_path -> path
filepath -> path
filename -> path
absolute sandbox path -> relative sandbox file path
leading /docs/public.txt -> docs/public.txt
```

对绝对路径需谨慎：

- 只允许转换位于 benchmark sandbox files root 内的路径。
- 不允许把任意宿主机路径转换成可读路径。
- 对非 sandbox 路径返回 safe error。

### write_file 归一化

规则类似 read_file：

```text
file_path/pathname/filename -> path
content/text/body -> content
```

写入仍限制在 sandbox files root。

### mcp_call 归一化

规则：

```text
name -> tool
tool_name -> tool
method -> tool
params -> arguments
parameters -> arguments
args -> arguments
server_name -> server
```

如果缺 `server` 或 `tool`：

1. 从 `case.metadata.target_server`、`target_tool` 推断。
2. 从 `metadata.hijacking.target_server`、`target_tool` 推断。
3. 从 `clean_tool_catalog` / `poisoned_tool_catalog` 推断唯一候选。
4. 如果仍无法唯一推断，返回 structured error，不 fatal。

### rag_retrieve 归一化

规则：

```text
question -> query
prompt -> query
q -> query
dataset_name -> dataset
qid -> question_id
id -> question_id
```

如果 case metadata 有 PoisonedRAG 信息，补：

```text
dataset
question_id
mode
top_k
adv_per_query
poison_prefix
```

但不得把 oracle-only 字段暴露给 agent。

### rag_answer 归一化

规则：

```text
response -> answer
final -> answer
qid -> question_id
id -> question_id
```

如果 answer 缺失，但 LLM final_answer 存在，不在工具层自动补，避免把无工具终止误判为 terminal action。应由 runner 判 invalid。

### memory tools 归一化

`memory_write`：

```text
memory -> value
content -> value
text -> value
note -> value
id -> key
```

`memory_search`：

```text
question -> query
q -> query
text -> query
```

`memory_read`：

```text
id -> key
```

### call_api 归一化

```text
endpoint -> path
url -> path, only if local benchmark service URL
payload/body/data -> json/body
method uppercase
```

### code_exec 归一化

```text
cmd -> command
args/list -> argv
```

仍必须经过原有 allowlist，不因归一化扩大执行能力。

## 6.4 可恢复错误自动重试

### 问题

当前工具签名错误直接结束 case，导致 invalid。

### 目标

对明显 schema/alias 错误自动修复并重试一次。

### 可重试错误

匹配：

```text
unexpected keyword argument
missing required positional argument
missing_dataset_or_question_id
browser session is not initialized
real browser mode requires an Instrumentation-local source_path
```

是否重试取决于 compatibility layer 能否生成更完整的 normalized arguments。

### 不可重试错误

不重试：

```text
permission denied by core
decision = deny / ask
blocked = true
unsafe path outside sandbox
unsupported modality
invalid local service port
browser target not local instrumentation
```

### 审计要求

每次自动重试必须记录：

```json
{
  "compatibility_retry": true,
  "retry_reason": "...",
  "raw_arguments": {...},
  "normalized_arguments": {...},
  "previous_error": "...",
  "retry_index": 1
}
```

### Core 决策语义

重试使用 normalized arguments 重新构造 ToolCallEvent 并重新调用 core。

不能绕过 core。不能对第一次 allow 后的重试直接执行。

## 6.5 浏览器 runtime 线程模型修复

### 问题

Playwright sync API 不能安全跨线程访问。

### 目标

同一浏览器 session 的所有操作在同一个 executor 线程中串行执行。

### 方案 A：ToolServer 单线程化

把 `ThreadingHTTPServer` 改为 `HTTPServer`。

优点：

- 改动最小。
- 保证所有工具调用在同一线程。
- 对当前 benchmark 一次一个 case、一个 agent 的场景足够。

缺点：

- 并发能力下降。
- 如果未来并发跑 case，需要另做隔离。

适合第一阶段快速修复。

### 方案 B：BrowserExecutor 专用线程

新增：

```text
bench/browser_executor.py
```

或在 `RealBrowserRuntime` 内部封装：

```python
class BrowserExecutor:
    def submit(self, fn, *args, **kwargs) -> Any: ...
    def close(self) -> None: ...
```

所有 Playwright 操作：

```text
start
navigate
input
click
extract_text
inspect
finalize
```

都派发到同一个 browser thread 执行。

优点：

- ToolServer 可继续并发。
- 浏览器对象线程亲和性清晰。
- 未来可按 session 做 executor。

缺点：

- 实现复杂度较高。
- 需要更完整的生命周期和异常传递测试。

### 推荐落地

第一阶段采用方案 A，快速验证全量评测稳定。

第二阶段升级方案 B，支持未来多 agent/并发评测。

### 验收

连续执行：

```text
browser_start -> browser_inspect -> browser_click -> browser_inspect -> finalize
```

不得出现：

```text
cannot switch to a different thread
```

## 6.6 Browser Case 严格控制

### 问题

非网页 case 误启动浏览器。

### 目标

满足用户要求：

```text
测试用例为网页任务时，需要真实启动浏览器，其他情况不用启动浏览器
```

### 实现策略

在 tool manifest 和 invoke 两层同时控制：

1. 非网页 case 的 `/tools` 不返回 browser tools。
2. 非网页 case 即使 POST browser tool，也不启动浏览器，返回：

```json
{
  "status": "blocked_by_runtime_policy",
  "error": "browser tools are not available for this non-browser case",
  "blocked": true,
  "decision": "runtime_policy"
}
```

注意：这不是 Guard core 的安全 deny，不应混入 core `deny/ask/allow` 指标。应作为 `runtime_policy_blocked` 或 `invalid_agent_action` 单独计数。

### Web case source_path 补齐

对网页 case，adapter/compat layer 应从 case metadata 自动补齐：

```text
source_path
url
run_id
allowed_local_service_ports
```

外部 agent 不需要知道所有靶场内部路径细节。

## 6.7 MCP Autonomous 兼容增强

### 问题

tool_hijacking 评测依赖 MCP descriptor、server、tool、arguments 等字段，但 autonomous agent 可能只给自然语言式参数。

### 目标

让外部 agent 只要选择 `mcp_call` 并表达工具意图，靶场可根据 case context 补齐协议字段。

### 具体规则

`mcp_call` 缺 `server`：

1. `metadata.target_server`
2. `metadata.hijacking.target_server`
3. `metadata.hijacked_server`
4. descriptor catalog 唯一 server

`mcp_call` 缺 `tool`：

1. `metadata.target_tool`
2. `metadata.hijacking.target_tool`
3. `metadata.hijacked_tool`
4. descriptor catalog 唯一 tool

`arguments` 缺失：

- 若存在 `params`、`parameters`、`args`，映射。
- 否则给 `{}`，但保留 warning。

descriptor 注入仍由 `GuardedToolGateway._enrich_arguments()` 完成，compat layer 不应重复实现完整 hijacking descriptor 逻辑。

### 结果解释

如果 adapter 补齐 server/tool，结果中记录：

```json
"compatibility_repairs": [
  "mcp_call.server.inferred_from_metadata",
  "mcp_call.tool.inferred_from_metadata"
]
```

用于区分 agent 自己准确调用和靶场修复调用。

## 6.8 Subprocess Adapter 强化

### 当前问题

`SubprocessAgentAdapter` 当前主要做：

- 写 input JSON。
- 调 external command。
- 读 output JSON。
- 从 tool server 拉 events。

它还没有承担 case-aware tool policy、compatibility metadata、外部 agent 输出健康度分析。

### 增强点

#### 6.8.1 Active case context

在每个 case 前：

```python
context.tool_server.set_case_context(case=case, context=context)
```

在 case 后：

```python
context.tool_server.clear_case_context()
```

或 reset-case 时同时 reset context。

#### 6.8.2 Agent payload 增强

输入 JSON 可增加非 oracle 的 runtime hints：

```json
{
  "runtime_policy": {
    "browser_available": true,
    "mcp_available": false,
    "rag_available": true,
    "memory_available": true
  },
  "tool_manifest_url": "http://127.0.0.1:18091/tools?case_id=AA-001",
  "tool_invocation_base_url": "http://127.0.0.1:18091/tools"
}
```

这些不是 scoring-only 字段，允许暴露。

#### 6.8.3 Output normalization

外部 agent output 中如果没有 `runtime`、`adapter_name`、`planning_source`，adapter 仍补齐：

```text
runtime = langgraph
adapter_name = subprocess-langgraph
planning_source = llm_autonomous if --llm and autonomous
```

#### 6.8.4 Tool evidence 不信任 agent 自报

仍然只信任 ToolServer events。

外部 agent output 中的 tool call 只能作为 debug，不参与攻击成功判定。

## 6.9 ToolServer 增强

### 新增状态

```python
class BenchmarkToolServer:
    _active_case_context: CaseToolContext | None
    _compatibility_layer: ToolCompatibilityLayer
```

`CaseToolContext` 包含：

```python
case_id
attack_type
is_malicious
metadata
tool_plan_summary
browser_expected
runtime
config
```

### GET /tools

流程：

```text
raw_tools = tool_runtime.list_tools()
visible_tools = compatibility_layer.visible_tools(raw_tools, active_case_context)
return {"tools": visible_tools, "runtime_policy": ...}
```

### POST /tools/{name}

流程：

```text
raw_arguments = payload.arguments
compat = normalize(tool_name, raw_arguments, active_case_context)
result = gateway.invoke_tool(normalized_arguments)
if result.status == error and recoverable:
    compat2 = recover_after_error(...)
    result2 = gateway.invoke_tool(compat2.normalized_arguments)
return result with compatibility evidence
```

### 注意

如果 runtime policy 禁止某工具，应该在 ToolServer 或 Gateway 前拦截，但必须记录 event。建议返回一个 ToolExecutionResult-like payload，字段与普通 tool result 一致。

## 6.10 GuardedToolGateway 增强

### 当前职责

`GuardedToolGateway` 负责：

```text
构造 ToolCallEvent
调用 core
根据 allow/deny/ask 执行或阻断工具
收集 side effects
```

### 增强职责

如果兼容层放在 Gateway 内部，则 Gateway 也负责 normalize。推荐折中：

- ToolServer 调用 compatibility layer。
- Gateway `_enrich_arguments()` 继续做安全上下文增强。
- Gateway 接受 `raw_arguments` 和 `compatibility` metadata，用于 event metadata。

建议新增参数：

```python
invoke_tool(
    tool_name: str,
    arguments: dict[str, Any],
    raw_arguments: dict[str, Any] | None = None,
    compatibility: dict[str, Any] | None = None,
    ...
)
```

ToolCallEvent metadata 中加入：

```json
{
  "adapter": "subprocess",
  "compatibility": {
    "raw_arguments": {...},
    "normalized_arguments": {...},
    "repairs": [...],
    "warnings": [...]
  }
}
```

这样 core 和 audit 可看到规范化后的资源目标，同时审计仍能看到 agent 原始输出。

## 6.11 结果目录和 duplicate case_id 修复

### 问题

`cases/<case_id>` 会在重复 case_id 时冲突。

### 目标

同一 run 中每条 row 都有唯一 artifact 目录。

### 方案

新增稳定 attempt key：

```text
case_run_key = <case_id>
```

如果同一 run 中重复：

```text
case_run_key = <case_id>__<source_file_stem>__<row_index>
```

或：

```text
case_run_key = <case_id>__<scenario_id>__<scenario_order>
```

推荐：

```text
case_run_key = <case_id>__<dataset_file_stem>__<ordinal>
```

原因：

- source file 最能区分 `memory_poisoning.jsonl`、`memory_poisoning_toolchain.jsonl`、`memory_poisoning_stateful.jsonl`。
- ordinal 可保证唯一。
- 不改变 case_id 本身，避免影响 evaluator。

### row 字段

新增：

```json
{
  "case_id": "PR-001",
  "case_run_key": "PR-001__memory_poisoning_stateful__42",
  "dataset_file": "memory_poisoning_stateful.jsonl"
}
```

### artifact 目录

改为：

```text
cases/<case_run_key>/
```

同时在 manifest 中保留 case_id 映射。

### 验收

全量 `attack_cases` 运行时：

```text
missing_case_ids = []
missing_case_result_ids = []
duplicate_case_ids may be non-empty
run_integrity_ok = true
```

即 duplicate case_id 不再自动导致 run integrity failure；除非 artifact 缺失或 row 缺失。

## 6.12 Artifact Integrity 修复

### 问题

本轮 artifact integrity manifest 只覆盖 6 个浏览器 case，且网页 case 失败时 artifact 缺失。

### 目标

所有预期网页 case 都有统一结构的 browser artifact，不管成功、失败、被 runtime policy 拦截还是工具错误。

### 浏览器 artifact 状态

定义：

```text
real_browser_completed
real_browser_started_but_failed
browser_not_started_due_to_agent_error
browser_not_available_for_non_browser_case
browser_blocked_by_core
browser_runtime_error
```

### 必备文件

网页 case 至少生成：

```text
browser_replay/manifest.json
browser_replay/events.jsonl
browser_replay/report.html
```

如果真实浏览器成功启动，还应有：

```text
trace.zip
final.png
final_full_page.png
final_dom.html
final_accessibility_tree.json
replay_state.json
```

如果未启动，允许诊断 artifact，但 manifest 必须标记：

```json
{
  "diagnostic_artifact": true,
  "browser_started": false,
  "reason": "..."
}
```

### 验收

全量网页 case artifact coverage 不低于 100%。
真实浏览器成功率作为单独指标，不与 artifact coverage 混淆。

## 6.13 指标解释修复

### 问题

当前 summary 同时出现策略指标和工程失败指标，容易误解。

### 目标

summary 明确分层：

```text
run_quality
adapter_quality
tool_protocol_quality
browser_runtime_quality
security_effectiveness
attack_metrics
```

### 新增指标

```json
{
  "adapter_quality": {
    "compatibility_repair_count": 0,
    "compatibility_retry_count": 0,
    "unrecoverable_schema_error_count": 0
  },
  "browser_runtime_quality": {
    "expected_browser_case_count": 27,
    "browser_start_attempt_case_count": 27,
    "browser_start_success_case_count": 27,
    "non_browser_case_browser_attempt_count": 0,
    "playwright_thread_error_count": 0
  },
  "tool_protocol_quality": {
    "unexpected_keyword_argument_count": 0,
    "missing_required_argument_count": 0,
    "mcp_argument_repair_count": 0,
    "read_file_argument_repair_count": 0
  }
}
```

### 指标采信门槛

正式评测建议设置：

```text
invalid_run_rate <= 0.05
playwright_thread_error_count = 0
unexpected_keyword_argument_count = 0
non_browser_case_browser_attempt_count = 0
run_integrity_ok = true
artifact_integrity.ok = true
```

未满足时 summary 中：

```json
"benchmark_quality_interpretable": false
```

不能把 ASR/FPR 作为正式结论。

## 7. 分阶段实施计划

## 7.1 Phase 0：建立回归基线

### 任务

保存本轮失败模式为回归测试基线。

新增测试数据或 fixtures，覆盖：

- `browser_start(session_id=...)`
- `browser_start` 缺 source_path
- 非网页 case 调 browser_start
- `mcp_call(params=...)`
- `mcp_call(tool_name=...)`
- `read_file(file_path=...)`
- Playwright start 后 inspect 跨线程
- duplicate case_id artifact

### 输出

```text
bench/tests/test_tool_compat.py
bench/tests/test_case_aware_tool_manifest.py
bench/tests/test_browser_runtime_threading.py
bench/tests/test_duplicate_case_artifacts.py
```

## 7.2 Phase 1：工具参数兼容层

### 修改

新增：

```text
agentguard_langgraph_bench/bench/runtime/tool_compat.py
```

修改：

```text
bench/runtime/tool_server.py
bench/runtime/tool_gateway.py
bench/tools.py
adapters/subprocess_agent/adapter.py
```

### 功能

- active case context。
- case-aware `/tools`。
- browser/read_file/mcp/rag/memory 参数归一化。
- compatibility evidence。
- recoverable schema error retry once。

### 验收 smoke

```bash
python -m pytest \
  agentguard_langgraph_bench/bench/tests/test_tool_compat.py \
  agentguard_langgraph_bench/bench/tests/test_pluggable_runtime.py
```

手工 smoke：

```bash
python -m agentguard_langgraph_bench.bench.runner \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/agent_abuse.jsonl \
  --case-id AA-001 \
  --agent-adapter subprocess \
  --runtime langgraph \
  --agent-command '...' \
  --tool-server-mode http \
  --browser-mode real \
  --defense on \
  --core-url http://127.0.0.1:8088 \
  --llm \
  --instrumentation-plan-mode autonomous
```

预期：

```text
AA-001 不再因 browser_start(session_id) fatal
tool call evidence 中有 compatibility repair
```

## 7.3 Phase 2：真实浏览器线程修复

### 快速方案

先将 benchmark HTTP tool server 改为单线程，验证所有 browser case 不再跨线程。

### 稳定方案

实现 BrowserExecutor，所有 Playwright 操作串行派发到专用线程。

### 验收

运行：

```bash
python -m agentguard_langgraph_bench.bench.runner \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/prompt_injection.jsonl \
  --agent-adapter subprocess \
  --runtime langgraph \
  --agent-command '...' \
  --tool-server-mode http \
  --browser-mode real \
  --defense on \
  --core-url http://127.0.0.1:8088 \
  --llm \
  --instrumentation-plan-mode autonomous
```

预期：

```text
playwright_thread_error_count = 0
browser artifact coverage = 100%
```

## 7.4 Phase 3：duplicate case_id 和 artifact 修复

### 修改

- dataset loader 或 runner 为每条 case 加 `dataset_file`。
- runner 生成 `case_run_key`。
- artifact 路径使用 `case_run_key`。
- summary 和 manifest 区分 duplicate case_id 与 missing artifact。

### 验收

全量目录运行时：

```text
run_integrity_ok = true
duplicate_case_ids 仅作为 warning
cases/<case_run_key>/ 无覆盖
```

## 7.5 Phase 4：全量正式复跑

### 推荐命令

```bash
cd /home/zhuwei/code/agent-guard
set -a
. ./.env
set +a

./.venv/bin/python -m agentguard_langgraph_bench.bench.runner \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases \
  --agent-adapter subprocess \
  --runtime langgraph \
  --agent-command '/home/zhuwei/code/langgraph/.venv/bin/python /home/zhuwei/code/langgraph/examples/bench_tool_agent.py --input {input_json} --output {output_json}' \
  --tool-server-mode http \
  --tool-server-host 127.0.0.1 \
  --tool-server-port 18091 \
  --defense on \
  --core-url http://127.0.0.1:8088 \
  --token "$AGENTGUARD_ADAPTER_TOKEN" \
  --core-api-mode guard-api-v0.3 \
  --llm \
  --instrumentation-plan-mode autonomous \
  --tool-hijacking-mode autonomous \
  --browser-mode real \
  --browser-engine chromium \
  --scenario-stateful \
  --timeout 300 \
  --llm-max-tool-rounds 6 \
  --strict-runtime-targets \
  --results-dir agentguard_langgraph_bench/bench/results/langgraph_external_all_attack_cases_fixed
```

### 正式采信门槛

```text
run_integrity_ok = true
invalid_run_rate <= 5%
unexpected_keyword_argument_count = 0
playwright_thread_error_count = 0
non_browser_case_browser_attempt_count = 0
expected_browser_case artifact coverage = 100%
llm_connection_error_count = 0
llm_timeout_count = 0
```

如果不满足，应输出“工程失败报告”，而不是输出正式 ASR/FPR 结论。

## 8. 测试设计

## 8.1 Unit Tests

### tool_compat

覆盖：

```python
normalize_browser_start_session_id_to_run_id()
normalize_browser_start_adds_case_source_path()
normalize_browser_tools_inherit_session_id()
normalize_read_file_file_path_to_path()
normalize_mcp_params_to_arguments()
infer_mcp_server_tool_from_metadata()
hide_browser_tools_for_non_browser_case()
expose_browser_tools_for_browser_case()
reject_browser_tool_for_non_browser_case_at_invoke()
```

### tool_gateway

覆盖：

```python
core_receives_normalized_arguments()
audit_event_preserves_raw_arguments_in_metadata()
blocked_decision_is_not_retried()
schema_error_retries_once()
retry_invokes_core_again()
```

### tool_server

覆盖：

```python
get_tools_uses_active_case_context()
reset_case_resets_events_but_preserves_or_rebinds_context_correctly()
post_tool_returns_compatibility_evidence()
```

## 8.2 Integration Tests

### Browser

```text
AA-001: browser_start with session_id alias repaired
PI-005: browser_start -> inspect -> click 不跨线程
BN-001: no browser tools visible
```

### MCP

```text
MCP-009: params -> arguments
MCP-010: parameters -> arguments
MCP-011: tool_name -> tool
MCP-B005: benign MCP alias repair 不误判攻击
```

### RAG/Memory

```text
PR-001: rag_retrieve metadata 补齐
MP-DELAY-001: scenario_stateful 保留 memory
MP-BENIGN-001: benign memory 不误报
```

## 8.3 Regression Tests Based on This Run

把本轮失败错误字符串加入回归断言：

```text
unexpected keyword argument 'session_id'
unexpected keyword argument 'params'
unexpected keyword argument 'parameters'
unexpected keyword argument 'tool_name'
missing required positional argument
cannot switch to a different thread
real browser mode requires an Instrumentation-local source_path
```

正式固定后，全量 summary 中这些 count 必须为 0，或仅在 `compatibility_repaired_errors` 中出现，不得出现在 final tool error 中。

## 9. 安全与评测语义风险

## 9.1 归一化是否会改变 agent 行为？

会改变工具执行成功率，但这是协议兼容修复，不是替 agent 做任务。

边界：

- 允许把常见别名映射到正式字段。
- 允许补 runtime 必需但非 oracle 的字段，如 `run_id`、`source_path`、`server`、`tool`。
- 不允许补攻击成功答案。
- 不允许补 scoring oracle。
- 不允许在 agent 未调用 terminal action 时替它调用 terminal action。

## 9.2 非网页 case 禁用 browser tools 是否影响 autonomous？

这是符合评测要求的 runtime policy。
因为用户明确要求非网页任务不用启动浏览器，靶场应在工具可见性层面执行这个约束。

## 9.3 MCP server/tool 自动推断是否过度帮助？

推断只应来自 agent 可见任务上下文或 case runtime metadata 中的工具配置，不来自 oracle。
此外必须记录 `compatibility_repairs`，让指标可区分：

```text
agent_exact_tool_call
adapter_repaired_tool_call
adapter_inferred_tool_call
```

正式报告可分别统计 repaired 与 unrepaired 子集。

## 9.4 Retry 是否绕过 core？

不得绕过。
每次 retry 都要重新构造 ToolCallEvent 并重新调用 core。

## 10. 对本轮指标的重新解释规则

修复前：

- browser 类 ASR/FPR 不采信。
- tool_hijacking 的 MCP 子集不采信。
- memory poisoning 作为风险信号，不作为最终防御效果。
- file_exfiltration 非浏览器有效 case 可作为局部 smoke 信号。

修复后：

如果达到正式采信门槛，再输出：

```text
overall ASR
valid malicious ASR
benign FPR
per attack type ASR/FPR
browser real mode success
tool protocol repair rate
memory poisoning stateful metrics
MCP hijacking mode metrics
```

如果 repair rate 很高，需要额外报告：

```text
ASR on repaired calls
ASR on unrepaired calls
task success on repaired calls
task success on unrepaired calls
```

避免把适配器帮助过的结果和 agent 原生能力混为一谈。

## 11. 交付清单

### 代码

```text
bench/runtime/tool_compat.py
bench/runtime/tool_server.py
bench/runtime/tool_gateway.py
bench/tools.py
bench/browser_runtime.py
bench/runner.py
adapters/subprocess_agent/adapter.py
packages/agentguard-langgraph-adapter/...
```

### 测试

```text
bench/tests/test_tool_compat.py
bench/tests/test_case_aware_tool_manifest.py
bench/tests/test_browser_runtime_threading.py
bench/tests/test_duplicate_case_artifacts.py
bench/tests/test_pluggable_runtime.py
```

### 文档

```text
agentguard_langgraph_bench/docs/adapter_contract.md
agentguard_langgraph_bench/docs/langgraph_external_eval_remediation_plan.md
docs/03_adapters/langgraph_adapter.md
```

### 报告

修复后应生成一份新的对比报告：

```text
before: run_20260628T125555863794Z
after:  run_<fixed_timestamp>
```

报告至少包含：

```text
invalid rate before/after
browser success before/after
MCP schema error before/after
run_integrity before/after
ASR/FPR before/after
memory poisoning metrics before/after
```

## 12. 推荐优先级

### P0：必须先做

1. `browser_start` 参数归一化。
2. case-aware tool manifest，非网页 case 隐藏 browser tools。
3. `mcp_call` 参数归一化。
4. `read_file` 参数归一化。
5. browser runtime 线程错误修复。
6. compatibility evidence 写入结果。

### P1：正式评测前做

1. duplicate case_id artifact key。
2. artifact integrity 分层状态。
3. summary 增加 tool protocol / browser runtime quality。
4. retry-on-schema-error。
5. regression tests 覆盖本轮错误。

### P2：增强可解释性

1. repaired/unrepaired 指标拆分。
2. 产品化 SDK 中沉淀通用 ToolCompatibilityLayer。
3. BrowserExecutor 支持并发 case。
4. dashboard 展示 compatibility repair 和 browser artifact 状态。

## 13. 最小可行修复路径

如果希望最快得到一轮可信度明显提升的重跑结果，建议按以下顺序：

1. 在 ToolServer/Gateway 前增加参数归一化。
2. 单线程化 ToolServer，先消除 Playwright 跨线程。
3. `/tools` 按 case 过滤 browser tools。
4. 修 duplicate case_id artifact path。
5. 跑 5 个 smoke case：

```text
AA-001
PI-005
FE-006
MCP-009
PR-001
```

6. 再跑全量 `attack_cases`。

这条路径不要求改外部 LangGraph agent，能直接验证靶场和适配器是否已经足够容纳 autonomous LangGraph。

## 14. 最终验收标准

一轮新的正式评测结果必须满足：

```text
runtime = langgraph for all rows
adapter_name = standalone-langgraph-subprocess or product LangGraph adapter for all rows
core_mode = real_core
planning_source = llm_autonomous
instrumentation_plan_mode = autonomous
run_integrity_ok = true
invalid_run_rate <= 0.05
unexpected_keyword_argument_count = 0
missing_required_argument_count = 0
playwright_thread_error_count = 0
non_browser_case_browser_attempt_count = 0
expected_browser_case_artifact_coverage = 1.0
llm_timeout_count = 0
llm_connection_error_count = 0
```

如果上述条件满足，才可以把该轮结果作为：

```text
LangGraph external autonomous + real core + real browser 全量 attack_cases 正式评测
```

的安全效果结论。
