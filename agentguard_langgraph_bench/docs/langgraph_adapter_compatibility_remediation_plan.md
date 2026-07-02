# LangGraph Adapter 协议兼容修复方案

## 1. 目标

本方案针对 test3 中真实 LangGraph 外部评测暴露的高无效率，尽量把修复压在 `agentguard-langgraph-adapter` 和其外层兼容包装上，不改动靶场评分逻辑，也不改动靶场 case 定义。

核心目标有三个：

1. 保持外部 LangGraph agent 仍然真实调用 LLM。
2. 保持网页 case 真实启动浏览器，非网页 case 不启动浏览器。
3. 让工具协议、参数别名、浏览器会话绑定、结果元数据在 adapter 层统一收口，减少无效评测。

## 2. test3 暴露的问题

test3 的主问题不是 core 没接上，而是外部 LangGraph 规划链路和靶场工具协议存在语义偏差。

典型表现：

- `browser_start` / `browser_input` / `browser_click` 的参数别名不一致。
- `browser_start` 常把 `session_id` 当作浏览器会话主键，而靶场语义更偏向 `run_id`。
- `browser_navigate` / `browser_extract_text` / `browser_inspect` 在 autonomous 输出里常带 `target`、`href`、`text` 等别名。
- `read_file`、`write_file`、`mcp_call`、`rag_*` 也会出现同类 schema 漂移。
- 外部 LangGraph 输出有时缺少终止动作，或者给出非标准 final answer 结构。
- 某些浏览器 case 依赖真实浏览器 session 绑定，但外部 planner 并不会稳定记住 session 语义。

## 3. 根因分层

### 3.1 agent 层

外部 `bench_tool_agent.py` 依赖 LLM 自主规划，但它本身并不知道靶场内部的 case-aware 工具约束。

### 3.2 adapter 层

这是最应该修的地方。adapter 负责：

- 工具 manifest 的可见性控制。
- 工具参数归一化。
- 兼容别名映射。
- ToolCallEvent / AuditEvent 元数据保留。
- 对 recoverable schema 错误的重试。

### 3.3 靶场层

靶场负责评分和真实执行，不应该为了 adapter 的适配问题改动核心判定。

## 4. 已实施的 adapter 修复

### 4.1 SDK 侧兼容层

新增 `packages/agentguard-langgraph-adapter/agentguard_langgraph_adapter/tool_compat.py`，提供：

- case-aware tool visible manifest。
- browser/file/MCP/RAG/memory/tool exec 参数归一化。
- recoverable error 重试判定。
- runtime policy block 结果。

### 4.2 事件保留

`ToolExecutionResult` 已补充：

- `compatibility`
- `compatibility_retry`
- `runtime_policy_blocked`

这样运行结果不会只在事件 metadata 里留痕。

### 4.3 gateway / node 收口

`GuardedToolGateway` 现在会把 raw arguments、normalized arguments、compatibility metadata 一并传给 Core 事件和结果对象。

`SecureToolNode` 现在在调用前先做参数归一化，再按浏览器 case policy 决定是否放行。

### 4.4 外部 LangGraph 包装器

新增 `scripts/langgraph_adapter_wrapper.py`，作用是：

- 读取外部 LangGraph 脚本，但不改它本体。
- 在运行时补工具可见性和参数归一化。
- 尽量把 planner 的 JSON 输出拉回到统一形态。
- 处理 recoverable schema error 的单次重试。

这一步很关键，因为当前 `bench_tool_agent.py` 并没有直接 import SDK。

## 5. 为什么只改 adapter 仍然不够

有些问题不是 adapter 能独立解决的：

- Playwright Sync API 的线程亲和性问题。
- 外部 agent 自己的 planner 停止条件。
- 外部 agent 彻底不输出工具调用。

这些问题最多只能被 adapter 缓解，不能凭空修正外部 agent 的逻辑缺陷。

所以本方案的现实预期是：

1. 大量 `unexpected keyword argument`、`missing required positional argument`、`session_id/run_id` 偏差会明显下降。
2. 非网页 case 误起浏览器会下降。
3. `planner_no_output` 这类问题会减少，但不会彻底消失。
4. 真正的浏览器线程问题如果继续出现，仍需要浏览器 runtime 侧再修一轮。

## 6. 验证计划

先做两层验证：

1. 纯协议层验证。
2. 小样本真实 runner 验证。

建议最小样本：

- `BN-001`
- `FE-001`
- `PI-001`

验证点：

- `browser_start` 的 `session_id` 是否会归一到 `run_id`。
- `browser_input` 的 `target/text` 是否会归一到 `selector/value`。
- `browser_navigate` 是否能接受 `href/target/path` 别名。
- 结果里是否记录 `compatibility` 和 `compatibility_retry`。

## 7. 推荐运行方式

如果继续沿用外部 LangGraph 脚本，建议通过 wrapper 启动：

```bash
python /home/zhuwei/code/agent-guard/scripts/langgraph_adapter_wrapper.py \
  --agent-path /home/zhuwei/code/langgraph/examples/bench_tool_agent.py \
  --input {input_json} \
  --output {output_json}
```

这能在不改外部 agent 文件的前提下，把 adapter 能做的协议修复先接上。

## 8. 后续迭代优先级

如果小样本验证后仍有明显 invalid run：

1. 优先补 browser runtime 的 session / thread 稳定性。
2. 再补 planner 输出解析的容错。
3. 最后才考虑改外部 agent 的 prompt 或 graph 结构。

