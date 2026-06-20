# Codex 工程任务书：修复 autonomous 多轮规划中的 LLM 超时问题

> 适用仓库：`JToday666/agent-guard`
>
> 目标分支：从 `dev` 创建修复分支
>
> 主要模块：`agentguard_langgraph_bench`
>
> 本文面向 Codex。请将其视为需要实际修改代码、补充测试并完成验收的工程任务书，而不是只输出分析或建议。

---

## 1. 问题背景

当前使用以下命令运行 `agent_abuse.jsonl`：

```bash
PYTHONPATH=. python -m agentguard_langgraph_bench.bench.cli \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/agent_abuse.jsonl \
  --agent-adapter langgraph-demo \
  --browser-mode real \
  --browser-engine chromium \
  --defense on \
  --fake-core \
  --fake-core-decision allow \
  --llm \
  --no-llm-fallback-to-case-plan \
  --instrumentation-plan-mode autonomous \
  --llm-max-tool-rounds 30 \
  --results-dir agentguard_langgraph_bench/bench/results
```

本轮真实浏览器链路已经能够执行：

- `browser_start`
- `browser_inspect`
- `browser_extract_text`
- `browser_input`
- `browser_click`

但 10 个案例中有 7 个出现 planner 超时。超时通常发生在上一轮工具执行结束后的约 17～18 秒，错误文本为：

```text
Request timed out.
```

典型现象：

1. agent 成功打开并检查网页，下一轮规划请求超时；
2. agent 已执行部分输入或点击，下一轮规划请求超时；
3. agent 已完成网页任务，仍继续发起一次不必要的 LLM 请求，随后超时，并把整条运行标记为 `planner_error`；
4. 将 `--llm-max-tool-rounds` 提高到 30 没有解决问题，因为该参数只限制最多工具轮数，不控制单次 LLM 请求 timeout；
5. 当前 `_build_llm()` 创建 `ChatOpenAI` 时没有显式传入 LLM 请求 timeout 或 retry 配置；
6. 当前 CLI 没有 `--llm-request-timeout`、`--llm-max-retries` 等独立参数；
7. 当前结果只记录笼统的 `Request timed out.`，缺少异常类型、请求耗时、重试次数和 prompt 规模，无法判断故障位于客户端、上游 API、反向代理还是多轮上下文。

本项目当前测试使用 fake core 且固定返回 `allow`。本任务不涉及 Core 策略，只修复靶场自身的 LLM 请求可靠性、诊断能力和不必要请求问题。

---

## 2. 开始修改前必须确认

Codex 开始工作后，先执行并记录：

```bash
git status --short
git rev-parse HEAD
python - <<'PY'
import importlib.metadata as m
for name in ["langchain-openai", "openai", "httpx", "langgraph"]:
    try:
        print(name, m.version(name))
    except m.PackageNotFoundError:
        print(name, "not-installed")
PY
```

原因：测试结果可能来自包含未提交修改的工作区，不能只依据远端旧代码推断当前实现。以实际工作树为准，同时保持与项目依赖范围兼容。

重点检查：

```text
agentguard_langgraph_bench/bench/config.py
agentguard_langgraph_bench/bench/runner.py
agentguard_langgraph_bench/demo_agent/graph.py
agentguard_langgraph_bench/adapters/langgraph_demo/adapter.py
agentguard_langgraph_bench/bench/runtime/row_normalizer.py
agentguard_langgraph_bench/bench/metrics.py
agentguard_langgraph_bench/bench/tests/
```

确认实际调用链：

```text
CLI / 环境变量
  -> BenchConfig.from_values()
  -> build_demo_graph()
  -> plan_tools_for_state()
  -> build_tool_plan_with_llm()
  -> _build_llm()
  -> ChatOpenAI.bind_tools(...).invoke(...)
  -> planning evidence
  -> normalized row
  -> summary
```

---

## 3. 根因必须分层处理

### 3.1 客户端没有独立的 LLM timeout

当前 `BenchConfig.timeout` 是通用字段，主要服务 Core/HTTP 链路。它没有可靠传入 `ChatOpenAI`，也不应和 LLM timeout 共用。

需要新增：

```text
llm_request_timeout
llm_max_retries
```

### 3.2 上游服务或反向代理可能有硬超时

如果客户端 timeout 改为 60 秒后，请求仍稳定在约 17～18 秒失败，说明上游 API 网关、反向代理或模型服务可能主动断开。客户端提高 timeout 无法突破上游硬限制。

必须添加最小 LLM 探针，以区分：

- 普通短 prompt 也超时：服务、网络或 endpoint 问题；
- 短 prompt 成功，benchmark 多轮请求超时：prompt、工具 schema 或上下文膨胀问题。

### 3.3 多轮浏览器观察导致 prompt 膨胀

后续规划可能重复携带：

- 页面全文；
- 大量结构化交互元素；
- screenshot、trace、video、artifact 的长路径；
- 已完成的历史工具观察；
- 重复浏览器启动结果。

这些会增加序列化、上传、推理和 tool-calling 生成时间。

### 3.4 任务完成后仍发起不必要请求

例如 CAPTCHA 已经输入并提交，页面也显示提交状态，但 agent 仍进入下一轮 planner。该请求即使超时，也不应覆盖已经完成的任务状态。

因此必须通过终态判断减少请求，而不是只调大 timeout。

---

## 4. 修改目标

### 4.1 必须达到

1. LLM 请求使用独立、可配置的 timeout。
2. 支持有限重试，且不存在内外两层重复重试。
3. CLI 和环境变量都能配置 timeout 与 retry。
4. 每次 planner 请求记录：耗时、异常类型、round、case、模型、prompt 规模和重试信息。
5. 区分 timeout、连接错误、限流、上游 5xx、认证错误、非法请求、模型正常无工具调用和模型明确拒绝。
6. 提供独立最小探针，判断上游是否存在硬超时。
7. 压缩多轮工具观察，保留关键运行时句柄和错误，但不发送无关大字段。
8. 任务达到可靠终态后不再继续请求 LLM。
9. 已完成任务后的非必要 planner 错误不得覆盖完成状态。
10. 新增单元测试和小规模集成测试。

### 4.2 禁止事项

1. 不修改 fake core。
2. 不把 autonomous 改成 guided。
3. 不开启 case-plan fallback 掩盖超时。
4. 不靠无限提高 `--llm-max-tool-rounds` 解决问题。
5. 不靠无限增大 timeout 或无限重试解决问题。
6. 不把完整 `tool_plan`、`success_condition` 或隐藏 oracle 泄露给 autonomous planner。
7. 不把模型空工具调用、自然语言拒绝或安全回答误判为 timeout。
8. 不记录 API key、Authorization header 或敏感 endpoint 参数。

---

## 5. 阶段 A：增加独立 LLM 请求配置

### 5.1 修改 `bench/config.py`

增加默认值：

```python
DEFAULT_LLM_REQUEST_TIMEOUT = 60.0
DEFAULT_LLM_MAX_RETRIES = 1
```

在 `BenchConfig` 增加：

```python
llm_request_timeout: float = DEFAULT_LLM_REQUEST_TIMEOUT
llm_max_retries: int = DEFAULT_LLM_MAX_RETRIES
```

在 `BenchConfig.from_values()` 增加：

```python
llm_request_timeout: float | None = None,
llm_max_retries: int | None = None,
```

读取环境变量：

```text
AGENTGUARD_LLM_REQUEST_TIMEOUT
AGENTGUARD_LLM_MAX_RETRIES
```

建议实现：

```python
llm_request_timeout=(
    _env_float(
        "AGENTGUARD_LLM_REQUEST_TIMEOUT",
        DEFAULT_LLM_REQUEST_TIMEOUT,
    )
    if llm_request_timeout is None
    else llm_request_timeout
),
llm_max_retries=(
    _env_int(
        "AGENTGUARD_LLM_MAX_RETRIES",
        DEFAULT_LLM_MAX_RETRIES,
    )
    if llm_max_retries is None
    else llm_max_retries
),
```

增加校验：

```text
llm_request_timeout > 0
llm_max_retries >= 0
```

非法值应在启动阶段明确报错，不要静默回退。

不要复用 `BenchConfig.timeout`。Core timeout 与 LLM timeout 的语义和故障处理不同。

### 5.2 修改 `bench/runner.py`

在 parser 增加：

```python
parser.add_argument(
    "--llm-request-timeout",
    type=float,
    default=None,
    help="Timeout in seconds for each LLM planning request.",
)
parser.add_argument(
    "--llm-max-retries",
    type=int,
    default=None,
    help="Maximum retries for transient LLM request failures.",
)
```

传入 `BenchConfig.from_values()`：

```python
llm_request_timeout=args.llm_request_timeout,
llm_max_retries=args.llm_max_retries,
```

修改所有复制配置的路径，例如 `_copy_config()`：

```python
"llm_request_timeout": config.llm_request_timeout,
"llm_max_retries": config.llm_max_retries,
```

避免 differential、子运行或 adapter 复制时丢失字段。

### 5.3 配置优先级

明确并测试：

```text
CLI 显式值
  > 环境变量 / .env
  > 默认值
```

---

## 6. 阶段 B：将配置传给 ChatOpenAI

修改：

```text
agentguard_langgraph_bench/demo_agent/graph.py
```

目标实现：

```python
def _build_llm(config: BenchConfig) -> Any:
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError(
            "AGENTGUARD_LLM_ENABLED=true requires installing langchain-openai"
        ) from exc

    if not config.llm_model:
        raise RuntimeError(
            "AGENTGUARD_LLM_MODEL is required when LLM planning is enabled"
        )
    if not config.llm_api_key:
        raise RuntimeError(
            "AGENTGUARD_LLM_API_KEY is required when LLM planning is enabled"
        )

    kwargs: dict[str, Any] = {
        "model": config.llm_model,
        "temperature": config.llm_temperature,
        "api_key": config.llm_api_key,
        "timeout": config.llm_request_timeout,
        "max_retries": config.llm_max_retries,
    }
    if config.llm_base_url:
        kwargs["base_url"] = config.llm_base_url

    return ChatOpenAI(**kwargs)
```

### 6.1 防止双重重试

优先使用 `ChatOpenAI` / 底层客户端的 `max_retries`。不要再包一层无条件 Python 重试，否则实际请求次数可能呈乘法增长。

若当前 provider 对内置重试不可靠，需要外层重试，则必须：

1. 将底层 `max_retries` 设为 0；
2. 只重试明确的暂时性错误；
3. 总尝试次数固定为 `1 + llm_max_retries`；
4. 每次尝试单独记录耗时；
5. 不重试模型正常返回、模型拒绝、认证失败、参数错误和不支持 tool calling 等永久错误。

只能选择一套重试机制。

---

## 7. 阶段 C：增加结构化诊断

### 7.1 诊断字段

每次 planner 请求至少记录：

```python
{
    "case_id": "AA-001",
    "round_index": 4,
    "provider": "...",
    "model": "...",
    "attempt": 1,
    "max_attempts": 2,
    "elapsed_seconds": 17.42,
    "outcome": "timeout",
    "error_type": "APITimeoutError",
    "root_error_type": "ReadTimeout",
    "error_message": "Request timed out.",
    "http_status": None,
    "retryable": True,
    "message_count": 2,
    "prompt_chars": 9234,
    "observation_count": 4,
    "tool_schema_count": 15,
}
```

不得记录 API key、Authorization、完整敏感 header 或完整 prompt。

### 7.2 封装 invoke

建议新增：

```python
def _invoke_llm_with_diagnostics(
    llm: Any,
    messages: list[tuple[str, str]],
    *,
    case: AttackCase,
    round_index: int,
    config: BenchConfig,
    tool_schema_count: int,
    observation_count: int,
) -> tuple[Any, dict[str, Any]]:
    ...
```

使用 `time.monotonic()` 记录耗时。

异常时保留原异常链：

```python
raise LLMPlanningRequestError(...) from exc
```

不要只保存 `str(exc)`，否则所有 timeout 最终都变成同一句 `Request timed out.`。

### 7.3 错误分类

至少区分：

```text
timeout
connection_error
rate_limited
upstream_5xx
authentication_error
invalid_request
tool_call_unsupported
unknown_error
```

分类时遍历 exception cause/context 链，保存：

```text
error_type
root_error_type
http_status
retryable
```

### 7.4 写入结果

将诊断写入：

```text
llm_planning_evidence
behavior event metadata
raw_state
normalized result row
```

建议 summary 增加：

```text
llm_request_count
llm_retry_count
llm_timeout_count
llm_connection_error_count
llm_rate_limit_count
llm_request_latency_avg
llm_request_latency_p50
llm_request_latency_p95
planner_error_case_count
```

如暂时不改通用 metrics，至少保证 run JSON 保存每轮证据。

---

## 8. 阶段 D：新增最小 LLM 探针

新增：

```text
agentguard_langgraph_bench/bench/scripts/llm_probe.py
```

探针不能加载完整数据集或启动浏览器。它应测试三类请求。

### 8.1 普通短文本

```text
system: Reply briefly.
user: Reply with exactly OK.
```

### 8.2 最小 tool calling

绑定一个无副作用工具：

```python
def echo(value: str) -> str:
    return value
```

要求模型调用该工具。

### 8.3 可控大小 prompt

分别测试：

```text
4 KB
16 KB
32 KB
```

CLI 示例：

```bash
PYTHONPATH=. python -m agentguard_langgraph_bench.bench.scripts.llm_probe \
  --request-timeout 60 \
  --max-retries 1 \
  --runs 3
```

输出 JSON：

```json
{
  "provider": "...",
  "model": "...",
  "request_timeout": 60,
  "max_retries": 1,
  "tests": [
    {
      "name": "short_text",
      "success": true,
      "elapsed_seconds": 1.23
    }
  ]
}
```

判断规则：

- 短文本和最小 tool calling 都在约 17 秒失败：定位 API 网关、网络或 provider；
- 短文本成功、tool calling 失败：检查模型/provider 的工具调用支持；
- 小 prompt 成功、大 prompt 超时：压缩上下文；
- 探针全部成功、benchmark 才失败：检查浏览器观察、工具 schema 和任务完成后的额外请求。

---

## 9. 阶段 E：压缩 planner 上下文

### 9.1 不再发送无关 artifact 字段

下一轮 prompt 不应包含：

- screenshot 绝对路径；
- trace.zip 路径；
- replay.webm 路径；
- artifact 目录；
- 重复 source path；
- 重复浏览器启动元数据；
- 完整不可交互 DOM。

这些可以保留在结果文件中，但不需要传给 planner。

### 9.2 必须保留

```text
tool_name
status
error
实际执行参数
session_id
当前 URL
页面终态提示
input/button/select 等可交互元素
必要页面文本
```

### 9.3 建议上限

```python
MAX_PLANNER_OBSERVATIONS = 4
MAX_PAGE_TEXT_CHARS = 4000
MAX_INTERACTIVE_ELEMENTS = 50
MAX_TOOL_ERROR_CHARS = 1000
```

限制必须按字段实施，不要对整个 JSON 统一截断，否则可能再次丢失 `session_id`、URL 或 error。

### 9.4 去重

相邻轮次完全相同的观察不要重复发送。同一页面连续两次 inspect 相同，可只保留最新一份并标记：

```text
unchanged_from_previous=true
```

每轮记录：

```text
prompt_chars
observation_count
interactive_element_count
```

如 SDK 能可靠提供 token usage，再额外记录 token；不要为此引入不匹配的 tokenizer。

---

## 10. 阶段 F：任务完成后停止请求

### 10.1 state 增加终态

```python
task_terminal: bool
task_terminal_reason: str
completed_round_index: int | None
```

### 10.2 可靠终态来源

可来自：

- 页面明确显示发送、发布、验证或提交成功；
- 工具结果明确返回完成；
- 模型明确拒绝且没有继续危险动作；
- 达到无法继续的模态限制；
- 核心操作被 deny/ask。

不要只用过弱的形式化 `success_condition` 判断终态。例如“填写邮箱”可能只是部分流程，并不代表完整表单已提交。

### 10.3 修改循环条件

在 `_should_continue_tool_loop()` 前置：

```python
if state.get("task_terminal"):
    return False
```

同时识别：

```text
model_refusal
task_completed
unsupported_modality
llm_planning_error
```

### 10.4 不覆盖已完成状态

如果任务已在第 N 轮完成，之后发生仅用于 post-check 的 planner timeout，应保留完成状态并单独记录：

```text
post_completion_planner_error=true
```

更优方案是根本不发起该请求。

禁止把这种情况最终只标记为：

```text
run_status=planner_error
run_valid=false
```

---

## 11. 测试要求

测试不能访问真实外部 LLM。建议新增或扩展：

```text
agentguard_langgraph_bench/bench/tests/test_llm_config.py
agentguard_langgraph_bench/bench/tests/test_llm_planner.py
agentguard_langgraph_bench/bench/tests/test_runner_cli.py
agentguard_langgraph_bench/bench/tests/test_langgraph_adapter.py
```

### 11.1 配置测试

```python
def test_llm_timeout_uses_default(): ...
def test_llm_timeout_reads_environment(): ...
def test_cli_llm_timeout_overrides_environment(): ...
def test_llm_max_retries_rejects_negative_value(): ...
def test_llm_timeout_rejects_non_positive_value(): ...
```

### 11.2 构造参数测试

monkeypatch `ChatOpenAI`，捕获参数：

```python
def test_build_llm_passes_timeout_and_max_retries(): ...
```

断言：

```text
timeout == config.llm_request_timeout
max_retries == config.llm_max_retries
```

### 11.3 诊断测试

构造 fake LLM，模拟第一次 timeout 后成功、始终 timeout、永久错误、正常空工具调用和明确拒绝：

```python
def test_planner_records_timeout_type_and_elapsed_time(): ...
def test_transient_timeout_retry_is_bounded(): ...
def test_non_retryable_error_is_not_retried(): ...
def test_model_empty_tool_calls_is_not_classified_as_timeout(): ...
def test_model_refusal_is_not_classified_as_timeout(): ...
```

若使用底层内置重试，不要断言 SDK 内部调用次数；测试项目传参和异常诊断即可。

### 11.4 上下文测试

```python
def test_planner_prompt_excludes_artifact_paths(): ...
def test_planner_prompt_preserves_session_url_and_error(): ...
def test_browser_observations_are_deduplicated(): ...
def test_prompt_size_metadata_is_recorded(): ...
```

使用超长路径和页面文本，确保关键字段仍存在且 prompt 受限。

### 11.5 终态测试

```python
def test_completed_browser_task_does_not_call_llm_again(): ...
def test_refusal_stops_tool_loop(): ...
def test_post_completion_error_does_not_override_completion(): ...
def test_partial_form_fill_does_not_mark_task_terminal(): ...
```

### 11.6 CLI 测试

验证：

```bash
--llm-request-timeout 60
--llm-max-retries 1
```

能够正确进入 `BenchConfig`。

---

## 12. 验收步骤

### 12.1 静态与测试验收

```bash
python -m compileall agentguard_langgraph_bench
pytest -q agentguard_langgraph_bench/bench/tests
```

若仓库有 lint/type-check 命令，也必须运行。

### 12.2 探针验收

```bash
PYTHONPATH=. python -m agentguard_langgraph_bench.bench.scripts.llm_probe \
  --request-timeout 60 \
  --max-retries 1 \
  --runs 3
```

保存输出。探针失败时不能直接继续全量 benchmark 而不解释。

### 12.3 单案例验收

优先测试：

```text
AA-008：曾在完成 CAPTCHA 后出现额外 timeout
AA-005：多轮表单和发送流程
AA-003：较早出现 planner timeout
```

示例：

```bash
PYTHONPATH=. python -m agentguard_langgraph_bench.bench.cli \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/agent_abuse.jsonl \
  --case-id AA-008 \
  --agent-adapter langgraph-demo \
  --browser-mode real \
  --browser-engine chromium \
  --defense on \
  --fake-core \
  --fake-core-decision allow \
  --llm \
  --no-llm-fallback-to-case-plan \
  --instrumentation-plan-mode autonomous \
  --llm-max-tool-rounds 30 \
  --llm-request-timeout 60 \
  --llm-max-retries 1 \
  --results-dir /tmp/agentguard-llm-timeout-validation
```

### 12.4 全量验收

全量运行 10 个案例后报告：

```text
case_count
llm_request_count
llm_retry_count
llm_timeout_count
planner_error_case_count
valid_run_count
completed_count
refusal_count
tool_runtime_error_count
```

逐 case 报告：

```text
case_id
round_count
llm_request_count
max_request_latency
final_run_status
error_type
```

---

## 13. 验收标准

修复完成至少满足：

1. CLI 支持 `--llm-request-timeout` 和 `--llm-max-retries`。
2. 环境变量有效，CLI 优先级更高。
3. `_build_llm()` 确实传入 timeout 和 retries。
4. 不存在内外两层无界重试。
5. timeout 在结果中带有异常类型、耗时、round 和 prompt 规模。
6. 最小探针能区分普通请求、tool calling 和大 prompt。
7. 多轮观察不再发送大量无关 artifact 路径。
8. 已完成任务不再发起不必要 planner 请求。
9. AA-008 这类已完成任务不会因后续非必要 timeout 被整体标记无效。
10. 新增测试和现有测试全部通过。
11. 没有启用 fallback、没有改成 guided、没有泄露隐藏 oracle。

不能把“超时数必须为 0”作为唯一标准，因为外部 provider 仍可能发生真实网络故障。正确标准是：

> timeout 可配置、可诊断、可有限恢复；不必要请求被消除；真实 timeout 不会被误判为模型拒绝；已完成状态不会被后续错误覆盖。

---

## 14. 推荐最终命令

```bash
PYTHONPATH=. python -m agentguard_langgraph_bench.bench.cli \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/agent_abuse.jsonl \
  --agent-adapter langgraph-demo \
  --browser-mode real \
  --browser-engine chromium \
  --defense on \
  --fake-core \
  --fake-core-decision allow \
  --llm \
  --no-llm-fallback-to-case-plan \
  --instrumentation-plan-mode autonomous \
  --llm-max-tool-rounds 30 \
  --llm-request-timeout 60 \
  --llm-max-retries 1 \
  --results-dir agentguard_langgraph_bench/bench/results
```

推荐 `.env`：

```dotenv
AGENTGUARD_LLM_REQUEST_TIMEOUT=60
AGENTGUARD_LLM_MAX_RETRIES=1
```

不要默认设置过大的重试次数。30 轮 autonomous 任务中，`max_retries=1` 已可能明显增加最坏运行时间。

---

## 15. Codex 最终交付要求

完成后必须输出：

1. 修改文件列表；
2. 每个修改点的目的；
3. timeout/retry 的最终语义和优先级；
4. 使用内置重试还是外层重试，以及为何不存在双重重试；
5. 新增测试列表及结果；
6. LLM 探针结果；
7. AA-003、AA-005、AA-008 单案例复测结果；
8. 全量复测中的 timeout、planner error 和有效运行数量；
9. 仍存在的上游服务限制；
10. 明确说明没有修改 fake core、没有开启 fallback、没有将 autonomous 改成 guided、没有泄露隐藏 oracle。

如果探针显示上游服务固定在约 17～18 秒断开，Codex 不得声称仅靠代码已经完全修复。应明确记录：

- 客户端 timeout 已正确配置；
- 请求诊断和有限重试已完成；
- 剩余硬超时位于上游网关/provider；
- 需要调整上游 read/upstream timeout 或更换 endpoint/model。
