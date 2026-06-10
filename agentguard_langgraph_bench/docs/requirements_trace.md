# 需求追踪

## 范围与审计状态

本文档是独立 LangGraph 评测靶场与适配器包的第一阶段只读审计记录：

```text
agentguard_langgraph_bench/
```

本阶段不修改 AgentGuard 平台既有代码。实现必须保留在 `agentguard_langgraph_bench/` 内，`AgentGuard_final_最终版实施文档/`、`MCPSafety/`、`Instrumentation/`、`PoisonedRAG/` 和 `skyvern/` 均作为只读来源。

## 已审计的十个最终实施文档

1. `00_项目总览与最终架构.md`
2. `01_接口契约与事件模型.md`
3. `02_Core设计与部署.md`
4. `03_LangGraph适配与评测靶场.md`
5. `04_OpenClaw插件接入与配置审计.md`
6. `05_Dashboard与审批流.md`
7. `06_AttackBench与评测指标.md`
8. `07_创新增强模块设计.md`
9. `08_Hook兼容性测试与风险缓解.md`
10. `09_实施路线与团队规范.md`

## 已审计的平台代码与文档

- `agent-guard/README.md`
- `agent-guard/docs/00_requirements/requirement_traceability_matrix.md`
- `agent-guard/docs/01_overview/architecture.md`
- `agent-guard/docs/02_core/interface_contract.md`
- `agent-guard/docs/02_core/core_design.md`
- `agent-guard/docs/02_core/threat_model.md`
- `agent-guard/docs/03_adapters/langgraph_adapter.md`
- `agent-guard/docs/05_redteam/attackbench.md`
- `agent-guard/docs/04_apps/dashboard_design.md`
- `agent-guard/docs/06_delivery/implementation_plan.md`
- `agent-guard/apps/dashboard/src/App.vue`
- `agent-guard/apps/dashboard/src/main.ts`
- `agent-guard/apps/dashboard/src/styles/main.scss`

当前仓库中主要是设计文档和最小 Vue dashboard shell。第一阶段审计时，在已跟踪的 `agent-guard` 树中没有发现已实现的 Agent Security Core backend routes、JSON Schema 文件或 Python Core package。`apps/dashboard/src/App.vue` 当前仅渲染空 `<main>`，因此 AuditEvent 和指标兼容性以文档契约为准，而不是以具体 TypeScript API model 为准。

## 已抽样的只读数据集来源

- `../MCPSafety/mcpuniverse/platform/hijacking.py`
- `../MCPSafety/mcpuniverse/platform/hijacking_gateway.py`
- `../MCPSafety/mcpuniverse/platform/configs/tool_call_hijacking_sync_agent.json`
- `../MCPSafety/mcpuniverse/platform/configs/tool_call_hijacking_submit_poll_agent.json`
- `../MCPSafety/mcpuniverse/platform/configs/tool_call_hijacking_agent_runtime_external_http.json`
- `../MCPSafety/mcpuniverse/benchmark/configs/test/*.yaml`
- `../Instrumentation/README.md`
- `../Instrumentation/A5_Credentials_and_Secrets_Leakage/EIA_A5_31_high/task.json`
- `../Instrumentation/B1_Local_File_Modification/VPI-bench_B1_41_low/task.json`
- `../Instrumentation/C4_Security_Control_Weakening/EIA_C4_1_high/task.json`
- `../Instrumentation/D1_Command_Execution/VPI-bench_D1_1/task.json`
- `../PoisonedRAG/README.md`
- `../PoisonedRAG/results/adv_targeted_results/{nq,msmarco,hotpotqa}.json`
- `../PoisonedRAG/datasets/{nq,msmarco,hotpotqa}/{corpus,queries}.jsonl`
- `../PoisonedRAG/dataset-registry/display_meta/H1_Knowledge_base_poisoning.json`

## 硬性需求追踪表

| 来源 | 需求 | 实现位置 | 测试或验收方式 |
|---|---|---|---|
| `00_项目总览与最终架构.md` | 使用“一核两壳”架构：Agent Security Core 是安全决策中心，LangGraph shell 是可控评测运行时。 | `src/agentguard_langgraph_bench/adapter.py`、`core_client.py`、`agent.py`、`runner.py` | adapter 在工具执行前调用 Core；runner 支持 defense on/off 回放 case。 |
| `00_项目总览与最终架构.md` | LangGraph shell 必须使用 LangGraph、LangChain Core、Mock Tools 和 LangGraph Adapter。 | `agent.py`、`tools.py`、`secure_tool_node.py`、`adapter.py` | demo graph smoke test 会调用 guarded LangChain Core tools。 |
| `00_项目总览与最终架构.md` | AttackBench 是评测事实和指标来源。 | `datasets/attack_cases/*.jsonl`、`dataset_loader.py`、`metrics.py`、`runner.py` | runner 输出逐 case 结果以及 ASR before/after、Block Rate、FPR。 |
| `01_接口契约与事件模型.md` | runtime 原生事件必须由 adapter 映射为统一 AgentGuard 事件；Core 不理解 LangGraph 原始 state。 | `adapter.py`、`models.py` | 单测校验 ToolCallEvent 从工具名、参数、security context 和 derived resources 构造。 |
| `01_接口契约与事件模型.md` | 所有 Core 调用必须携带 `Authorization: Bearer <AGENTGUARD_TOKEN>`。 | `core_client.py` | Core client 测试断言 evaluate 和 audit 请求都带 Authorization header。 |
| `01_接口契约与事件模型.md` | 工具执行前检查接口为 `POST /v1/evaluate/tool-call`。 | `core_client.py` | mock Core 或 HTTP 测试校验路由与 payload。 |
| `01_接口契约与事件模型.md` | 审计提交接口为 `POST /v1/audit/event`。 | `core_client.py`、`adapter.py` | mock Core 或 HTTP 测试校验路由与 audit payload。 |
| `01_接口契约与事件模型.md` | ToolCallEvent 包含 schema version、event id/type、runtime、trace id、case id、attack type、恶意标记、timestamp、security context、tool、arguments、derived resources、pre-execution 和 metadata。 | `models.py`、`adapter.py` | `test_tool_call_event.py` 校验必需字段和 `pre_execution=true`。 |
| `01_接口契约与事件模型.md`、`agent-guard/docs/02_core/interface_contract.md` | 最终文档使用 `schema_version: "0.3"` 和 `event_type: "tool_call_proposed"`；当前平台 P0 契约使用 `schema_version: "0.1"` 和 `event_type: "tool_call"`。 | `models.py`、`config.py`、`adapter.py` | 契约测试覆盖共同语义字段；若真实 Core 只接受一种 wire 形态，版本和类型需可配置。 |
| `01_接口契约与事件模型.md` | P0 PolicyDecision 只包含 `allow`、`deny`、`ask`；P1/P2 决策是未来扩展。 | `models.py`、`adapter.py`、`secure_tool_node.py` | `test_policy_decision.py` 覆盖 allow 执行、deny 阻断、ask 阻断/等待。 |
| `01_接口契约与事件模型.md` | AuditEvent 必须包含 audit id、trace id、case id、runtime、timestamp、stage、event type、summary、decision、risk score、severity、blocked、resource targets、rule hits 和 reason；最终文档还包含 schema version、links 和可选防篡改字段。 | `models.py`、`adapter.py` | `test_audit_event.py` 校验 P0 共同字段；可选字段不得破坏 Dashboard/Core 消费。 |
| `02_Core设计与部署.md` | Core 负责 schema validation、detectors、policy、audit、metrics 和 approval；Core 不执行工具，也不修改 LangGraph state。 | `core_client.py`、`adapter.py`、相关文档 | 测试只把 mock Core fixture 当作决策提供者；工具只在 adapter 收到 `allow` 后执行。 |
| `02_Core设计与部署.md` | P0 策略阈值为 allow/ask/deny；敏感文件读取、secret 外发、cloud metadata、安全绕过 memory write 等硬规则应 deny；可疑 outbound 可 ask。 | `datasets/attack_cases/*.jsonl`、mock Core fixture | 数据集对相关 case 使用 `deny` 或 `ask`；本地 smoke test 可使用 mock deny。 |
| `02_Core设计与部署.md` | 指标包括 ASR before、ASR after、Block Rate、FPR 和未来可选指标。 | `metrics.py`、`runner.py`、`results/summary_*.json` | `test_runner_metrics.py` 校验 malicious 与 benign 指标计算。 |
| `03_LangGraph适配与评测靶场.md` | LangGraph 接入优先级：ToolNode wrapper、SecureToolNode fallback、手写 StateGraph node fallback。 | `secure_tool_node.py`、`adapter.py`、`agent.py` | 测试证明无论 LangGraph prebuilt wrapper 支持情况如何，工具调用都会经过 guard。 |
| `03_LangGraph适配与评测靶场.md` | graph input 包含 `messages` 和 `security`，其中有 case id、trace id、attack type、恶意标记、source type/trust 和 user task。 | `models.py`、`agent.py`、`runner.py` | demo graph 测试调用 case 并断言 security 字段进入 ToolCallEvent。 |
| `03_LangGraph适配与评测靶场.md` | ToolNode wrapper 必须捕获 tool calls，转换为 ToolCallEvent，调用 Core，并执行 allow/deny/ask。 | `secure_tool_node.py`、`adapter.py` | allow 执行；deny/ask 返回安全 ToolMessage 或 blocked result 且无副作用。 |
| `03_LangGraph适配与评测靶场.md` | Mock tools 必须覆盖 `read_file`、`write_file`、`send_email`、`call_api`、`code_exec`、`memory_write`。 | `tools.py` | `test_mock_tools.py` 校验行为和 sandbox-only 副作用。 |
| `03_LangGraph适配与评测靶场.md` | 每个工具结果必须记录是否执行、是否阻断、副作用、上下文/持久化意图、清洗状态和敏感/指令类标记。 | `secure_tool_node.py`、`runner.py`、可选 `models.py` | runner 逐 case 输出 tool calls、decisions、blocked 状态和 side effects。 |
| `04_OpenClaw插件接入与配置审计.md` | OpenClaw 不属于本任务范围；ToolCallEvent 映射概念仍用于统一字段。 | 本模块文档 | 本包不实现 OpenClaw，但输出事件保留 runtime tag，并与 dashboard 兼容。 |
| `05_Dashboard与审批流.md` | Dashboard 仅读取 Core API，并消费 AuditEvent、trace details、approvals 和 metrics。 | `results/*.json`、`core_client.py`、文档 | 结果使用文档指标名；AuditEvent 包含 dashboard 字段：decision、risk_score、severity、tool/resource、reason。 |
| `05_Dashboard与审批流.md` | `ask` 创建 approval 或 timeout default deny；`allow_once` 由 Core 拥有。 | `adapter.py`、`secure_tool_node.py` | 本地靶场中 `ask` 不执行工具；测试断言无副作用。 |
| `06_AttackBench与评测指标.md` | AttackCase 字段包括 `case_id`、`attack_type`、`is_malicious`、`runtime_targets`、`input`、`target_behavior`、`expected_decision`、`success_condition`。 | `models.py`、`datasets/attack_cases/*.jsonl` | `test_attackcase_schema.py` 校验所有 JSONL 文件。 |
| `06_AttackBench与评测指标.md` | 支持 prompt injection、jailbreak、tool_hijack、file_exfiltration、api_abuse、code_exec、memory_poisoning、environment_poisoning、benign 等类别。 | `datasets/attack_cases/*.jsonl`、`attackcase_converter.py` | dataset loader 测试确认提示注入、工具劫持、文件泄露、agent abuse/code exec、记忆污染和 benign 可加载。 |
| `06_AttackBench与评测指标.md` | 攻击成功包括敏感文件读取/泄露、攻击者 outbound、非任务工具执行、高风险代码执行、恶意 memory write、污染上下文影响。 | `metrics.py`、`runner.py` | success checker 对比 side effects 与 target_behavior/success_condition。 |
| `06_AttackBench与评测指标.md` | P0 至少有 3 类攻击、10 条正常样本，以及 ASR/Block Rate/FPR。 | `datasets/attack_cases/*.jsonl`、`metrics.py` | 当前 AGENTS 范围要求 P0 之外还包含 agent abuse 和 memory poisoning；final report 记录数量。 |
| `07_创新增强模块设计.md` | Provenance Graph、Memory Guard、Action Critic、Tamper Evident Audit、Continuous Red Team Loop 是分阶段增强模块。 | `models.py` 可选 metadata、文档 | P0/P1 包不实现 P2 功能，除非需要可选 metadata；不引入不兼容字段。 |
| `08_Hook兼容性测试与风险缓解.md` | LangGraph hook 风险要求兼容 fallback，并证明 ToolNode wrapper 可阻断。 | `secure_tool_node.py`、测试 | 测试证明 before-tool interception、block、ask 表达和 trace correlation。 |
| `09_实施路线与团队规范.md` | Adapter 不写 core rules；Core 不执行工具；所有事件需要 trace_id；评测事件需要 case_id；新增字段只能可选。 | `adapter.py`、`models.py`、`runner.py` | 单测断言事件含 trace_id 和 case_id；adapter 只消费决策，不嵌入真实策略逻辑。 |
| `09_实施路线与团队规范.md` | P0 验收：攻击样本触发工具调用，Core 返回 deny，工具未执行，dashboard 可显示阻断，ASR before/after 可计算。 | 整个包 | 使用 mock deny Core 或真实 Core 执行 runner defense on/off smoke test。 |
| 任务测试范围 | 开启防御的测试可使用 mock Core 或真实 Core，但 adapter 行为必须由 PolicyDecision 驱动，并在 Core 失败时失败关闭。 | `core_client.py`、`adapter.py`、测试 | mock/fake Core fixture 仅为本地测试替身，不编码生产策略。 |

## 兼容策略

最终实施文档与当前平台文档在少数契约细节上不一致：

| 主题 | 最终实施文档 | 当前 `agent-guard/docs` | 策略 |
|---|---|---|---|
| ToolCallEvent schema version | `schema_version: "0.3"` | `schema_version: "0.1"` | 在真实 Core 明确支持 `0.3` 前，默认使用当前平台 P0 契约 `0.1`；保留 `0.3` 作为配置/迁移路径，不改变决策语义。 |
| ToolCallEvent event type | `tool_call_proposed` | `tool_call` | 为严格兼容 P0 Core，默认使用 `tool_call`，或将该值配置化。保留 `pre_execution=true` 和 `stage=before_tool_call`，让两种形态语义等价。 |
| AuditEvent schema version 与 hash 字段 | 最终文档包含 `schema_version`、links 和可选防篡改字段 | 当前文档是较小的 P0 AuditEvent，无 schema/hash 字段 | 按要求输出当前 P0 AuditEvent 字段；schema version、links、hash-chain 字段作为可选扩展，因为防篡改 audit 属于 P2。 |
| attack type 名称 | `indirect_prompt_injection`、`tool_hijack`、`file_exfiltration` 等 | 当前文档使用相同示例；AGENTS 示例有时使用 `prompt_injection`/`tool_hijacking` 文件名 | JSONL 记录使用最终文档中的 attack_type 类枚举值；文件名可保留任务导向名称，例如 `prompt_injection.jsonl`、`tool_hijacking.jsonl`。 |
| 决策归属 | Core 拥有 `allow`/`deny`/`ask` | 相同 | adapter 绝不自行决定策略。本地 mock/fake Core client 只是测试替身；生产语义必须来自 Agent Security Core。 |

## 第一阶段验收证据

- 已阅读十个最终实施文档。
- 已阅读现有 `agent-guard` 文档和 dashboard 占位实现。
- 已只读检查 MCPSafety、Instrumentation 和 PoisonedRAG。
- 本文档将硬性需求映射到实现文件和测试方式。
- 第一阶段编辑限定在 `agentguard_langgraph_bench/docs/` 下的审计文档；既有未跟踪文件视为工作区已有状态，未修改任何已跟踪平台代码。
