# 命题要求追踪矩阵

## 1. 文档定位

本矩阵用于把命题一《面向大模型及其应用的安全性研究》的原文要求，映射到 AgentGuard 的开发模块、实施阶段和验收证据。它主要服务需求追踪和答辩说明，同时约束开发范围。

关联入口：

- [命题一题目解读总结](命题一_题目解读总结.md)
- [系统总体架构](../01_overview/architecture.md)
- [实施路线与验收标准](../06_delivery/implementation_plan.md)
- [AttackBench 攻击样本与评测](../05_redteam/attackbench.md)

阶段约定：

| 阶段 | 含义                           |
| ---- | ------------------------------ |
| P0   | 最小可运行闭环，必须优先完成   |
| P1   | 完整可解释链路，支撑正式演示   |
| P2   | 冲奖增强项，提升创新性和完整度 |

状态约定：

| 状态     | 含义                                           |
| -------- | ---------------------------------------------- |
| 已设计   | 已有文档方案，但尚未形成可运行实现             |
| 待实现   | 需要在代码、样本或页面中落地                   |
| 待验证   | 需要先验证外部框架或 Hook 可用性               |
| 已实现   | 已有可运行实现，但尚未完成验证或演示           |
| 已验证   | 已通过测试、runner 或兼容性验证                |
| 部分实现 | 已有可运行子集，但未覆盖全部验收证据           |
| 已演示   | 已具备可用于答辩展示的截图、录屏或现场演示证据 |

状态应随开发进展持续更新，不能长期停留在“已设计”。

## 2. 命题原文要求追踪

| 编号 | 命题要求                                       | AgentGuard 响应                                                                                                       | 对应文档 / 模块                                                                                                                                                         | 阶段  | 验收证据                                                              | 当前状态                               |
| ---- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | --------------------------------------------------------------------- | -------------------------------------- |
| R01  | 从红队视角研究大语言模型及智能化应用典型攻击面 | 建立 Threat Model 和 AttackBench，覆盖提示注入、越狱、工具劫持、文件泄露、代码执行滥用、记忆中毒、环境污染等攻击面    | [威胁模型](../02_core/threat_model.md)、[AttackBench](../05_redteam/attackbench.md)、`agentguard_langgraph_bench/bench/datasets/`                                       | P0-P1 | 风险分析报告；攻击样本清单；每类攻击的成功条件                        | 部分实现                               |
| R02  | 研究提示注入攻击                               | 设计间接提示注入样本，模拟恶意邮件、文档或网页诱导 Agent 偏离用户任务                                                 | [AttackBench](../05_redteam/attackbench.md)、[演示脚本](../06_delivery/demo_script.md)、`agentguard_langgraph_bench/bench/datasets/attack_cases/prompt_injection.jsonl` | P0    | `PI-*` 样本；无防御攻击成功记录；有防御阻断记录                       | 已验证                                 |
| R03  | 研究模型越狱攻击                               | 将越狱用例作为模型输入/输出过滤测试集，验证模型行为监测和输出检测能力                                                 | [AttackBench](../05_redteam/attackbench.md)、`agentguard_langgraph_bench/bench/datasets/attack_cases/jailbreak.jsonl`、`post_model_hook`                                | P1    | 越狱测试用例集；模型输出检测记录；召回率/误报率                       | 已设计，待实现                         |
| R04  | 研究训练数据泄露或上下文泄露风险               | 将敏感文件、系统提示词、记忆内容、上下文来源纳入泄露检测目标                                                          | [威胁模型](../02_core/threat_model.md)、[Core 设计](../02_core/core_design.md)、`SensitiveResourceDetector`、`OutboundDetector`                                         | P0-P1 | 敏感资源访问阻断记录；输出泄露检测记录                                | 部分实现                               |
| R05  | 研究滥用风险                                   | 监控邮件外发、API 上传、代码执行等可被滥用的工具行为                                                                  | [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)、[接口契约](../02_core/interface_contract.md)、`send_email`、`call_api`、`code_exec`                          | P0-P1 | 外发审批或阻断记录；API 滥用样本评测                                  | 已验证                                 |
| R06  | 研究工具调用劫持                               | 在工具调用前由 ToolNode wrapper 拦截，交给 Guard API 调用 Core 判断是否偏离任务                                       | [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)、[Core 设计](../02_core/core_design.md)、`SensitiveResourceDetector`、`TaskMismatchDetector`                  | P0    | Agent 生成异常工具调用；Guard API 返回 `deny` 或 `ask`；工具未执行    | 已验证                                 |
| R07  | 研究记忆中毒                                   | 对长期记忆写入建立 MemoryEvent 和 Memory Guard，审计来源、内容和持久化风险                                            | [接口契约](../02_core/interface_contract.md)、[Core 设计](../02_core/core_design.md)、`agentguard_langgraph_bench/bench/datasets/attack_cases/memory_poisoning.jsonl`   | P1-P2 | 恶意记忆写入样本；拒绝持久化记录；记忆变更日志                        | Core/contract/backend 部分实现，runtime memory 接入待补齐 |
| R08  | 研究环境感知污染                               | 标记外部文档、网页、API 返回值、工具结果为不可信来源，并审计其进入上下文的路径                                        | [威胁模型](../02_core/threat_model.md)、[接口契约](../02_core/interface_contract.md)、`ContextBuildEvent`、`ToolResultEvent`                                            | P1    | 环境污染样本；上下文来源记录；污染来源到危险动作的 trace              | Core/contract 已覆盖，runtime 上下文接入待补齐 |
| R09  | 设计可嵌入或旁路的行为监督机制                 | 采用四层目标架构：Adapter 拦截运行时动作，Guard API / Control Plane 统一入口，Core 无状态判定，Dashboard 展示监督结果 | [总体架构](../01_overview/architecture.md)、[OpenClaw 插件](../03_adapters/openclaw_plugin.md)                                                                          | P0-P1 | LangGraph wrapper 可运行；OpenClaw 插件触发 Guard API 评估            | P0 已验证，OpenClaw 插件包已实现，真机 E2E 需持续复验 |
| R10  | 对工具调用进行实时审计与异常判定               | 统一 `GuardEvent`，其中 `ToolCallEvent` 是 P0 payload；工具执行前调用 Guard API，返回 `allow`、`deny`、`ask`          | [接口契约](../02_core/interface_contract.md)、[Core 设计](../02_core/core_design.md)、`packages/agentguard-core/`                                                       | P0    | 工具调用前审计日志；阻断后工具无副作用                                | 已验证                                 |
| R11  | 对代码执行进行实时审计与异常判定               | 将 `code_exec` 作为 Mock Tool，检测危险命令、系统探测、外连、删除等风险                                               | [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)、`agentguard_langgraph_bench/bench/tools.py`                                                                  | P1    | 代码执行滥用样本；危险命令阻断记录                                    | 部分实现                               |
| R12  | 对文件访问进行实时审计与异常判定               | 对 `read_file`、`write_file` 参数进行路径白名单、敏感文件名、任务一致性检测                                           | [接口契约](../02_core/interface_contract.md)、[演示脚本](../06_delivery/demo_script.md)、`SensitiveResourceDetector`                                                    | P0    | `/private/token.txt` 或 `.env` 读取被拒绝；Dashboard 展示原因         | 已验证                                 |
| R13  | 构造对抗性输入                                 | 用 AttackCase JSONL 表达攻击类型、输入来源、目标行为、预期决策、成功条件                                              | [AttackBench](../05_redteam/attackbench.md)、`agentguard_langgraph_bench/bench/datasets/attack_cases/`                                                                  | P0    | 至少 3 类攻击样本；每类包含可复现实例                                 | 已验证                                 |
| R14  | 设计可落地的防御策略                           | 策略引擎支持规则命中、风险评分、`allow` / `deny` / `ask` 决策和解释原因                                               | [Core 设计](../02_core/core_design.md)、[接口契约](../02_core/interface_contract.md)、`packages/agentguard-core/agentguard_core/policy.py`                              | P0    | 策略配置；命中规则；风险评分；可解释 `GuardDecision`                  | 部分实现                               |
| R15  | 支持输入输出过滤                               | 通过 `pre_model_hook` 和 `post_model_hook` 执行输入污染检测、模型输出泄露检测和越狱检测                               | [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)、`PromptInjectionDetector`、`JailbreakDetector`、`OutboundDLPDetector`                                        | P1    | 输入过滤记录；模型输出检测记录；误报率统计                            | Core 检测器部分实现，adapter model hooks 待补齐 |
| R16  | 支持上下文隔离                                 | 在上下文拼接时保留来源、信任级别、派生资源，避免不可信内容直接升级为指令                                              | [接口契约](../02_core/interface_contract.md)、`SecurityContext`、`ContextBuildEvent`                                                                                    | P1    | 上下文来源链路；不可信来源标记；任务一致性判断证据                    | Core/contract 已支持，runtime 隔离执行策略待补齐 |
| R17  | 支持模型行为监测                               | 记录模型输入、输出、意图、工具调用意图与实际动作之间的差异                                                            | [接口契约](../02_core/interface_contract.md)、`pre_model_hook`、`post_model_hook`、`TaskMismatchDetector`                                                               | P1    | 模型调用链路 trace；任务偏离告警；攻击链路页                          | Trace/API 已实现，adapter model hooks 待补齐 |
| R18  | 安全风险分析报告至少包含 3 类攻击场景          | 报告主线聚焦间接提示注入、工具调用劫持/文件越权、记忆中毒，补充越狱和环境污染                                         | [题目解读](命题一_题目解读总结.md)、[威胁模型](../02_core/threat_model.md)                                                                                              | P0-P1 | 正式报告章节；每类攻击的原理、样本、脚本、结果                        | 部分实现                               |
| R19  | 每类场景包括模型对抗样本与越狱测试用例集       | AttackBench 同时维护恶意样本、越狱样本和 benign 正常样本                                                              | [AttackBench](../05_redteam/attackbench.md)、`agentguard_langgraph_bench/bench/datasets/attack_cases/`                                                                  | P0-P1 | JSONL 测试集；样本字段校验；批量 runner 输出                          | 部分实现                               |
| R20  | 每类场景包括智能体攻击脚本                     | 为每类核心攻击编写脚本，准备恶意输入、触发 Agent、记录防御前后结果                                                    | `agentguard_langgraph_bench/bench/runner.py`、`agentguard_langgraph_bench/bench/scripts/`、[演示脚本](../06_delivery/demo_script.md)                                    | P0    | 批量 runner 和分析脚本；运行日志；攻击成功/阻断结果                   | 已实现                                 |
| R21  | 行为监督原型系统拦截智能体集群与外部工具的交互 | Guard API 对所有外部动作统一接入，调用无状态 Core 做策略评估，Adapter 负责映射和执行拦截结果                          | [总体架构](../01_overview/architecture.md)、[接口契约](../02_core/interface_contract.md)、`packages/agentguard-core/`                                                   | P0-P1 | 多工具调用被 Guard API 审计；Adapter 不绕过策略                       | P0 已验证                              |
| R22  | 基于安全策略或异常检测模型进行监控             | P0 使用规则和风险评分，P1/P2 可增加 LLM-as-Judge / Action Critic                                                      | [Core 设计](../02_core/core_design.md)、`packages/agentguard-core/`、`Action Critic`                                                                                    | P0-P2 | 策略命中率；消融实验；规则和模型对比                                  | P0 已验证，P1/P2 已设计                |
| R23  | 提供一个开源智能化应用，如 OpenClaw            | 将 OpenClaw 作为真实应用接入场景，采用插件方式接入 Guard API                                                          | [OpenClaw 插件](../03_adapters/openclaw_plugin.md)、`packages/agentguard-openclaw-plugin/`                                                                              | P1    | OpenClaw 中触发 `before_tool_call`；Guard API 记录 `runtime=openclaw` | OpenClaw 插件包已实现，verify 状态后端已接入，展示接入待确认 |
| R24  | 提供模拟业务工具：发送邮件、读写文件、调用 API | LangGraph 靶场提供 `send_email`、`read_file`、`write_file`、`call_api`，并可扩展 `code_exec`、`memory_write`          | [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)、`agentguard_langgraph_bench/bench/tools.py`                                                                  | P0    | Mock Tool 可运行；工具副作用写入沙箱或 mock outbox                    | 已验证                                 |
| R25  | 提供模型调用链路的安全监控插件                 | 通过 LangGraph hook 和 OpenClaw plugin 记录上下文构建、模型输入输出、工具调用和工具结果                               | [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)、[OpenClaw 插件](../03_adapters/openclaw_plugin.md)、[接口契约](../02_core/interface_contract.md)             | P1    | trace_id 串联模型调用和工具动作；攻击链路页展示完整链路               | 部分实现                               |
| R26  | 提供基座模型检测或过滤原型                     | 将输入过滤、输出过滤、越狱检测、DLP 检测作为模型侧安全原型                                                            | [LangGraph 评测靶场](../03_adapters/langgraph_adapter.md)、`PromptInjectionDetector`、`JailbreakDetector`、`OutboundDLPDetector`                                        | P1    | 模型侧检测报告；越狱用例检出率和误报率                                | 部分实现                               |
| R27  | 监督端实时展示告警或阻断记录                   | Dashboard 展示 AuditEvent、阻断原因、审批项、攻击链路和评测指标                                                       | [Dashboard 与审批流](../04_apps/dashboard_design.md)、`apps/dashboard/`                                                                                                 | P0-P1 | 调查列表；阻断记录；trace 时间线；指标页截图                          | 已验证                                 |

## 3. P0 最小验收闭环

```text
AttackCase
→ LangGraph Agent
→ Mock Tool 调用意图
→ ToolNode wrapper 拦截
→ Guard API 调用 `agentguard-core` 评估
→ GuardDecision: deny / ask / allow
→ AuditEvent
→ Dashboard 展示阻断或审批记录
→ AttackBench 输出 ASR before / ASR after / Block Rate / FPR
```

P0 至少覆盖：

| 攻击场景                | 样本                           | 工具行为                           | 预期决策        | 关键证据                                       |
| ----------------------- | ------------------------------ | ---------------------------------- | --------------- | ---------------------------------------------- |
| 间接提示注入            | 恶意邮件诱导读取 token         | `read_file('/private/token.txt')`  | `deny`          | 工具未执行；Dashboard 显示敏感文件和任务不一致 |
| 工具调用劫持 / 外发泄露 | 恶意上下文诱导发送结果给攻击者 | `send_email(attacker@example.com)` | `ask` 或 `deny` | 审批或阻断记录；非白名单收件人证据             |
| 正常任务                | 读取公开文档并总结             | `read_file('/docs/public.txt')`    | `allow`         | 工具执行；用于计算 FPR                         |

## 4. 答辩证据清单

| 证据                 | 对应要求          | 说明                                              |
| -------------------- | ----------------- | ------------------------------------------------- |
| 安全风险分析报告     | R01-R08、R18      | 解释攻击面、攻击链、防御策略和实验结果            |
| AttackBench 数据集   | R13、R19          | 至少 3 类攻击样本和 benign 样本                   |
| 智能体攻击脚本       | R20               | 支持防御前后重放和结果对比                        |
| Guard API / SDK      | R09-R12、R14、R21 | 证明行为监督不是事后日志，而是工具执行前拦截      |
| Mock Tools           | R24               | 证明命题要求的发送邮件、读写文件、调用 API 已覆盖 |
| OpenClaw 插件演示    | R23、R25          | 证明可接入开源智能化应用                          |
| Dashboard 截图或录屏 | R27               | 展示实时告警、阻断、审批和攻击链路                |
| 指标报告             | R22、R26          | 展示 ASR、Block Rate、FPR、FNR、Latency           |

## 5. 当前边界

P0 闭环已有可运行实现：AttackCase 样本、LangGraph 评测靶场、工具调用前拦截、Guard API / Control Plane、无状态 Core、审计与审批、Dashboard 调查和评测页均已落地。当前边界是：

1. 真实 OpenClaw Hook 兼容性尚未验证；现有 `openclaw` 模块是 AttackBench 的外部 Agent 适配器。
2. 越狱专项数据集和完整的模型输出过滤评测仍属 P1 规划。
3. 完整的上下文溯源、记忆防护、Action Critic 和审计完整性仍属 P1/P2 规划。
4. 依赖外部数据源或真实运行时的评测，只能在所需资源可用时作为完整兼容性证据。
