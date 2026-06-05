# 威胁模型

## 1. 文档定位

本文定义 AgentGuard 的保护目标、攻击面、非目标和验证场景。检测器、策略和 AttackBench 样本应从本文派生。

关联入口：

- [接口契约与事件模型](interface_contract.md)
- [Agent Security Core 设计](core_design.md)
- [AttackBench 攻击样本与评测](../05_redteam/attackbench.md)
- [命题要求追踪矩阵](../00_requirements/requirement_traceability_matrix.md)

## 2. 保护目标

AgentGuard 保护大模型 Agent 的运行时高风险行为：

| 保护目标       | P0/P1/P2 |
| -------------- | -------- |
| 工具调用       | P0       |
| 文件读写       | P0       |
| 邮件或消息外发 | P0-P1    |
| API 调用       | P0-P1    |
| 代码执行       | P1       |
| 记忆写入       | P1-P2    |
| 上下文拼接     | P1       |
| 工具结果回流   | P1       |
| 最终输出       | P1       |

## 3. 攻击面

| 攻击面       | 示例                                 | 防御入口                                 |
| ------------ | ------------------------------------ | ---------------------------------------- |
| 提示注入     | 恶意邮件、文档、网页要求模型忽略规则 | 输入检测、上下文隔离、工具调用审计       |
| 模型越狱     | 角色扮演、指令覆盖、多轮诱导         | 输入输出过滤、模型行为监测               |
| 工具调用劫持 | 诱导调用非任务所需工具               | ToolCallEvent、TaskMismatchDetector      |
| 文件泄露     | 读取 `.env`、token、secret           | SensitiveFileDetector                    |
| API 滥用     | 上传敏感数据、SSRF、越权调用         | OutboundDLPDetector、NetworkSSRFDetector |
| 代码执行滥用 | 执行 shell、读取环境变量             | CodeExecDetector                         |
| 记忆中毒     | 写入恶意长期规则                     | MemoryPoisoningDetector、Memory Guard    |
| 环境感知污染 | README、日志、API 返回污染           | ContextBuildEvent、ToolResultEvent       |
| 工具结果污染 | 工具返回结果中夹带指令               | ToolResultEvent、上下文来源标记          |
| 外发泄露     | 邮件、消息、API 上传敏感数据         | OutboundDLPDetector                      |

## 4. 攻击链示例

```text
恶意邮件
→ 拼入上下文
→ 模型生成 read_file('/private/token.txt')
→ ToolNode wrapper 拦截
→ Core 判断来源不可信 + 敏感文件 + 任务不一致
→ PolicyDecision: deny
→ 工具未执行
→ Dashboard 展示攻击链
```

## 5. 非目标

P0/P1 不承诺覆盖：

- 绕过 Agent runtime 的宿主机级文件访问；
- 恶意 OS 进程；
- 完整沙箱逃逸检测；
- 生产级多租户隔离；
- 基座模型训练或微调；
- 对真实邮箱、真实生产 API 的攻击演示。

## 6. 验收证据

威胁模型验收不看概念覆盖数量，而看是否能形成可复现证据：

1. 每个 P0 攻击面至少有一个 AttackCase。
2. 每个 AttackCase 有目标行为和成功条件。
3. 无防御时能触发危险动作或危险意图。
4. 有防御时 Core 在执行前给出 `deny` 或 `ask`。
5. Dashboard 能展示原因和 trace。
