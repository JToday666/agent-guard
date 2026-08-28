# 威胁模型

## 1. 文档定位

本文定义 AgentGuard 的保护目标、攻击面、非目标和验证场景。检测器、策略和 AttackBench 样本应从本文派生。

关联入口：

- [接口契约与事件模型](interface_contract.md)
- [`agentguard-core` 设计](core_design.md)
- [AttackBench 攻击样本与评测](../05_redteam/attackbench.md)

## 2. 保护目标

AgentGuard 保护大模型 Agent 的运行时高风险行为：

| 保护目标       | 当前状态 | 边界 |
| -------------- | -------- | ---- |
| 工具调用       | 已支持   | Core 判定和 LangGraph 执行前门禁已实现；其他 Runtime 以各自宿主能力为准 |
| 文件读写       | 已支持   | 覆盖受控 Runtime 中可见的文件工具，不覆盖绕过 Runtime 的宿主机访问 |
| 邮件或消息外发 | 已支持   | 支持策略判定和受控 Adapter/Plugin 拦截；实际投递结果仍以运行时回执为准 |
| API 调用       | 已支持   | 支持出站 DLP、SSRF 和任务一致性检测；不替代网络沙箱 |
| 代码执行       | 已支持   | 支持受控工具调用判定；不覆盖独立恶意 OS 进程或沙箱逃逸 |
| 记忆写入       | 受限     | 事件、检测器和控制面生命周期已支持；真实 runtime transaction/rollback 未支持 |
| 上下文拼接     | 已支持   | schema、Core 检测与已接入 Runtime 的输入门禁已实现，具体 hook 覆盖依 Runtime 而异 |
| 工具结果回流   | 已支持   | schema、检测器与受控净化路径已实现；不声称撤销工具已经产生的副作用 |
| 最终输出       | 受限     | 模型输出检测和已接入 hook 已实现；不同宿主的原子替换/封印能力并不等价 |

## 3. 攻击面

| 攻击面       | 示例                                 | 防御入口                                                 |
| ------------ | ------------------------------------ | -------------------------------------------------------- |
| 提示注入     | 恶意邮件、文档、网页要求模型忽略规则 | 输入检测、上下文隔离、工具调用审计                       |
| 模型越狱     | 角色扮演、指令覆盖、多轮诱导         | 输入输出过滤、模型行为监测                               |
| 工具调用劫持 | 诱导调用非任务所需工具               | GuardEvent / ToolCallEvent payload、TaskMismatchDetector |
| 文件泄露     | 读取 `.env`、token、secret           | SensitiveFileDetector                                    |
| API 滥用     | 上传敏感数据、SSRF、越权调用         | OutboundDLPDetector、NetworkSSRFDetector                 |
| 代码执行滥用 | 执行 shell、读取环境变量             | CodeExecDetector                                         |
| 记忆中毒     | 写入恶意长期规则                     | MemoryPoisoningDetector、Memory Guard                    |
| 环境感知污染 | README、日志、API 返回污染           | ContextBuildEvent、ToolResultEvent                       |
| 工具结果污染 | 工具返回结果中夹带指令               | ToolResultEvent、上下文来源标记                          |
| 外发泄露     | 邮件、消息、API 上传敏感数据         | OutboundDLPDetector                                      |

## 4. 攻击链示例

```text
恶意邮件
→ 拼入上下文
→ 模型生成 read_file('/private/token.txt')
→ ToolNode wrapper 拦截
→ Guard API 调用 Core 判断来源不可信 + 敏感文件 + 任务不一致
→ GuardDecision: deny
→ Adapter 按契约拒绝调用工具
→ runtime_outcome(not_invoked) 或宿主调用计数确认实际未执行
→ Dashboard 展示攻击链
```

`deny` 是权威的策略拒绝，不单独证明运行时效果。缺少关联的运行时回执或宿主调用计数时，
执行状态必须保持未知；不得从 policy audit 的 `deny`/`blocked` 推导零调用或零副作用。

## 5. 非目标

当前产品边界不承诺覆盖：

- 绕过 Agent runtime 的宿主机级文件访问；
- 恶意 OS 进程；
- 完整沙箱逃逸检测；
- 生产级多租户隔离；
- 基座模型训练或微调；
- 对真实邮箱、真实生产 API 的攻击演示。

## 6. 验收证据

威胁模型验收不看概念覆盖数量，而看是否能形成可复现证据：

1. 每个已支持攻击面至少有一个代表性 AttackCase 或契约测试。
2. 每个 AttackCase 有目标行为和成功条件。
3. 无防御时能触发危险动作或危险意图。
4. 有防御时 Guard API 在执行前给出 `deny` 或 `ask`，Adapter 按契约阻断或等待审批。
5. 对“未执行”的断言有 `runtime_outcome(not_invoked)` 或等价的宿主调用计数证据。
6. Dashboard 能分别展示策略决定、审批结果、运行时结果和 trace。
