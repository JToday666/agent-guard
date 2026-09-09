# Product 本机消息目标修正

本修正属于 Core V2.1 official 双真实运行时接入的独立 09a 批次，
用于完成既定文件、命令、记忆、消息 allow/deny/ask 验收中的本机消息路径。
执行目标仍限定在本次隔离验收环境，未新增个人或外部消息渠道。
本文件记录契约修正，不代表候选签署、双运行时真实闭环或长期验证已经通过。

## 唯一消息目标

Product `message` 工具只接受以下目标组合：

| 字段 | 固定值 |
| --- | --- |
| action | `send` |
| channel | `agentguard-fixture` |
| target | `fixture-inbox@agentguard.invalid` |
| 实际网络目的 | 已签署 execution 中的 `http://127.0.0.1:<port>/inbox` |

地址形式的 target 是本机渠道的逻辑收件标识。工具仍向受保护运行清单中的
字面 loopback HTTP 端点投递，不按 target 解析 DNS、选择邮件渠道或连接 SMTP。
目标全文、消息全文和 channel 仍被同一模型输出证明及动作授权指纹绑定。
最终资源和 `sent_to` 数据流仍指向已签署的本机 API，不能用逻辑标识替换它。

旧 `fixture-inbox`、其他邮箱、其他域名、大小写变化、首尾空白、mailto 或 URL
均不是合法 Product target；不得在调用前自动纠正，再借用先前审批或证明。
LangGraph 工具 schema、实际执行资源与工厂参数校验保持一致。
OpenClaw 使用 pinned SDK 的实际 message schema，并由 Product mapper、
受保护 profile、私有 message permit 和本机 channel 再次校验唯一目标。
不得更改原生 schema 来伪造新的 inventory 摘要。

## 既有策略与判定

现有 P005 的收件人允许规则要求目标包含域名。旧裸标识无法命中合法
`allowed_email_domains`，普通消息因此至少为 ASK，无法验证直接 ALLOW。
新标识允许通过既有、完整且已版本化签署的 PolicyBundle 表达本机目标政策：

| 隔离 policy 条件 | 普通消息的现有 Core recipient 判定 |
| --- | --- |
| 默认 policy | `ASK / P005_external_send` |
| 在默认 allowed_email_domains 追加 `agentguard.invalid` | `ALLOW` |
| 默认 policy，P005 的 decision override 收紧为 `deny` | `DENY / P005_external_send` |

这些是现有 Core recipient 规则的条件，不能替代完整 Product Active 判定。
数据、任务授权、能力、行为、上下文、敏感内容及全部必检证据仍参与原有决策。
Core detector、V2.1 fusion、current/raw 严格程度比较和 rank floor 均不变。
域名 allowlist 不授予任务权限，也不升级模型或来源的信任。

真实 ALLOW 必须是官方所选 ALLOW，不能把审批后的 allow_once 改称 ALLOW。
真实 ASK 必须经过审批、lease consume、一次实际投递及已确认回执；
真实动作 DENY 必须发生于目标消息事件，并证明零投递。
上游内容拒绝、非法参数、运行时故障或 API 503 不能计为消息动作 DENY。

不同 policy 必须有各自匹配的 admission、activation、受保护 manifest 和新 ACK。
切换已签隔离 policy 时按正常生命周期关闭并重新启动对应服务和会话；
禁止修改 policy 后继续使用旧 activation 或旧 ACK。

## 工具语义版本与历史兼容

当前 Product 工具语义为 **`isolated-product-tools-2`**，替代新动作上的
`isolated-product-tools-1`。正常化、ACK、receipt、数据证明、coverage、
fact builder、必检计划及七事件的 schema 版本保持不变。

本次变更改变了工具允许的参数集合，不能只依赖 schema 摘要自然变化。
OpenClaw 原生 message target 仍可能是通用 string，实际 schema 摘要可能相同。
独立语义版本进入每个工具的 semantics digest 以及签署 runtime profile digest，
确保新旧允许集合不能共用原语义身份；不允许事件自报选择旧版。
服务端 catalog 与 LangGraph 本地 profile 校验同步选择版本 2，旧 catalog、
旧语义 profile 或旧 activation 混用于新动作时阻断。

B01 baseline 保留 `fixture-inbox` 默认值、原配置与历史采样制品。
通用本机 inbox 可兼容原简单名称及唯一的新 Product alias；Product 专用 profile、
bridge 和 channel 则只接受新 alias。不能借 baseline 兼容性获得 Product authority。
历史回执仍使用原始 ACK 和原不可变 payload，按历史发行窗口补投；
本修正不改写历史工具参数，不把历史记录升级成当前候选的通过证据。

## 不变的执行边界与验收

LangGraph 保留 strong binding。OpenClaw 保留 restricted allow_once、
`C3=false`、`CF-13=NOT_SUPPORTED` 和全部五项残余边界：

- 没有权威 invocation-start hook。
- hook 不能原子替换并封存最终动作。
- 宿主 message_sending 异常或超时可能放行。
- 非工具 Memory 写入没有原生执行前 hook。
- 同步持久化 hook 不能等待远端判定或回滚。

目标修正不会消除这些宿主限制；Product 私有 permit、投递门禁和实际 after hook
仍按已冻结能力实施，不生成没有宿主证据的权威开始或成功回执。
模型仍为 `unknown / model_judgment`，数据与控制影响保持分离，污点不清除。
本轮仍不支持真实 Memory 回滚、不新增激活旁路或 shadow/current fallback。

必须验证旧目标和其他邮箱零执行、baseline 兼容、旧语义混用拒绝、两 runtime
实际 agent loop 的 channel/目标/参数完整绑定、本机收件结果以及审批/lease/回执关联。
单测、受控模型或 synthetic candidate 的 HTTP 测试须如实标注证据范围。
最后从实际合入的固定 `dev` SHA 重新构建并干净安装制品，重新采集真实清单，
完成必需 conformance 后重新签署 admission、限定环境 residual acceptance 和 activation，
再以双方真实 ACK、真实 Provider、浏览器审批与 PostgreSQL 证据完成最终验收。
`internal_rc_canary` 仅保留既有签署范围，不代表长期验证或生产就绪。
