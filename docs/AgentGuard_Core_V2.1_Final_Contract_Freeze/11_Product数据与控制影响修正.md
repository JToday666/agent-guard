# Product 数据与控制影响修正

本修正属于 Core V2.1 official 双真实运行时接入的独立 06a 批次。
授权来源：2026-09-08 本次隔离验收任务中，用户明确允许独立契约修正，
并要求保留 LangGraph strong binding 和 OpenClaw 全部残余边界。
授权不等于实现、独立审查或最终验收已经通过。

## 不变的安全约束

数据传递不能授予权限，模型仍为 `trust=unknown / authority=model_judgment`。
已认证的运行时不自动拥有任务授权；真实工具语义须来自服务端验证的清单。
缺少必检证据不能解释为安全，敏感污点不能因字节复制得到清除。
审批仍需完整必检 coverage、权限绑定和原子 lease consume。

LangGraph 保留 strong binding。OpenClaw 保留 restricted allow_once、
`C3=false`、`CF-13=NOT_SUPPORTED` 及五项既有残余边界。
本修正不新增激活接口，不允许 shadow/current 作为 Product Active 回退。

## 可信工具语义与参数承诺

服务端读取受保护的本地运行清单，重新计算 descriptor/schema/来源摘要，
并与既有签署 activation 和当前 ACK 的 inventory、binding、候选身份匹配。
只有清单中经过代码审核的真实工具画像可以选择新的规范化路径。
事件自报 `descriptor_digest`、工具名字、`readonly` 或 `derived_resources`
均不能单独授予该语义。未知、重复、缺失、版本或来源漂移均阻断。

冻结隔离工具为 `read/write/edit/exec/process/message` 及 SQLite 记忆读写。
`process` 仅允许清单的只读查询画像；`exec` 保留代码执行与持久副作用，
只绑定固定脚本和效果目标。文件落盘不等同于 Memory 域依赖。
Memory 写入为本轮限定的首次写入，不声明真实回滚；消息仅发送本机测试收件端。

授权指纹必须覆盖真实工具身份、清单语义身份、全部安全参数和最终资源。
Memory 的 key/value、message 的 channel/target/全文均纳入参数承诺，
不能沿用空参数摘要。改变内容、目的地、工具 schema 或语义会改变授权绑定。

## 模型内容证据

服务端在实际完整模型输出上生成有界摘要承诺，绑定模型输出事件、输入动作、
call ID、真实工具名、整份 arguments 及必需字段摘要。常规审计只保留摘要和引用，
不新增原始敏感内容日志。脱敏 preview、截断内容或客户端自签证明不能补足该证据。

后续动作必须引用原始模型输出。服务端验证原 Product 判定、输出检查回执和
模型动作终态均已接受，且 task/scope/trace/runtime/binding/profile 一致。
重新计算当前实际 arguments 的完整摘要与逐字段摘要；只换目标、加删字段、
重复 call ID、缺任一回执或跨作用域复用均拒绝。

当前动作的完整摘要证明保存在 policy Audit 的 `evidence.product_action_data`。
其 `EvidenceRef` 使用 `record_type=product_action_data` 和原 `event_id`，
由服务端的 event → policy Audit 唯一索引解析；`digest` 为完整证明摘要。
该引用参与 assessment/decision 摘要，避免最终 Audit ID 对自身摘要产生循环。
模型输出承诺使用独立的 `evidence.product_model_content`；两类记录均由服务端写入。

精确绑定仅证明“已观察的模型参数被原样传给当前工具”，不证明模型生成过程
与上下文之间存在精确复制关系。上下文到模型及动作的 `influenced_by/possible`
控制影响和所有污点继续保留。

## Coverage、风险与审批

在独立数据证明完整、依赖闭包有界且无缺失的条件下，已识别的模型控制边
不再单独构成数据复制缺证。来源身份与分类已验证可以具有完整 source coverage，
同时保持模型不可信。未知 producer、歧义来源、截断、状态缺口或未验证参数仍阻断。

数据完整性不等于 ALLOW。所有控制影响仍参与风险融合；未解决的敏感或恶意
依赖不能通过 ASK 补足。真实 ALLOW 仍需全部现有放行条件，合法 ASK 仅用于
证据齐全、目标可界定之后的策略审批。

`CREDENTIAL`、`SENSITIVE`、`EXTERNAL_INSTRUCTION`、`PERSISTENT_UNTRUSTED`
或 hostile instruction 均禁止此证明产生可审批资格。`UNTRUSTED` 不单独代替
策略判定，仍完整参与风险融合，审批不能清除标签或升级来源信任。

Memory 仅在可信语义和完整依赖闭包证明没有记忆依赖时为不适用；真实或未解析
memory refs 始终必检。模型生成的记忆内容不能提升为 user/trusted 或 clean；
后续 context 隔离保留，unknown/quarantined 内容不得借本修正自动进入模型。

## 版本与重放

新 Product 路径使用以下独立版本；历史无新证明的记录保留原保守含义。

| 契约 | 新 Product 版本 | 历史路径 |
| --- | --- | --- |
| 工具语义 | `isolated-product-tools-1` | 不从事件自报选择 |
| 工具规范化 | `v21-product-tool-normalizer-1` | 原 normalizer 保留 |
| 完整数据证明 | `product-data-1` | 无证明不得升级 coverage |
| 证明 coverage | `product-data-coverage-1` | 原 coverage 保留 |
| 必检计划 | `v21-04-plan-5` | `v21-04-plan-4` 保留 |
| 动作事实映射 | `ct-product-fact-1` | `ct-fact-1/2` 保留 |

只有完整证明匹配真实 ActionIR 的三个 Product 动作事件使用新事实映射。
模型输出到当前参数、当前内容到清单最终目标的实际传输可记为 `exact/observed`；
上下文和祖先到模型或动作的控制影响仍为 `possible/semantic_inferred`。
新动作 FlowFact 使用固定 producer `ct-product-fact-builder-1`，其信封声明和
bundle 摘要必须匹配 `ct-product-fact-1`，混合 producer 或版本替换均拒绝。
原 CT 数据容器和 projector 不变，不能把历史 `possible` 投影重写为 `exact`。
Memory 仅继承当前直接依赖，完整祖先闭包的污点继续保留；无关历史不是当前输入。

新增决策证据绑定其完整输入摘要，版本或摘要不匹配时拒绝重放。
最终候选必须重新构建、签署并完成真实验收。

本批只交付契约与执行前验证；双运行时 Product Active 的公开启用限制持续保留，
最终状态以固定 `dev` SHA 上的完整闭环报告为准。
