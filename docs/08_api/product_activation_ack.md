# Product Active：Activation ACK 接线

本页描述 P0-V21-01d 的 Control Plane 接口和验证边界。默认不配置 Product activation；启用时使用签名的 `ProductActivationBundleV1`。运行时真实宿主、工具清单、canary 与 Internal RC 仍按后续独立批次验收。

## Heartbeat 与请求

Product runtime 向 `POST /v1/adapters/{runtime}/heartbeat` 提交 `ProductRuntimeHeartbeatV2`。Bearer 身份必须匹配签署的 principal、runtime 和 agent；状态按 `(runtime, agent_id, runtime_binding_id, profile_id)` 存储。

成功响应包含 `runtime_status` 和 `activation_ack`，并设置 `Cache-Control: no-store`。服务端签发的 ACK 有效期为 120 秒，且不会超过 activation 或对应 runtime entry 的到期时间。插件仅持有短时 ACK，不持有服务器 HMAC 密钥。

调用以下接口时，插件在 `X-AgentGuard-Activation-Ack` header 中回传 `activation_ack.ack_token`：

- `POST /v1/guard/evaluate`
- `POST /v1/approvals/{approval_id}/execution-leases/consume`

同一运行时在无漂移的情况下允许多代未过期 ACK 共存，避免新的 heartbeat 使在途请求失效。合法激活身份报告 inventory、binding、capability 或其他冻结字段漂移时，状态更新与该身份全部 ACK 的撤销原子提交。其他 principal/agent 无权撤销该 entry 的 ACK。

## 失败与事务边界

| 条件 | HTTP / code | 行为 |
| --- | --- | --- |
| 未带 ACK | 503 / `V21_PRODUCT_ACTIVATION_ACK_REQUIRED` | 无 evaluation 或消费写入 |
| ACK 错误、过期、未来签发或已撤销 | 503 / `V21_PRODUCT_ACTIVATION_ACK_NOT_CURRENT` | 阻断当前请求 |
| ACK registry 无法读取 | 503 / `V21_PRODUCT_ACTIVATION_ACK_VERIFIER_UNAVAILABLE` | 阻断当前请求，不返回私有后端错误 |
| 任一 runtime 的冻结状态或最新 ACK 不匹配 | 503 / `V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH` | 阻断当前请求 |
| Product authority 与 Active pipeline 组合不完整或不一致 | 503 / `V21_PRODUCT_SELECTOR_UNAVAILABLE`；历史 Product replay 保持 `V21_PRODUCT_REPLAY_UNAVAILABLE` | 首次请求与历史重放均禁止落入旧判定 |
| activation、TaskFact、policy 或其他权威变化 | 对应 Product 503 | 禁止回退 `source=current` |

`evaluate` 在请求入口、锁内 Phase B、提交前，以及 exact replay 修复前后重验 ACK。token 显式传递，不进入事件请求 digest 或稳定的 replay authority digest。成功的适用事件返回 `source=v21`、`mode=active`、`selection_basis=profile_all`。

`consume` 在锁内、首次消费及 exact replay 返回前复核 ACK，使用获得锁后的服务端时间；lease expiry 不得超过 ACK expiry。Memory 和 PostgreSQL 按 runtime → approval authority 的顺序锁定，receipt 同样先锁 runtime，避免反向等待。消费失败不会自动恢复旧 authority。

## 延迟 receipt

`POST /v1/audit/events` 的 runtime outcome 使用已有的 `metadata.activation_ack` 携带完整 ACK，不要求重复 header。服务端在 receipt 事务中读取不可变 policy parent、ACK issuance 和相关 lease：

- 无 lease 时，按 policy parent 中服务端 Phase-B 写入的 `product_authority_initial_checked_at` 验证 ACK；该时间只证明判定时的 authority。
- 有 lease 时，按该 action 的服务端 `ExecutionLease.issued_at` 验证 ACK，并匹配 runtime binding、approval 和 consumption。
- 时间窗口为 `issued_at <= anchor < expires_at`；撤销时间必须晚于 anchor。
- receipt 的终态时间可以晚于 ACK 到期时间，后续 heartbeat、同签名密钥的 activation 替换或 ACK 撤销不会丢弃此前有效的历史证据。签名密钥轮换前须先 drain 历史 receipt；本批未引入历史 keyring。
- malformed、未签发、篡改或历史窗口不符为 422 / `RUNTIME_OUTCOME_INVALID`；parent 或 immutable content 冲突仍为 409。存储/服务故障保留 5xx。

历史 ACK 校验不证明宿主 invocation-start。OpenClaw 仍为 `C3=false`，其非权威执行开始时间只能按签署的 residual boundaries 解释。真实 start receipt 和 Host exactly-once 边界在 runtime 批次验收。

ACK 原文只出现在 heartbeat 响应和运行时回传中。私有 issuance 表保存 token 的 SHA-256 digest 和签名字段投影；审计/溯源和 Dashboard 状态写入前脱敏，`repr` 不显示 token 或服务器密钥。

## OpenClaw restricted allow_once 消费

Product OpenClaw 只消费原 official ASK 的 `restricted_allow_once` 指令。仍使用
`POST /v1/approvals/{approval_id}/execution-leases/consume`，请求为
`{"mode":"restricted_allow_once","action_id":"<原动作标识>"}`；禁止提交
`authorization_fingerprint`。LangGraph 的 strong binding 请求与响应保持兼容。

服务端将原 action 的指纹和 `release_mode` 保存在私有授权记录中，并从不可变
policy parent 核验 runtime、profile、binding、approval 和指令。只有真实审批入口
确认的 human `allow_once` 才能注册 grant；原子消费检查模式、ACK 和一次性状态。
指纹不返回 OpenClaw，也不意味着 Host 具备 strong binding。缺失私有记录或模式
不匹配均拒绝消费，不降级到旧审批路径。

运行时等待审批后刷新 ACK；一次 consume 的不确定结果重试固定请求体与 ACK。
restricted 回执携带原消费 ACK、lease 和 consumption，使用
`release_mode=restricted_allow_once`、`binding_check_status=not_performed`，
不记录权威 invocation-start。实际执行终态来自宿主 after hook；宿主中断而结果
未知时持久保留未知状态，恢复只补回执。SQLite 写入成功的实际终态可推进对应
memory change，内容仍保留原 provenance/trust，不能据此取得可信来源身份。

迁移 `0020_restricted_approval_mode` 为旧记录默认补入 `strong_binding`。
存在 restricted 记录时禁止降级删除模式；降级检查与 DDL 在排他锁内执行，
避免并发插入造成记录语义丢失。第 07 批公开 Product 注册仍保持关闭，完整
内容链和组合检查在第 08、09 批接通后才可显式启用。

## 本批验证入口

```bash
uv run pytest -q tests/test_product_activation_ack_storage.py -m 'not postgres'
uv run pytest -q tests/test_product_activation_ack_authority.py
uv run pytest -q tests/test_product_activation_ack_receipt.py
uv run pytest -q tests/test_product_authority_replay.py tests/test_product_context_replay_race.py
```

完整 required checks 和 PostgreSQL 使用[贡献指南](../../CONTRIBUTING.md)的独立测试库流程；这些 Control Plane 测试不构成双运行时真实宿主或 24 小时 canary 的完成证据。
