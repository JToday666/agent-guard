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
| 任一 runtime 的冻结状态或最新 ACK 不匹配 | 503 / `V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH` | 阻断当前请求 |
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

## 本批验证入口

```bash
uv run pytest -q tests/test_product_activation_ack_storage.py -m 'not postgres'
uv run pytest -q tests/test_product_activation_ack_authority.py
uv run pytest -q tests/test_product_activation_ack_receipt.py
uv run pytest -q tests/test_product_authority_replay.py tests/test_product_context_replay_race.py
```

完整 required checks 和 PostgreSQL 使用[贡献指南](../../CONTRIBUTING.md)的独立测试库流程；这些 Control Plane 测试不构成双运行时真实宿主或 24 小时 canary 的完成证据。
