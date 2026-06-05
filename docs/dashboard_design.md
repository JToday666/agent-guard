# Dashboard 与审批流

## 1. 定位

Dashboard 是监督端，只连接 Core。

负责：

- 实时事件；
- 告警；
- 阻断记录；
- 攻击链路；
- 审批；
- 指标；
- 配置审计；
- 审计完整性。

## 2. 页面

| 页面 | 内容 |
|---|---|
| 总览 | 事件数、风险数、阻断数、ASR、FPR |
| 实时事件 | AuditEvent 列表 |
| 攻击链路 | trace_id 时间线 |
| Provenance 图 | 来源影响图 |
| 审批中心 | allow_once / deny |
| 指标评测 | ASR、Block Rate、FPR、Latency |
| 配置审计 | OpenClaw 配置风险 |
| 审计完整性 | hash chain 验证 |

## 3. 数据来源

```text
GET /v1/audit/events
GET /v1/audit/traces/{trace_id}
GET /v1/metrics/runtime
GET /v1/metrics/eval
GET /v1/approvals/pending
POST /v1/approvals/{id}/resolve
```

## 4. 多渠道审批

P0：Dashboard 审批。  
P1：CLI 审批。  
P2：OpenClaw 社交审批。
