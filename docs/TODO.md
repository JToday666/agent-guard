# 后端待处理项（前端预留能力）

## 安全评测 ASR 数据接口

**背景**：前端评测页已预留 `asrBefore / asrAfter` 字段显示，但当前 Guard API `/v1/metrics/eval` 不返回 ASR 数据。

**建议方案**：新增只读接口 `GET /v1/evaluations/latest`，返回：

```json
{
  "run_id": "string",
  "run_at": "ISO8601",
  "asr_before": 0.732,
  "asr_after": 0.048,
  "per_attack": {
    "prompt_injection": { "asr_before": 0.85, "asr_after": 0.05 }
  },
  "cases": [
    {
      "case_id": "PI-001",
      "attack_type": "prompt_injection",
      "runtime": "langgraph",
      "expected_decision": "deny",
      "actual_decision": "deny",
      "blocked": true,
      "attack_success": false,
      "trace_id": "trace_001"
    }
  ]
}
```

**前端已就绪**：`EvaluationSummary.asrBefore / asrAfter` 类型已定义，显示逻辑已实现，空状态文案已更新为"请运行 AttackBench 评测并导入结果"。

**优先级**：P1（竞赛展示时如有真实评测数据，建议接入）

---

## 配置审计 findings 只读接口

**背景**：配置审计结果落成 `event_type=config_audit` 的 AuditEvent，metadata 含 `finding_count`，但无法查询完整 finding 列表（title / evidence / recommendation）。

**建议方案**：`GET /v1/config-audit/findings?trace_id=&target_id=`

**前端现状**：系统状态页配置审计区块显示 finding_count，不展示 finding 详情（因为接口不存在）。

**优先级**：P2

---

## OpenClaw 插件验证状态接口

**背景**：CLI `agentguardctl openclaw verify` 能验证插件安装状态，但前端无法调用 CLI，也没有对应 REST 接口。

**建议方案**：`GET /v1/adapters/openclaw/status`，返回插件是否 loaded、hookCount、最近 verify 时间。

**前端现状**：系统状态页显示"未接入验证结果"，只基于审计事件统计 OpenClaw 活动。

**优先级**：P2
