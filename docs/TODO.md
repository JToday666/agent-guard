# 已完成后端能力与剩余接入项

## 状态

本文件记录原前端预留能力的后端落地状态。三项后端能力均已完成：

- 安全评测 ASR 数据：已提供导入与 latest 查询接口。
- 配置审计 findings：已提供只读查询接口。
- OpenClaw 插件验证状态：已提供最近一次 verify 状态写入与读取接口。

剩余工作主要是 Dashboard 展示接入。按当前协作约束，默认不修改 `apps/dashboard/**`；如需在页面展示 ASR、finding 明细或 OpenClaw verify 状态，需要另行确认前端改动范围。

## 安全评测 ASR 数据接口

后端采用“导入并保存”方案，评测结果由 CLI/API 写入 Guard API，再由 Dashboard 或 CLI 读取最新一次 run。

### 写入

`POST /v1/evaluations`

- 鉴权：control token。
- 用途：导入 AttackBench/Core matrix 等评测结果。
- ASR 字段允许 `null`；非 `null` 时必须在 `[0, 1]`。

```json
{
  "run_id": "eval_20260628",
  "run_at": "2026-06-28T00:00:00+00:00",
  "asr_before": 0.732,
  "asr_after": 0.048,
  "per_attack": {
    "prompt_injection": { "asr_before": 0.85, "asr_after": 0.05 }
  },
  "cases": [
    {
      "case_id": "PI-001",
      "attack_type": "prompt_injection",
      "runtime": "openclaw",
      "expected_decision": "deny",
      "actual_decision": "ask",
      "blocked": true,
      "attack_success": false,
      "trace_id": "trace_001"
    }
  ]
}
```

### 读取

`GET /v1/evaluations/latest`

- 鉴权：browser session 或 control token。
- 无数据：`404 EVALUATION_NOT_FOUND`。

### CLI

```bash
uv run agentguardctl eval import /path/to/evaluation-run.json
```

## 配置审计 findings 只读接口

`GET /v1/config-audit/findings?trace_id=&target_id=&target_type=&severity=&limit=`

- 鉴权：browser session 或 control token。
- 数据来源：`/v1/config-audit/evaluate` 写入的 `config_audit_findings`。
- 返回 finding 原文，并附带 `runtime`、`target_type`、`target_id`、`trace_id`、`event_id`、`timestamp`。

## OpenClaw 插件验证状态接口

OpenClaw 状态不是每次 Dashboard 刷新实时 shell 探测，而是最近一次 verify 上报结果。

### 写入

`PUT /v1/adapters/openclaw/status`

- 鉴权：control token。
- 写入方：`agentguardctl openclaw verify --record` 或 `scripts/openclaw-plugin-dev.mjs verify --record`。

```json
{
  "status": "loaded",
  "loaded": true,
  "hook_count": 16,
  "expected_hook_count": 16,
  "last_verified_at": "2026-06-28T00:00:00+00:00",
  "error": null,
  "source": "agentguardctl"
}
```

### 读取

`GET /v1/adapters/openclaw/status`

- 鉴权：browser session 或 control token。
- 无记录：返回 `status="unknown"`。

## 前端接入待确认

以下属于 Dashboard 改动，需单独确认后再做：

- `EvaluationPage` 读取 `/v1/evaluations/latest` 并展示 `asrBefore/asrAfter`。
- `SystemPage` 展示 OpenClaw verify 状态。
- `SystemPage` 展示配置审计 finding 明细。
