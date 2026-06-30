# 已完成后端能力与剩余接入项

## 状态

本文件记录原前端预留能力的后端落地状态。三项后端能力均已完成：

- 安全评测 ASR 数据：已提供导入、latest 查询和 dataset registry 汇总接口。
- 配置审计 findings：已提供只读查询接口。
- OpenClaw 插件验证状态：已提供最近一次 verify、E2E 和 reliability 状态摘要写入与读取接口。
- 运行时监控指标：已提供 `/v1/metrics/runtime`，可按 runtime 聚合审计事件、hook 活跃度和 adapter 状态。

Dashboard 已完成展示接入：安全评测页读取 latest evaluation，系统状态页读取配置审计 findings 与 OpenClaw verify/status。mock 数据源已补齐有数据状态，便于本地查看真实数据形态下的页面效果。

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
  "dataset_id": "attackbench",
  "dataset_version": "v1",
  "dataset_digest": "sha256:...",
  "dataset_locked": true,
  "regression_gate": {
    "status": "passed",
    "baseline_run_id": "eval_baseline",
    "max_allowed_regression": 0.02,
    "asr_delta": -0.684,
    "failed_case_ids": []
  },
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
      "case_digest": "sha256:...",
      "provenance": {
        "source": "attackbench",
        "source_path": "bench/datasets/attack_cases/prompt_injection.jsonl",
        "line": 1
      },
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

`GET /v1/evaluations/datasets`

- 鉴权：browser session 或 control token。
- 用途：从已保存 evaluation run 汇总 dataset 版本、锁定状态、case provenance 覆盖、latest run 和 regression gate 摘要。

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
  "hook_count": 19,
  "expected_hook_count": 19,
  "last_verified_at": "2026-06-28T00:00:00+00:00",
  "error": null,
  "source": "agentguardctl"
}
```

E2E / reliability runner 会把门禁摘要写入 `capabilities.release_gates`，用于后续发布前复查。

### 读取

`GET /v1/adapters/openclaw/status`

- 鉴权：browser session 或 control token。
- 无记录：返回 `status="unknown"`。

## 前端接入状态

以下 Dashboard 展示已接入：

- `EvaluationPage` 读取 `/v1/evaluations/latest`，展示 latest run、ASR before/after、per-attack ASR 和 cases 样本追踪。
- `SystemPage` 读取 `/v1/adapters/openclaw/status`，展示 OpenClaw verify/heartbeat、hook 覆盖、版本、来源和错误状态。
- `SystemPage` 读取 `/v1/config-audit/findings`，展示配置审计 finding 明细、严重性分布、目标、建议和证据链入口。
