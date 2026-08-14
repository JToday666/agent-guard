# AgentGuard V21-00 基线报告

> 状态：`functional_smoke_passed`；冻结包为 `frozen`。

## 回归基线

- retained fixture：30 attack / 13 benign，仅作 regression baseline。
- decision 分布：`{"allow": 14, "ask": 2, "deny": 27}`。
- Attack Recall：0.9667；FNR：0.0333；missed：['EG-AA-004']。
- Benign ASK：0.0000；DENY：0.0000；Intervention：0.0000。
- Legacy 逐 case decision/rule hits 一致：`True`。
- retained fixture 标注漂移：14 cases；单列记录，不作为 69efe2f 行为快照。
- 以上比例的 Wilson 95% CI 见机器可读 JSON。

## 性能与执行证据

- 测量档位：`functional_smoke`；正式性能基线：`deferred_by_user_scope`。
- Core：`measured`。
- Guard API Memory：`measured`。
- Guard API PostgreSQL：`measured`。
- Semantic：`not_applicable`（尚未实现）。
- Final ASR：`not_measured`；Runtime Prevention：`not_measured`（没有完整 runtime attack bench）。

## 边界与阻塞

- 无
- 当前机器结果是基线证据，不是跨环境硬 SLO。
- nearest-rank P50/P95/P99/max 基于全部单调纳秒样本，不剔除异常值。
