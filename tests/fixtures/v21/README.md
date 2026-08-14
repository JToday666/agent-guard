# V21 fixture 边界

- `baseline_scenarios.json` 仅从现有 30 attack / 13 benign retained fixture 选取性能代表载荷，不是独立评测集。
- `multi_event/` 使用独立 Schema，显式保存 trace、step、parent、event 与 action 标识；当前样例只验证框架和回归执行能力。
- `locked_holdout_manifest.json` 不保存真实案例。真实 locked holdout 只能由受控路径注入；仓库内只记录状态、类别数量和数据摘要。
- `not_provisioned` 与零计数是明确阻塞状态，不得解释为已满足 100/100 Limited Enable 门禁。
