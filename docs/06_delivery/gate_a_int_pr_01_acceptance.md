# Gate A（INT-PR-01）后端验收记录

日期：2026-08-16
分支：`codex/gate-a-int-pr-01`
验证基线：`f435bff`

## 结论

Gate A 后端功能已实现并通过本地验收。实现保持 V2.1 Shadow-only、两个功能开关默认关闭，Legacy 官方决策与公开响应不变；本记录不代表整个 S3 Stage、Dashboard 或真实 Runtime 交付完成。

验证结束时本分支 `HEAD` 与 `origin/dev` 均为 `f435bff`。同步纳入的 S1 Dashboard 与 RTE-05 preparation 未改变 Gate A 的隔离边界；`evaluation.py` 的唯一重叠已保留双方语义并通过全量回归。

## 已闭合链路

```text
Historical Snapshot + Legacy detection
→ build one TransientSecurityFacts bundle
→ Core shadow assessment with an ephemeral current-event overlay
→ atomic audit commit
→ deterministic CT delta/project
→ next Historical Snapshot
```

- `SecurityContext.visible_source_refs` 冻结了 `None`（Runtime 无法证明）与 `[]`（明确为空）的不同语义，并保持未提供字段时的旧 wire shape。
- 服务端仅接受同 task/scope Snapshot 中的 canonical SourceFact，或能由唯一 `returned_by` 边解析的历史 action alias；未知、跨 scope、歧义或超预算输入整组拒绝。
- 真实 `tool_result_produced → model_output → high-impact tool_call` 链会产生 UNTRUSTED SourceFact、`influenced_by/possible` FlowFact 和 `behavior:B2`；只有 verified lineage 能触发 B2。
- Current Action 只存在于 precommit overlay，不写入 CT `action_additions`。
- Core 对同一 `overlay_digest` 做消费握手；未消费或被篡改的 overlay 不得进入 CT audit/project。
- 降级 overlay 以 audit-only CT envelope 留痕，但 `projection_eligible=false`，不会投影或 backfill。
- 新 CT envelope 为 schema `1.1` / fact builder `ct-fact-2`；schema `1.0` / `ct-fact-1` 的历史审计仍可校验和 backfill。
- relevant-flow traversal 执行 depth/width/node `4/32/256` 预算，并在索引/合并前执行总量硬限制；同 trace 的无关分支不进入当前动作证据。

## 验收证据

| 检查门 | 结果 |
| --- | --- |
| Black（22 个变更 Python 文件） | 通过 |
| Ruff（`apps packages scripts tests`） | 通过 |
| Pyright | `0 errors, 0 warnings, 0 informations` |
| `git diff --check` | 通过 |
| Gate A + CT + V21 全组 | `1342 passed, 16 skipped` |
| Python 全量（含 Legacy、Runtime safety、RTE-05 与 LangGraph Adapter） | `1906 passed, 146 skipped` |
| PostgreSQL reopen/readback | 在带测试数据库配置的 Gate A 全组中实际执行并通过，非 skip |

Gate A HTTP 验收使用真实 `/v1/guard/evaluate` 请求，覆盖 Memory 与 PostgreSQL store、B2 A/B lineage、三门矩阵、非法 secret、不泄漏 secret、缺失/伪造 refs、未消费 overlay、builder/Core failure、audit window、Trace readback、integrity、divergence tool 和 flag rollback。现有 CT/V21 回归继续覆盖 stale、budget dropped、commit/project failure、replay、backfill 与 rebuild。

## 隔离边界

本变更仅涉及 Guard API、AgentGuard Core、独立后端测试与本验收记录。未修改 Dashboard、LangGraph Adapter、CI、S1 runtime E2E、数据库迁移或 Runtime enforcement；未启用 limited-enable、Memory Bridge、cross-session、完整 declassification、RTE strong binding 或 Trace Diff。
