# V21-00 Freeze Readiness

当前结论：**V21-00 功能门禁与用户冻结签字均已满足，契约状态已切换为 Frozen**。

已完成：

- Frozen 机器契约与融合矩阵均有 Draft 2020-12 JSON Schema；JSON-compatible YAML 可解析，跨文件枚举、F0、模型引用和聚合文档一致性可自动校验。
- `69efe2f` Legacy 快照覆盖 30 attack / 13 benign，当前逐 case decision、rule hits 和整体分布一致。
- Core、Guard API Memory 与多事件框架已通过小迭代功能测试；统计、Wilson CI、nearest-rank 百分位、脱敏和错误路径已有自动测试。
- Guard API PostgreSQL 已在本地 `postgres:16-alpine` 测试容器完成七类代表场景与低并发 functional smoke，报告状态为 `functional_smoke_passed`，blockers 为空。
- 基线可信证明勘误已完成：正式档位强制 Memory/PostgreSQL 双后端，Legacy 快照拒绝 staged/unstaged/untracked 输入；当前报告绑定可达 source commit 与 source tree，并由 Frozen 校验工具复核。
- 当前正式效果边界为 Final ASR `not_measured`、Runtime Prevention `not_measured`、Semantic `not_applicable`。

未完成或被明确延后：

- 按用户最新范围，本阶段只跑 `functional_smoke`；200/5000、100/1000、8×2000 的正式性能基线保留在工具与契约中，当前状态为 `deferred_by_user_scope`。
- locked holdout 尚未受控注入；100 attack / 100 benign 是 Limited Enable 前置条件，不是本次伪造的完成项。
