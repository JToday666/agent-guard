# OpenClaw External Agent Adapter

该目录是 AttackBench 的 OpenClaw 外部 Agent 适配器，不是 OpenClaw runtime security plugin。它把 OpenClaw 当作外部智能体目标，通过 benchmark HTTP Tool Server 执行 AttackCase 中的工具计划；评分仍由 `agentguard_langgraph_bench/bench` 中的 runner、scoring 和 metrics 逻辑完成。

## 与 security plugin 的区别

- 本适配器服务评测 runner，用于把 OpenClaw 纳入 AttackBench 批量测试。
- `packages/agentguard-openclaw-plugin/` 是真实 OpenClaw hook 插件，用于运行时检测、阻断、审批和审计。
- 本适配器不实现策略、不替代 Guard API、不直接写审计数据库。

## 运行入口

在仓库根目录查看统一 runner 参数：

```bash
uv run agentguardctl eval run --help
```

OpenClaw 外部 Agent 评测需要同时准备 OpenClaw agent endpoint、本地 tool server、Guard API 配置和 AttackCase 数据集。具体参数以 runner help 输出为准。
