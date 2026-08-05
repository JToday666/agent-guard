# AgentGuard OpenClaw Bench Tools

`@agentguard/openclaw-bench-tools` 是 OpenClaw AttackBench 场景使用的本地工具桥接插件。它把 OpenClaw agent 的工具调用转发到当前本地 HTTP Tool Server，使 OpenClaw 可以执行与 LangGraph 靶场相同的 AttackCase 工具计划。

## 职责

- 桥接 `local-task-runner` OpenClaw agent 与本地工具服务。
- 保持工具调用、工具结果和副作用证据可被 AttackBench runner 评分。
- 配合 AgentGuard OpenClaw security plugin 验证真实 runtime 接入。

## 非职责

- 不实现安全策略。
- 不判断攻击是否成功。
- 不调用 `agentguard-core`。
- 不替代 `@agentguard-ai/openclaw-plugin` 的检测、阻断和审计能力。

## 验证

在仓库根目录执行：

```bash
pnpm --filter @agentguard/openclaw-bench-tools build
pnpm --filter @agentguard/openclaw-bench-tools test
pnpm openclaw:bench-tools:build
pnpm openclaw:bench-tools:verify
pnpm openclaw:bench-shim:test
```

如果需要安装到本机 OpenClaw 开发环境，使用仓库脚本：

```bash
pnpm openclaw:bench-tools:install
pnpm openclaw:bench-tools:uninstall
```
