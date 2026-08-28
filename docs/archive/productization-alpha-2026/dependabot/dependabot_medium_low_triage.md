# Dependabot medium/low 分诊与修复记录

## 1. 范围与结论

- 分析基线：`dev@8ae6c1ef5bb68b088a55eed81e06ffd1a7c2e169`。
- 数据来源：2026-08-25 通过 GitHub REST 获取的开放 Dependabot `general` alerts。
- 输入共 95 条：medium 28、low 67，对应 15 个 advisory。逐条 alert number、manifest、受影响范围、首个修复版本、分诊结论和目标版本固化在[机器可读告警清单](dependabot_medium_low_alerts.json)。
- 静态分诊结果为 `needs_review=6`、`not_actionable=89`、`confirmed=0`。
- 6 条 `needs_review` 都是 OpenClaw/MCP 上游运行时树中的传递依赖；AgentGuard 仓库未证明危险调用可达，也无法仅凭本仓库替代外部宿主审查。
- 89 条 `not_actionable` 中，88 条来自 11 份相同的 legacy benchmark fixture 锁文件，1 条属于仅处理仓库受信输入的 Dashboard 构建链。

`not_actionable` 只描述当前仓库和 Alpha 支持边界内的静态可达性，不表示上游 advisory 无效。本轮不 dismiss 告警，仍升级全部锁文件并等待 GitHub Dependency Graph 重新分析。

## 2. 根 pnpm 锁文件

| 严重性 | Advisory | Alert | 组件 | 静态结论 | 目标版本 |
| --- | --- | ---: | --- | --- | --- |
| medium | `GHSA-frvp-7c67-39w9` | 159 | `@hono/node-server` | needs_review：MCP SDK 传递依赖；本仓库不导入 `serveStatic`，bridge 使用 stdio transport | `1.19.15` |
| medium | `GHSA-f23p-vx2j-j53r` | 157 | `hono` | needs_review：MCP SDK 传递依赖；本仓库不使用 Hono JSX `memo()` | `4.12.34` |
| low | `GHSA-79qm-7rj5-m7r9` | 156 | `hono` | needs_review：同一上游运行时树；本仓库没有 proxy helper 调用 | `4.12.34` |
| medium | `GHSA-54fx-42gc-7vw4` | 155 | `hono` | needs_review：同一上游运行时树；本仓库没有 language middleware 调用 | `4.12.34` |
| medium | `GHSA-8j4g-w8fx-2239` | 154 | `hono` | needs_review：同一上游运行时树；本仓库没有 Hono CORS 调用 | `4.12.34` |
| medium | `GHSA-fxqj-rqcc-2cmp` | 144 | `postcss` | not_actionable：Dashboard 构建链只处理仓库控制的 CSS/Vue 输入 | `8.5.23` |
| medium | `GHSA-j3f2-48v5-ccww` | 135 | `protobufjs` | needs_review：经 `@google/genai` 进入 OpenClaw 宿主树；仓库无 `.proto` 输入或 parser 调用 | `7.6.5` |

根修复通过 `pnpm-workspace.yaml` 的精确 override 完成，不升级 MCP SDK、OpenClaw 或公共包版本。OpenClaw 仍是插件的 peer/开发宿主，因此本轮不能扩大声称为“任意外部 OpenClaw 安装均已修复”。

## 3. Legacy benchmark fixture

以下 8 组 advisory 各作用于相同的 11 份 `agentguard_langgraph_bench/bench/datasets/instrumentation/Browser-art_*/package-lock.json`，共 88 条：

| 严重性 | Advisory | Alerts | 组件 | 首个修复版本 | 本轮目标版本 |
| --- | --- | --- | --- | --- | --- |
| medium | `GHSA-q8mj-m7cp-5q26` | 163–173 | `qs` | `6.15.2` | `6.15.3` |
| low | `GHSA-v422-hmwv-36x6` | 11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 121 | `body-parser` | `1.20.6` | `1.20.6` |
| low | `GHSA-w7fw-mjwx-w883` | 9, 20, 31, 42, 53, 64, 75, 86, 97, 108, 119 | `qs` | `6.14.2` | `6.15.3` |
| medium | `GHSA-6rw7-vpxm-498p` | 8, 19, 30, 41, 52, 63, 74, 85, 96, 107, 118 | `qs` | `6.14.1` | `6.15.3` |
| low | `GHSA-pxg6-pf52-xh8x` | 6, 17, 28, 39, 50, 61, 72, 83, 94, 105, 116 | `cookie` | `0.7.0` | `0.7.2` |
| low | `GHSA-m6fv-jmcg-4jfg` | 5, 16, 27, 38, 49, 60, 71, 82, 93, 104, 115 | `send` | `0.19.0` | `0.19.2` |
| low | `GHSA-cm22-4g7w-348p` | 4, 15, 26, 37, 48, 59, 70, 81, 92, 103, 114 | `serve-static` | `1.16.0` | `1.16.3` |
| low | `GHSA-qw6h-vgh9-j6wx` | 3, 14, 25, 36, 47, 58, 69, 80, 91, 102, 113 | `express` | `4.20.0` | `4.22.2` |

这些 fixture 不在 pnpm workspace 内，当前产品、CI 和 benchmark runner 不会安装或启动其中的 `text_server`；它们仍可被开发者手工运行，所以保留 `private` manifest、升级到 Express 4 的最新兼容线，并通过精确 override 固化 `body-parser`、`qs` 与既有 `path-to-regexp` 安全版本。11 份 manifest 和 lock 必须继续分别保持字节一致。

## 4. 验证与出口条件

1. 根 `pnpm` frozen install 与代表 fixture 的隔离 `npm ci` 成功，锁中所有同名节点均达到安全下限。
2. MCP bridge、OpenClaw 插件/bench tools/shim、Dashboard build 和 fixture Express 4 路由/static smoke 通过。
3. `tests/test_dependency_security_floors.py` 解析实际 YAML/lock 结构，拒绝任意低于下限的同名节点；不能只检查字符串存在。
4. Productization Alpha 本地门禁和 GitHub `dev` 的 11 项 required checks 通过。
5. 变更合入 `dev` 后回读 Dependabot；95 条输入必须成为 `fixed` 且没有 `dismissed_at`，否则重新核对 manifest、版本范围和 Dependency Graph 状态。

候选分支的本地审计结果为 workspace `pnpm audit --audit-level low` 0 个已知漏洞，代表 fixture `npm audit --package-lock-only --omit=dev --audit-level=low` 0 个已知漏洞。11 份 fixture 的 manifest 与 lock 分别字节一致；代表 fixture 的隔离 `npm ci` 与 Express 4 JSON、参数路由、OPTIONS 和 static smoke 均通过。Productization Alpha fast gate 为 2,339 passed、16 skipped、181 deselected；Dashboard 229、OpenClaw 206、bench tools 4、shim/installer/runtime 68 项 Node 测试和 Dashboard production build 均通过。

## 5. 合入与 GitHub 回读

- [PR #196](https://github.com/JToday666/agent-guard/pull/196) 的 11 项 required checks 全部成功，候选以 squash commit [`ee775dc`](https://github.com/JToday666/agent-guard/commit/ee775dc272cf68de0535fee94585fb509c61c3ed) 合入 `dev`；`main` 未更新，也没有发布包、镜像、标签或 release。
- [PR CI run 32823275837](https://github.com/JToday666/agent-guard/actions/runs/32823275837)、[source build run 32823275756](https://github.com/JToday666/agent-guard/actions/runs/32823275756)、[post-merge dev CI run 32824258903](https://github.com/JToday666/agent-guard/actions/runs/32824258903) 与 [post-merge source build run 32824258897](https://github.com/JToday666/agent-guard/actions/runs/32824258897) 均成功；手动 OpenClaw live gate 按阶段契约为 skipped，不计入 required checks。
- GitHub REST 逐条回读确认 95 条输入全部为 `fixed`，没有缺失项，`dismissed_at` 均为空；修复时间范围为 `2026-08-25T07:59:08Z` 至 `2026-08-25T07:59:18Z`。逐条状态固化在[机器可读回读清单](dependabot_medium_low_fixed_readback.json)。
- 重扫后的开放 Dependabot 告警为 0。该值是当前依赖图快照，不是“永远无漏洞”的声明；新增 advisory 或依赖变更仍须重新进入分诊和门禁流程。

本批出口条件已全部达成。它不授权更新 `main`、发布包/镜像或宣称生产就绪。
