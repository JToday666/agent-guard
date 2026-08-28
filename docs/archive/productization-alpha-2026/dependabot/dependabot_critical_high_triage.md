# Dependabot critical/high 分诊与修复记录

## 1. 范围与结论

- 分析基线：`dev@7f58e531c63cb7a3c6f372f4255bb6d80e06e1cf`。
- 数据来源：GitHub REST 的开放 Dependabot general alerts；malware alerts 为空。
- 输入共 64 条：critical 1、high 63；逐条的 alert number、advisory、manifest、受影响范围、首个修复版本、分诊结论和本轮目标版本固化在[机器可读告警清单](dependabot_critical_high_alerts.json)。
- 64 条输入对应 24 个 advisory。静态分诊结果为 `needs_review=14`、`not_actionable=50`、`confirmed=0`。
- `needs_review` 表示锁文件存在受影响的 OpenClaw/MCP 传递依赖，但攻击者输入到上游危险调用的完整路径和外部宿主版本无法仅从 AgentGuard 仓库证明；它不是漏洞确认，也不是忽略理由。
- 50 条 `not_actionable` 中，44 条来自 11 份相同的 legacy benchmark fixture 锁文件，5 条只存在于受信任的 Dashboard 构建链，1 条 Starlette 告警缺少任何 `request.form()` / FastAPI `Form` 路由。

本轮没有 dismiss 告警。所有涉及的锁文件都升级到 advisory 给出的最高安全下限或更高版本；GitHub 只有在变更进入扫描分支并重新分析后才会关闭告警。

## 2. Alpha 锁文件告警

| 严重性 | Advisory | GitHub alert | 组件 | 静态结论 | 本轮目标版本 |
| --- | --- | ---: | --- | --- | --- |
| critical | `GHSA-23hp-3jrh-7fpw` | 133 | `tar` | needs_review：OpenClaw 传递依赖；未证明 archive sink 可达 | `7.5.21` |
| high | `GHSA-r292-9mhp-454m` | 141 | `tar` | needs_review | `7.5.21` |
| high | `GHSA-8x88-c5mf-7j5w` | 132 | `tar` | needs_review | `7.5.21` |
| high | `GHSA-vmh5-mc38-953g` | 125 | `undici` | needs_review：OpenClaw proxy/TLS 传递依赖 | `8.9.0` |
| high | `GHSA-4cwx-7wf7-3272` | 146 | `undici` | needs_review | `8.9.0` |
| high | `GHSA-vxpw-j846-p89q` | 127 | `undici` | needs_review | `8.9.0` |
| high | `GHSA-38rv-x7px-6hhq` | 123 | `undici` | needs_review | `8.9.0` |
| high | `GHSA-mwp4-54f8-5fhr` | 153 | `ip-address` | needs_review：MCP SDK rate-limit 传递依赖 | `10.3.1` |
| high | `GHSA-7p8r-x3mc-p8w7` | 145 | `fast-uri` | needs_review：AJV URI-format 传递依赖 | `3.1.5` |
| high | `GHSA-v2hh-gcrm-f6hx` | 139 | `fast-uri` | needs_review | `3.1.5` |
| high | `GHSA-4c8g-83qw-93j6` | 138 | `fast-uri` | needs_review | `3.1.5` |
| high | `GHSA-rgw5-rvv9-x895` | 143 | `brace-expansion` | needs_review：OpenClaw/minimatch 传递依赖 | `5.0.9` |
| high | `GHSA-mh99-v99m-4gvg` | 142 | `brace-expansion` | needs_review | `5.0.9` |
| high | `GHSA-3jxr-9vmj-r5cp` | 130 | `brace-expansion` | needs_review | `5.0.9` |
| high | `GHSA-82w8-qh3p-5jfq` | 162 | `starlette` | not_actionable：产品 API 未使用受影响的 form parser | `1.6.0`；同时 FastAPI `0.141.1` |
| high | `GHSA-2v37-7h3g-55p8` | 160 | `nanoid` | not_actionable：PostCSS 构建链，无外部 size 参数 | `3.3.18` |
| high | `GHSA-28wg-ghj8-5hjv` | 158 | `nanoid` | not_actionable：PostCSS 构建链，无外部 size 参数 | `3.3.18` |
| high | `GHSA-r28c-9q8g-f849` | 140 | `postcss` | not_actionable：只处理仓库控制的 Dashboard 构建输入 | `8.5.18` |
| high | `GHSA-xvcm-6775-5m9r` | 137 | `immutable` | not_actionable：Sass 构建链 | `5.1.8` |
| high | `GHSA-v56q-mh7h-f735` | 136 | `immutable` | not_actionable：Sass 构建链 | `5.1.8` |

Node 安全版本通过根 `pnpm-workspace.yaml` 的同主版本 override 固化；Python 通过 Guard API 的最低依赖版本和根/应用双锁文件固化。OpenClaw 插件仍把宿主作为 peer，不因 override 扩大为“已修复任意外部 OpenClaw 安装”的声明。

## 3. Legacy benchmark fixture 告警

以下四组 advisory 各作用于相同的 11 份 `agentguard_langgraph_bench/bench/datasets/instrumentation/Browser-art_*/package-lock.json`，共 44 条：

| Advisory | GitHub alerts | 组件 | 静态结论 | 本轮目标版本 |
| --- | --- | --- | --- | --- |
| `GHSA-qwcr-r2fm-qrc7` | 112, 101, 90, 79, 68, 57, 46, 35, 24, 13, 2 | `body-parser` | not_actionable：fixture 未被产品、CI 或 benchmark runner 安装/启动 | `1.20.3` |
| `GHSA-37ch-88jc-xwx2` | 120, 109, 98, 87, 76, 65, 54, 43, 32, 21, 10 | `path-to-regexp` | not_actionable：同上 | `0.1.13` |
| `GHSA-rhx6-c78j-4q9w` | 117, 106, 95, 84, 73, 62, 51, 40, 29, 18, 7 | `path-to-regexp` | not_actionable：同上 | `0.1.13` |
| `GHSA-9wv6-86v2-598j` | 111, 100, 89, 78, 67, 56, 45, 34, 23, 12, 1 | `path-to-regexp` | not_actionable：同上 | `0.1.13` |

这些目录仍包含可由开发者手工运行的 standalone Express fixture，因此没有删除或 dismiss 其依赖记录；本轮把 manifest 标记为 `private`，增加安全 override，并生成 11 份字节一致的锁文件。它们仍不是 Productization Alpha 支持入口。

## 4. 出口条件

1. frozen `pnpm` / `uv` / fixture `npm` 安装成功；所有目标锁文件均不再包含本批 critical/high advisory 的受影响版本。
2. Dashboard、OpenClaw、MCP bridge、Guard API 与 benchmark fixture 的定向测试通过。
3. Productization Alpha 完整本地门禁和 GitHub `dev` 的 11 项 required checks 通过。
4. 变更进入 `dev` 后回读 Dependabot；critical/high 必须降为 0，或对仍存在的 alert 重新核对 manifest 与 GitHub 分析状态。

候选分支的本地 registry 审计结果为：workspace `pnpm audit --audit-level high` 的 critical/high 均为 0，仍有 moderate 6、low 1；11 份字节一致 fixture 锁中的代表目录执行 `npm audit --omit=dev --audit-level=high` 后 critical/high 均为 0，仍有 moderate 2、low 4。Python `uv pip check` 报告全部已安装包兼容。残余 medium/low 属于下一批分诊输入，不因本批通过而被忽略或宣称清零。

## 5. 合入与 GitHub 回读

- [PR #192](https://github.com/JToday666/agent-guard/pull/192) 的 11 项 required checks 全部成功，候选以 squash commit [`2fdbe203`](https://github.com/JToday666/agent-guard/commit/2fdbe20396b3dda4d3990a89688106e7720ddc6b) 合入 `dev`；`main` 未更新，也没有发布包、镜像、标签或 release。
- [PR CI run 32758020031](https://github.com/JToday666/agent-guard/actions/runs/32758020031)、[source build run 32758019835](https://github.com/JToday666/agent-guard/actions/runs/32758019835) 与精确针对合入提交运行的 [post-merge dev CI run 32759050061](https://github.com/JToday666/agent-guard/actions/runs/32759050061) 均成功；手动 OpenClaw live gate 按阶段契约为 skipped，不计入 required checks。
- [Dependency Graph run 32759055721](https://github.com/JToday666/agent-guard/actions/runs/32759055721) 成功后，GitHub REST 回读确认本批 1 条 critical 与 63 条 high 全部为 `fixed`，`dismissed_at` 均为空；修复时间范围为 `2026-08-24T17:52:41Z` 至 `2026-08-24T17:52:57Z`。
- 重扫后的开放告警为 critical 0、high 0、medium 28、low 67。medium/low 仍须进入后续分诊，不能把本批结论扩大成“依赖零风险”。

第 4 项已经达成，critical/high 依赖告警不再构成单独阻塞项；这不会自动授权外部试用或生产发布，仍须遵守 Productization Alpha 的其他限制和单独 go/no-go 决策。
