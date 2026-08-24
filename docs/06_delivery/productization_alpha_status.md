# Productization Alpha Status

| 字段 | 当前值 |
| --- | --- |
| Status | **completed** |
| 状态日期 | 2026-08-24 |
| 集成分支 | `dev` |
| 代码基线 | `origin/dev@5986538`，其上以 PR #189 rebase 集成 20 个独立提交 |
| 产品代码集成 SHA | `a9702bc83ce1b9f24d987368912f20fd7c4e3e0e` |
| 平台治理记录基线 | `dev@f0ae6226b1f30db3f6274396f6a1560ce2aaf379`（本记录分支的 base） |
| 托管 CI run | [CI 32713623227](https://github.com/JToday666/agent-guard/actions/runs/32713623227)：全部自动门禁通过；[Internal Source Build Check 32713623191](https://github.com/JToday666/agent-guard/actions/runs/32713623191)：通过 |

> Productization Alpha 产品代码在 `a9702bc` 进入 `dev`，收尾状态在 `f0ae622` 进入 `dev`；本记录使用分支 base 表达平台治理前置状态，避免提交自引用。`PA01` 继续保持活动以执行功能冻结，直到独立的恢复开发评审决定是否协调释放其表面并关闭节点。completed 不代表生产就绪，也不扩大下文明确列出的能力边界。

## 本轮目标

- 阶段从竞赛/答辩驱动切换为 Productization Alpha；严格冻结新功能，只接受缺陷、安全边界、契约兼容、结构治理、迁移、可观测性、文档和发布工程。
- 保持 monorepo，以及 `apps/`、`packages/`、`benchmarks/`、`schemas/` 的现有职责；本阶段不拆成多个仓库。
- 建立贡献、安全、所有权、变更记录、架构职责和兼容矩阵。
- 把产品文档与历史竞赛/答辩材料分开。
- 提供不依赖 ignored 本地脚本或临时目录的最小示例。
- 将自动 CI 拆分为 unit、contract、integration、PostgreSQL 和 E2E；live 保持手动 opt-in。
- 恢复 official/shadow/demo 的事实边界，避免展示层扩大权威声明。
- 机器路线图以 `PA01` 集成节点记录本阶段；节点活动期间占用全表面，显式落实功能冻结并阻止并行功能分支误占产品路径。

这是内部里程碑：本阶段不创建或发布 `v0.2.0-alpha.1`，不推送镜像或包，不修改 `main`，也不对外宣称生产就绪。

## 已有产品能力

- Core 无状态 `allow` / `deny` / `ask` 判定与可解释规则命中。
- Guard API 的 credential、策略快照、原子审批、AuditEvent 哈希链、Trace、指标和 PostgreSQL 存储。
- LangGraph Adapter 和 OpenClaw 24-hook 插件接入。
- Dashboard 调查、审批、证据、评测和系统状态视图。
- LangGraph 评测 runner、70 条主数据集及 V2 competition profile 的实现表面。

## 尚未完成或不可扩大宣称

- 真实外部 Provider 的固定 A0–A4、70 例、`70×5=350` qualifying matrix 尚未完成；stub/contracts/demo 运行不能替代。
- R05 仍被 OpenClaw 宿主缺少 atomic replace-and-seal 与 authoritative invocation-start 阻塞，因此 Gate B 和正式 S4 不能关闭。
- Memory Guard 的 `commit` / `rollback` 目前只更新控制面变更记录，不会回滚或恢复真实 runtime memory。
- action receipt 覆盖率、跨 run 回归阈值、完整生产运维、容器/包公开发布、可归档与可复现 SBOM、签名、provenance 和 Trusted Publishing 仍未完成。本轮仅为精确候选 SHA 本地生成并校验 SBOM，不构成发布或长期制品归档。
- 多租户、用户登录、OAuth/SSO、自动备份与恢复不属于当前 Alpha 已有能力。
- 公开 `v0.1.0-beta.1`/对应 npm 制品是 22-hook 基线，当前未发布源码为 24 hooks，但包版本仍为 `0.1.0-beta.1`。本阶段不发布；下一次构建可发布制品前必须统一提升 Python/Node 版本和映射，禁止以同版本覆盖不同内容。
- `scripts/` 已完成职责分类和兼容入口说明，但物理迁移与超大模块拆分尚未完成；继续拆分时必须保持公共 import、CLI 和 `/v1` 行为不变。
- legacy benchmark 的 standalone LangGraph subprocess 已移除开发者机器默认路径，必须显式提供 agent command/path；但对应 849 项旧测试仍未进入门禁，它也不属于产品示例或 clean-clone acceptance。测试和依赖完成重整前不得把该 adapter 称为 Alpha 支持入口。
- 四份既有 demo 设计/运行文档因 roadmap 与外部链接兼容暂留 `docs/06_delivery/`，已统一标记 historical/unsupported 并从产品入口降级；物理迁入 archive 留待保留引用关系的独立迁移。
- CODEOWNERS 已进入仓库；截至 2026-08-24，classic branch protection endpoint 对 `dev` 仍返回未启用，但 active repository ruleset `dev merge check` 会阻止删除、非快进和绕过 PR，只允许 squash，并严格要求下文 11 个 GitHub Actions checks 基于最新 `dev` 全部通过。每个 context 均绑定 GitHub Actions App `integration_id=15368`，ruleset 无 bypass actor。
- 仓库级 secret scanning、push protection、Private Vulnerability Reporting、Dependabot alerts 与 Dependabot security updates 已启用并经 API 回读确认。启用后的初始快照为 secret scanning 开放告警 0 个、Dependabot 开放告警 162 个（critical 1、high 63、medium 28、low 70）；这是治理入口与待办基线，不是“依赖安全”或“无漏洞”的证明。critical/high 告警完成去重、可达性分析和修复前，不开始外部技术试用。

## CI 状态口径

本阶段进入 `dev` 的 CI 定义包含以下自动 job：clean-checkout 最小示例验收、静态检查、unit/contract/integration/e2e Python 测试、PostgreSQL 16 migration/tests、Node 检查、Dashboard build、Playwright Chromium E2E。浏览器 job 除 mock/API-stub 模式外，还以 memory backend 启动真实 Guard API 与 Dashboard，执行 S1 allow、浏览器审批、deny 零调用和 flag-off 回滚四场景。连接真实外部宿主或 Provider 的 `live` 仍仅在手动 workflow dispatch 明确 opt-in 时运行。

`dev` ruleset 现强制以上 10 个 CI job context，加上独立的 `Build and verify ephemeral source artifacts`，共 11 项。手动 `Manual OpenClaw live gate` 因正常状态为 skipped，不属于 required checks；任何 required context 改名都必须先迁移 ruleset，避免形成永久等待。

Python 六层分类当前只覆盖根 `tests/` 与 LangGraph adapter tests，共收集 2,533 项：unit 1,187、contract 383、integration 782、postgres 156、e2e 24、live 1。`agentguard_langgraph_bench/bench/tests` 的 849 项旧 benchmark 测试尚未纳入该矩阵：其中混有浏览器/本地 socket 用例、已移除 fixtures 和历史外部依赖，必须先完成依赖与 marker 重整；该 legacy tree 当前也有 31 项 Ruff 诊断，尚未进入默认 Ruff/Pyright。因而“Python 分层/静态检查通过”不能扩大为“全仓 benchmark 已覆盖”。

Dashboard 的 API-mode Playwright 会拦截 `/api/v1/**`，只验证前端 API 映射；独立 S1 memory 场景才是 Dashboard 到真实 Guard API 的浏览器全栈验证。clean-clone acceptance 另在隔离临时目录中验证安装后健康、临时凭证、benign allow、malicious deny、审计查询、Dashboard shell/静态资源和凭证撤销，两者覆盖边界不同。

实际集成代码 `a9702bc83ce1b9f24d987368912f20fd7c4e3e0e` 的 [push CI run 32709561355](https://github.com/JToday666/agent-guard/actions/runs/32709561355) 中，11 个自动作业全部成功；其中 Playwright 作业真实执行了 mock、API-stub 和 memory Guard API 全栈三组场景。`Manual OpenClaw live gate` 按阶段契约跳过，未被计作自动通过。相同 SHA 的 [Release Check run 32709561323](https://github.com/JToday666/agent-guard/actions/runs/32709561323) 成功构建并验证临时源码制品，没有发布或上传 release artifact。

## 验证与出口证据

本阶段整理期间已在当前工作区完成以下验证：

- 完整 unit 层为 1,171 passed、16 skipped；完整 contract 层为 383 passed，其中 Markdown 链接契约 5 项、exact-wheel 选择契约 2 项、roadmap 工具契约 26 项。
- 审批截止时间、C1 message receipt/action 关联和 AgentGuard runtime/lease token 脱敏的定向回归为 87 passed；受影响的 legacy benchmark gateway 定向回归另为 41 passed、3 skipped。
- Productization Alpha 默认 Python 门禁范围内的 Ruff 与 Pyright 通过；Python 发布包的 Black 检查逐文件通过；`git diff --check` 与 roadmap contract 检查通过。该范围明确不含上文披露的 legacy benchmark tree 及其现存 Ruff 诊断。
- Dashboard format/lint/typecheck/unit（40 个测试文件）和 production build 通过；OpenClaw 插件 18 个测试文件通过，本地 shim/installer/runtime 相关测试 68 passed。
- Markdown 相对目标检查对全部 137 份 tracked/unignored 文档通过。
- 隔离 clean-clone acceptance 在 memory backend 下完成 8/8：真实启动 Guard API，验证健康、临时凭证、benign allow、malicious deny、审计查询、Dashboard shell/静态资源、凭证撤销与临时资源清理；外部 Provider 保持关闭。
- Dashboard 隐藏页暂停与终态停止轮询的两项定向 Playwright 回归通过。
- Dashboard 到真实 Guard API 的 memory 浏览器闭环本地为 4/4 passed：official allow、浏览器 allow-once 审批、deny 零调用/not-invoked receipt、flag-off 回滚只读。
- 使用运行时代码候选 `ee2800277c79fd841b2341a2fdfe2dfd015abeef` 的本地 wheel 构建 `agentguard-api:productization-alpha-ee28002`；其后的提交只更新状态证明与 roadmap 证据，没有修改发布包或运行时代码。镜像摘要为 `sha256:e0c704993f4594816de70267251af9b7b79dd907fe79b23bd2bd1bcb746d35b3`；非特权用户、memory backend、无端口暴露的临时容器启动成功，Docker health 状态为 healthy，`/health` 返回 `200 {"status":"ok"}`，随后容器已停止并自动移除。
- 对该本地镜像生成未发布的 SPDX SBOM：Docker Scout 索引 155 个依赖包，SPDX 文档含 156 个 package entry、大小 3,424,170 bytes，SHA-256 为 `719870ddf6360a3056c58b880bc2c755f09411ccda77e0857077fcd8b8a25d7d`。SBOM 留在临时本地证据路径，不进入 Git、不上传、不发布。
- GitHub API 回读确认 `dev` ruleset 的 11 个 required checks、strict latest-base policy、GitHub Actions 来源绑定和无 bypass 均已生效；secret scanning、push protection、Private Vulnerability Reporting、Dependabot alerts/security updates 也均已启用。告警数量只记录启用后的初始快照，后续以 GitHub Security 页面实时状态为准。

托管 CI 已覆盖完整默认 integration、PostgreSQL、Python E2E、浏览器 E2E 与真实 Dashboard→Guard API memory 链路；本地补充完成了镜像启动和 SBOM 生成。仍未验证的能力只按上文范围限制处理，不得把本次 Alpha 结论扩大为生产就绪、真实 Provider 效果完成、OpenClaw live 宿主完成或 legacy benchmark 全仓通过。

## 后续优先级

1. 对 162 个初始 Dependabot 告警去重并按可达性分批处理，先完成 1 个 critical 与 63 个 high；安全更新仍受完整 required checks 约束，不批量绕过或自动合并。
2. 保持 `PA01` 的功能冻结；需要恢复功能开发时，另行评审并协调释放其产品表面。
3. 完成 Python/Node 唯一版本映射和内部 release candidate，再进行两次独立干净环境试用验收；在此之前不发布 `v0.2.0-alpha.1`。
4. 核对 roadmap 中 LGV2-C/I/B/FE 的代码、验收和 evidence lifecycle，不凭大合并提交批量标绿。
5. 真实 Memory Guard、R05 host capability、正式 350-run 与生产发布留在后续里程碑，不在本次 completed 结论内。
