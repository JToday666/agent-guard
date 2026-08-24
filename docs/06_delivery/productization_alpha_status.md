# Productization Alpha Status

| 字段 | 当前值 |
| --- | --- |
| Status | **in progress** |
| 状态日期 | 2026-08-24 |
| 集成分支 | `codex/productization-alpha` |
| 代码基线 | `origin/dev@5986538`，另含已归档竞赛证据提交 |
| 已验证代码 SHA | `<由状态证明提交填写其 parent SHA>` |
| 托管 CI run | `<由维护者填写 run URL/ID 与结果>` |

> 本页在已验证代码 SHA 和托管 CI run 填写前不得改为 completed，也不得用“CI 已配置”替代“CI 已成功运行”。为避免提交自引用，状态证明提交记录其 parent（被验证代码）SHA，而不是声称包含自身 SHA。

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
- action receipt 覆盖率、跨 run 回归阈值、完整生产运维、容器公开发布、SBOM、签名、provenance 和 Trusted Publishing 仍未完成。
- 多租户、用户登录、OAuth/SSO、自动备份与恢复不属于当前 Alpha 已有能力。
- 公开 `v0.1.0-beta.1`/对应 npm 制品是 22-hook 基线，当前未发布源码为 24 hooks，但包版本仍为 `0.1.0-beta.1`。本阶段不发布；下一次构建可发布制品前必须统一提升 Python/Node 版本和映射，禁止以同版本覆盖不同内容。
- `scripts/` 已完成职责分类和兼容入口说明，但物理迁移与超大模块拆分尚未完成；继续拆分时必须保持公共 import、CLI 和 `/v1` 行为不变。
- legacy benchmark 的 standalone LangGraph subprocess 已移除开发者机器默认路径，必须显式提供 agent command/path；但对应 849 项旧测试仍未进入门禁，它也不属于产品示例或 clean-clone acceptance。测试和依赖完成重整前不得把该 adapter 称为 Alpha 支持入口。
- 四份既有 demo 设计/运行文档因 roadmap 与外部链接兼容暂留 `docs/06_delivery/`，已统一标记 historical/unsupported 并从产品入口降级；物理迁入 archive 留待保留引用关系的独立迁移。
- CODEOWNERS、required checks、分支保护和 GitHub Private Vulnerability Reporting 是否实际启用属于平台外部状态，仓库文件无法自证；外部试用前必须由维护者核验并记录。

## CI 状态口径

本分支定义了以下自动 job：clean-checkout 最小示例验收、静态检查、unit/contract/integration/e2e Python 测试、PostgreSQL 16 migration/tests、Node 检查、Dashboard build、Playwright Chromium E2E。浏览器 job 除 mock/API-stub 模式外，还以 memory backend 启动真实 Guard API 与 Dashboard，执行 S1 allow、浏览器审批、deny 零调用和 flag-off 回滚四场景。连接真实外部宿主或 Provider 的 `live` 仍仅在手动 workflow dispatch 明确 opt-in 时运行。

Python 六层分类当前只覆盖根 `tests/` 与 LangGraph adapter tests，共收集 2,533 项：unit 1,187、contract 383、integration 782、postgres 156、e2e 24、live 1。`agentguard_langgraph_bench/bench/tests` 的 849 项旧 benchmark 测试尚未纳入该矩阵：其中混有浏览器/本地 socket 用例、已移除 fixtures 和历史外部依赖，必须先完成依赖与 marker 重整；该 legacy tree 当前也有 31 项 Ruff 诊断，尚未进入默认 Ruff/Pyright。因而“Python 分层/静态检查通过”不能扩大为“全仓 benchmark 已覆盖”。

Dashboard 的 API-mode Playwright 会拦截 `/api/v1/**`，只验证前端 API 映射；独立 S1 memory 场景才是 Dashboard 到真实 Guard API 的浏览器全栈验证。clean-clone acceptance 另在隔离临时目录中验证安装后健康、临时凭证、benign allow、malicious deny、审计查询、Dashboard shell/静态资源和凭证撤销，两者覆盖边界不同。

这些 job 只有在同一已验证代码 SHA 的 GitHub Actions 全部成功后，才构成本轮通过证据。维护者应以单独的状态证明提交记录其 parent SHA、run URL/ID 和结果；在此之前状态保持 **in progress**。本地通过、workflow 定义存在或历史报告都不能替代托管 CI 结果。

## 本地验证（非 Alpha 出口证明）

本分支整理期间已在当前工作区完成以下验证：

- 完整 unit 层为 1,171 passed、16 skipped；完整 contract 层为 383 passed，其中 Markdown 链接契约 5 项、exact-wheel 选择契约 2 项、roadmap 工具契约 26 项。
- 审批截止时间、C1 message receipt/action 关联和 AgentGuard runtime/lease token 脱敏的定向回归为 87 passed；受影响的 legacy benchmark gateway 定向回归另为 41 passed、3 skipped。
- Productization Alpha 默认 Python 门禁范围内的 Ruff 与 Pyright 通过；Python 发布包的 Black 检查逐文件通过；`git diff --check` 与 roadmap contract 检查通过。该范围明确不含上文披露的 legacy benchmark tree 及其现存 Ruff 诊断。
- Dashboard format/lint/typecheck/unit（40 个测试文件）和 production build 通过；OpenClaw 插件 18 个测试文件通过，本地 shim/installer/runtime 相关测试 68 passed。
- Markdown 相对目标检查对全部 137 份 tracked/unignored 文档通过。
- 隔离 clean-clone acceptance 在 memory backend 下完成 8/8：真实启动 Guard API，验证健康、临时凭证、benign allow、malicious deny、审计查询、Dashboard shell/静态资源、凭证撤销与临时资源清理；外部 Provider 保持关闭。
- Dashboard 隐藏页暂停与终态停止轮询的两项定向 Playwright 回归通过。
- Dashboard 到真实 Guard API 的 memory 浏览器闭环本地为 4/4 passed：official allow、浏览器 allow-once 审批、deny 零调用/not-invoked receipt、flag-off 回滚只读。

受本机环境限制，本轮没有把完整 integration 层、PostgreSQL job、完整 Python/浏览器 E2E、Docker/SBOM 构建或托管 GitHub Actions 标记为已验证。它们仍是 Alpha 出口的必需门禁；上面的本地结果不能替代。

## 后续优先级

1. 核对 roadmap 中 LGV2-C/I/B/FE 的代码、验收和 evidence lifecycle，不凭大合并提交批量标绿。
2. 验证新增 CI 在托管环境真实通过，处理 flaky、超时和 marker 误分类。
3. 推进真实 Memory Guard/runtime receipt 和 OpenClaw 宿主能力，不用演示绕过替代产品实现。
4. 再开展模块拆分、供应链和生产部署自动化。
