# Changelog

本文件记录面向使用者的显著变化。格式参考 Keep a Changelog；版本号遵循 Semantic Versioning 的预发布约定。

## [Unreleased]

### Added

- Productization Alpha 的贡献、安全、所有权、兼容性、安装升级、状态和目录治理文档。
- 可从干净 clone 运行的最小 benign/blocked Core 示例。
- Python 测试分层以及独立 PostgreSQL、Dashboard build、Playwright browser E2E CI 定义。

### Changed

- 产品入口改为运行时安全与控制面，不再以竞赛或答辩演示为默认叙事。
- 历史竞赛证据移至 `docs/archive/competition-2026/`，并明确其不可复现依赖和证据边界。
- 开发路线收敛为根目录 `ROADMAP.md` 中人工维护的能力节点与依赖关系；细粒度 backlog 继续由 `docs/TODO.md` 承载。
- 当前未发布源码的 OpenClaw hook 契约统一为 24；公开 Beta 1 制品仍是历史 22-hook 构建，两者不混称。

### Fixed

- LangGraph message approval 在本地等待截止时间后保持 fail closed；获批 C1 message 的 started/terminal receipt 关联其真实 message action 与 policy audit。
- 显式启用 evidence content preview 时，服务端同时脱敏 AgentGuard runtime credential 与 execution lease token；默认关闭行为不变。
- 提升 Guard API、OpenClaw/MCP、Dashboard 构建链和 legacy benchmark fixture 的 critical/high 传递依赖安全下限，并增加锁文件回退契约。

### Known limitations

- Productization Alpha 是已完成的内部基线，不代表生产就绪；当前贡献与发布限制以 `CONTRIBUTING.md` 为准。
- 真实外部 Provider 的 LangGraph V2 `70×5=350` 正式测评尚未完成。
- OpenClaw R05 仍受宿主 atomic replace-and-seal / authoritative invocation-start 能力阻塞。
- Memory Guard 的 commit/rollback 仍只改变控制面记录状态，尚未执行真实 runtime memory 回滚。
- 当前源码仍沿用 Beta 1 包版本号但内容已变化；本阶段禁止发布，下一次任何可发布构建前必须统一升版并禁止同版本覆盖。
- 容器公开发布、SBOM、签名、provenance、Trusted Publishing 和生产部署自动化尚未完成。

## [0.1.0-beta.1] - 2026-08-05

### Added

- 发布 `aegis-agentguard-core`、`aegis-agentguard-api`、`aegis-agentguard-cli` Python Beta 包。
- 发布 `@agentguard-ai/openclaw-plugin` npm Beta 包和 Git tag `v0.1.0-beta.1`。
- 提供 Guard API、CLI、Dashboard、LangGraph 评测和 OpenClaw 插件的首个 Beta 闭环。

### Known limitations

- Guard API 容器和 GHCR 未发布。
- 自动注册表发布、SBOM、制品签名和可信发布未配置。

历史发布的完整复现说明见 [`docs/06_delivery/beta_release.md`](docs/06_delivery/beta_release.md)。
