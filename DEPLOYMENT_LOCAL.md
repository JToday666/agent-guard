# AgentGuard 本地部署入口

本文件只提供仓库根目录的最小启动入口。安装、升级与故障排查从
[产品化入口](docs/06_delivery/install_upgrade_troubleshooting.md)开始；完整环境变量、
Dashboard、鉴权、无头模式和 OpenClaw 细节维护在
[部署、安装与使用说明](docs/06_delivery/deployment_install_usage.md)，不要在本文件复制完整流程。

其他直接入口：

- [文档地图](docs/README.md)
- [Productization Alpha Status](docs/06_delivery/productization_alpha_status.md)
- [兼容矩阵](docs/06_delivery/compatibility_matrix.md)
- [OpenClaw 插件部署与验证](docs/03_adapters/openclaw_plugin_deployment.md)
- [AgentGuard 0.1.0 Beta 1 发布记录](docs/06_delivery/beta_release.md)

## 最小初始化

在仓库根目录执行：

```bash
uv sync --locked --all-groups
pnpm install --frozen-lockfile
```

从 `.env.example` 创建本地 `.env`，至少配置独立的 PostgreSQL 开发库、测试库和
control token。API 启动后为每个 runtime/agent 签发 adapter credential，不使用未注册的静态 token。`.env`、真实密码、token、launch code、CSRF token、
approval nonce 和 browser session 均不得提交。

可选：`AGENTGUARD_V21_SEMANTIC_*`（V21-13 Stage 1 shadow 语义评判，见
`.env.example` 对应段落）默认关闭；开启后每个 DEFER 评估在请求线程上增加至多
`AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS` 秒的同步 LLM 往返，仅建议 shadow
评测环境开启。

## Guard API 与 CLI

第一个终端启动 Guard API：

```bash
pnpm guard-api:dev
```

第二个终端验证服务和数据库：

```bash
uv run agentguardctl health --check-db
```

CLI 的审计、指标、Trace、评测结果导入和 Dashboard launch 用法见完整部署文档。
公开 CLI 只提供 `eval import`，不内置 LangGraph runner。

## OpenClaw 最小验证

```bash
pnpm --filter @agentguard-ai/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
pnpm openclaw:plugin:verify
```

开发安装、E2E、reliability、Gateway 配置和卸载步骤见 OpenClaw 插件部署文档。
