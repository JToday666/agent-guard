# AgentGuard 本地部署入口

本文件只提供仓库根目录的最小启动入口。完整安装、Dashboard、鉴权、无头模式、
OpenClaw 和故障排查统一维护在
[部署、安装与使用说明](docs/06_delivery/deployment_install_usage.md)，不要在本文件
复制完整流程。

其他直接入口：

- [文档地图](docs/README.md)
- [OpenClaw 插件部署与验证](docs/03_adapters/openclaw_plugin_deployment.md)
- [AgentGuard 0.1.0 Beta 1 本地预发布清单](docs/06_delivery/beta_pre_release.md)

## 最小初始化

在仓库根目录执行：

```bash
uv sync --frozen
pnpm install --frozen-lockfile
```

从 `.env.example` 创建本地 `.env`，至少配置独立的 PostgreSQL 开发库、测试库、
adapter token 和 control token。`.env`、真实密码、token、launch code、CSRF token、
approval nonce 和 browser session 均不得提交。

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
