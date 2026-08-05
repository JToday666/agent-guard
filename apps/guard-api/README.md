# aegis-agentguard-api

AgentGuard Guard API / Control Plane 的 PyPI 分发名为 `aegis-agentguard-api`，内部 Python
import 保持为 `guard_api`。服务提供安全判定、策略、审批、审计、指标与溯源 HTTP API。

```bash
pip install --pre aegis-agentguard-api
agentguard-api
```

默认监听地址与数据库连接由 `AGENTGUARD_HOST`、`AGENTGUARD_PORT` 和 `AGENTGUARD_DATABASE_URL` 等环境变量控制。
