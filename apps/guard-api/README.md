# aegis-agentguard-api

AgentGuard Guard API / Control Plane 的 PyPI 分发名为 `aegis-agentguard-api`，内部 Python
import 保持为 `guard_api`。服务提供安全判定、策略、审批、审计、指标与溯源 HTTP API。

```bash
pip install --pre aegis-agentguard-api
agentguard-api
```

默认监听地址与数据库连接由 `AGENTGUARD_HOST`、`AGENTGUARD_PORT` 和 `AGENTGUARD_DATABASE_URL` 等环境变量控制。

Guard API 不接受环境变量中未注册的静态 adapter token。服务启动后使用 control token 签发绑定运行时身份的凭证：

```bash
agentguardctl credential issue --runtime openclaw --agent-id main
```

完整 token 只在签发响应中出现一次，Guard API 数据库只保存 hash；消费端可把该 token 注入自身的 `AGENTGUARD_ADAPTER_TOKEN`。
