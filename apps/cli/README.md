# aegis-agentguard-cli

AgentGuard 无头控制与诊断命令行工具。PyPI 分发名为 `aegis-agentguard-cli`，console
script 继续使用 `agentguardctl`，内部 Python import 保持为 `agentguard_cli`。

```bash
pip install --pre aegis-agentguard-cli
agentguardctl --help
```

CLI 默认通过 `AGENTGUARD_API_URL` 连接 Guard API，不保存长期凭证。
