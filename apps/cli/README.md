# aegis-agentguard-cli

AgentGuard 无头控制与诊断命令行工具。PyPI 分发名为 `aegis-agentguard-cli`，console
script 继续使用 `agentguardctl`，内部 Python import 保持为 `agentguard_cli`。

```bash
pip install --pre aegis-agentguard-cli
agentguardctl --help
```

CLI 默认通过 `AGENTGUARD_API_URL` 连接 Guard API，不保存长期凭证。

审计导出读取一个固定 sequence 快照并自动跟随 cursor：

```bash
agentguardctl audit export --runtime openclaw --limit 1000 --output audit.jsonl
```

历史策略指标必须给出明确的评估时间范围：

```bash
agentguardctl metrics \
  --evaluated-from 2026-08-01T00:00:00Z \
  --evaluated-to 2026-08-02T00:00:00Z \
  --json
```
