# AgentGuard

`agentguard` 是 AgentGuard 的轻量安装入口，默认安装无状态安全内核，不提供同名 Python import package。

```bash
pip install --pre agentguard
pip install --pre "agentguard[api]"
pip install --pre "agentguard[cli]"
pip install --pre "agentguard[all]"
```

实际导入路径为 `agentguard_core`、`guard_api` 和 `agentguard_cli`。
