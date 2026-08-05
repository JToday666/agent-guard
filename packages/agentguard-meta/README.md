# AgentGuard

`aegis-agentguard` 是 AgentGuard 的轻量安装入口，默认安装无状态安全内核，并提供
`aegis_agentguard` 稳定 Python 门面。为避免与第三方项目冲突，本项目不提供顶层
`agentguard` Python 模块。

```bash
pip install --pre aegis-agentguard
pip install --pre "aegis-agentguard[api]"
pip install --pre "aegis-agentguard[cli]"
pip install --pre "aegis-agentguard[all]"
```

推荐导入稳定门面：

```python
from aegis_agentguard import (
    GuardDecision,
    GuardEngine,
    GuardEvent,
    PolicyBundle,
    evaluate,
)
```

组件级 import 继续使用 `agentguard_core`、`guard_api` 和 `agentguard_cli`。
