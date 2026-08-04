# agentguard-core

AgentGuard 的无状态安全判定内核。它负责规范化安全事件、执行检测器与策略，并返回可审计的 `GuardDecision`。

```bash
pip install --pre agentguard-core
```

```python
from agentguard_core import GuardEngine, GuardEvent, PolicyBundle

decision = GuardEngine().evaluate(event, PolicyBundle())
```

Core 不访问网络或数据库，也不管理审批状态。
