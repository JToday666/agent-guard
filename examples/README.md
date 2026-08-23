# AgentGuard minimal examples

本目录提供干净 clone 可运行的最小 Core 示例。它们只读取仓库内 JSON，调用无状态 `agentguard_core.evaluate()`，不会访问网络、数据库、`.openclaw-dev` 或系统临时目录，也不会执行真实工具副作用。

## 准备

在仓库根目录执行：

```bash
uv sync --locked
```

## Benign：允许读取公开文档

```bash
uv run python examples/evaluate_events.py examples/events/benign-read.json
```

预期输出包含：

```json
"decision": "allow"
```

## Blocked：拒绝读取敏感 token 文件

```bash
uv run python examples/evaluate_events.py examples/events/blocked-sensitive-read.json
```

预期输出包含：

```json
"decision": "deny"
```

并包含规则 `P001_sensitive_file_access`。

这两个示例只证明当前 Core 对给定事件的确定性判断，不证明某个 runtime 已执行阻断，也不代表真实 Provider 的效果评测。产品接入还必须通过 Adapter 在副作用前执行决定并回传 runtime receipt。
