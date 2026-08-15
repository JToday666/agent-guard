# Runtime Conformance Suite（PR-RTE-04）

把“跨 Runtime 语义一致”从文档描述变成自动化证据（契约 05 §1）。

> 给定一个确定的 GuardDecision，Runtime 是否按契约执行。

## 文件

| 文件 | 作用 |
| ---- | ---- |
| `contract_cases.json` | CF-01~CF-12 机读 case 定义（P0 第一批，06 §6）；CF-13~CF-17 属 P1，不在本套件 |
| `expected_capabilities.json` | 能力矩阵：每个 runtime × case 的状态与 evidence 引用 |

## 状态枚举（05 §5）

只允许 `PASS / FAIL / NOT_SUPPORTED / BLOCKED_BY_DEPENDENCY`。**禁止 PARTIAL PASS**；部分能力必须拆成更细 case。

## Profile 执行位置

| Profile | 位置 | CI 拾取 |
| ---- | ---- | ---- |
| LangGraph（CF-01~08、12） | `tests/test_runtime_conformance_langgraph.py` | `python` job（`uv run pytest tests ...`） |
| Guard API 幂等/冲突（CF-10/11，两个 runtime 共享后端） | `tests/test_runtime_conformance_guard_api.py` | 同上 |
| OpenClaw in-process（CF-01~07、12） | `packages/agentguard-openclaw-plugin/test/rte-conformance-openclaw.test.mjs`（已标注 case ID） | `node` job（插件 test glob） |
| OpenClaw Tier 3（CF-08/09） | `rte-conformance-tier3-evidence.test.mjs` 绑定 live 证据 `rte02-live-evidence.json(.jsonl)`（证据版本锁定 2026.7.1-2）；CI `openclaw-runtime-smoke` 验证 24-hook 集安装/注册/heartbeat，并在每个安装版本上复跑 spike 探针复验 CF-08/09 语义（探测版本漂移，RTE-04 硬化）；live observer emission 由归档取证工件锁定 | 独立 smoke job |

CI 零 workflow 改动：所有测试文件都在既有 job 的拾取路径内。

## 矩阵维护规则

1. 新增/修改 case 必须**同时**更新 `contract_cases.json` 与 `expected_capabilities.json`；registry guard 测试会断言两者键集合一致。
2. 每个 `PASS` 条目必须带 `evidence`，且路径必须存在；guard 测试逐条校验。
3. 矩阵声明与实际测试漂移时 guard 测试必须红——先写测试，再改矩阵。
4. `NOT_SUPPORTED` 必须带 `note` 说明原因（如 LangGraph 无 after-hook 语义、插件委托 Guard API）。

## 本地运行

```bash
uv run pytest tests/test_runtime_conformance_registry.py \
  tests/test_runtime_conformance_langgraph.py \
  tests/test_runtime_conformance_guard_api.py -q
pnpm --filter @agentguard-ai/openclaw-plugin test
```
