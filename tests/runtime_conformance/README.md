# Runtime Conformance Suite（RTE-04 / RTE-05）

把“跨 Runtime 语义一致”从文档描述变成自动化证据（契约 05 §1）。

> 给定一个确定的 GuardDecision，Runtime 是否按契约执行。

## 文件

| 文件 | 作用 |
| ---- | ---- |
| `contract_cases.json` | CF-01~CF-12（RTE-04）与 CF-13~CF-17（RTE-05 Strong Approval Binding）机读 case 定义 |
| `expected_capabilities.json` | 能力矩阵：每个 runtime × case 的状态与 evidence 引用 |

## 状态枚举（05 §5）

只允许 `PASS / FAIL / NOT_SUPPORTED / BLOCKED_BY_DEPENDENCY`。**禁止 PARTIAL PASS**；部分能力必须拆成更细 case。

## Profile 执行位置

| Profile | 位置 | CI 拾取 |
| ---- | ---- | ---- |
| LangGraph（CF-01~08、12） | `tests/test_runtime_conformance_langgraph.py` | 按 marker 进入分层 Python job；无独立 runtime job |
| Guard API 幂等/冲突（CF-10/11，两个 runtime 共享后端） | `tests/test_runtime_conformance_guard_api.py` | 按 marker 进入分层 Python/PostgreSQL job |
| OpenClaw in-process（CF-01~07、12） | `packages/agentguard-openclaw-plugin/test/rte-conformance-openclaw.test.mjs`（已标注 case ID） | Node quality 的插件 test glob |
| OpenClaw Tier 3（CF-08/09） | `rte-conformance-tier3-evidence.test.mjs` 只绑定归档 live 证据 `rte02-live-evidence.json(.jsonl)`（证据版本锁定 2026.7.1-2）；真实安装、注册、heartbeat 与 spike 探针必须另行手动运行 `scripts/openclaw-runtime-smoke.mjs` 并归档 | CI 只校验归档工件契约；没有 runtime smoke 矩阵 |
| LangGraph Strong Binding（CF-13~16） | `tests/test_rte05_runtime_conformance_langgraph.py`：真实 Guard API 链覆盖 exact consume、TOCTOU、replay/expiry、LLM 隔离及 invocation-count；CF-17 因同步边界无 active-call cache 明确为 `NOT_SUPPORTED` | 按 marker 进入分层 Python/PostgreSQL job；没有独立 RTE-05 matrix |
| OpenClaw Strong Binding（CF-13~17） | `packages/agentguard-openclaw-plugin/test/rte05-strong-binding.test.mjs` 覆盖 fail-closed、TOCTOU、lease/LLM 隔离与 capacity；`scripts/openclaw-rte05-host-chain.mjs` 可在显式 opt-in 下连接真实 Uvicorn Guard API。当前 public host 既无 atomic replace-and-seal，也无 authoritative tool-start hook，故 CF-13 为 `NOT_SUPPORTED`；插件不得合成 production start fact，单插件 restricted-path canary 也不是 C3 能力声明，heartbeat 保持 `C3=false` | 插件契约进入 Node quality；真实宿主链仅为手动 live，OpenClaw blocker 未解除前不得把 RTE-05 标记完整完成 |

当前 CI 由通用 Python 分层、PostgreSQL 16、Node quality 和手动 live job 组成，
并没有本节旧设计中的独立 RTE-05 双存储 matrix。`AGENTGUARD_RTE05_STORAGE_BACKEND`
仍可用于维护者的专项复验，但在真实宿主链与两个 storage profile 都被托管 CI
实际执行前，不得把通用测试结果表述为专项 gate 已闭合。

## 矩阵维护规则

1. 新增/修改 case 必须**同时**更新 `contract_cases.json` 与 `expected_capabilities.json`；registry guard 测试会断言两者键集合一致。
2. 每个 `PASS` 条目必须带 `evidence`，且路径必须存在；guard 测试逐条校验。
3. 矩阵声明与实际测试漂移时 guard 测试必须红——先写测试，再改矩阵。
4. `NOT_SUPPORTED / BLOCKED_BY_DEPENDENCY` 必须带 `note` 说明原因（如 LangGraph 无 after-hook 或 active-call cache 语义、插件委托 Guard API、依赖尚未落地）。

## 本地运行

```bash
uv run pytest tests/test_runtime_conformance_registry.py \
  tests/test_runtime_conformance_langgraph.py \
  tests/test_rte05_runtime_conformance_langgraph.py \
  tests/test_rte05_execution_lease_api.py \
  tests/test_runtime_conformance_guard_api.py -q
pnpm --filter @agentguard-ai/openclaw-plugin build
node --test packages/agentguard-openclaw-plugin/test/rte05-strong-binding.test.mjs
AGENTGUARD_RTE05_LIVE_GATE=1 \
  AGENTGUARD_RTE05_STORAGE_BACKEND=memory \
  uv run pytest tests/test_rte05_openclaw_live.py -q
```
