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
| LangGraph（CF-01~08、12） | `tests/test_runtime_conformance_langgraph.py` | `python` job（`uv run pytest tests ...`） |
| Guard API 幂等/冲突（CF-10/11，两个 runtime 共享后端） | `tests/test_runtime_conformance_guard_api.py` | 同上 |
| OpenClaw in-process（CF-01~07、12） | `packages/agentguard-openclaw-plugin/test/rte-conformance-openclaw.test.mjs`（已标注 case ID） | `node` job（插件 test glob） |
| OpenClaw Tier 3（CF-08/09） | `rte-conformance-tier3-evidence.test.mjs` 绑定 live 证据 `rte02-live-evidence.json(.jsonl)`（证据版本锁定 2026.7.1-2）；CI `openclaw-runtime-smoke` 验证 24-hook 集安装/注册/heartbeat，并在每个安装版本上复跑 spike 探针复验 CF-08/09 语义（探测版本漂移，RTE-04 硬化）；live observer emission 由归档取证工件锁定 | 独立 smoke job |
| LangGraph Strong Binding（CF-13~16） | `tests/test_rte05_runtime_conformance_langgraph.py`：真实 Guard API 链覆盖 exact consume、TOCTOU、replay/expiry、LLM 隔离及 invocation-count；CF-17 因同步边界无 active-call cache 明确为 `NOT_SUPPORTED` | 独立 `rte05-strong-binding` Memory/PostgreSQL matrix gate |
| OpenClaw Strong Binding（CF-13~17） | `packages/agentguard-openclaw-plugin/test/rte05-strong-binding.test.mjs` 覆盖 fail-closed、TOCTOU、lease/LLM 隔离与 capacity；`scripts/openclaw-rte05-host-chain.mjs` 经 pinned `openclaw@2026.7.1-2` 的真实 global hook runner、agent-harness tool wrapper 和 after helper 连接真实 Uvicorn Guard API，复验 consume→invoke→terminal 同一 IDs、失败零调用及 secret exclusion。当前 public host 既无 atomic replace-and-seal，也无 authoritative tool-start hook，故 CF-13 为 `NOT_SUPPORTED`；插件不得合成 production start fact，单插件 restricted-path canary 也不是 C3 能力声明，heartbeat 保持 `C3=false`。CF-14~17 各自输入语义独立通过 | 同一独立 RTE-05 Memory/PostgreSQL matrix gate，在每个 storage profile 构建插件并运行契约与跨进程 live test；OpenClaw host seal/start-hook blocker 未解除前不得把 RTE-05 标记完整完成 |

既有 S1 job 的命令与语义保持不变。RTE-05 使用独立 matrix job；PostgreSQL
profile 固定以 PostgreSQL 16 service 为双存储验收权威；matrix 通过 pytest
filter 选择 Guard API/lease tests，并以 `AGENTGUARD_RTE05_STORAGE_BACKEND`
让 LangGraph 只产生对应 backend fixture。两个 profile 都执行 Guard API/lease、
LangGraph 真实链和 OpenClaw strong-binding 契约，不用既有全仓测试替代专项 gate。

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
