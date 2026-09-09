# Product 候选与签署工具

本入口为固定隔离 profile 准备 Core V2.1 official 激活材料。签署成功表示候选与
预激活材料通过校验，真实 Active 运行仍须完成
[双运行时实施计划](product_runtime_implementation_plan.md)中的后续验收。
它不创建发布 tag，也不发布 Python、npm 或 Docker 制品。

## 候选身份与安装

候选包含以下九个实际构建的归档。源码归档、构建日志、依赖包缓存和安装报告放在
制品目录外，避免与待校验的产品集合混合。

| 组件 | 实际版本 | 归档 |
| --- | --- | --- |
| `aegis-agentguard-core` | `0.1.0rc1` | wheel、sdist |
| `aegis-agentguard-api` | `0.1.0rc1` | wheel、sdist |
| `aegis-agentguard-cli` | `0.1.0rc1` | wheel、sdist |
| `agentguard-langgraph-adapter` | `0.1.0rc1` | wheel、sdist |
| `@agentguard-ai/openclaw-plugin` | `0.1.0-rc.1` | npm tgz |

Python 原生依赖固定为 LangGraph `1.2.7`、`langgraph-prebuilt 1.1.0` 和
`langchain-core 1.4.8`。API 依赖精确版本 Core；根锁文件和 API 独立锁文件均
引用仓库中的候选源码。独立的 LangGraph `native` 安装不依赖 Core 或 benchmark。
OpenClaw 安装检查分别加载兼容宿主 `2026.6.6` 和 Product 宿主 `2026.7.1-2`；
后者用于本轮真实 Product 接入。

源码必须是最终 `dev` 的固定完整 SHA，且没有跟踪文件修改或未忽略的新增文件。
以 `umask 022` 创建全新的 checkout，保证源码及生成的安装文件没有组或其他用户
写权限。证据根目录和保留的环境根目录使用 `0700`。安装目录、运行清单和候选归档
必须保留在原路径，后续校验会重新读取实际字节、metadata、RECORD 和加载来源。
符号链接、硬链接、可写安装文件、错误版本及 editable 安装会被拒绝。

以下变量由验收操作者设置为本次固定路径；`PRODUCT_EVIDENCE_ROOT` 必须是新的独立
绝对路径。构建命令要求预先安装仓库锁定的开发依赖。

```bash
umask 022
PRODUCT_SOURCE_SHA=$(git rev-parse HEAD)
PRODUCT_CHECKOUT=$(pwd -P)
PRODUCT_EVIDENCE_ROOT=/absolute/path/to/fixed-sha-evidence
mkdir -m 700 "$PRODUCT_EVIDENCE_ROOT"

.venv/bin/python scripts/check-release-versions.py
uv lock --check
uv lock --project apps/guard-api --check
.venv/bin/python scripts/product-runtime-candidate.py build \
  --checkout "$PRODUCT_CHECKOUT" \
  --expected-source-revision "$PRODUCT_SOURCE_SHA" \
  --evidence-root "$PRODUCT_EVIDENCE_ROOT" \
  --artifacts-root "$PRODUCT_EVIDENCE_ROOT/artifacts"
```

构建器记录真实子进程、退出码、工具版本、源码和九个归档的原始 SHA-256。
`source/source.tar` 与 `build/build-evidence.json` 同时保存。任一构建失败都不会生成
完整候选。归档文件名正确不能替代内部 metadata 校验。

`install` 调用 `scripts/verify-wheel-install.py` 和
`scripts/verify-npm-tarball.mjs`，实际运行导入、版本及公开入口检查，再回读验证
实际文件。保留的安装环境和报告位于 `installation/`。Python 使用独立解包，避免
共享缓存保留旧文件权限；需要离线安装时另提供 `--dependency-wheelhouse`，该目录
也应放在产品制品目录外。这些检查保持 Product 执行关闭，外部 Provider 请求为零；
安装成功不等于真实模型、审批或回执闭环通过。

```bash
.venv/bin/python scripts/product-runtime-candidate.py install \
  --checkout "$PRODUCT_CHECKOUT" \
  --expected-source-revision "$PRODUCT_SOURCE_SHA" \
  --evidence-root "$PRODUCT_EVIDENCE_ROOT" \
  --artifacts-root "$PRODUCT_EVIDENCE_ROOT/artifacts"

.venv/bin/python scripts/product-runtime-candidate.py create \
  --checkout "$PRODUCT_CHECKOUT" \
  --expected-source-revision "$PRODUCT_SOURCE_SHA" \
  --evidence-root "$PRODUCT_EVIDENCE_ROOT" \
  --artifacts-root "$PRODUCT_EVIDENCE_ROOT/artifacts" \
  --source-archive "$PRODUCT_EVIDENCE_ROOT/source/source.tar" \
  --build-evidence "$PRODUCT_EVIDENCE_ROOT/build/build-evidence.json" \
  --installation-evidence "$PRODUCT_EVIDENCE_ROOT/installation/installation-evidence.json" \
  --output "$PRODUCT_EVIDENCE_ROOT/candidate-manifest.json"

.venv/bin/python scripts/product-runtime-candidate.py verify \
  --checkout "$PRODUCT_CHECKOUT" \
  --expected-source-revision "$PRODUCT_SOURCE_SHA" \
  --evidence-root "$PRODUCT_EVIDENCE_ROOT" \
  --manifest "$PRODUCT_EVIDENCE_ROOT/candidate-manifest.json"
```

候选 `create` 读取实际构建和安装报告，`verify` 对已经生成的 manifest 重新校验。
二者均要求相同的 `--checkout`、`--expected-source-revision` 和 `--evidence-root`。
候选 manifest 的 canonical digest 与文件的原始 SHA-256 分开记录，不能互换。
通用 `release-artifact-manifest.py` 保留原有源码构建检查用途；Product admission
必须使用这里的严格候选材料。

## 预激活报告

签署输入模型位于 `scripts/product_runtime/models.py`，必需用例由
`scripts/product_runtime/requirements.py` 固定，不能由报告删减。两份报告各自覆盖
真实宿主八工具基线、七事件消费者、ACK、审批、重复请求、持久投递、恢复和
ALLOW/ASK/DENY 策略组合。LangGraph 检查 strong binding，OpenClaw 检查 restricted
allow_once、`C3=false`、`CF-13=NOT_SUPPORTED` 和五项残余边界。

报告必须区分两种来源：

- `native_baseline`：真实 StateGraph/ToolNode 或 OpenClaw agent loop，受控本机模型，
  独立基线目录，尚无 Product authority。
- `deterministic_contract`：实际安装的生产消费者接受受控协议输入；使用测试签名
  或 ACK 时明确标为 `synthetic_contract_fixture`，且作用域与正式 profile 分离。

报告顶层保持 `phase=pre_activation`、`product_active_enabled=false`、
`external_provider_requests=0`。任何 FAIL、SKIP、缺项、摘要冲突、源码不一致或
证据不足都不能签署。真实宿主结果与副作用 fixture 分别留证，再通过调用身份关联；
不能把工具返回值另存为文件便声称验证了实际文件、记忆或消息效果。

策略材料须包含原始 SecuritySnapshot、工具 catalog、模型内容承诺、历史审计和
ACK 发行记录。校验器用生产 Core、数据流证明 reader 和 Active 选择器重算完整
判定，不接受调用者提供的资格布尔值。命令 ASK 还需核验先前真实形状的 read 与
tool result 来源；记忆 ALLOW 需关联同一策略和作用域下的首次 ASK 写入、审批消费、
原始历史 ACK、已接受终态和 committed MemoryFact。记忆提交不改变其隔离信任状态。
这些离线契约重算仍属于 `synthetic_contract_fixture`，真实宿主调用另行取证。

LangGraph 的目标动作及前置读取还必须关联已被 API 确认的 action-intent 开始记录，
确认时间早于宿主调用，终态保留原始开始记录和策略父记录关联。OpenClaw 依据真实
after hook 校验终态，并单独验证结果隔离，不生成权威 invocation-start。HTTP 原始
字节及其摘要与服务端规范化后的审计记录分别保存，历史 ACK 保留在原始回执中。

每份证据引用包含相对路径、大小和原始 SHA-256。校验器限制文件大小、JSON 深度、
路径和文件类型，拒绝重复 JSON 键；签署前再次检查已读取文件。工具来源顺序与 hook
执行顺序分开保存。观测到的未激活能力与用于 activation 的目标能力也分别保存，
不能改写观测报告中的启用状态。

## 校验与签署

`signing-request.json` 需要真实候选、双运行时 conformance、能力矩阵、工具 catalog、
固定用例清单、冻结契约文件、三组策略及独立审查记录的带摘要引用。审查记录保存
实际审查者标识、审查类型和本次隔离验收的用户授权来源；AI 审查不能写作人工风险
接受。报告制备由后续预激活 runner 完成，不能手工填 PASS 代替执行。

```bash
.venv/bin/python scripts/product-runtime-admission.py verify \
  --request signing-request.json \
  --evidence-root "$PRODUCT_EVIDENCE_ROOT" \
  --checkout "$PRODUCT_CHECKOUT" \
  --expected-source-revision "$PRODUCT_SOURCE_SHA"

.venv/bin/python scripts/product-runtime-admission.py sign \
  --request signing-request.json \
  --evidence-root "$PRODUCT_EVIDENCE_ROOT" \
  --checkout "$PRODUCT_CHECKOUT" \
  --expected-source-revision "$PRODUCT_SOURCE_SHA" \
  --key-file /absolute/private/product-signing.key \
  --shadow-key-file /absolute/private/existing-shadow-signing.key \
  --output-dir /absolute/private/new-product-signatures
```

两个 key 文件均保存原始 32 字节，要求当前用户拥有、权限 `0600`、无链接；Product
密钥必须与既有 shadow 密钥不同。输出父目录为 `0700`，目标目录必须不存在。
签署器复用既有 admission、residual acceptance 和 activation 签署函数，写入后由
生产 reader 再次校验，并原子提交完整输出。普通输出不包含密钥或 ACK token。

限定环境的 residual acceptance 仍使用既有 `internal_rc_canary` 签署范围，结果
明确记录 `product_active_run_completed=false`。签署后必须启动真实 Guard API、
独立 PostgreSQL 和双运行时，等待双方 ACK 后再执行真实 Active 故障矩阵、浏览器
审批与 Qwen 场景。任何后续修复都要求换用新的最终 SHA，重新构建、验收和签署。

工具退出码 `0` 表示当前命令的校验完成，`1` 表示输入或验证失败，`2` 表示环境或
必要证据不可用。真实闭环完成与否以最终总报告为准。
