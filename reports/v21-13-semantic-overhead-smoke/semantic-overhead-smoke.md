# V21-13 semantic shadow 接入开销 smoke 报告（04 §21 latency delta + rollback）

> 任务：V21-13 Stage 1 shadow LLM 辅助评判接入——04 §21 门禁的 latency
> delta 证据与 rollback 证据。
> 分支：`codex/llm-semantic-judgment`；测量基于基线提交 `8e94940`。
> dirty 声明：测量时工作树 dirty=true，未提交改动为 V21-13 semantic
> shadow 接入实现（settings/semantic provider/pipeline 钩子/评估
> metadata/main 组装/测试）+ 本次测量工具
> `scripts/v21-13-semantic-overhead-smoke.py` 与本目录文件。
> 口径声明：**机器结果非跨环境硬 SLO，CI 只校验工具正确性（05 §9）**；
> 本次为缩减 smoke 口径（A/B/C 预热 10 测 100，D 档预热 3 测 30，
> memory 后端，单进程），不跑 05 §9 完整协议档。

## 1. 测量配置

| 项 | 值 |
|---|---|
| 恒定项 | V21 shadow pipeline 启用（`v21_mode=shadow` + server secret 在场，栈构造与 `tests/test_v21_09_pipeline.py` 同口径）；backend=memory；`sample_rate` 默认 1.0 |
| 对照变量 | 仅 semantic 接面：flag / configured / provider 形态（四档见 §2） |
| workload | code_execution 类 DEFER fixture：shell exec 形状 `tool_call_proposed`（`name=exec, category=shell, kind=exec`，benign 参数）+ memory store 预播权威 TaskFact（事件 metadata 携带 `task_id` trusted claim，snapshot 直出路径）；每次迭代新 event_id，走 Phase A 事务外 → Phase B 短事务 → 审计提交全链路 |
| fixture 声明 | 钩子仅对 DEFER 触发；脚本内置 disposition 哨兵断言，实测 fixture disposition 恒 `DEFER`（否则测量面不成立，脚本直接失败） |
| 测量目标 | evaluate 请求级，单进程直调 EvaluationService（与 CT-PR-03b smoke 先例同口径，非 TestClient） |
| 协议参数 | A/B/C：warmup 10 / iterations 100；D：warmup 3 / iterations 30（缩减以免耗时，如实声明） |
| 百分位 | nearest-rank P50/P95/P99/max，单调纳秒样本（`time.perf_counter_ns`），不剔除异常值 |
| 环境 | Linux（WSL2，kernel 6.18.33.2-microsoft-standard，glibc 2.39），Python 3.12.3；`perf_counter_ns` 为 Linux CLOCK_MONOTONIC 纳秒分辨率时钟，无 Windows 先例中的毫秒级定时器量化台阶 |

### 四档语义（全部无需真实 LLM）

| 档位 | provider 形态 | 语义 |
|---|---|---|
| A `a_off` | `semantic_provider_from_settings` → None | semantic flag off（基线） |
| B `b_flag_on_unconfigured` | flag on 缺 api_key/model → None | 配置门控零开销证明（应与 A 同分布） |
| C `c_fake_provider` | 确定性 in-process fake callable 直接注入 | 纯进程内净增量（judgment 产出 + `validate_semantic_binding` 五 digest 比对 + 证据槽填充 + 审计 metadata 五引用键写入） |
| D `d_unreachable_endpoint` | 真实 `HttpSemanticJudge` 指向 `http://127.0.0.1:9`（timeout 保持默认 3.0s） | fail-closed 上界（连接快速拒绝路径每请求额外延迟） |

## 2. 四档延迟对照（单位 ms）

| 档位 | 样本 | P50 | P95 | P99 | max | mean | provider 调用次数 |
|---|---|---|---|---|---|---|---|
| A off（基线） | 100 | 28.124 | 85.970 | 93.207 | 96.985 | 33.064 | —（恒 None） |
| B flag on 未 configured | 100 | 29.127 | 84.787 | 94.468 | 99.930 | 32.547 | —（恒 None） |
| C fake provider | 100 | 29.690 | 83.172 | 98.136 | 98.339 | 33.002 | 111（预热 10 + 测 100 + probe 1） |
| D 端点不可达 | 30 | 13.519 | 19.617 | 60.138 | 60.138 | 15.441 | 34（预热 3 + 测 30 + probe 1） |

### 增量表（相对 A 基线）

| 对照 | ΔP50 | ΔP95 | ΔP99 | Δmax |
|---|---|---|---|---|
| B vs A（配置门控） | +1.004 | -1.183 | +1.261 | +2.945 |
| C vs A（进程内净增量） | +1.566 | -2.798 | +4.929 | +1.354 |
| D vs A（fail-closed 上界） | -14.605 | -66.353 | -33.069 | -36.847 |

**解读**：

1. **B vs A：配置门控零开销**。flag on 未 configured 相对 flag off 的
   全部百分位增量（|Δ| ≤ 3.0ms）无单调方向、落在小样本噪声内——
   provider 两档恒 None、钩子同点短路，与结构性断言一致
   （`test_semantic_settings_default_off` /
   `test_semantic_settings_configured_requires_key_and_model`）。
2. **C vs A：进程内净增量不可测**。fake provider 全链路在场（111 次
   调用，judgment 产出 + 五 digest 比对 + 信封双槽填充 + 审计 metadata
   五引用键写入）相对基线 ΔP50 +1.6ms、ΔP95 -2.8ms——全部落在 ±5ms
   噪声带内，纯进程内 semantic 消费面未引入可测串行开销；100 样本下
   净增量上界读数 < 5ms。
3. **D vs A：fail-closed 路径行为证据**。真实 HTTP provider 每请求
   往返为 loopback 连接快速拒绝（connection refused，非超时等待），
   34 次调用全部 fail-closed 收敛 None，evaluate 全链路照常完成。
   d_vs_a 百分位呈负值**不是性能增益**：D 档样本量（30）与档内 store
   累积深度（审计/投影行数随迭代单调增长，A 档在 D 之前以 110 次迭代
   收尾）不对称，跨样本量百分位直接相减不具可比性；有效结论是每请求
   fail-closed 往返未产生超时级（3.0s hard deadline）阻塞。真实端点
   慢响应上界由 timeout 结构封顶（03 §13），归 05 §9 完整协议档复测。

## 3. 结论与已知局限

1. 四档 smoke 支持 04 §21 latency delta 门禁的 smoke 级结论：semantic
   接面在 flag off / 未 configured 两档零开销（provider 恒 None、钩子
   短路）；在场消费面（C 档）进程内净增量不可测（±5ms 噪声带内）；
   fail-closed 路径（D 档）无超时级阻塞。
2. 已知局限：a) 缩减样本量（100/30），百分位读数噪声大，可靠增量结论
   需按 05 §9 完整协议档复测；b) D 档不可达端点为连接拒绝快路径，未
   覆盖慢响应/超时等待路径（该路径上界 = timeout 3.0s，由
   `HttpSemanticJudge` 的 httpx timeout 结构封顶）；c) fixture 为单一
   code_execution 类 DEFER 场景，非 DEFER 事件钩子零调用由门控测试
   锁定（`test_non_defer_disposition_makes_zero_http_calls`），不在
   本 smoke 测量面；d) memory 后端单进程，未覆盖 postgres / 并发档。

## 4. Rollback（回滚路径）

**flag `AGENTGUARD_V21_SEMANTIC_ENABLED` 默认 `false` 即完全回滚**，
无需任何数据迁移或 schema 变更：

1. **flag off 时 provider 恒 None、钩子短路零 I/O**：
   `semantic_provider_from_settings` 在 flag off / 未 configured /
   v21_mode=off 三态均返回 None；`V21PipelineService._finish_phase_a`
   钩子首判 `provider is not None` 即短路。测试锁定：
   `test_pipeline_without_provider_is_byte_identical_to_baseline`
   （provider=None 接线与基线 Phase A/B 产物逐字节一致）、
   `test_pipeline_hook_zero_provider_calls_on_snapshot_failure`
   （snapshot 缺态时 provider 零调用）。
2. **append-only 审计不产生需回滚的写入**：semantic 五个引用键只条件性
   追加进既有评测审计记录的 metadata（不新增记录、不改 wire schema）；
   flag off 时键集逐字节不变（`test_e2e_metadata_keyset_byte_identical_without_judgment`、
   `test_e2e_metadata_flag_off_keyset_matches_pre_wiring_baseline`）。
   已写入的历史 semantic 引用键为 append-only 审计的合法存量，回滚后
   自然停写，无需清理。
3. **semantic 两槽缺省恒 None 与改动前逐字节一致**：信封
   `semantic_judgment_id` / `semantic_digest` 双槽在 judgment 缺席 /
   binding invalid / revalidation stale 时恒 None，与未接入前的
   `build_decision_evidence_v21` 缺省形状逐字节一致
   （`test_phase_b_envelope_rest_byte_identical_to_baseline`、
   `test_competition_rebuilt_envelope_omits_semantic_slots`）；
   schemas/ 与 divergence 词表零改动，finalize 调用点恒不传 semantic。
4. **进程资源回滚**：provider 持有的共享 `httpx.Client` 连接池在
   FastAPI lifespan shutdown 关闭（`HttpSemanticJudge.close()` 仅关
   自有 client），flag off 时不构造、无连接池残留。

## 机器可读证据

- `semantic-overhead-smoke.json`：本次 smoke 完整机器报告（四档
  百分位 + 两两增量 + provider 调用计数 + 环境指纹 + 口径 notes）。
- 复跑命令：`uv run python scripts/v21-13-semantic-overhead-smoke.py`
  （支持 `--warmup / --iterations / --d-warmup / --d-iterations /
  --output` 覆写协议参数）。
