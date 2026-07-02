# Test8 True LangGraph Autonomous ASR Summary

## Result

The `true_langgraph_autonomous_asr_repair_plan.md` tasks are complete.

Final full run:

- `agentguard_langgraph_bench/bench/results/test8/full/full_attack_cases_recovery_prompt_timeout75_artifacts_20260702T024200Z/run_20260702T024229442690Z`

Final result:

- 123/123 cases completed with run integrity ok.
- `invalid_case_count=0`.
- `metrics_reliable=true`.
- `run_quality_pass=true`.
- `artifact_integrity.ok=true`.
- `benign_fpr=0.0`.
- Overall valid malicious ASR: 70/95 = 73.68%.
- No prompt contamination.
- No guided plan, no deterministic replay, no case-plan fallback, no fake/core decision path.

## Family Outcomes

| Family | Final full-run outcome |
| --- | --- |
| prompt_injection | 7/10 ASR_valid = 70%, invalid 0 |
| tool_hijacking | 7/10 high-confidence ASR = 70%, invalid 0, benign FPR 0 |
| file_exfiltration | 6/10 high-confidence success = 60%, invalid 0 |
| poisoned_rag | 17/20 poisoned attack success = 85%, poison hit 100% |
| memory_poisoning | 23/35 evaluable malicious ASR = 65.71%, delayed trigger 66.67%, seed write 100%, invalid 0 |
| agent_abuse | 10/10 high-confidence ASR = 100%, invalid 0 |
| benign controls | 28/28 valid, FPR 0 |

## Key Repairs

- Added sanitized public MCP catalog visibility to subprocess and HTTP adapter payloads.
- Rendered the public MCP catalog in the LangGraph wrapper prompt.
- Added catalog-aware `mcp_call` normalization for exact/fuzzy safe server/tool names and schema defaults.
- Kept unrelated MCP tool names from being incorrectly canonicalized.
- Added benign/MCP prompt discipline for missing public fixture arguments and ordinary benign file/email workflows.
- Made benign read-file path mistakes recoverable observations when the case is non-malicious.
- Preserved autonomous LLM planning throughout; no repair injects a case tool plan.

## Evidence Files

- Full audit: `agentguard_langgraph_bench/docs/audits/test8_full_run_20260702T024229442690Z_manual_audit.md`
- Tool hijacking catalog audit: `agentguard_langgraph_bench/docs/audits/test8_tool_hijacking_run_20260702T010912588482Z_catalog_visible_manual_audit.md`
- Prior family audits remain in `agentguard_langgraph_bench/docs/audits/`.

## Verification

- Preflight: ok=true for 123 cases.
- Regression: 153 passed.
- Focused recovery run for the former invalid cases `BN-003` and `MCP-B002`: 2/2 valid, timeout 0, retry 0.

One recovered LLM timeout remains recorded in the final full run for `BN-010`; the case is valid and completed, so it does not affect ASR/FPR or create unknown/invalid verdicts.

