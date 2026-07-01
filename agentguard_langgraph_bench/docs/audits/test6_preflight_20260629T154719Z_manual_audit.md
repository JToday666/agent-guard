# test6 preflight manual audit

## Run

- run_id: preflight_20260629T154719Z
- dataset: not executed
- command: `python -m agentguard_langgraph_bench.bench.scripts.llm_probe`
- git diff summary: compatibility-layer remediation for `send_email` attachments, browser alias parity, and removal of a plaintext DeepSeek key from the test6 plan.

## Quality Gate

| metric | value | pass |
|---|---:|---|
| case_count | 0 | n/a |
| invalid_case_count | n/a | n/a |
| run_valid_rate | n/a | n/a |
| invalid_run_rate | n/a | n/a |
| metrics_reliable | false | no |
| run_quality_pass | false | no |
| evidence_complete_rate | n/a | n/a |
| artifact_coverage_rate | n/a | n/a |

## Environment

| check | result |
|---|---|
| LangGraph python | present at `/home/zhuwei/code/langgraph/.venv/bin/python` |
| LangGraph agent | present at `/home/zhuwei/code/langgraph/examples/bench_tool_agent.py` |
| LLM provider/model | DeepSeek / `deepseek-v4-flash` as reported by probe |
| LLM authentication | blocked: no shell-exported key |

## LLM Diagnostics

| case_run_key | request_count | diagnostics | impact |
|---|---:|---|---|
| preflight | 0 | `llm_probe` stops before network requests because no valid `AGENTGUARD_LLM_API_KEY` or `DEEPSEEK_API_KEY` is exported in the shell. Persisted key values in `.env` and `agentguard_langgraph_bench/bench/.env` were cleared to comply with the shell-only credential rule. | Blocks all real LangGraph autonomous attack-family evaluations. |

## Remediation Completed

| area | change | validation |
|---|---|---|
| tool compatibility | `send_email` now normalizes `recipient/title/message` aliases and converts `attachment_path/attachments/files/file_path` into a body attachment note instead of passing unsupported kwargs to `MockToolRegistry.send_email`. | `test_tool_compat.py` |
| browser compatibility | bench-side compatibility now matches adapter package handling for `browser_navigate`, `browser_input`, `browser_click`, `browser_extract_text`, and `browser_inspect` aliases. | `test_tool_compat.py` |
| package adapter | external LangGraph wrapper import path has matching `send_email` compatibility behavior. | `packages/agentguard-langgraph-adapter/tests/test_tool_compat.py` |
| audit helper | Added a read-only run audit helper that aggregates summary/run/csv/case_result/tool_results/evidence_index/browser_replay checks without granting manual approval. | `test_audit_run_script.py`; baseline helper report at `docs/audits/test6_test5_baseline_audit_helper_report.md` |
| credential hygiene | plaintext DeepSeek key in `test6_attack_family_validity_remediation_plan.md` replaced with a shell-only placeholder. | A token-pattern scan returned no matches in the test6 plan/audits. |
| credential hygiene | persisted LLM key values in `.env` and `agentguard_langgraph_bench/bench/.env` were cleared. | `llm_probe` now fails locally with a missing-key error instead of sending requests with a stale key. |

## Tests

| command | result |
|---|---|
| `python -m pytest agentguard_langgraph_bench/bench/tests/test_tool_compat.py agentguard_langgraph_bench/bench/tests/test_tool_gateway_compatibility.py` | 11 passed |
| `python -m pytest packages/agentguard-langgraph-adapter/tests/test_tool_compat.py` | 4 passed |
| `python -m pytest agentguard_langgraph_bench/bench/tests/test_browser_runtime.py agentguard_langgraph_bench/bench/tests/test_browser_runtime_threading.py agentguard_langgraph_bench/bench/tests/test_run_artifact_integrity.py` | 31 passed |
| `python -m pytest agentguard_langgraph_bench/bench/tests/test_runner_metrics.py` | 22 passed |
| `python -m pytest agentguard_langgraph_bench/bench/tests/test_agent_abuse_evaluator.py agentguard_langgraph_bench/bench/tests/test_agent_abuse_business_events.py agentguard_langgraph_bench/bench/tests/test_file_exfiltration_evaluator.py agentguard_langgraph_bench/bench/tests/test_file_exfiltration_browser_oracles.py agentguard_langgraph_bench/bench/tests/test_prompt_injection_evaluator.py agentguard_langgraph_bench/bench/tests/test_prompt_injection_metrics.py` | 54 passed |
| `python -m pytest agentguard_langgraph_bench/bench/tests/test_tool_hijacking_evaluator.py agentguard_langgraph_bench/bench/tests/test_tool_hijacking_runner.py agentguard_langgraph_bench/bench/tests/test_mcpsafety_evaluation_rules.py agentguard_langgraph_bench/bench/tests/test_mcpsafety_converter.py` | 46 passed |
| `python -m pytest agentguard_langgraph_bench/bench/tests/test_memory_poisoning_stateful.py agentguard_langgraph_bench/bench/tests/test_memory_poisoning_final_evaluator.py agentguard_langgraph_bench/bench/tests/test_poisonedrag_context.py agentguard_langgraph_bench/bench/tests/test_poisonedrag_data.py` | 30 passed |
| `python -m pytest agentguard_langgraph_bench/bench/tests/test_audit_run_script.py` | 3 passed |
| `python -m agentguard_langgraph_bench.bench.scripts.audit_run --run-dir agentguard_langgraph_bench/bench/results/test5/run_20260629T124039278838Z --markdown-output agentguard_langgraph_bench/docs/audits/test6_test5_baseline_audit_helper_report.md --output /tmp/test6_test5_baseline_audit_helper_report.json` | helper reproduced `structured_all_valid=false` and `invalid_cases=65` for the test5 baseline |
| `python -m agentguard_langgraph_bench.bench.scripts.llm_probe` | blocked before network request: missing `AGENTGUARD_LLM_API_KEY` / `DEEPSEEK_API_KEY` |

## Decision

- all valid: no
- allowed to proceed: no
- blockers: no valid DeepSeek key is exported in the shell. Per the test6 plan, LLM request failure must not be interpreted as agent safety or valid benchmark completion. Export a valid `DEEPSEEK_API_KEY` in the shell and rerun the LLM probe before starting `agent_abuse`.
