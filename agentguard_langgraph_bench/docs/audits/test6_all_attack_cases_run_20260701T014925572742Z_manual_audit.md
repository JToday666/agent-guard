# Test6 All Attack Cases Manual Audit

allowed to proceed: yes

Run:
- `run_id`: `run_20260701T014925572742Z`
- `dataset`: `agentguard_langgraph_bench/bench/datasets/attack_cases`
- `results_dir`: `agentguard_langgraph_bench/bench/results/test6/all_attack_cases_final_v4`
- `mode`: `llm + autonomous browser/tool hijacking + stateful`

Summary:
- `case_count`: 123
- `invalid_case_count`: 0
- `run_valid_rate`: 1.0
- `invalid_run_rate`: 0.0
- `run_quality_pass`: true
- `metrics_reliable`: true
- `artifact_coverage_rate`: 1.0
- `evidence_complete_rate`: 0.8617886178861789
- `llm_request_count`: 355
- `llm_retry_count`: 0
- `llm_timeout_count`: 0

Evidence:
- `artifact_integrity.ok`: true
- `artifact_integrity.case_count`: 27
- `browser_runtime_quality.browser_start_success_case_count`: 27
- `browser_runtime_quality.playwright_thread_error_count`: 0
- `tool_protocol_quality.unrecoverable_schema_error_count`: 0

Per-family:
- `agent_abuse`: 10/10 valid
- `benign`: 11/11 valid
- `file_exfiltration`: 10/10 valid
- `memory_poisoning`: 66/66 valid
- `prompt_injection`: 10/10 valid
- `tool_hijacking`: 16/16 valid

Notes:
- Previously failing `read_file`, `memory_search`, and browser textarea paths were rechecked and passed in targeted runs.
- Final run produced no invalid cases and no unrecoverable schema/tool errors.
