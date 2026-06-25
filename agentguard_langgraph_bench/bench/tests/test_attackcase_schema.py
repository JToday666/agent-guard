from pathlib import Path
from collections import Counter
import json
import re

from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.demo_agent.graph import _llm_messages_for_case
from agentguard_langgraph_bench.bench.browser_runtime import resolve_local_source
from agentguard_langgraph_bench.bench.config import ensure_sandbox


HTML_REF_RE = re.compile(r"['\"]?((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.html)['\"]?")


def _local_url(source_path: str) -> str:
    local_prefix = "agentguard_langgraph_bench/bench/datasets/instrumentation/"
    if source_path.startswith(local_prefix):
        rel = source_path.removeprefix(local_prefix)
        return f"http://127.0.0.1:18080/local-instrumentation/{rel}?mode=record&run_id=agentguard"
    rel = source_path.removeprefix("Instrumentation/")
    return f"http://127.0.0.1:18080/instrumentation/{rel}?mode=record&run_id=agentguard"


def _payload_from_task_user_goal(user_goal: str, web_entry_source_path: str | None) -> str:
    if not web_entry_source_path:
        return user_goal
    return HTML_REF_RE.sub(_local_url(web_entry_source_path), user_goal, count=1)


def _is_migrated_file_or_prompt_case(case) -> bool:
    return case.metadata.get("source_group") in {"file_exfiltration_p0", "instrumentation_prompt_ABC"}


def _payload_with_task_url(user_goal: str, web_entry_source_path: str) -> str:
    url = _local_url(web_entry_source_path)
    updated_goal = HTML_REF_RE.sub(url, user_goal, count=1)
    return f"Task URL: {url}\n\n{updated_goal}"


def test_attackcase_schema_loads_all_jsonl_files():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)

    assert len(cases) >= 60
    assert {case.attack_type for case in cases} == {
        "agent_abuse",
        "file_exfiltration",
        "memory_poisoning",
        "prompt_injection",
        "tool_hijacking",
        "benign",
    }
    malicious_counts = Counter(case.attack_type for case in cases if case.is_malicious)
    assert malicious_counts["agent_abuse"] >= 10
    assert malicious_counts["file_exfiltration"] >= 10
    assert malicious_counts["memory_poisoning"] >= 10
    assert malicious_counts["prompt_injection"] >= 10
    assert malicious_counts["tool_hijacking"] >= 10
    benign_counts = Counter(case.attack_type for case in cases if not case.is_malicious)
    assert benign_counts["benign"] >= 10
    assert all("langgraph" in case.runtime_targets for case in cases)


def test_attackcase_source_groups_keep_requested_dataset_split():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)
    groups = Counter(case.metadata.get("source_group") for case in cases)

    assert groups["instrumentation_prompt_ABC"] == 10
    assert groups["instrumentation_agent_abuse_DEFG"] == 10
    assert groups["mcpsafety_mcp"] == 10
    assert groups["poisonedrag_qa"] >= 10


def test_mcpsafety_tool_hijacking_cases_cover_main_modes():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir / "tool_hijacking.jsonl")
    modes = Counter(case.metadata.get("hijacking_mode") for case in cases)

    assert len(cases) == 10
    assert set(modes) >= {
        "tool_shadowing",
        "tool_redirect",
        "argument_hijacking",
        "return_hijacking",
        "gateway_hijacking",
    }
    assert all((case.metadata.get("hijacking") or {}).get("mode") == case.metadata.get("hijacking_mode") for case in cases)

    evaluators = Counter(case.metadata.get("mcpsafety_evaluator") for case in cases)
    assert evaluators["check_dependency"] >= 2
    assert evaluators["check_network_request_poisoning_attack"] >= 1


def test_mcpsafety_tool_hijacking_cases_reference_real_local_resources():
    bench_root = Path(__file__).resolve().parents[1]
    sandbox_dir = bench_root / "sandbox"
    ensure_sandbox(sandbox_dir)
    cases = load_attack_cases(bench_root / "datasets" / "attack_cases" / "tool_hijacking.jsonl")

    assert len(cases) == 10
    for case in cases:
        serialized = json.dumps(case.model_dump(), ensure_ascii=False)
        assert "attacker.com" not in serialized, case.case_id
        assert "placeholder" not in serialized.lower(), case.case_id
        assert "mock" not in case.input.payload.lower(), case.case_id

        resources = case.metadata.get("real_benchmark_resources")
        assert resources, case.case_id
        for resource in resources:
            if resource.startswith("sandbox/"):
                assert (bench_root / resource).exists(), (case.case_id, resource)
            elif resource.startswith("http://"):
                assert resource.startswith("http://127.0.0.1:18085/"), (case.case_id, resource)
            else:
                raise AssertionError((case.case_id, resource))


def test_attackcase_tool_plans_preserve_source_execution_features():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)

    prompt_cases = [case for case in cases if case.metadata.get("source_group") == "instrumentation_prompt_ABC"]
    abuse_cases = [case for case in cases if case.metadata.get("source_group") == "instrumentation_agent_abuse_DEFG"]
    mcp_cases = [case for case in cases if case.metadata.get("source_group") == "mcpsafety_mcp"]
    rag_cases = [case for case in cases if case.metadata.get("source_group") == "poisonedrag_qa"]

    assert all(any(step.tool == "browser_start" for step in case.tool_plan) for case in prompt_cases)
    assert all(any(step.tool == "browser_start" for step in case.tool_plan) for case in abuse_cases)
    assert all(any(step.tool == "mcp_call" for step in case.tool_plan) for case in mcp_cases)
    assert all({step.tool for step in case.tool_plan} >= {"rag_retrieve", "rag_answer"} for case in rag_cases)

    for case in prompt_cases + abuse_cases:
        browser_start = next(step for step in case.tool_plan if step.tool == "browser_start")
        source_path = browser_start.arguments.get("source_path")
        assert source_path
        assert resolve_local_source(source_path) is not None


def test_all_instrumentation_cases_have_openable_local_page():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)
    instrumentation_cases = [
        case for case in cases if case.metadata.get("source_dataset") == "Instrumentation"
    ]

    assert instrumentation_cases
    assert all(any(step.tool == "browser_start" for step in case.tool_plan) for case in instrumentation_cases)

    for case in instrumentation_cases:
        browser_start = next(step for step in case.tool_plan if step.tool == "browser_start")
        source_path = browser_start.arguments.get("source_path")
        assert source_path == case.metadata.get("web_entry_source_path")
        assert resolve_local_source(source_path) is not None
        if _is_migrated_file_or_prompt_case(case):
            assert source_path.startswith("agentguard_langgraph_bench/bench/datasets/instrumentation/")
            assert "/local-instrumentation/" in browser_start.arguments["url"]


def test_attackcase_payloads_do_not_inline_attack_metadata():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)
    forbidden = (
        "User goal:",
        "Untrusted attack delivery",
        "Attacker goal:",
        "Expected safe behavior:",
        "Poisoned MCP metadata",
        "asks the agent to call",
    )

    for case in cases:
        assert not any(marker in case.input.payload for marker in forbidden), case.case_id


def test_benign_payloads_are_concrete_tasks():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir / "benign.jsonl")

    assert len(cases) == 10
    for case in cases:
        payload = case.input.payload
        assert "Perform benign action" not in payload, case.case_id
        assert "benign action" not in payload.lower(), case.case_id
        assert "mock" not in payload.lower(), case.case_id
        assert "placeholder" not in payload.lower(), case.case_id
        assert len(payload.split()) >= 10, case.case_id


def test_benign_cases_reference_real_benchmark_fixtures():
    bench_root = Path(__file__).resolve().parents[1]
    dataset_dir = bench_root / "datasets" / "attack_cases"
    ensure_sandbox(bench_root / "sandbox")
    sandbox_files = bench_root / "sandbox" / "files"
    cases = load_attack_cases(dataset_dir / "benign.jsonl")

    for case in cases:
        for fixture in case.metadata.get("fixture_files", []):
            assert (bench_root / fixture).exists(), (case.case_id, fixture)
        for step in case.tool_plan:
            args = step.arguments
            if step.tool == "read_file":
                assert (sandbox_files / str(args["path"]).lstrip("/")).exists(), case.case_id
            if step.tool == "write_file":
                assert (sandbox_files / str(args["path"]).lstrip("/")).parent.exists(), case.case_id
            if step.tool == "browser_start":
                assert resolve_local_source(args.get("source_path")) is not None, case.case_id
            if step.tool == "rag_retrieve" and args.get("context_path"):
                assert (sandbox_files / str(args["context_path"]).lstrip("/")).exists(), case.case_id
            if step.tool == "mcp_call" and args.get("server") == "weather":
                assert (bench_root / "sandbox" / "mcp" / "weather_forecasts.json").exists(), case.case_id


def test_benign_api_payload_uses_local_startable_site():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    case = next(case for case in load_attack_cases(dataset_dir / "benign.jsonl") if case.case_id == "BN-004")
    url = "http://127.0.0.1:18081/status"
    call_api_step = next(step for step in case.tool_plan if step.tool == "call_api")

    assert "api.example.local" not in case.input.payload
    assert case.target_behavior.resource == url
    assert case.success_condition.resource == url
    assert call_api_step.arguments["url"] == url


def test_file_exfiltration_cases_reference_real_benchmark_resources():
    bench_root = Path(__file__).resolve().parents[1]
    dataset_dir = bench_root / "datasets" / "attack_cases"
    sandbox_files = bench_root / "sandbox" / "files"
    ensure_sandbox(bench_root / "sandbox")
    cases = load_attack_cases(dataset_dir / "file_exfiltration.jsonl")
    forbidden = (
        "mock-secret",
        "attacker.example",
        "placeholder",
        "IMPORTANT FOR AGENT",
        "MISDIRECTION",
        "TACACS",
        "bank password",
        "Force a custom desktop wallpaper",
        "Complete the MCP benchmark task",
        "content_ref",
    )

    assert len(cases) == 10
    recipients = json.loads((sandbox_files / "contacts" / "exfiltration_recipients.json").read_text(encoding="utf-8"))
    registered_mailboxes = set(recipients["registered_review_mailboxes"])
    for case in cases:
        visible_payload = {
            "input": case.input.model_dump(),
            "metadata": case.metadata,
            "tool_plan": [step.model_dump() for step in case.tool_plan],
            "target_behavior": case.target_behavior.model_dump(),
            "success_condition": case.success_condition.model_dump(),
        }
        serialized = json.dumps(visible_payload, ensure_ascii=False)
        assert not any(marker in serialized for marker in forbidden), case.case_id

        if case.metadata.get("source_dataset") == "Instrumentation":
            browser_start = next(step for step in case.tool_plan if step.tool == "browser_start")
            assert browser_start.arguments["url"].startswith("http://127.0.0.1:18080/"), case.case_id
            assert resolve_local_source(browser_start.arguments["source_path"]) is not None, case.case_id
            assert browser_start.arguments["source_path"] == case.metadata.get("web_entry_source_path"), case.case_id
            assert any(step.tool == "browser_start" for step in case.tool_plan), case.case_id

        for step in case.tool_plan:
            args = step.arguments
            if step.tool == "read_file":
                assert (sandbox_files / str(args["path"]).lstrip("/")).exists(), (case.case_id, args["path"])
            if step.tool == "write_file":
                target = sandbox_files / str(args["path"]).lstrip("/")
                assert target.parent.exists(), (case.case_id, args["path"])
                assert "mock" not in str(args.get("content", "")).lower(), case.case_id
            if step.tool == "send_email":
                assert args["to"] in registered_mailboxes, (case.case_id, args["to"])
                assert "mock" not in args["body"].lower(), case.case_id
            if step.tool == "call_api" and str(args.get("url", "")).endswith(("/collect/env", "/collect/token")):
                assert args["url"].startswith("http://127.0.0.1:18086/"), (case.case_id, args["url"])

    fe003 = next(case for case in cases if case.case_id == "FE-003")
    assert fe003.metadata["web_entry_source_path"].endswith("/amazon/index.html")
    assert "completion.html" not in json.dumps(fe003.model_dump(), ensure_ascii=False)


def test_instrumentation_payload_and_llm_prompt_use_local_url_not_relative_page():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)
    case = next(item for item in cases if item.case_id == "AA-001")

    prompt = _llm_messages_for_case(case)[-1][1]
    bare_relative_page = re.compile(r"(?<!http://127\\.0\\.0\\.1:18080/)(?<!http://localhost:18080/)['\"]?amazon/index\\.html['\"]?")

    assert bare_relative_page.search(case.input.payload) is None
    assert "benchmark" not in case.input.payload.lower()
    assert "sandbox" not in case.input.payload.lower()
    assert "http://127.0.0.1:" in prompt
    assert bare_relative_page.search(prompt) is None
    assert "source_path:" not in prompt


def test_instrumentation_payloads_are_task_user_goals():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)
    instrumentation_cases = [
        case for case in cases if case.metadata.get("source_dataset") == "Instrumentation"
    ]

    assert instrumentation_cases
    for case in instrumentation_cases:
        task_path = case.metadata.get("source_path")
        assert task_path, case.case_id
        task_json_path = resolve_local_source(task_path)
        assert task_json_path is not None, case.case_id

        task_data = json.loads(task_json_path.read_text(encoding="utf-8"))
        user_goal = task_data["user_goal"]
        web_entry = case.metadata.get("web_entry_source_path")

        metadata_goal = case.metadata.get("user_goal")
        if case.metadata.get("localized_for_real_benchmark"):
            assert metadata_goal, case.case_id
            assert case.input.payload.strip(), case.case_id
            assert "AgentGuard" not in case.input.payload, case.case_id
            assert "benchmark" not in case.input.payload.lower(), case.case_id
            assert "sandbox" not in case.input.payload.lower(), case.case_id
            assert "Instrumentation" not in case.input.payload, case.case_id
        elif _is_migrated_file_or_prompt_case(case):
            assert web_entry.startswith("agentguard_langgraph_bench/bench/datasets/instrumentation/")
            if case.case_id == "PI-010":
                assert case.metadata.get("original_id") == "EIA_A6_39_high"
                assert case.input.payload.startswith(f"Task URL: {_local_url(web_entry)}\n\n")
                assert "Tesla Schedule a Demo Drive" in case.input.payload
                assert "COMP-INTEL-2025-04-MARKET" in case.input.payload
                assert "ignore any suspicious" in case.input.payload
                assert case.input.source_type != "direct_user_instruction"
            else:
                assert case.input.payload == _payload_with_task_url(user_goal, web_entry), case.case_id
        else:
            assert metadata_goal == user_goal, case.case_id
            assert case.input.payload == _payload_from_task_user_goal(user_goal, web_entry), case.case_id
        assert "inspect the visible task context" not in case.input.payload


def test_agent_abuse_cases_only_use_browser_art_defg():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir / "agent_abuse.jsonl")
    allowed_prefixes = ("D", "E", "F", "G")

    assert len(cases) == 10
    for case in cases:
        source_subset = case.metadata.get("source_subset", "")
        assert case.metadata.get("source_dataset") == "Instrumentation", case.case_id
        assert case.metadata.get("dataset_source") == "BrowserART", case.case_id
        assert source_subset.startswith(allowed_prefixes), case.case_id
        assert case.metadata.get("original_id", "").startswith("Browser-art_"), case.case_id


def test_agent_abuse_cases_reference_real_local_resources():
    bench_root = Path(__file__).resolve().parents[1]
    dataset_dir = bench_root / "datasets" / "attack_cases"
    ensure_sandbox(bench_root / "sandbox")
    cases = load_attack_cases(dataset_dir / "agent_abuse.jsonl")
    forbidden = (
        "malware.example",
        "attacker.example",
        "platform.example",
        "payments.example",
        "records.example",
        "phish.example",
        "victim@example",
        "company.com",
        "app.goog1e",
        "#identity-application",
        "#captcha-bypass",
        "placeholder",
    )

    assert len(cases) == 10
    for case in cases:
        payload = case.model_dump()
        serialized = json.dumps(payload, ensure_ascii=False)
        assert not any(marker in serialized for marker in forbidden), case.case_id
        assert "mock" not in case.input.payload.lower(), case.case_id
        assert case.metadata.get("localized_for_real_benchmark") is True, case.case_id
        browser_start = next(step for step in case.tool_plan if step.tool == "browser_start")
        assert browser_start.arguments["url"].startswith("http://127.0.0.1:18080/"), case.case_id
        assert resolve_local_source(browser_start.arguments["source_path"]) is not None, case.case_id

        if case.target_behavior.tool == "call_api":
            url = case.target_behavior.resource
            assert url and url.startswith("http://127.0.0.1:18083/"), case.case_id
            call_api_step = next(step for step in case.tool_plan if step.tool == "call_api")
            assert call_api_step.arguments["url"] == url, case.case_id

        for resource in case.metadata.get("real_benchmark_resources", []):
            if resource.startswith("sandbox/files/"):
                assert (bench_root / resource).exists(), (case.case_id, resource)
            elif resource.startswith("Instrumentation/"):
                assert resolve_local_source(resource) is not None, (case.case_id, resource)
            elif resource.startswith("http://"):
                assert resource.startswith(("http://127.0.0.1:18080/", "http://127.0.0.1:18083/")), (case.case_id, resource)


def test_poisonedrag_payload_is_question_plus_contexts():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)
    rag_cases = [
        case
        for case in cases
        if case.metadata.get("source_dataset") == "PoisonedRAG" and any(step.tool == "rag_retrieve" for step in case.tool_plan)
    ]

    assert rag_cases
    for case in rag_cases:
        retrieve = next(step for step in case.tool_plan if step.tool == "rag_retrieve")
        question = retrieve.arguments["question"].lower()
        payload = case.input.payload.lower()
        assert question in payload or {"chicago", "fire", "season", "4"}.issubset(set(re.findall(r"[a-z0-9]+", payload)))
        if retrieve.arguments.get("contexts"):
            assert "Contexts:\n" in case.input.payload
            assert retrieve.arguments["contexts"][0] in case.input.payload
        else:
            resource_files = case.metadata.get("resource_files", {})
            if resource_files:
                assert "local case package" in case.input.payload
                for resource in resource_files.values():
                    assert (Path(__file__).resolve().parents[2] / resource).exists(), (case.case_id, resource)
            else:
                assert retrieve.arguments.get("source") == "poisonedrag"


def test_mcpsafety_payload_uses_original_task_text():
    dataset_dir = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"
    cases = load_attack_cases(dataset_dir)
    mcp_004 = next(case for case in cases if case.case_id == "MCP-004")
    mcp_010 = next(case for case in cases if case.case_id == "MCP-010")

    assert mcp_004.input.payload.startswith("Help me find a one-way flight")
    assert mcp_010.input.payload.startswith("Hi! I'm just starting to learn about LLMs")
