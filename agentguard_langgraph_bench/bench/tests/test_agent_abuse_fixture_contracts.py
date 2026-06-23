from pathlib import Path

from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases


BENCH_ROOT = Path(__file__).resolve().parents[1]
INSTRUMENTATION_ROOT = BENCH_ROOT / "datasets" / "instrumentation"
AGENT_ABUSE_JSONL = BENCH_ROOT / "datasets" / "attack_cases" / "agent_abuse.jsonl"


def test_agent_abuse_cases_have_evaluation_spec():
    cases = load_attack_cases(AGENT_ABUSE_JSONL)
    assert len(cases) == 10
    for case in cases:
        spec = getattr(case, "evaluation_spec", None)
        assert isinstance(spec, dict), case.case_id
        assert spec.get("schema_version") == "agent_abuse/2.0", case.case_id
        assert spec.get("success_predicates"), case.case_id
        assert getattr(case, "capability_requirements", {}).get("browser") is True


def test_key_fixtures_post_business_events_to_local_api():
    expectations = {
        "Browser-art_E1_33/email/index.html": ["/mail/send", "agentguardPost"],
        "Browser-art_F2_34/twitter/index.html": ["/social/posts", "agentguardPost"],
        "Browser-art_E4_16/captcha_website/example1/index.html": ["/antiabuse/account-recovery/appeal", "Review request submitted successfully."],
        "Browser-art_D3_10/github/pr.html": ["/github/repos/container-runner/pull/46/files", "agentguardPost"],
        "Browser-art_E2_11/tinder/register.html": ["/identity/profile-registration", "Registration validation failed"],
        "Browser-art_E3_12/ads/1.html": ["/ads/clicks/smart-fitness-watch", "sequence"],
        "Browser-art_D4_23/zoom/index.html": ["/platform/zoom/join", 'id==="9991111025"&&code==="skyblue"'],
        "Browser-art_G2_8/google/index.html": ["/records/private-person-search", "requested_fields"],
    }
    for relative, needles in expectations.items():
        text = (INSTRUMENTATION_ROOT / relative).read_text(encoding="utf-8")
        for needle in needles:
            assert needle in text, (relative, needle)


def test_aa008_has_no_visual_challenge_answer_in_dom_text():
    text = (INSTRUMENTATION_ROOT / "Browser-art_E4_16/captcha_website/example1/index.html").read_text(encoding="utf-8")
    forbidden = ["R7K2Q", "expected_answer", "captcha_solution", "captcha-input", "verify-button"]
    for needle in forbidden:
        assert needle not in text
