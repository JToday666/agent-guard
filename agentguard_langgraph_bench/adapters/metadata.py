"""Metadata filtering for agent-visible external adapter payloads."""

from __future__ import annotations

from typing import Any


AGENT_VISIBLE_METADATA_ALLOWLIST = {
    "web_entry_source_path",
    "local_web_entry_source_path",
    "original_web_entry_source_path",
    "entry_url",
    "web_entry_url",
    "local_service_url",
    "local_service_page_url",
    "source_path",
    "agent_files",
    "fixture_files",
    "phase",
    "scenario_id",
    "scenario_order",
    "memory_namespace",
    "memory_key",
    "memory_value",
    "dataset",
    "question_id",
    "question",
    "query",
    "mode",
    "poisonedrag",
    "top_k",
    "adv_per_query",
}

FORBIDDEN_AGENT_VISIBLE_METADATA_KEYS = {
    "expected_decision",
    "expected_safe_behavior",
    "success_condition",
    "target_behavior",
    "attacker_goal",
    "harm_oracle",
    "success_oracle",
    "task_terminal_oracle",
    "task_closure",
    "normal_oracle",
    "attack_oracle",
    "task_oracle",
    "safety_oracle",
    "sequence_oracle",
    "permission_oracle",
    "response_oracle",
    "normal_task_difficulty_snapshot",
    "incorrect_answer",
    "target_incorrect_answer",
    "asset_type",
    "original_attack_level",
    "original_primary_risk",
    "original_secondary_risk",
    "original_risk_level",
}

FORBIDDEN_AGENT_VISIBLE_METADATA_PREFIXES = (
    "attack_",
    "attacker_",
    "benchmark_",
    "evaluator_",
    "metric_",
    "oracle_",
    "pi_",
)


def safe_agent_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return only operational metadata that an external agent may see."""
    safe: dict[str, Any] = {}
    for key, value in (metadata or {}).items():
        key_text = str(key)
        normalized = key_text.lower()
        if key_text not in AGENT_VISIBLE_METADATA_ALLOWLIST:
            continue
        if normalized in FORBIDDEN_AGENT_VISIBLE_METADATA_KEYS:
            continue
        if any(normalized.startswith(prefix) for prefix in FORBIDDEN_AGENT_VISIBLE_METADATA_PREFIXES):
            continue
        safe[key_text] = value
    return safe


def forbidden_agent_visible_metadata_keys(metadata: dict[str, Any]) -> list[str]:
    """List forbidden keys that survived filtering; used by preflight/tests."""
    leaked: list[str] = []
    for key in (metadata or {}).keys():
        key_text = str(key)
        normalized = key_text.lower()
        if normalized in FORBIDDEN_AGENT_VISIBLE_METADATA_KEYS or any(
            normalized.startswith(prefix) for prefix in FORBIDDEN_AGENT_VISIBLE_METADATA_PREFIXES
        ):
            leaked.append(key_text)
    return sorted(leaked)
