"""Trust classification applied before benchmark metrics are calculated."""

from __future__ import annotations

from typing import Any

CORE_UNAVAILABLE_REASON = "core_unavailable_fail_closed"


def classify_infrastructure_failures(results: list[dict[str, Any]]) -> None:
    """Invalidate rows where availability failure masqueraded as a policy block."""

    for row in results:
        reasons = infrastructure_failure_reasons(row)
        if not reasons:
            row.setdefault("infrastructure_failure", False)
            continue
        previous_status = str(row.get("run_status") or "")
        if previous_status and previous_status != "infrastructure_error":
            row.setdefault("reported_run_status", previous_status)
        row["infrastructure_failure"] = True
        row["infrastructure_failure_reasons"] = reasons
        row["run_valid"] = False
        row["run_status"] = "infrastructure_error"
        row["invalid_reasons"] = sorted(
            {
                *[str(item) for item in row.get("invalid_reasons") or []],
                *reasons,
            }
        )


def infrastructure_failure_reasons(row: dict[str, Any]) -> list[str]:
    reasons: set[str] = set()
    for call in _tool_calls(row):
        if _has_fail_closed_rule(call):
            reasons.add(CORE_UNAVAILABLE_REASON)
        operational_text = " ".join(
            str(call.get(key) or "")
            for key in ("safe_message", "error", "runtime_receipt_error")
        ).lower()
        if (
            "agentguard core was unavailable" in operational_text
            or "core unavailable or invalid" in operational_text
            or "core request failed" in operational_text
        ):
            reasons.add(CORE_UNAVAILABLE_REASON)
    adapter_error = str(row.get("adapter_error") or "").lower()
    if "core request failed" in adapter_error or "core unavailable" in adapter_error:
        reasons.add(CORE_UNAVAILABLE_REASON)
    return sorted(reasons)


def _has_fail_closed_rule(call: dict[str, Any]) -> bool:
    direct = call.get("rule_hits")
    if isinstance(direct, list) and "AGENTGUARD_FAIL_CLOSED" in {
        _rule_id(item) for item in direct
    }:
        return True
    audit_event = call.get("audit_event")
    if not isinstance(audit_event, dict):
        return False
    hits = audit_event.get("rule_hits")
    return isinstance(hits, list) and "AGENTGUARD_FAIL_CLOSED" in {
        _rule_id(item) for item in hits
    }


def _rule_id(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("rule_id") or "")
    return str(value)


def _tool_calls(row: dict[str, Any]) -> list[dict[str, Any]]:
    calls = row.get("tool_calls")
    if not isinstance(calls, list):
        return []
    return [item for item in calls if isinstance(item, dict)]
