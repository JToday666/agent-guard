"""HTTP client and fake Core for AgentGuard Core APIs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol

import httpx

from .config import DEFAULT_API_MODE, validate_api_mode
from .event_models import PolicyDecision, RuleHit


class CoreClientProtocol(Protocol):
    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]: ...

    def evaluate_guard_event(self, event: dict[str, Any]) -> dict[str, Any]: ...

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]: ...

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]: ...


class CoreClientError(RuntimeError):
    pass


class UnsupportedApiModeError(CoreClientError):
    """Raised when a legacy Core cannot provide a v0.3-only capability."""


@dataclass(slots=True)
class AgentGuardCoreClient:
    config: Any

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.token}",
            "Content-Type": "application/json",
        }

    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        if _api_mode(self.config) == "guard-api-v0.3":
            return self.evaluate_guard_event(_guard_api_v03_event(event))
        return self._post_json("/v1/evaluate/tool-call", event)

    def evaluate_guard_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if _api_mode(self.config) != "guard-api-v0.3":
            if event.get("event_type") == "tool_call_proposed":
                return self.evaluate_tool_call(event)
            raise UnsupportedApiModeError(
                "legacy api_mode only supports tool_call_proposed; "
                "use guard-api-v0.3 for runtime GuardEvent evaluation"
            )
        response = self._post_json("/v1/guard/evaluate", event)
        decision = response.get("decision")
        if isinstance(decision, dict):
            return _decision_with_top_level_approval(decision, response)
        return response

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if _api_mode(self.config) == "guard-api-v0.3":
            return self._post_json("/v1/audit/events", event)
        return self._post_json("/v1/audit/event", event)

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        if _api_mode(self.config) != "guard-api-v0.3":
            raise UnsupportedApiModeError(
                "legacy api_mode does not support Guard API approval waiting; "
                "use guard-api-v0.3"
            )
        return self._get_json(f"/v1/approvals/{approval_id}/wait", timeout=timeout)

    def _get_json(self, path: str, timeout: float | None = None) -> dict[str, Any]:
        return self._request_json(
            "GET",
            path,
            timeout=timeout if timeout is not None else self.config.timeout,
        )

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request_json(
            "POST",
            path,
            payload=payload,
            timeout=self.config.timeout,
        )

    def _request_json(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        timeout: float,
    ) -> dict[str, Any]:
        url = self.config.core_base_url.rstrip("/") + path
        try:
            with httpx.Client(timeout=timeout) as client:
                if method == "GET":
                    response = client.get(url, headers=self._headers())
                else:
                    response = client.post(url, headers=self._headers(), json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            detail = _response_error_detail(exc.response)
            raise CoreClientError(
                f"Core returned HTTP {exc.response.status_code} for {path}{detail}"
            ) from exc
        except httpx.RequestError as exc:
            raise CoreClientError(f"Core request failed for {path}: {exc}") from exc
        except ValueError as exc:
            raise CoreClientError(f"Core returned invalid JSON for {path}") from exc
        if not isinstance(data, dict):
            raise CoreClientError(f"Core returned non-object JSON for {path}")
        return data


def _api_mode(config: Any) -> str:
    mode = getattr(
        config, "core_api_mode", getattr(config, "api_mode", DEFAULT_API_MODE)
    )
    return validate_api_mode(mode)


def _guard_api_v03_event(event: dict[str, Any]) -> dict[str, Any]:
    if "payload" in event:
        return event
    payload_keys = ("tool", "arguments", "derived_resources")
    if not any(key in event for key in payload_keys):
        return event
    payload = {key: event[key] for key in payload_keys if key in event}
    return {
        **{key: value for key, value in event.items() if key not in payload_keys},
        "payload": payload,
    }


def _decision_with_top_level_approval(
    decision: dict[str, Any], response: dict[str, Any]
) -> dict[str, Any]:
    enriched = dict(decision)
    approval = response.get("approval")
    if isinstance(approval, dict) and "approval" not in enriched:
        enriched["approval"] = approval
    # evaluate 响应回显本次写入的 policy_evaluation 审计 ID（契约 §9.9），
    # 透传到 PolicyDecision 供后续 runtime_outcome 回执关联。
    policy_audit_id = response.get("policy_audit_id")
    if isinstance(policy_audit_id, str) and policy_audit_id:
        enriched["policy_audit_id"] = policy_audit_id
    return enriched


def _response_error_detail(response: httpx.Response) -> str:
    text = response.text.strip()
    if not text:
        return ""
    return f": {text[:500]}"


@dataclass(slots=True)
class FakeDenyCoreClient:
    """Local test double that makes Agent Security Core deny every tool call."""

    reason: str = "Fake Agent Security Core is configured to deny every tool call."

    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        resource_targets = [
            item.get("target", "")
            for item in event.get("derived_resources", [])
            if isinstance(item, dict) and item.get("target")
        ]
        decision = PolicyDecision(
            decision_id="dec_fake_deny",
            decision="deny",
            risk_score=100,
            severity="high",
            rule_hits=[
                RuleHit(
                    rule_id="FAKE_CORE_ALWAYS_DENY",
                    rule_name="Fake Core Always Deny",
                    severity="high",
                    evidence=resource_targets or ["local smoke test fake core"],
                )
            ],
            reason=self.reason,
            safe_message="The tool call was blocked by the fake Agent Security Core.",
            approval=None,
            latency_ms=0,
        )
        return decision.model_dump()

    def evaluate_guard_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return self.evaluate_tool_call(event)

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "audit_id": event.get("audit_id")}

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        return {"status": "resolved", "decision": "deny"}


@dataclass(slots=True)
class FakeAskCoreClient:
    """Local test double that asks for approval for every tool call."""

    reason: str = (
        "Fake Agent Security Core is configured to require approval for every tool call."
    )

    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        resource_targets = [
            item.get("target", "")
            for item in event.get("derived_resources", [])
            if isinstance(item, dict) and item.get("target")
        ]
        decision = PolicyDecision(
            decision_id="dec_fake_ask",
            decision="ask",
            risk_score=70,
            severity="medium",
            rule_hits=[
                RuleHit(
                    rule_id="FAKE_CORE_ALWAYS_ASK",
                    rule_name="Fake Core Always Ask",
                    severity="medium",
                    evidence=resource_targets or ["local smoke test fake core"],
                )
            ],
            reason=self.reason,
            safe_message="The tool call requires approval from the fake Agent Security Core.",
            approval={"required": True, "mode": "fake_core"},
            latency_ms=0,
        )
        return decision.model_dump()

    def evaluate_guard_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return self.evaluate_tool_call(event)

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "audit_id": event.get("audit_id")}

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        return {"status": "pending", "decision": None}


@dataclass(slots=True)
class FakeAllowCoreClient:
    """Local test double that makes Agent Security Core allow every tool call."""

    reason: str = "Fake Agent Security Core is configured to allow every tool call."

    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        decision = PolicyDecision(
            decision_id="dec_fake_allow",
            decision="allow",
            risk_score=0,
            severity="low",
            rule_hits=[],
            reason=self.reason,
            safe_message=None,
            approval=None,
            latency_ms=0,
        )
        return decision.model_dump()

    def evaluate_guard_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return self.evaluate_tool_call(event)

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "audit_id": event.get("audit_id")}

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        return {"status": "resolved", "decision": "allow_once"}
