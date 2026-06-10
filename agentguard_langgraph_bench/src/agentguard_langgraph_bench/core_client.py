"""HTTP client and fake Core for AgentGuard Core APIs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .config import BenchConfig
from .models import PolicyDecision


class CoreClientProtocol(Protocol):
    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        ...

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        ...


class CoreClientError(RuntimeError):
    pass


@dataclass(slots=True)
class AgentGuardCoreClient:
    config: BenchConfig

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.token}",
            "Content-Type": "application/json",
        }

    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        return self._post_json("/v1/evaluate/tool-call", event)

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return self._post_json("/v1/audit/event", event)

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = self.config.core_base_url.rstrip("/") + path
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.post(url, headers=self._headers(), json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            raise CoreClientError(f"Core returned HTTP {exc.response.status_code} for {path}") from exc
        except httpx.RequestError as exc:
            raise CoreClientError(f"Core request failed for {path}: {exc}") from exc
        except ValueError as exc:
            raise CoreClientError(f"Core returned invalid JSON for {path}") from exc
        if not isinstance(data, dict):
            raise CoreClientError(f"Core returned non-object JSON for {path}")
        return data


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
                {
                    "rule_id": "FAKE_CORE_ALWAYS_DENY",
                    "rule_name": "Fake Core Always Deny",
                    "severity": "high",
                    "evidence": resource_targets or ["local smoke test fake core"],
                }
            ],
            reason=self.reason,
            safe_message="The tool call was blocked by the fake Agent Security Core.",
            approval=None,
            latency_ms=0,
        )
        return decision.model_dump()

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "audit_id": event.get("audit_id")}


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

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "audit_id": event.get("audit_id")}
