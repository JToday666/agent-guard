"""HTTP client and fake Core for AgentGuard Core APIs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import time
from typing import Any, Literal, Protocol

import httpx

from .config import DEFAULT_API_MODE, validate_api_mode
from .endpoint_policy import GuardApiEndpointError, validate_guard_api_base_url
from .event_models import PolicyDecision, RuleHit
from .strong_binding import (
    ExecutionLeaseConsumeError,
    ExecutionLeaseCorrelation,
    ExecutionLeaseReference,
)

_LEASE_TOKEN = re.compile(r"^lease-v1:[0-9a-f]{64}$")
_LEASE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_LEASE_RESPONSE_KEYS = frozenset(
    {"lease_id", "consumption_id", "lease_token", "expires_at"}
)
_MAX_LEASE_CONSUME_ATTEMPTS = 5


class CoreClientProtocol(Protocol):
    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]: ...

    def evaluate_guard_event(self, event: dict[str, Any]) -> dict[str, Any]: ...

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]: ...

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]: ...

    def consume_execution_lease(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        deadline: float,
    ) -> ExecutionLeaseReference: ...


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
        if _LEASE_IDENTIFIER.fullmatch(approval_id) is None:
            raise ExecutionLeaseConsumeError("rejected")
        return self._get_json(f"/v1/approvals/{approval_id}/wait", timeout=timeout)

    def consume_execution_lease(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        deadline: float,
    ) -> ExecutionLeaseReference:
        """Consume an exact execution lease with bounded, same-body retries."""

        if _api_mode(self.config) != "guard-api-v0.3":
            raise UnsupportedApiModeError(
                "legacy api_mode does not support execution leases; use guard-api-v0.3"
            )
        if (
            _LEASE_IDENTIFIER.fullmatch(approval_id) is None
            or _LEASE_IDENTIFIER.fullmatch(action_id) is None
            or re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", authorization_fingerprint)
            is None
        ):
            raise ExecutionLeaseConsumeError("rejected")
        try:
            base_url = validate_guard_api_base_url(self.config.core_base_url)
        except GuardApiEndpointError as exc:
            raise ExecutionLeaseConsumeError("rejected") from exc
        path = f"/v1/approvals/{approval_id}/execution-leases/consume"
        url = base_url + path
        # Serialize exactly once. Every retry uses these identical bytes.
        body = json.dumps(
            {
                "action_id": action_id,
                "authorization_fingerprint": authorization_fingerprint,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        for attempt in range(_MAX_LEASE_CONSUME_ATTEMPTS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ExecutionLeaseConsumeError("timed_out")
            timeout = min(float(self.config.timeout), remaining)
            try:
                with httpx.Client(
                    timeout=max(timeout, 0.001), follow_redirects=False
                ) as client:
                    response = client.post(
                        url,
                        headers=self._headers(),
                        content=body,
                    )
            except httpx.RequestError:
                if attempt + 1 >= _MAX_LEASE_CONSUME_ATTEMPTS:
                    raise ExecutionLeaseConsumeError("lease_unavailable") from None
                _lease_retry_pause(attempt=attempt, deadline=deadline)
                continue

            status = response.status_code
            if response.is_redirect:
                raise ExecutionLeaseConsumeError("rejected", status_code=status)
            if status in {408, 429} or status >= 500:
                if attempt + 1 >= _MAX_LEASE_CONSUME_ATTEMPTS:
                    if deadline - time.monotonic() <= 0:
                        raise ExecutionLeaseConsumeError(
                            "timed_out", status_code=status
                        )
                    raise ExecutionLeaseConsumeError(
                        "lease_unavailable", status_code=status
                    )
                _lease_retry_pause(attempt=attempt, deadline=deadline)
                continue
            if not 200 <= status < 300:
                raise _lease_http_error(response)
            try:
                payload = response.json()
            except ValueError:
                raise ExecutionLeaseConsumeError(
                    "invalid_response", status_code=status
                ) from None
            lease = _lease_reference_from_response(payload, status_code=status)
            if deadline - time.monotonic() <= 0:
                raise ExecutionLeaseConsumeError(
                    "timed_out",
                    status_code=status,
                    correlation=ExecutionLeaseCorrelation(
                        lease_id=lease.lease_id,
                        consumption_id=lease.consumption_id,
                    ),
                )
            return lease
        raise ExecutionLeaseConsumeError("lease_unavailable")

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
        try:
            base_url = validate_guard_api_base_url(self.config.core_base_url)
        except GuardApiEndpointError as exc:
            raise CoreClientError(str(exc)) from exc
        url = base_url + path
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                if method == "GET":
                    response = client.get(url, headers=self._headers())
                else:
                    response = client.post(url, headers=self._headers(), json=payload)
            if response.is_redirect:
                raise CoreClientError("Guard API redirects are not allowed")
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            raise CoreClientError(
                f"Core returned HTTP {exc.response.status_code} for {path}"
            ) from exc
        except httpx.RequestError as exc:
            raise CoreClientError(
                f"Core request failed for {path} ({type(exc).__name__})"
            ) from exc
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
    # Keep the strong binding transient on PolicyDecision.  The model marks it
    # repr/serialization-excluded so its fingerprint cannot enter receipts or
    # runtime state through a generic model_dump().
    if "enforcement_binding" in response:
        enriched["enforcement_binding"] = response.get("enforcement_binding")
    return enriched


def _lease_retry_pause(*, attempt: int, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ExecutionLeaseConsumeError("timed_out")
    delay = min(0.05 * (2**attempt), 0.25, remaining)
    if delay > 0:
        time.sleep(delay)


def _lease_http_error(response: httpx.Response) -> ExecutionLeaseConsumeError:
    status = response.status_code
    code: str | None = None
    try:
        payload = response.json()
        error = payload.get("error") if isinstance(payload, dict) else None
        raw_code = error.get("code") if isinstance(error, dict) else None
        if isinstance(raw_code, str):
            code = raw_code
    except ValueError:
        pass
    failure_by_code = {
        "APPROVAL_NOT_FOUND": "approval_not_found",
        "APPROVAL_NOT_CONSUMABLE": "approval_not_consumable",
        "APPROVAL_CONSUMPTION_CONFLICT": "consumption_conflict",
        "APPROVAL_EXPIRED": "approval_expired",
        "EXECUTION_LEASE_EXPIRED": "lease_expired",
        "EXECUTION_LEASE_REVOKED": "lease_revoked",
        "EXECUTION_LEASE_UNAVAILABLE": "lease_unavailable",
    }
    if status == 403:
        failure = "identity_denied"
    elif code in failure_by_code:
        failure = failure_by_code[code]
    elif status == 404:
        failure = "approval_not_found"
    elif status == 503:
        failure = "lease_unavailable"
    else:
        failure = "rejected"
    return ExecutionLeaseConsumeError(failure, status_code=status)


def _lease_reference_from_response(
    payload: object, *, status_code: int
) -> ExecutionLeaseReference:
    if not isinstance(payload, dict) or set(payload) != _LEASE_RESPONSE_KEYS:
        raise ExecutionLeaseConsumeError("invalid_response", status_code=status_code)
    lease_id = payload.get("lease_id")
    consumption_id = payload.get("consumption_id")
    lease_token = payload.pop("lease_token", None)
    expires_at = payload.get("expires_at")
    correlation: ExecutionLeaseCorrelation | None = None
    if (
        isinstance(lease_id, str)
        and _LEASE_IDENTIFIER.fullmatch(lease_id) is not None
        and isinstance(consumption_id, str)
        and _LEASE_IDENTIFIER.fullmatch(consumption_id) is not None
    ):
        correlation = ExecutionLeaseCorrelation(
            lease_id=lease_id,
            consumption_id=consumption_id,
        )
    if (
        correlation is None
        or not isinstance(lease_token, str)
        or _LEASE_TOKEN.fullmatch(lease_token) is None
        or not isinstance(expires_at, str)
        or _RFC3339.fullmatch(expires_at) is None
    ):
        if isinstance(lease_token, str):
            del lease_token
        raise ExecutionLeaseConsumeError(
            "invalid_response",
            status_code=status_code,
            correlation=correlation,
        )
    # The bearer lease token is validated and immediately discarded.  Only the
    # non-secret IDs and expiry leave this call frame.
    del lease_token
    try:
        parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        raise ExecutionLeaseConsumeError(
            "invalid_response",
            status_code=status_code,
            correlation=correlation,
        ) from None
    if parsed_expiry.tzinfo is None or parsed_expiry <= datetime.now(timezone.utc):
        raise ExecutionLeaseConsumeError(
            "invalid_response",
            status_code=status_code,
            correlation=correlation,
        )
    return ExecutionLeaseReference(
        lease_id=correlation.lease_id,
        consumption_id=correlation.consumption_id,
        expires_at=parsed_expiry.astimezone(timezone.utc).isoformat(),
    )


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

    def consume_execution_lease(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        deadline: float,
    ) -> ExecutionLeaseReference:
        raise ExecutionLeaseConsumeError("lease_unavailable")


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

    def consume_execution_lease(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        deadline: float,
    ) -> ExecutionLeaseReference:
        raise ExecutionLeaseConsumeError("lease_unavailable")


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

    def consume_execution_lease(
        self,
        approval_id: str,
        *,
        action_id: str,
        authorization_fingerprint: str,
        deadline: float,
    ) -> ExecutionLeaseReference:
        raise ExecutionLeaseConsumeError("lease_unavailable")
