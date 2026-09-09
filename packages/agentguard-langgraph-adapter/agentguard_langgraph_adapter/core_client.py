"""HTTP client and fake Core for AgentGuard Core APIs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
import time
from threading import Lock
from typing import Any, Callable, Literal, Protocol

import httpx

from .activation_ack import ActivationAckV1, ProductActivationError
from .activation_session import ProductActivationSession
from .config import DEFAULT_API_MODE, product_configuration_digest, validate_api_mode
from .endpoint_policy import GuardApiEndpointError, validate_guard_api_base_url
from .event_models import PolicyDecision, RuleHit
from .product_manifest import ProductActivationManifest, ProductRuntimeObservation
from .product_delivery import ProductReceiptTransportResult
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
_PRODUCT_DRIFT_CODES = frozenset(
    {
        "V21_PRODUCT_ACTIVATION_NOT_CURRENT",
        "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH",
        "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH",
    }
)


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
    _product_manifest: ProductActivationManifest | None = field(
        default=None, init=False, repr=False
    )
    _product_session: ProductActivationSession | None = field(
        default=None, init=False, repr=False
    )
    _product_config_digest: str | None = field(default=None, init=False, repr=False)
    _product_failed: bool = field(default=False, init=False, repr=False)
    _product_transport: tuple[str, str, float] | None = field(
        default=None, init=False, repr=False
    )
    _product_session_lock: Any = field(default_factory=Lock, init=False, repr=False)
    _product_session_owner: object | None = field(default=None, init=False, repr=False)
    _product_session_observer: Any = field(default=None, init=False, repr=False)
    _composed_session: ProductActivationSession | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        if getattr(self.config, "product_manifest_path", None) is not None:
            self._product_config_digest = product_configuration_digest(self.config)
            manifest = ProductActivationManifest.from_file(
                self.config.product_manifest_path
            )
            if (
                self.config.agent_id != manifest.agent_id
                or self.config.runtime_binding_id != manifest.runtime_binding_id
            ):
                raise ProductActivationError("identity_mismatch")
            self._product_manifest = manifest
            self._product_transport = (
                self.config.core_base_url,
                self.config.token,
                float(self.config.timeout),
            )

    @property
    def product_enabled(self) -> bool:
        # Keep the original opt-in even if the mutable compatibility config is
        # subsequently changed to None or to defense-off.
        return (
            self._product_manifest is not None
            or getattr(self.config, "product_manifest_path", None) is not None
        )

    def _check_product(self) -> ProductActivationManifest:
        if self._product_failed or self._product_manifest is None:
            raise ProductActivationError("session_unavailable")
        try:
            if product_configuration_digest(self.config) != self._product_config_digest:
                raise ProductActivationError("configuration_drift")
            self._product_manifest.assert_unchanged()
        except Exception:
            self._product_failed = True
            if self._product_session is not None:
                self._product_session.close()
            raise ProductActivationError("configuration_drift") from None
        return self._product_manifest

    def start_product_session(
        self, *, observe: Callable[[], ProductRuntimeObservation]
    ) -> ActivationAckV1:
        manifest = self._check_product()
        with self._product_session_lock:
            if self._product_session_owner is not None:
                raise ProductActivationError("session_owner_mismatch")
            if self._product_session is None:
                self._product_session = ProductActivationSession(
                    manifest,
                    send_heartbeat=self._send_product_heartbeat,
                    observe=observe,
                    refresh_interval_seconds=self.config.product_refresh_interval_seconds,
                    max_ack_age_seconds=self.config.activation_ack_max_age_seconds,
                )
            session = self._product_session
        return session.start()

    def _start_composed_session(
        self, owner: object, *, observe: Callable[[], ProductRuntimeObservation]
    ) -> ActivationAckV1:
        manifest = self._check_product()
        with self._product_session_lock:
            if self._product_session_owner is not owner:
                if (
                    self._product_session_owner is not None
                    or self._product_session is not None
                ):
                    raise ProductActivationError("session_owner_mismatch")
                self._product_session_owner = owner
                self._product_session_observer = observe
            if self._product_session_observer is not observe:
                raise ProductActivationError("session_owner_mismatch")
            if self._product_session is None:
                self._product_session = ProductActivationSession(
                    manifest,
                    send_heartbeat=self._send_product_heartbeat,
                    observe=observe,
                    refresh_interval_seconds=self.config.product_refresh_interval_seconds,
                    max_ack_age_seconds=self.config.activation_ack_max_age_seconds,
                )
            session = self._product_session
            if self._composed_session is None:
                self._composed_session = session
            if session is not self._composed_session or session._observe is not observe:
                raise ProductActivationError("session_owner_mismatch")
        return session.start()

    def _assert_composed_session(self, owner: object, observe: Any) -> None:
        with self._product_session_lock:
            if (
                self._product_session_owner is not owner
                or self._product_session_observer is not observe
                or self._product_session is None
                or self._product_session is not self._composed_session
                or self._product_session._observe is not observe
                or self._product_session._manifest is not self._product_manifest
                or self._product_session._send_heartbeat != self._send_product_heartbeat
                or self._product_session._refresh_interval
                != self.config.product_refresh_interval_seconds
                or self._product_session._max_ack_age
                != self.config.activation_ack_max_age_seconds
            ):
                raise ProductActivationError("session_owner_mismatch")

    def _send_product_heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._check_product()
        return self._post_json("/v1/adapters/langgraph/heartbeat", payload)

    def refresh_product_ack(self) -> ActivationAckV1:
        self._check_product()
        if self._product_session is None:
            raise ProductActivationError("session_not_started")
        return self._product_session.refresh()

    def snapshot_product_ack(self) -> ActivationAckV1:
        self._check_product()
        if self._product_session is None:
            raise ProductActivationError("session_not_started")
        return self._product_session.snapshot()

    def close_product_session(self) -> None:
        self._product_failed = True
        session = (
            self._composed_session
            if self._composed_session is not None
            else self._product_session
        )
        if session is not None:
            session.close()

    def _headers(self, activation_ack: ActivationAckV1 | None = None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._product_transport[1] if self._product_transport else self.config.token}",
            "Content-Type": "application/json",
        }
        if activation_ack is not None:
            headers["X-AgentGuard-Activation-Ack"] = activation_ack.header_value()
        return headers

    def evaluate_tool_call(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.product_enabled:
            return self.evaluate_product_event(_guard_api_v03_event(event))[0]
        if _api_mode(self.config) == "guard-api-v0.3":
            return self.evaluate_guard_event(_guard_api_v03_event(event))
        return self._post_json("/v1/evaluate/tool-call", event)

    def evaluate_guard_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.product_enabled:
            return self.evaluate_product_event(event)[0]
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

    def evaluate_product_event(
        self, event: dict[str, Any]
    ) -> tuple[dict[str, Any], ActivationAckV1]:
        """Return an official decision and the immutable ACK actually sent."""

        manifest = self._check_product()
        event = _guard_api_v03_event(event)
        context = event.get("security_context")
        if (
            event.get("runtime") != manifest.runtime
            or not isinstance(context, dict)
            or context.get("agent_id") != manifest.agent_id
        ):
            raise ProductActivationError("event_identity_mismatch")
        ack = self.snapshot_product_ack()
        response = self._post_json("/v1/guard/evaluate", event, activation_ack=ack)
        try:
            raw = response.get("decision")
            if (
                not isinstance(raw, dict)
                or not isinstance(raw.get("decision_id"), str)
                or not raw["decision_id"].strip()
            ):
                raise ValueError
            # Authority is a server-owned sibling. Do not accept a nested or
            # absent projection left over from compatibility response shapes.
            if not all(
                name in response
                for name in (
                    "decision_authority",
                    "approval_release_directive",
                    "policy_audit_id",
                )
            ):
                raise ValueError
            for name in (
                "approval",
                "policy_audit_id",
                "decision_authority",
                "approval_release_directive",
                "enforcement_binding",
                "context_plan",
            ):
                if name in raw and raw[name] != response.get(name):
                    raise ValueError
            enriched = _decision_with_top_level_approval(raw, response)
            decision = PolicyDecision.model_validate(enriched)
            authority = decision.decision_authority
            directive = decision.approval_release_directive
            if (
                authority is None
                or directive is None
                or authority.source != "v21"
                or authority.mode != "active"
                or authority.selection_basis != "profile_all"
                or authority.matched_path_ids
                # The retained safety floor can strengthen an official V2.1
                # decision to ASK/DENY. It never supplies an execution grant;
                # ASK still needs the exact strong approval/lease boundary.
                or (
                    authority.legacy_floor_applied
                    and decision.decision not in {"ask", "deny"}
                )
                or authority.activation_ref_digest != ack.activation_ref_digest
                or directive.activation_ref_digest != ack.activation_ref_digest
                or directive.capability_digest != ack.capability_digest
                or directive.mode == "restricted_allow_once"
                or not decision.policy_audit_id
                or (
                    decision.decision == "ask"
                    and directive.mode == "strong_binding"
                    and decision.enforcement_binding is None
                )
            ):
                raise ValueError
        except Exception:
            self.close_product_session()
            raise ProductActivationError("official_response_mismatch") from None
        return enriched, ack

    def submit_audit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        # Historical outcomes remain deliverable after session close/expiry.
        # Keep the original endpoint/credential; never refresh their carrier.
        if self.product_enabled or _api_mode(self.config) == "guard-api-v0.3":
            return self._post_json("/v1/audit/events", event)
        return self._post_json("/v1/audit/event", event)

    def submit_product_receipt_wire(
        self, payload: bytes
    ) -> ProductReceiptTransportResult:
        """Send one immutable durable envelope payload using its original transport.

        No session refresh, current ACK header, hidden retries, or response body
        escapes this boundary. The outbox owns retry scheduling and persistence.
        """
        transport = self._product_transport
        if transport is None or type(payload) is not bytes or len(payload) > 512 * 1024:
            return ProductReceiptTransportResult(
                "failed", error_code="product_transport_unavailable"
            )
        try:
            data = json.loads(payload)
            audit_id = data.get("audit_id") if isinstance(data, dict) else None
            if (
                not isinstance(audit_id, str)
                or not audit_id
                or data.get("runtime") != "langgraph"
                or data.get("record_type")
                not in {"runtime_outcome", "runtime_observation"}
            ):
                raise ValueError
        except (ValueError, TypeError):
            return ProductReceiptTransportResult(
                "failed", error_code="receipt_payload_invalid"
            )
        base_url, token, timeout = transport
        status: int | None = None
        try:
            deadline = time.monotonic() + timeout
            with httpx.Client(
                timeout=timeout, follow_redirects=False, trust_env=False
            ) as client:
                with client.stream(
                    "POST",
                    base_url + "/v1/audit/events",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    content=payload,
                ) as response:
                    status = response.status_code
                    if status in {408, 429} or status >= 500:
                        return ProductReceiptTransportResult(
                            "retryable", audit_id, status, "http_retryable"
                        )
                    if status >= 300:
                        return ProductReceiptTransportResult(
                            "permanent_rejected",
                            audit_id,
                            status,
                            "http_permanent_rejection",
                        )
                    if status < 200:
                        return ProductReceiptTransportResult(
                            "failed", audit_id, status, "receipt_response_invalid"
                        )
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if len(body) + len(chunk) > 1024 * 1024:
                            return ProductReceiptTransportResult(
                                "failed", audit_id, status, "receipt_response_too_large"
                            )
                        if time.monotonic() >= deadline:
                            return ProductReceiptTransportResult(
                                "retryable",
                                audit_id,
                                status,
                                "receipt_response_timeout",
                            )
                        body.extend(chunk)
            acknowledged = json.loads(body)
            if (
                not isinstance(acknowledged, dict)
                or acknowledged.get("ok") is not True
                or acknowledged.get("audit_id") != audit_id
                or "skipped" in acknowledged
            ):
                return ProductReceiptTransportResult(
                    "failed", audit_id, status, "receipt_acknowledgement_invalid"
                )
            return ProductReceiptTransportResult("recorded", audit_id, status)
        except httpx.RequestError:
            return ProductReceiptTransportResult(
                "retryable", audit_id, status, "receipt_network_unavailable"
            )
        except (ValueError, TypeError):
            return ProductReceiptTransportResult(
                "failed", audit_id, status, "receipt_response_invalid"
            )
        except Exception:
            return ProductReceiptTransportResult(
                "failed", audit_id, status, "receipt_transport_failed"
            )

    def wait_for_approval(
        self, approval_id: str, timeout: float | None = None
    ) -> dict[str, Any]:
        if self.product_enabled:
            self._check_product()
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
        activation_ack: ActivationAckV1 | None = None,
    ) -> ExecutionLeaseReference:
        """Consume an exact execution lease with bounded, same-body retries."""

        if self.product_enabled:
            manifest = self._check_product()
            if activation_ack is None:
                raise ProductActivationError("consume_ack_required")
            ActivationAckV1.read(
                activation_ack.to_wire(),
                expected=manifest,
                now=datetime.now(timezone.utc),
                max_age_seconds=self.config.activation_ack_max_age_seconds,
            )
            deadline = min(
                deadline,
                time.monotonic()
                + activation_ack.remaining_seconds(
                    now=datetime.now(timezone.utc),
                    max_age_seconds=self.config.activation_ack_max_age_seconds,
                ),
            )
        elif activation_ack is not None:
            raise ProductActivationError("unexpected_activation_ack")

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
        # ACK and request bytes are fixed for this consume, including retries.
        headers = self._headers(activation_ack)

        for attempt in range(_MAX_LEASE_CONSUME_ATTEMPTS):
            if self.product_enabled:
                self._check_product()
                assert activation_ack is not None
                if (
                    activation_ack.remaining_seconds(
                        now=datetime.now(timezone.utc),
                        max_age_seconds=self.config.activation_ack_max_age_seconds,
                    )
                    <= 0
                ):
                    raise ExecutionLeaseConsumeError("timed_out")
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
                        headers=headers,
                        content=body,
                    )
            except httpx.RequestError:
                if attempt + 1 >= _MAX_LEASE_CONSUME_ATTEMPTS:
                    raise ExecutionLeaseConsumeError("lease_unavailable") from None
                _lease_retry_pause(attempt=attempt, deadline=deadline)
                continue

            status = response.status_code
            self._reject_product_drift(response, close_session=True)
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

    def _reject_product_drift(
        self, response: httpx.Response, *, close_session: bool
    ) -> None:
        if not self.product_enabled or response.status_code < 400:
            return
        try:
            rejected = response.json()
            error = rejected.get("error") if isinstance(rejected, dict) else None
            code = error.get("code") if isinstance(error, dict) else None
        except ValueError:
            code = None
        if isinstance(code, str) and code in _PRODUCT_DRIFT_CODES:
            if close_session:
                self.close_product_session()
            raise ProductActivationError(code)

    def _post_json(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        activation_ack: ActivationAckV1 | None = None,
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            path,
            payload=payload,
            timeout=(
                self._product_transport[2]
                if self._product_transport
                else self.config.timeout
            ),
            activation_ack=activation_ack,
        )

    def _request_json(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        timeout: float,
        activation_ack: ActivationAckV1 | None = None,
    ) -> dict[str, Any]:
        try:
            base_url = validate_guard_api_base_url(
                self._product_transport[0]
                if self._product_transport
                else self.config.core_base_url
            )
        except GuardApiEndpointError as exc:
            raise CoreClientError(str(exc)) from exc
        url = base_url + path
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                if method == "GET":
                    response = client.get(url, headers=self._headers())
                else:
                    response = client.post(
                        url, headers=self._headers(activation_ack), json=payload
                    )
            if response.is_redirect:
                raise CoreClientError("Guard API redirects are not allowed")
            if path != "/v1/audit/events":
                # Preserve only fixed authority-drift codes. Never echo an
                # arbitrary server error or retain its response body as cause.
                self._reject_product_drift(
                    response, close_session=path != "/v1/adapters/langgraph/heartbeat"
                )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            raise CoreClientError(
                f"Core returned HTTP {exc.response.status_code} for {path}"
            ) from None
        except httpx.RequestError as exc:
            raise CoreClientError(
                f"Core request failed for {path} ({type(exc).__name__})"
            ) from None
        except ValueError:
            raise CoreClientError(f"Core returned invalid JSON for {path}") from None
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
    # ContextAssemblyPlan is returned beside the official decision.  Preserve
    # it only on the transient PolicyDecision field; model_dump/audit/receipts
    # exclude it by construction.
    if "context_plan" in response:
        enriched["context_plan"] = response.get("context_plan")
    if "decision_authority" in response:
        enriched["decision_authority"] = response.get("decision_authority")
    if "approval_release_directive" in response:
        enriched["approval_release_directive"] = response.get(
            "approval_release_directive"
        )
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
