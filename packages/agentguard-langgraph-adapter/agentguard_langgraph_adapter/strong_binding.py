"""RTE-05 strong approval binding helpers.

The authorization fingerprint and lease token are deliberately confined to this
module's short-lived call frames.  Public results, receipts, logs, and exception
messages only carry non-secret correlation IDs and bounded reason codes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
import time
from typing import Any, Callable, Literal, TypeGuard

_AUTHORIZATION_FINGERPRINT = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_RUNTIME_SECRET_MATERIAL = re.compile(r"^(?:hmac-sha256|lease-v1):[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "action_id",
        "authorization_fingerprint",
        "runtime_binding_id",
        "requires_execution_lease",
    }
)

GateState = Literal[
    "evaluating",
    "allowed",
    "approval_pending",
    "approval_released",
    "blocked",
    "timed_out",
    "binding_failed",
    "unknown",
]
BindingCheckStatus = Literal[
    "not_applicable", "not_performed", "passed", "failed", "unknown"
]
LeaseConsumeOutcome = Literal[
    "not_applicable",
    "not_attempted",
    "consumed",
    "expired",
    "revoked",
    "rejected",
    "unknown",
]

RTE05_REASON_CODES = frozenset(
    {
        "rte-05:binding_exact",
        "rte-05:binding_invalid",
        "rte-05:binding_mismatch",
        "rte-05:approval_not_human",
        "rte-05:approval_not_consumable",
        "rte-05:approval_not_found",
        "rte-05:approval_expired",
        "rte-05:identity_denied",
        "rte-05:approval_timed_out",
        "rte-05:lease_consumed",
        "rte-05:consumption_conflict",
        "rte-05:lease_rejected",
        "rte-05:lease_expired",
        "rte-05:lease_revoked",
        "rte-05:lease_unavailable",
        "rte-05:lease_response_invalid",
        "rte-05:lease_consume_timed_out",
        "rte-05:multiple_binding_conflict",
        "rte-05:correlation_capacity_exhausted",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class EnforcementBindingSnapshot:
    """Immutable, transient copy of the authoritative evaluate binding."""

    schema_version: str
    action_id: str
    authorization_fingerprint: str
    runtime_binding_id: str
    requires_execution_lease: bool

    def __repr__(self) -> str:
        return "EnforcementBindingSnapshot(<redacted>)"


@dataclass(frozen=True, slots=True)
class ExecutionLeaseReference:
    """Non-secret lease data safe to retain in runtime state and receipts."""

    lease_id: str
    consumption_id: str
    expires_at: str


@dataclass(frozen=True, slots=True)
class ExecutionLeaseCorrelation:
    """Non-secret IDs retained when a 2xx consume cannot authorize invoke."""

    lease_id: str
    consumption_id: str


@dataclass(frozen=True, slots=True)
class EnforcementEvidence:
    gate_state: GateState
    binding_check_status: BindingCheckStatus
    lease_consume_outcome: LeaseConsumeOutcome
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.reason_codes) <= 4:
            raise ValueError("RTE-05 enforcement evidence requires 1-4 reason codes")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("RTE-05 enforcement reason codes must be unique")
        if any(code not in RTE05_REASON_CODES for code in self.reason_codes):
            raise ValueError(
                "RTE-05 enforcement evidence contains an unknown reason code"
            )

    def as_dict(self) -> dict[str, object]:
        return {
            "gate_state": self.gate_state,
            "binding_check_status": self.binding_check_status,
            "lease_consume_outcome": self.lease_consume_outcome,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class StrongBindingRelease:
    approval_resolution: dict[str, Any]
    approval_wait_latency_ms: int
    lease: ExecutionLeaseReference
    enforcement: EnforcementEvidence
    deadline: float


class ExecutionLeaseConsumeError(RuntimeError):
    """Stable consume failure that never retains a response body or secret."""

    def __init__(
        self,
        failure: str,
        *,
        status_code: int | None = None,
        correlation: ExecutionLeaseCorrelation | None = None,
    ) -> None:
        super().__init__(f"Execution lease consume failed: {failure}")
        self.failure = failure
        self.status_code = status_code
        self.correlation = correlation


class StrongBindingFailure(RuntimeError):
    """Fail-closed outcome suitable for bounded public runtime evidence."""

    def __init__(
        self,
        evidence: EnforcementEvidence,
        *,
        approval_resolution: dict[str, Any] | None = None,
        approval_wait_latency_ms: int | None = None,
        correlation: ExecutionLeaseCorrelation | None = None,
    ) -> None:
        super().__init__("Strong approval binding failed closed")
        self.evidence = evidence
        self.approval_resolution = approval_resolution
        self.approval_wait_latency_ms = approval_wait_latency_ms
        # Only non-secret correlation data is retained.  A post-consume failure
        # must keep this pair so its not-invoked receipt cannot hide that the
        # single-use authority was already spent.
        self.correlation = correlation


class ApprovalResolutionValidationError(ValueError):
    """An approval timestamp was not a strict timezone-aware RFC3339 value."""


def raw_enforcement_binding(decision: Any) -> object | None:
    return getattr(decision, "enforcement_binding", None)


def capture_enforcement_binding(
    decision: Any,
    *,
    expected_action_id: str,
    expected_runtime_binding_id: str | None,
) -> EnforcementBindingSnapshot | None:
    """Capture an exact binding without deriving or serializing its fingerprint."""

    raw = raw_enforcement_binding(decision)
    if raw is None:
        return None
    return _parse_binding(
        raw,
        expected_action_id=expected_action_id,
        expected_runtime_binding_id=expected_runtime_binding_id,
    )


def authorize_strong_approval(
    guard_adapter: Any,
    decision: Any,
    *,
    expected_action_id: str,
    expected_runtime_binding_id: str | None,
    approval_id: str | None,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.25,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> StrongBindingRelease | None:
    """Wait, re-check, and consume an exact human ``allow_once`` binding.

    ``None`` means no binding was present and the caller must preserve the C1
    behavior.  Any declared-but-invalid or non-consumable binding raises a
    bounded failure and must never fall back to C1.
    """

    monotonic = monotonic or time.monotonic
    sleep = sleep or time.sleep
    try:
        snapshot = capture_enforcement_binding(
            decision,
            expected_action_id=expected_action_id,
            expected_runtime_binding_id=expected_runtime_binding_id,
        )
    except StrongBindingFailure:
        raise
    if snapshot is None:
        return None
    if (
        getattr(decision, "decision", None) != "ask"
        or not _valid_identifier(approval_id)
        or not _valid_identifier(getattr(decision, "policy_audit_id", None))
    ):
        raise _failure(
            "binding_failed",
            "failed",
            "not_attempted",
            "rte-05:binding_invalid",
        )
    if timeout_seconds <= 0:
        raise _failure(
            "timed_out",
            "passed",
            "not_attempted",
            "rte-05:binding_exact",
            "rte-05:approval_timed_out",
        )

    started = monotonic()
    deadline = started + timeout_seconds
    resolution = _wait_for_resolution(
        guard_adapter,
        approval_id=approval_id,
        deadline=deadline,
        poll_interval_seconds=poll_interval_seconds,
        monotonic=monotonic,
        sleep=sleep,
    )
    latency_ms = max(0, int((monotonic() - started) * 1000))
    try:
        safe_resolution = _bounded_resolution(resolution)
    except ApprovalResolutionValidationError:
        raise _failure(
            "binding_failed",
            "passed",
            "rejected",
            "rte-05:binding_exact",
            "rte-05:approval_not_consumable",
            approval_resolution=_bounded_resolution_without_timestamp(resolution),
            approval_wait_latency_ms=latency_ms,
        ) from None
    status = str(resolution.get("status") or "").strip().lower()
    approval_decision = str(resolution.get("decision") or "").strip().lower()
    resolution_source = str(resolution.get("resolution_source") or "").strip().lower()
    if status == "timeout" or approval_decision == "timeout":
        raise _failure(
            "timed_out",
            "passed",
            "not_attempted",
            "rte-05:binding_exact",
            "rte-05:approval_timed_out",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )
    if status == "infrastructure_unavailable":
        raise _failure(
            "binding_failed",
            "passed",
            "unknown",
            "rte-05:binding_exact",
            "rte-05:lease_unavailable",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )
    if status == "expired":
        raise _failure(
            "binding_failed",
            "passed",
            "expired",
            "rte-05:binding_exact",
            "rte-05:approval_expired",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )
    if status != "resolved" or approval_decision != "allow_once":
        raise _failure(
            "binding_failed",
            "passed",
            "rejected",
            "rte-05:binding_exact",
            "rte-05:approval_not_consumable",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )
    if resolution_source != "human":
        raise _failure(
            "binding_failed",
            "passed",
            "rejected",
            "rte-05:binding_exact",
            "rte-05:approval_not_human",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )
    if resolution.get("enforcement_binding") is not None:
        raise _failure(
            "binding_failed",
            "failed",
            "not_attempted",
            "rte-05:multiple_binding_conflict",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )

    try:
        current = capture_enforcement_binding(
            decision,
            expected_action_id=expected_action_id,
            expected_runtime_binding_id=expected_runtime_binding_id,
        )
    except StrongBindingFailure as exc:
        raise StrongBindingFailure(
            exc.evidence,
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
            correlation=exc.correlation,
        ) from None
    if current is None or current != snapshot:
        raise _failure(
            "binding_failed",
            "failed",
            "not_attempted",
            "rte-05:binding_mismatch",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )

    consume = getattr(guard_adapter, "consume_execution_lease", None)
    if not callable(consume):
        raise _failure(
            "binding_failed",
            "passed",
            "unknown",
            "rte-05:binding_exact",
            "rte-05:lease_unavailable",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )
    try:
        lease = consume(
            approval_id,
            action_id=snapshot.action_id,
            authorization_fingerprint=snapshot.authorization_fingerprint,
            deadline=deadline,
        )
    except ExecutionLeaseConsumeError as exc:
        raise _consume_failure(
            exc,
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        ) from None
    except Exception:
        raise _failure(
            "binding_failed",
            "passed",
            "unknown",
            "rte-05:binding_exact",
            "rte-05:lease_unavailable",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        ) from None
    if not isinstance(lease, ExecutionLeaseReference):
        raise _failure(
            "binding_failed",
            "passed",
            "rejected",
            "rte-05:binding_exact",
            "rte-05:lease_response_invalid",
            approval_resolution=safe_resolution,
            approval_wait_latency_ms=latency_ms,
        )
    release = StrongBindingRelease(
        approval_resolution=safe_resolution,
        approval_wait_latency_ms=latency_ms,
        lease=lease,
        enforcement=EnforcementEvidence(
            gate_state="approval_released",
            binding_check_status="passed",
            lease_consume_outcome="consumed",
            reason_codes=("rte-05:binding_exact", "rte-05:lease_consumed"),
        ),
        deadline=deadline,
    )
    validate_strong_release_for_invocation(release, monotonic=monotonic)
    return release


def normalize_approval_resolution(resolution: dict[str, Any]) -> dict[str, Any]:
    """Copy a resolution while strictly validating its optional timestamp."""

    normalized = dict(resolution)
    resolved_at = normalized.get("resolved_at")
    if resolved_at is None:
        normalized.pop("resolved_at", None)
        return normalized
    normalized["resolved_at"] = _normalize_rfc3339_timestamp(resolved_at)
    return normalized


def validate_strong_release_for_invocation(
    release: StrongBindingRelease,
    *,
    monotonic: Callable[[], float] | None = None,
    now: Callable[[], datetime] | None = None,
) -> None:
    """Fail closed unless a consumed release is live at the start boundary.

    Callers perform their final check immediately before persisting the start
    observation.  A successful start observation commits the runtime to invoke;
    lease validity at that point authorizes the resulting in-flight action.
    """

    monotonic = monotonic or time.monotonic
    now = now or _utc_now
    if monotonic() >= release.deadline:
        raise _failure(
            "timed_out",
            "passed",
            "consumed",
            "rte-05:binding_exact",
            "rte-05:lease_consume_timed_out",
            approval_resolution=release.approval_resolution,
            approval_wait_latency_ms=release.approval_wait_latency_ms,
            correlation=_lease_correlation(release.lease),
        )
    try:
        expires_at = _parse_rfc3339_timestamp(release.lease.expires_at)
    except ApprovalResolutionValidationError:
        raise _failure(
            "binding_failed",
            "passed",
            "consumed",
            "rte-05:binding_exact",
            "rte-05:lease_response_invalid",
            approval_resolution=release.approval_resolution,
            approval_wait_latency_ms=release.approval_wait_latency_ms,
            correlation=_lease_correlation(release.lease),
        ) from None
    current = now()
    if current.tzinfo is None:
        raise _failure(
            "binding_failed",
            "passed",
            "consumed",
            "rte-05:binding_exact",
            "rte-05:lease_response_invalid",
            approval_resolution=release.approval_resolution,
            approval_wait_latency_ms=release.approval_wait_latency_ms,
            correlation=_lease_correlation(release.lease),
        )
    if expires_at <= current.astimezone(timezone.utc):
        raise _failure(
            "binding_failed",
            "passed",
            "consumed",
            "rte-05:binding_exact",
            "rte-05:lease_expired",
            approval_resolution=release.approval_resolution,
            approval_wait_latency_ms=release.approval_wait_latency_ms,
            correlation=_lease_correlation(release.lease),
        )


def _parse_binding(
    raw: object,
    *,
    expected_action_id: str,
    expected_runtime_binding_id: str | None,
) -> EnforcementBindingSnapshot:
    if not isinstance(raw, dict) or set(raw) != _BINDING_KEYS:
        raise _failure(
            "binding_failed",
            "failed",
            "not_attempted",
            "rte-05:binding_invalid",
        )
    schema_version = raw.get("schema_version")
    action_id = raw.get("action_id")
    fingerprint = raw.get("authorization_fingerprint")
    runtime_binding_id = raw.get("runtime_binding_id")
    requires_lease = raw.get("requires_execution_lease")
    if (
        schema_version != "2.1"
        or not _valid_identifier(action_id)
        or not isinstance(fingerprint, str)
        or _AUTHORIZATION_FINGERPRINT.fullmatch(fingerprint) is None
        or not _valid_identifier(runtime_binding_id)
        or requires_lease is not True
    ):
        raise _failure(
            "binding_failed",
            "failed",
            "not_attempted",
            "rte-05:binding_invalid",
        )
    if action_id != expected_action_id:
        raise _failure(
            "binding_failed",
            "failed",
            "not_attempted",
            "rte-05:binding_mismatch",
        )
    # The expected binding is trusted runtime configuration provisioned beside
    # the credential.  Never accept a runtime-binding claim from event payloads.
    if (
        not _valid_identifier(expected_runtime_binding_id)
        or runtime_binding_id != expected_runtime_binding_id
    ):
        raise _failure(
            "binding_failed",
            "failed",
            "not_attempted",
            "rte-05:binding_mismatch",
        )
    return EnforcementBindingSnapshot(
        schema_version=schema_version,
        action_id=action_id,
        authorization_fingerprint=fingerprint,
        runtime_binding_id=runtime_binding_id,
        requires_execution_lease=True,
    )


def _valid_identifier(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _wait_for_resolution(
    guard_adapter: Any,
    *,
    approval_id: str,
    deadline: float,
    poll_interval_seconds: float,
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
) -> dict[str, Any]:
    wait = getattr(guard_adapter, "wait_for_approval", None)
    if not callable(wait):
        return {"status": "infrastructure_unavailable", "decision": None}
    transient_failures = 0
    while True:
        remaining = max(deadline - monotonic(), 0.0)
        if remaining <= 0:
            return {"status": "timeout", "decision": "timeout"}
        try:
            try:
                raw = wait(approval_id, timeout=remaining)
            except TypeError:
                raw = wait(approval_id)
        except Exception:
            raw = {"status": "error", "decision": "deny"}
        if not isinstance(raw, dict):
            raw = {"status": "error", "decision": "deny"}
        status = str(raw.get("status") or "").strip().lower()
        if status == "error":
            transient_failures += 1
            if transient_failures >= 5:
                return {
                    "status": "infrastructure_unavailable",
                    "decision": None,
                }
            remaining = max(deadline - monotonic(), 0.0)
            if remaining <= 0:
                return {"status": "timeout", "decision": "timeout"}
            sleep(min(max(poll_interval_seconds, 0.001), remaining))
            continue
        if status != "pending":
            return dict(raw)
        remaining = max(deadline - monotonic(), 0.0)
        if remaining <= 0:
            return {"status": "timeout", "decision": "timeout"}
        sleep(min(max(poll_interval_seconds, 0.001), remaining))


def _bounded_resolution(resolution: dict[str, Any]) -> dict[str, Any]:
    """Keep only non-secret approval lifecycle facts required downstream."""

    resolution = normalize_approval_resolution(resolution)
    result: dict[str, Any] = {}
    for key in ("status", "decision", "resolution_source", "resolved_at"):
        value = resolution.get(key)
        if value is None:
            continue
        text = str(value)
        result[key] = text[:160]
    return result


def _bounded_resolution_without_timestamp(
    resolution: dict[str, Any],
) -> dict[str, Any]:
    """Retain safe lifecycle facts after rejecting an untrusted timestamp."""

    result: dict[str, Any] = {}
    for key in ("status", "decision", "resolution_source"):
        value = resolution.get(key)
        if not isinstance(value, str) or _RUNTIME_SECRET_MATERIAL.fullmatch(value):
            continue
        result[key] = value[:160]
    return result


def _normalize_rfc3339_timestamp(value: object) -> str:
    return _parse_rfc3339_timestamp(value).astimezone(timezone.utc).isoformat()


def _parse_rfc3339_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise ApprovalResolutionValidationError(
            "approval resolved_at must be a timezone-aware RFC3339 timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ApprovalResolutionValidationError(
            "approval resolved_at must be a timezone-aware RFC3339 timestamp"
        ) from None
    if parsed.tzinfo is None:
        raise ApprovalResolutionValidationError(
            "approval resolved_at must be a timezone-aware RFC3339 timestamp"
        )
    return parsed


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _consume_failure(
    error: ExecutionLeaseConsumeError,
    *,
    approval_resolution: dict[str, Any],
    approval_wait_latency_ms: int,
) -> StrongBindingFailure:
    mapping: dict[str, tuple[GateState, LeaseConsumeOutcome, str]] = {
        "identity_denied": (
            "binding_failed",
            "rejected",
            "rte-05:identity_denied",
        ),
        "approval_not_found": (
            "binding_failed",
            "rejected",
            "rte-05:approval_not_found",
        ),
        "approval_not_consumable": (
            "binding_failed",
            "rejected",
            "rte-05:approval_not_consumable",
        ),
        "consumption_conflict": (
            "binding_failed",
            "rejected",
            "rte-05:consumption_conflict",
        ),
        "approval_expired": (
            "binding_failed",
            "expired",
            "rte-05:approval_expired",
        ),
        "lease_expired": (
            "binding_failed",
            "expired",
            "rte-05:lease_expired",
        ),
        "lease_revoked": (
            "binding_failed",
            "revoked",
            "rte-05:lease_revoked",
        ),
        "lease_unavailable": (
            "binding_failed",
            "unknown",
            "rte-05:lease_unavailable",
        ),
        "timed_out": (
            "timed_out",
            "unknown",
            "rte-05:lease_consume_timed_out",
        ),
        "invalid_response": (
            "binding_failed",
            "rejected",
            "rte-05:lease_response_invalid",
        ),
        "rejected": ("binding_failed", "rejected", "rte-05:lease_rejected"),
    }
    gate, lease_outcome, reason = mapping.get(
        error.failure,
        ("binding_failed", "rejected", "rte-05:lease_rejected"),
    )
    if error.correlation is not None and error.failure in {
        "timed_out",
        "invalid_response",
    }:
        # A parsed 2xx may cross the local deadline or fail strict response
        # validation after the server has already spent the one-use grant.  It
        # cannot authorize invocation, but its safe IDs must remain correlated.
        lease_outcome = "consumed"
    return _failure(
        gate,
        "passed",
        lease_outcome,
        "rte-05:binding_exact",
        reason,
        approval_resolution=approval_resolution,
        approval_wait_latency_ms=approval_wait_latency_ms,
        correlation=error.correlation,
    )


def _failure(
    gate_state: GateState,
    binding_check_status: BindingCheckStatus,
    lease_consume_outcome: LeaseConsumeOutcome,
    *reason_codes: str,
    approval_resolution: dict[str, Any] | None = None,
    approval_wait_latency_ms: int | None = None,
    correlation: ExecutionLeaseCorrelation | None = None,
) -> StrongBindingFailure:
    return StrongBindingFailure(
        EnforcementEvidence(
            gate_state=gate_state,
            binding_check_status=binding_check_status,
            lease_consume_outcome=lease_consume_outcome,
            reason_codes=tuple(reason_codes),
        ),
        approval_resolution=approval_resolution,
        approval_wait_latency_ms=approval_wait_latency_ms,
        correlation=correlation,
    )


def _lease_correlation(
    lease: ExecutionLeaseReference,
) -> ExecutionLeaseCorrelation:
    return ExecutionLeaseCorrelation(
        lease_id=lease.lease_id,
        consumption_id=lease.consumption_id,
    )
