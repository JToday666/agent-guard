"""Policy snapshot validation and optimistic-concurrency service."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address

from agentguard_core import (
    SUPPORTED_POLICY_RULE_IDS,
    PolicyBundle,
    utc_now_iso,
)

from guard_api.storage.base import (
    ControlPlaneStore,
    PolicyRevisionConflictError,
    PolicySnapshotRecord,
)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class PolicyValidationIssue:
    code: str
    field: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "field": self.field,
            "message": self.message,
        }


class PolicyValidationError(ValueError):
    def __init__(self, issues: list[PolicyValidationIssue]) -> None:
        self.issues = issues
        super().__init__("policy bundle failed semantic validation")


class PolicyService:
    def __init__(
        self,
        *,
        store: ControlPlaneStore | None = None,
        policy_bundle: PolicyBundle | None = None,
        policy_provider: Callable[[], PolicyBundle] | None = None,
    ) -> None:
        if policy_bundle is not None and policy_provider is not None:
            raise ValueError(
                "PolicyService accepts either policy_bundle or policy_provider, not both"
            )
        self.store = store
        self.policy_bundle = policy_bundle or PolicyBundle()
        self.policy_provider = policy_provider
        self._local_record: PolicySnapshotRecord | None = None

    def current_snapshot(self) -> PolicyBundle:
        return self.current_state()[0]

    def current_state(self) -> tuple[PolicyBundle, int]:
        record = self.current_snapshot_record()
        if record is not None:
            return record.policy_bundle, record.revision
        if self.policy_provider is not None:
            return self.policy_provider(), 0
        return self.policy_bundle, 0

    def current_revision(self) -> int:
        return self.current_state()[1]

    def save_snapshot(
        self,
        policy_bundle: PolicyBundle,
        *,
        expected_revision: int,
        updated_by: str = "system",
    ) -> PolicySnapshotRecord:
        issues = validate_policy_bundle(policy_bundle)
        if issues:
            raise PolicyValidationError(issues)
        if self.store is not None:
            return self.store.save_policy_snapshot(
                policy_bundle,
                expected_revision=expected_revision,
                updated_by=updated_by,
            )
        current_revision = self.current_revision()
        if expected_revision != current_revision:
            raise PolicyRevisionConflictError(
                expected_revision=expected_revision,
                current_revision=current_revision,
            )
        record = PolicySnapshotRecord(
            revision=current_revision + 1,
            policy_bundle=policy_bundle,
            updated_at=utc_now_iso(),
            updated_by=updated_by,
        )
        self._local_record = record
        self.policy_bundle = policy_bundle
        return record

    def current_snapshot_record(self) -> PolicySnapshotRecord | None:
        if self.store is not None:
            return self.store.get_policy_snapshot_record()
        return self._local_record

    def list_history(self, *, limit: int = 100) -> list[PolicySnapshotRecord]:
        if self.store is not None:
            return self.store.list_policy_snapshot_history(limit=limit)
        return [self._local_record] if self._local_record is not None else []


def validate_policy_bundle(policy: PolicyBundle) -> list[PolicyValidationIssue]:
    issues: list[PolicyValidationIssue] = []
    if not policy.bundle_id.strip():
        issues.append(_issue("VALUE_EMPTY", "bundle_id", "bundle_id cannot be blank"))
    if not policy.version.strip():
        issues.append(_issue("VALUE_EMPTY", "version", "version cannot be blank"))

    _validate_string_lists(policy, issues)

    configured_rule_ids = set(policy.disabled_rules) | set(policy.rule_overrides)
    for rule_id in sorted(configured_rule_ids - SUPPORTED_POLICY_RULE_IDS):
        issues.append(
            _issue(
                "RULE_UNKNOWN",
                (
                    "disabled_rules"
                    if rule_id in policy.disabled_rules
                    else "rule_overrides"
                ),
                f"unsupported policy rule: {rule_id}",
            )
        )
    for rule_id in sorted(set(policy.disabled_rules) & set(policy.rule_overrides)):
        issues.append(
            _issue(
                "RULE_CONFIGURATION_CONFLICT",
                f"rule_overrides.{rule_id}",
                "a disabled rule cannot also define an override",
            )
        )

    for index, domain in enumerate(policy.allowed_email_domains):
        if not _is_domain(domain):
            issues.append(
                _issue(
                    "DOMAIN_INVALID",
                    f"allowed_email_domains.{index}",
                    "allowed email domains must be host names without scheme, port, path, or @",
                )
            )
    for index, host in enumerate(policy.allowed_api_hosts):
        if not _is_host(host):
            issues.append(
                _issue(
                    "HOST_INVALID",
                    f"allowed_api_hosts.{index}",
                    "allowed API hosts must not include scheme, port, path, or credentials",
                )
            )
    for index, path in enumerate(policy.allowed_api_paths):
        if not path.startswith("/") or path.startswith("//") or "\\" in path:
            issues.append(
                _issue(
                    "PATH_INVALID",
                    f"allowed_api_paths.{index}",
                    "allowed API paths must be absolute origin paths",
                )
            )

    for name, profile in policy.tool_profiles.items():
        field = f"tool_profiles.{name}"
        if not name.strip():
            issues.append(
                _issue("VALUE_EMPTY", field, "tool profile name cannot be blank")
            )
        if not profile.categories and not profile.kinds:
            issues.append(
                _issue(
                    "TOOL_PROFILE_IDENTITY_EMPTY",
                    field,
                    "tool profile must define at least one category or kind",
                )
            )
        if not profile.operations and not profile.directions:
            issues.append(
                _issue(
                    "TOOL_PROFILE_BEHAVIOR_EMPTY",
                    field,
                    "tool profile must define at least one operation or direction",
                )
            )
        for attribute in ("categories", "kinds", "operations", "directions"):
            _validate_string_list(
                getattr(profile, attribute),
                field=f"{field}.{attribute}",
                issues=issues,
            )

    for tool_name, aliases in policy.tool_action_aliases.items():
        field = f"tool_action_aliases.{tool_name}"
        if not tool_name.strip():
            issues.append(
                _issue("VALUE_EMPTY", field, "tool alias key cannot be blank")
            )
        _validate_string_list(aliases, field=field, issues=issues)

    return issues


def _validate_string_lists(
    policy: PolicyBundle, issues: list[PolicyValidationIssue]
) -> None:
    for field_name, value in policy.model_dump(mode="python").items():
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            _validate_string_list(value, field=field_name, issues=issues)


def _validate_string_list(
    values: list[str],
    *,
    field: str,
    issues: list[PolicyValidationIssue],
) -> None:
    seen: set[str] = set()
    for index, value in enumerate(values):
        normalized = value.strip().casefold()
        if not normalized:
            issues.append(
                _issue("VALUE_EMPTY", f"{field}.{index}", "list values cannot be blank")
            )
            continue
        if normalized in seen:
            issues.append(
                _issue(
                    "VALUE_DUPLICATE",
                    f"{field}.{index}",
                    "list values must be unique after trimming and case folding",
                )
            )
        seen.add(normalized)


def _is_domain(value: str) -> bool:
    normalized = value.strip().rstrip(".")
    return (
        bool(normalized)
        and "://" not in normalized
        and "/" not in normalized
        and "@" not in normalized
        and ":" not in normalized
        and _DOMAIN_RE.fullmatch(normalized) is not None
    )


def _is_host(value: str) -> bool:
    normalized = value.strip().rstrip(".")
    if not normalized or "://" in normalized or "/" in normalized or "@" in normalized:
        return False
    try:
        ip_address(normalized)
        return True
    except ValueError:
        return ":" not in normalized and _DOMAIN_RE.fullmatch(normalized) is not None


def _issue(code: str, field: str, message: str) -> PolicyValidationIssue:
    return PolicyValidationIssue(code=code, field=field, message=message)
