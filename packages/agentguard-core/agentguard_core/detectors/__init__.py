"""Deterministic detectors for the stateless Core."""

from .base import (
    Detector,
    apply_rule_override,
    apply_rule_override as _apply_rule_override,
    is_rule_disabled,
    is_rule_disabled as _is_rule_disabled,
)
from .code import CodeExecDetector
from .environment import EnvironmentPoisoningDetector
from .memory import MemoryPoisoningDetector
from .model import JailbreakDetector
from .outbound import (
    OutboundDetector,
    is_allowed_recipient,
    is_allowed_recipient as _is_allowed_recipient,
    is_collection_endpoint,
    is_collection_endpoint as _is_collection_endpoint,
    tool_email_has_sensitive_text,
    tool_email_has_sensitive_text as _tool_email_has_sensitive_text,
)
from .prompt import PromptInjectionDetector
from .sensitive import SensitiveResourceDetector
from .tool import (
    TaskMismatchDetector,
    ToolHijackDetector,
    UnprofiledToolResourceDetector,
    action_aliases,
    action_aliases as _action_aliases,
    resource_is_high_risk_for_unprofiled_tool,
    resource_is_high_risk_for_unprofiled_tool as _resource_is_high_risk_for_unprofiled_tool,
    task_allows_tool_action,
    task_allows_tool_action as _task_allows_tool_action,
    task_negates_action,
    task_negates_action as _task_negates_action,
    verb_for_tool,
    verb_for_tool as _verb_for_tool,
)

__all__ = [
    "CodeExecDetector",
    "Detector",
    "EnvironmentPoisoningDetector",
    "JailbreakDetector",
    "MemoryPoisoningDetector",
    "OutboundDetector",
    "PromptInjectionDetector",
    "SensitiveResourceDetector",
    "TaskMismatchDetector",
    "ToolHijackDetector",
    "UnprofiledToolResourceDetector",
    "_action_aliases",
    "_apply_rule_override",
    "_is_allowed_recipient",
    "_is_collection_endpoint",
    "_is_rule_disabled",
    "_resource_is_high_risk_for_unprofiled_tool",
    "_task_allows_tool_action",
    "_task_negates_action",
    "_tool_email_has_sensitive_text",
    "_verb_for_tool",
    "action_aliases",
    "apply_rule_override",
    "is_allowed_recipient",
    "is_collection_endpoint",
    "is_rule_disabled",
    "resource_is_high_risk_for_unprofiled_tool",
    "task_allows_tool_action",
    "task_negates_action",
    "tool_email_has_sensitive_text",
    "verb_for_tool",
]
