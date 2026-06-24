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
    action_aliases,
    action_aliases as _action_aliases,
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
    "_action_aliases",
    "_apply_rule_override",
    "_is_allowed_recipient",
    "_is_collection_endpoint",
    "_is_rule_disabled",
    "_tool_email_has_sensitive_text",
    "_verb_for_tool",
    "action_aliases",
    "apply_rule_override",
    "is_allowed_recipient",
    "is_collection_endpoint",
    "is_rule_disabled",
    "tool_email_has_sensitive_text",
    "verb_for_tool",
]
