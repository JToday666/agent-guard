"""Tool identity and task alignment detectors."""

from __future__ import annotations

import ast
import json
import re
import shlex
from typing import Any
from urllib.parse import urlparse

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolCallPayload, derive_resources, is_exec_like_tool
from ..matchers import (
    has_credential_command_text,
    has_dangerous_command_text,
    has_high_confidence_memory_poisoning_text,
    has_instruction_like_text,
    has_memory_poisoning_text,
    normalize_match_text,
)
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class ToolHijackDetector(Detector):
    rule_id = "P002_tool_identity_mismatch"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        profile = policies.tool_profiles.get(event.payload.tool.name)
        if profile is None:
            return []
        tool = event.payload.tool
        category = (tool.category or "").lower()
        kind = (tool.kind or tool.name).lower()
        evidence: list[str] = []

        profile_categories = {item.lower() for item in profile.categories}
        profile_kinds = {item.lower() for item in profile.kinds}
        profile_directions = {item.lower() for item in profile.directions}
        profile_operations = {item.lower() for item in profile.operations}

        if category and profile_categories and category not in profile_categories:
            evidence.append(f"tool_category={category}")
        if kind and profile_kinds and kind not in profile_kinds:
            evidence.append(f"tool_kind={kind}")

        evidence.extend(tool_argument_hijack_evidence(event, policies))

        for resource in derive_resources(event):
            direction = resource.direction.lower()
            operation = resource.operation.lower()
            if direction and profile_directions and direction not in profile_directions:
                evidence.append(f"resource_direction={direction}")
            if operation and profile_operations and operation not in profile_operations:
                evidence.append(f"resource_operation={operation}")

        if not evidence:
            return []

        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=88,
                category="tool_hijack",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Tool Identity Mismatch",
                    severity="high",
                    evidence=[f"tool={tool.name}", *evidence],
                ),
                reason="The tool identity or derived resource behavior conflicts with its built-in profile.",
                severity="high",
            ),
            policies,
        )
        return [result] if result is not None else []


class UnprofiledToolResourceDetector(Detector):
    rule_id = "P007_unprofiled_tool_resource_review"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        if event.payload.tool.name in policies.tool_profiles:
            return []
        if scoped_runtime_manifest_allows_tool(event):
            return []
        if trusted_low_risk_memory_write(event, policies):
            return []

        risky_resources = [
            resource
            for resource in derive_resources(event)
            if resource_is_high_risk_for_unprofiled_tool(resource.direction, resource.operation)
        ]
        if not risky_resources:
            return []

        resource = risky_resources[0]
        result = apply_rule_override(
            DetectionResult(
                decision="ask",
                risk_score=58,
                category="unprofiled_tool_resource_review",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Unprofiled Tool Resource Review",
                    severity="medium",
                    evidence=[
                        f"tool={event.payload.tool.name}",
                        f"resource_direction={resource.direction}",
                        f"resource_operation={resource.operation}",
                        f"resource_target={resource.target}",
                    ],
                ),
                reason="An unprofiled tool targets a high-risk resource and requires approval.",
                approval_resource=resource.target,
                severity="medium",
            ),
            policies,
        )
        return [result] if result is not None else []


class TaskMismatchDetector(Detector):
    rule_id = "P004_task_mismatch"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        source_trust = event.security_context.source_trust.lower()
        if source_trust != "untrusted":
            return []
        if low_risk_observation_action_allowed(event, policies):
            return []
        if scoped_runtime_manifest_allows_low_risk_tool(event, policies):
            return []
        tool_name = event.payload.tool.name
        if tool_name in {"send_email", "call_api", "read_file", "write_file", "memory_write", "code_exec"} or is_exec_like_tool(
            event.payload.tool
        ):
            if not task_allows_tool_action(event.security_context.user_task, tool_name, policies):
                result = apply_rule_override(
                    DetectionResult(
                        decision="ask",
                        risk_score=45,
                        category="task_mismatch",
                        rule_hit=RuleHit(
                            rule_id=self.rule_id,
                            rule_name="Task Mismatch",
                            severity="medium",
                            evidence=[f"tool={tool_name}", "source_trust=untrusted"],
                        ),
                        reason="The tool action is not clearly aligned with the current user task.",
                        severity="medium",
                    ),
                    policies,
                )
                return [result] if result is not None else []
        return []


def action_aliases(tool_name: str, policies: PolicyBundle) -> set[str]:
    aliases = {tool_name.lower(), verb_for_tool(tool_name).lower()}
    aliases.update(alias.lower() for alias in policies.tool_action_aliases.get(tool_name, []))
    return aliases


def tool_argument_hijack_evidence(event: GuardEvent, policies: PolicyBundle) -> list[str]:
    if not isinstance(event.payload, ToolCallPayload):
        return []
    if event.security_context.source_trust.lower() in {"trusted", "verified", "sanitized", "clean"}:
        return []

    evidence: list[str] = []
    external_keys = {_compact_key(key) for key in policies.tool_hijack_external_argument_keys}
    semantic_keys = {_compact_key(key) for key in policies.tool_hijack_semantic_bias_argument_keys}
    for key_path, value in _argument_items(event.payload.arguments):
        key_name = key_path.rsplit(".", 1)[-1]
        compact_key = _compact_key(key_name)
        value_text = normalize_match_text(str(value))
        if compact_key in external_keys and _argument_value_points_to_external_sink(value_text):
            if "callback" in compact_key:
                evidence.append(f"unsafe_callback_argument={key_name}")
            else:
                evidence.append(f"external_sink_argument={key_name}")
        if compact_key in semantic_keys and str(value).strip():
            evidence.append(f"semantic_bias_argument={key_name}")
    return list(dict.fromkeys(evidence))


def _argument_items(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        items: list[tuple[str, Any]] = []
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            items.extend(_argument_items(child, path))
        return items
    if isinstance(value, list):
        items = []
        for index, child in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            items.extend(_argument_items(child, path))
        return items
    return [(prefix, value)] if prefix else []


def _compact_key(value: str) -> str:
    return "".join(ch for ch in normalize_match_text(value) if ch.isalnum())


def _argument_value_points_to_external_sink(value: str) -> bool:
    return bool(value) and (
        "http://" in value
        or "https://" in value
        or "/collect/" in value
        or "webhook" in value
        or "exfil" in value
    )


def task_allows_tool_action(user_task: str, tool_name: str, policies: PolicyBundle) -> bool:
    aliases = action_aliases(tool_name, policies)
    if task_negates_action(user_task, aliases):
        return False
    normalized = normalize_task_text(user_task)
    return any(alias in normalized for alias in aliases)


def task_negates_action(user_task: str, aliases: set[str]) -> bool:
    normalized = normalize_task_text(user_task)
    for alias in aliases:
        escaped = re.escape(alias)
        patterns = [
            rf"\bdo not {escaped}\b",
            rf"\bdon't {escaped}\b",
            rf"\bnever {escaped}\b",
            rf"\bnot {escaped}\b",
            rf"不要{escaped}",
            rf"不要 {escaped}",
            rf"禁止{escaped}",
            rf"禁止 {escaped}",
        ]
        if any(re.search(pattern, normalized) for pattern in patterns):
            return True
    return False


def normalize_task_text(value: str) -> str:
    lowered = value.lower()
    lowered = re.sub(r"[\t\r\n]+", " ", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def resource_is_high_risk_for_unprofiled_tool(direction: str, operation: str) -> bool:
    return direction.lower() in {"outbound", "persistent"} or operation.lower() in {
        "delete",
        "execute",
        "patch",
        "post",
        "put",
        "send",
        "write",
    }


def trusted_low_risk_memory_write(event: GuardEvent, policies: PolicyBundle) -> bool:
    if not isinstance(event.payload, ToolCallPayload):
        return False
    if event.payload.tool.name != "memory_write":
        return False
    if event.security_context.source_trust.lower() not in {"trusted", "verified", "sanitized", "clean"}:
        return False
    argument_trust = str(event.payload.arguments.get("source_trust") or "").lower()
    if argument_trust and argument_trust not in {"trusted", "verified", "sanitized", "clean"}:
        return False
    text = _memory_write_argument_text(event.payload.arguments)
    return not (
        has_high_confidence_memory_poisoning_text(text, policies)
        or has_memory_poisoning_text(text, policies)
        or has_instruction_like_text(text, policies)
    )


def _memory_write_argument_text(arguments: dict[str, Any]) -> str:
    selected = {
        key: value
        for key, value in arguments.items()
        if key in {"namespace", "key", "value", "value_preview", "content", "text", "source_trust"}
    }
    if not selected:
        selected = arguments
    try:
        return json.dumps(selected, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(selected)


def scoped_runtime_manifest_allows_tool(event: GuardEvent) -> bool:
    if not isinstance(event.payload, ToolCallPayload):
        return False
    policy = runtime_policy_for_event(event)
    if not policy:
        return False
    if not truthy(policy.get("tool_manifest_scoped")):
        return False
    declared_tools = normalized_string_set(policy.get("declared_tools"))
    if not declared_tools:
        return False
    return event.payload.tool.name.lower() in declared_tools


def scoped_runtime_manifest_allows_low_risk_tool(event: GuardEvent, policies: PolicyBundle) -> bool:
    if not isinstance(event.payload, ToolCallPayload):
        return False
    if not scoped_runtime_manifest_allows_tool(event):
        return False
    if event.payload.tool.name != "read_file":
        return False
    resources = derive_resources(event)
    if not resources:
        return False
    return all(resource_is_low_risk_local_read(resource, policies) for resource in resources)


def low_risk_observation_action_allowed(event: GuardEvent, policies: PolicyBundle) -> bool:
    if not isinstance(event.payload, ToolCallPayload):
        return False
    tool_name = event.payload.tool.name
    if tool_name == "read_file":
        resources = derive_resources(event)
        return bool(resources) and all(resource_is_low_risk_local_read(resource, policies) for resource in resources)
    if tool_name == "call_api":
        return api_call_is_low_risk_local_get(event.payload.arguments, policies)
    if is_exec_like_tool(event.payload.tool):
        return exec_command_is_low_risk_observation(
            event.payload.arguments,
            policies,
            user_task=event.security_context.user_task,
        )
    return False


def resource_is_low_risk_local_read(resource: Any, policies: PolicyBundle) -> bool:
    return (
        str(resource.direction).lower() in {"local", "runtime"}
        and str(resource.operation).lower() in {"read", "get", "extract", "extract_text"}
        and str(resource.data_classification or "").lower() != "sensitive"
        and not resource_target_has_marker(str(resource.target or ""), policies.sensitive_resource_markers)
    )


def api_call_is_low_risk_local_get(arguments: dict[str, Any], policies: PolicyBundle) -> bool:
    method = str(arguments.get("method") or "GET").upper()
    if method not in {"GET", "HEAD"}:
        return False
    target = str(arguments.get("url") or arguments.get("path") or "")
    if not target:
        return False
    parsed = urlparse(target.lower())
    if parsed.scheme or parsed.netloc:
        if parsed.hostname not in {host.lower() for host in policies.allowed_api_hosts}:
            return False
    elif not target.startswith("/"):
        return False
    if resource_target_has_marker(target, policies.sensitive_resource_markers):
        return False
    if resource_target_has_marker(target, policies.collection_path_markers):
        return False
    return not any(arguments.get(key) for key in ("body", "data", "json", "payload"))


def exec_command_is_low_risk_observation(
    arguments: dict[str, Any],
    policies: PolicyBundle,
    *,
    user_task: str = "",
) -> bool:
    command = str(arguments.get("command") or arguments.get("cmd") or arguments.get("code") or "")
    if not command.strip():
        return False
    if has_credential_command_text(command, policies) or has_dangerous_command_text(command, policies):
        return False
    python_code = extract_python_inline_code(command) or extract_python_heredoc(command)
    if python_code is not None:
        return task_allows_computation(user_task) and python_code_is_side_effect_free(python_code)

    normalized_command = strip_safe_shell_fallback(command) or command
    if shell_command_has_control_operator(normalized_command):
        return False
    try:
        parts = shlex.split(normalized_command)
    except ValueError:
        return False
    if not parts:
        return False
    program = parts[0].rsplit("/", 1)[-1].lower()
    if program not in {"cat", "head", "tail", "wc", "ls"}:
        if program != "mkdir":
            return False
        if "-p" not in parts[1:]:
            return False
        if not task_allows_tool_action(user_task, "write_file", policies):
            return False
    targets = [part for part in parts[1:] if part and not part.startswith("-")]
    if not targets:
        return False
    return all(command_target_is_low_risk_observation(target, policies) for target in targets)


def strip_safe_shell_fallback(command: str) -> str | None:
    match = re.match(
        r"^\s*(?P<primary>.+?)\s*(?:2>\s*/dev/null\s*)?\|\|\s*echo\s+(?P<message>.+?)\s*$",
        command,
        re.DOTALL,
    )
    if not match:
        return None
    primary = match.group("primary").strip()
    message = match.group("message").strip()
    if not primary or not message:
        return None
    if shell_command_has_control_operator(primary):
        return None
    if re.search(r"[;&|<>`$()\n\r]", message):
        return None
    try:
        echo_parts = shlex.split(f"echo {message}")
    except ValueError:
        return None
    if len(echo_parts) != 2 or echo_parts[0] != "echo":
        return None
    return primary


def shell_command_has_control_operator(command: str) -> bool:
    return bool(re.search(r"[;&|<>`$()\n\r]", command))


def command_target_is_low_risk_observation(target: str, policies: PolicyBundle) -> bool:
    if resource_target_has_marker(target, policies.sensitive_resource_markers):
        return False
    if resource_target_has_marker(target, policies.collection_path_markers):
        return False
    lowered = target.lower()
    return not lowered.startswith(("/dev/", "/etc/", "/proc/", "/sys/", "/var/run/"))


def extract_python_heredoc(command: str) -> str | None:
    match = re.match(
        r"^\s*(?:python|python3)\s+<<\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?\s*\n(?P<code>.*)\n\1\s*$",
        command.strip(),
        re.DOTALL,
    )
    if not match:
        return None
    return match.group("code")


def extract_python_inline_code(command: str) -> str | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if len(parts) != 3:
        return None
    program = parts[0].rsplit("/", 1)[-1].lower()
    if program not in {"python", "python3"}:
        return None
    if parts[1] != "-c":
        return None
    return parts[2]


def task_allows_computation(user_task: str) -> bool:
    normalized = normalize_task_text(user_task)
    return any(
        marker in normalized
        for marker in (
            "calculate",
            "compute",
            "analyze",
            "analyse",
            "analysis",
            "derive",
            "estimate",
            "signal",
            "return",
            "计算",
            "分析",
        )
    )


def python_code_is_side_effect_free(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False

    allowed_modules = {"datetime", "decimal", "fractions", "json", "math", "statistics"}
    blocked_names = {
        "__import__",
        "compile",
        "eval",
        "exec",
        "globals",
        "input",
        "locals",
        "open",
        "setattr",
        "vars",
    }
    blocked_attrs = {
        "connect",
        "download",
        "mkdir",
        "open",
        "popen",
        "read_text",
        "remove",
        "rename",
        "replace",
        "request",
        "rmdir",
        "send",
        "system",
        "unlink",
        "upload",
        "urlopen",
        "write",
        "write_text",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".", 1)[0] not in allowed_modules for alias in node.names):
                return False
            continue
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".", 1)[0] not in allowed_modules:
                return False
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While, ast.Try)):
            return False
        if isinstance(node, ast.Name) and node.id in blocked_names:
            return False
        if isinstance(node, ast.Attribute) and node.attr in blocked_attrs:
            return False
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in blocked_names:
                return False
            if isinstance(func, ast.Attribute) and func.attr in blocked_attrs:
                return False
    return True


def resource_target_has_marker(target: str, markers: list[str]) -> bool:
    lowered = target.lower()
    return any(marker.lower() in lowered for marker in markers)


def runtime_policy_for_event(event: GuardEvent) -> dict[str, Any]:
    for value in (
        event.metadata.get("runtime_policy"),
        event.metadata.get("runtimePolicy"),
        event.security_context.metadata.get("runtime_policy"),
        event.security_context.metadata.get("runtimePolicy"),
    ):
        policy = normalized_runtime_policy(value)
        if policy:
            return policy
    return {}


def nested_mapping(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        return value.get(key)
    return None


def normalized_runtime_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    policy = dict(value)
    declared_tools = normalized_string_set(policy.get("declared_tools"))
    declared_tools.update(normalized_string_set(policy.get("tools")))
    if declared_tools:
        policy["declared_tools"] = sorted(declared_tools)

    return policy


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes"}
    return False


def normalized_string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    normalized: set[str] = set()
    for item in value:
        if isinstance(item, str) and item.strip():
            normalized.add(item.strip().lower())
        elif isinstance(item, dict):
            name = item.get("name") or item.get("tool_name") or item.get("id")
            if isinstance(name, str) and name.strip():
                normalized.add(name.strip().lower())
    return normalized


def verb_for_tool(tool_name: str) -> str:
    if tool_name in {"code_exec", "exec", "shell", "command", "bash", "sh", "powershell", "terminal"}:
        return "execute"
    return {
        "read_file": "read",
        "write_file": "write",
        "send_email": "email",
        "call_api": "api",
        "memory_write": "memory",
    }.get(tool_name, tool_name)
