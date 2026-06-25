"""Code execution abuse detectors."""

from __future__ import annotations

from ..decisions import DetectionResult, RuleHit
from ..events import GuardEvent, ToolCallPayload, tool_argument_text
from ..matchers import has_dangerous_command_text
from ..policies import PolicyBundle
from .base import Detector, apply_rule_override, is_rule_disabled


class CodeExecDetector(Detector):
    rule_id = "P103_code_execution_abuse"

    def evaluate(self, event: GuardEvent, policies: PolicyBundle) -> list[DetectionResult]:
        if is_rule_disabled(self.rule_id, policies):
            return []
        if not isinstance(event.payload, ToolCallPayload):
            return []
        if event.payload.tool.name != "code_exec":
            return []
        command = tool_argument_text(event.payload.arguments, "command", "cmd", "code")
        if not has_dangerous_command_text(command, policies):
            return []
        result = apply_rule_override(
            DetectionResult(
                decision="deny",
                risk_score=92,
                category="code_execution_abuse",
                rule_hit=RuleHit(
                    rule_id=self.rule_id,
                    rule_name="Dangerous Code Execution",
                    severity="critical",
                    evidence=[f"command={command}"],
                ),
                reason="The code execution request contains dangerous shell behavior.",
                severity="critical",
            ),
            policies,
        )
        return [result] if result is not None else []
