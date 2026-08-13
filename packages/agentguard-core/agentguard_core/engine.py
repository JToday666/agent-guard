"""Stateless AgentGuard Core evaluation engine."""

from __future__ import annotations

from time import perf_counter

from .detectors import (
    AgentAbuseDetector,
    CodeExecDetector,
    CredentialExposureDetector,
    Detector,
    EnvironmentPoisoningDetector,
    FileExfiltrationDetector,
    JailbreakDetector,
    MemoryPoisoningDetector,
    McpToolHijackingDetector,
    OutboundDetector,
    PromptInjectionDetector,
    SensitiveResourceDetector,
    TaskMismatchDetector,
    ToolHijackDetector,
    UnprofiledToolResourceDetector,
)
from .decisions import GuardDecision, build_guard_decision
from .events import GuardEvent
from .policies import PolicyBundle


class GuardEngine:
    """Stateless evaluation engine.

    Detector selection semantics:
    - ``detectors=None``（默认）：加载内置默认检测器列表。
    - ``detectors=[]``（显式空列表）：不运行任何检测器，评估仅产出
      无检测结果的基线决策。
    """

    def __init__(self, *, detectors: list[Detector] | None = None) -> None:
        self.detectors = (
            detectors
            if detectors is not None
            else [
                SensitiveResourceDetector(),
                McpToolHijackingDetector(),
                FileExfiltrationDetector(),
                ToolHijackDetector(),
                UnprofiledToolResourceDetector(),
                OutboundDetector(),
                AgentAbuseDetector(),
                TaskMismatchDetector(),
                PromptInjectionDetector(),
                JailbreakDetector(),
                CredentialExposureDetector(),
                CodeExecDetector(),
                MemoryPoisoningDetector(),
                EnvironmentPoisoningDetector(),
            ]
        )

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle | None = None
    ) -> GuardDecision:
        policy_bundle = policies or PolicyBundle()
        started_at = perf_counter()
        detections = []
        for detector in self.detectors:
            detections.extend(detector.evaluate(event, policy_bundle))
        return build_guard_decision(detections, started_at=started_at)


def evaluate(event: GuardEvent, policies: PolicyBundle | None = None) -> GuardDecision:
    return GuardEngine().evaluate(event, policies)
