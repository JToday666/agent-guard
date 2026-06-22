"""Stateless AgentGuard Core evaluation engine."""

from __future__ import annotations

from time import perf_counter

from .detectors import Detector, OutboundDetector, SensitiveResourceDetector, TaskMismatchDetector, ToolHijackDetector
from .models import GuardDecision, GuardEvent, PolicyBundle
from .policy import build_guard_decision


class GuardEngine:
    def __init__(self, *, detectors: list[Detector] | None = None) -> None:
        self.detectors = detectors or [
            SensitiveResourceDetector(),
            ToolHijackDetector(),
            OutboundDetector(),
            TaskMismatchDetector(),
        ]

    def evaluate(self, event: GuardEvent, policies: PolicyBundle | None = None) -> GuardDecision:
        policy_bundle = policies or PolicyBundle()
        started_at = perf_counter()
        detections = []
        for detector in self.detectors:
            detections.extend(detector.evaluate(event, policy_bundle))
        return build_guard_decision(detections, started_at=started_at)


def evaluate(event: GuardEvent, policies: PolicyBundle | None = None) -> GuardDecision:
    return GuardEngine().evaluate(event, policies)
