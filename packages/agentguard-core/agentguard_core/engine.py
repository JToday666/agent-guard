"""Stateless AgentGuard Core evaluation engine."""

from __future__ import annotations

import logging
from time import perf_counter

from .decisions import DetectionResult, GuardDecision, RuleHit, build_guard_decision
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
from .events import GuardEvent
from .policies import PolicyBundle

logger = logging.getLogger(__name__)

# 检测器失败契约（见 docs/02_core/interface_contract.md「检测器失败语义」）：
# 失败即保守（ask），不提供任何 fail-open 配置。
DETECTOR_FAILURE_CATEGORY = "detector_failure"
DETECTOR_FAILURE_DECISION = "ask"
DETECTOR_FAILURE_RISK_SCORE = 60
DETECTOR_FAILURE_SEVERITY = "medium"


class GuardEngine:
    """Stateless evaluation engine.

    Detector selection semantics:
    - ``detectors=None``（默认）：加载内置默认检测器列表。
    - ``detectors=[]``（显式空列表）：不运行任何检测器，评估仅产出
      无检测结果的基线决策。

    Detector failure contract:
    - 单个检测器抛出异常时，异常不会向外传播；该检测器被转换为一条结构化
      保守检测结果：``decision="ask"``、``category="detector_failure"``，
      rule hit 携带检测器标识与异常类别（不含完整 traceback）。
    - 失败即保守（fail-closed）：不提供任何 fail-open 配置，失败一律
      转入人工审批而非放行。
    - 单个检测器失败不影响其他检测器继续评估；失败证据与正常检测结果
      一起交给既有聚合（deny 优先语义不变）。
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

    def evaluate_with_results(
        self, event: GuardEvent, policies: PolicyBundle | None = None
    ) -> tuple[GuardDecision, list[DetectionResult]]:
        """只读旁路：返回 legacy 决策与其全部 ``DetectionResult``。

        V21-08 shadow 接线点：shadow 评估需要 legacy 检测结果经
        ``signals/legacy_adapter`` 映射为 V2.1 signal/degradation；本方法
        与 ``evaluate()`` 共享同一条检测/聚合链，不改变任何判定语义
        （检测器失败契约、deny 优先、started_at 计时均不变）。纯新增
        旁路，判定路径依旧不 import actions（V21-02 AST 导入隔离守卫）。
        """
        policy_bundle = policies or PolicyBundle()
        started_at = perf_counter()
        detections: list[DetectionResult] = []
        for detector in self.detectors:
            try:
                detections.extend(detector.evaluate(event, policy_bundle))
            except Exception as exc:  # 检测器失败契约：失败即保守 ask，不外抛。
                logger.warning(
                    "detector %s failed during evaluation; emitting conservative "
                    "ask result",
                    type(detector).__name__,
                    exc_info=exc,
                )
                detections.append(_detector_failure_result(detector, exc))
        decision = build_guard_decision(detections, started_at=started_at)
        return decision, detections

    def evaluate(
        self, event: GuardEvent, policies: PolicyBundle | None = None
    ) -> GuardDecision:
        decision, _ = self.evaluate_with_results(event, policies)
        return decision


def _detector_failure_result(detector: Detector, exc: Exception) -> DetectionResult:
    """Build the structured conservative result for a failed detector.

    对外 reason 只暴露检测器标识与异常类别，不泄漏异常消息与完整
    traceback；完整堆栈仅通过内部日志（``exc_info``）留存。
    """
    detector_name = type(detector).__name__
    exception_class = type(exc).__name__
    rule_id = f"detector_failure:{detector_name}"
    return DetectionResult(
        decision=DETECTOR_FAILURE_DECISION,
        risk_score=DETECTOR_FAILURE_RISK_SCORE,
        category=DETECTOR_FAILURE_CATEGORY,
        rule_hit=RuleHit(
            rule_id=rule_id,
            rule_name="Detector Failure",
            severity=DETECTOR_FAILURE_SEVERITY,
            evidence=[
                f"detector {detector_name} raised {exception_class}",
                "fail-closed: detector failure always requires review",
            ],
        ),
        reason=(
            f"Detector {detector_name} failed with {exception_class}; "
            "evaluation is conservatively requiring approval."
        ),
        approval_resource=None,
        severity=DETECTOR_FAILURE_SEVERITY,
    )


def evaluate(event: GuardEvent, policies: PolicyBundle | None = None) -> GuardDecision:
    return GuardEngine().evaluate(event, policies)
