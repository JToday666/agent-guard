from __future__ import annotations

import aegis_agentguard
import agentguard_core


def test_aegis_agentguard_exports_stable_core_facade() -> None:
    assert aegis_agentguard.__version__ == "0.1.0b1"
    assert aegis_agentguard.GuardEngine is agentguard_core.GuardEngine
    assert aegis_agentguard.GuardEvent is agentguard_core.GuardEvent
    assert aegis_agentguard.GuardDecision is agentguard_core.GuardDecision
    assert aegis_agentguard.PolicyBundle is agentguard_core.PolicyBundle
    assert aegis_agentguard.evaluate is agentguard_core.evaluate


def test_aegis_agentguard_public_surface_is_intentional() -> None:
    assert aegis_agentguard.__all__ == [
        "__version__",
        "GuardDecision",
        "GuardEngine",
        "GuardEvent",
        "PolicyBundle",
        "evaluate",
    ]
