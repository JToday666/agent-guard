"""Actual Core context plans consumed by Node; not native Host qualification."""

from dataclasses import replace
import json
from pathlib import Path
import subprocess

import pytest

from agentguard_core import ContextBuildPayload, ContextSource
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.canonical_resources import (
    ResourceNormalizationInput,
    normalize_memory_resource,
)
from guard_api.security_state import SecurityStateService
from guard_api.services.context_builder import ContextBuilderService
from guard_api.services.ct_projection import CtProjectionService
from tests.support.product_evaluation import create_product_evaluation_harness
from tests.test_openclaw_product_activation_http import (
    ROOT,
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
)

pytestmark = pytest.mark.contract


def test_actual_product_plan_preserves_task_isolates_sources_and_rejects_drift(
    tmp_path,
):
    harness = create_product_evaluation_harness(
        tmp_path, runtime="openclaw", action_types=("context_build",)
    )
    settings = replace(harness.settings, context_builder_enabled=True)
    harness.evaluation.context_builder_service = ContextBuilderService(
        settings=settings
    )
    harness.evaluation.ct_projection_service = CtProjectionService(
        settings=settings,
        store=harness.store,
        state_service=SecurityStateService(harness.store),
    )
    task = "verify authority-aware exact Product replay"
    content = [
        ("user", "trusted", "user", task, False),
        ("tool_result", "untrusted", "user", "A < B and B > C & C.", False),
        (
            "memory",
            "unknown",
            "user",
            "An unproven memory value remains private.",
            False,
        ),
        (
            "model",
            "unknown",
            "assistant",
            "Earlier model text must remain excluded.",
            False,
        ),
        ("runtime", "unknown", "system", "Unverified Host system instructions.", False),
    ]
    memory_id = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="resource:context-memory",
            memory_namespace=str(tmp_path / "memory.sqlite"),
            target="fixture",
        )
    ).canonical_id
    sources = [
        dict(
            source_id=memory_id if kind == "memory" else f"local:{i}",
            source_type=kind,
            source_trust=trust,
            role=role,
            content=text,
        )
        for i, (kind, trust, role, text, _) in enumerate(content)
    ]
    descriptors = [
        ContextSource(
            source_id=sources[i]["source_id"],
            source_type=kind,
            source_trust=trust,
            role=role,
            summary=text,
            content_digest=canonical_sha256(text),
            sequence_index=i,
            contains_instruction_like_text=instruction,
        )
        for i, (kind, trust, role, text, instruction) in enumerate(content)
    ]
    event = harness.event(event_id="evt:oc-context-plan-contract").model_copy(
        update={
            "event_type": "context_assembled",
            "payload": ContextBuildPayload(sources=descriptors),
        }
    )
    evaluation = harness.evaluate(event)
    assert evaluation.decision.decision == "allow"
    assert evaluation.context_plan is not None
    result = subprocess.run(
        [
            "node",
            str(Path(ROOT) / "tests/support/openclaw-product-context-plan-probe.mjs"),
        ],
        input=json.dumps(
            {
                "event": event.model_dump(mode="json"),
                "evaluation": evaluation.model_dump(mode="json"),
                "sources": sources,
                "expected": {"scopeDigest": harness.scope_digest, "taskSummary": task},
            }
        ),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["passed"] >= 25
    assert summary["published_messages"] == 2
