"""Actual JS action mapping obeys the unchanged Core exec identity profile.

The origin is synthetic: this tests the cross-language event contract, not model
admission, policy authority, approval release, or an actual command invocation.
"""

import json
import subprocess

import pytest

from agentguard_core import GuardEvent, PolicyBundle
from agentguard_core.detectors.tool import ToolHijackDetector
from agentguard_core.events import derive_resources
from tests.test_openclaw_product_activation_http import (
    ROOT,
    _build_actual_openclaw_sdk as _build_actual_openclaw_sdk,
)

pytestmark = pytest.mark.contract

_SCRIPT = """
import {readNativeProductToolCall,buildProductToolEvent} from './packages/agentguard-openclaw-plugin/dist/mapping/product-events.js';
import {restrictedDigest} from './packages/agentguard-openclaw-plugin/dist/runtime/canonical.js';
const context={agentId:'main',sessionKey:'agent:main:exec-contract',runId:'run_exec',toolCallId:'call_exec',toolName:'exec'};
const args={command:'node marker.mjs'};
const call=readNativeProductToolCall({...context,params:args},context);
const source='source:model:evt_exec_model';
const origin={modelOutputAuditId:'policy_exec_model',modelSourceRef:source,callId:call.toolCallId,runId:call.runId,argumentsDigest:restrictedDigest(args),taskId:'task_exec',userTask:'Run the approved node marker.mjs command in the isolated workspace.',traceId:'trace_exec',visibleSourceRefs:[source]};
const profile={agentId:'main',workspaceRoot:'/workspace/fixture',memoryNamespace:'/workspace/fixture/memory.sqlite',inboxUrl:'http://127.0.0.1:45678/inbox'};
process.stdout.write(JSON.stringify(buildProductToolEvent(call,origin,profile)));
"""


@pytest.fixture(scope="module")
def mapped_exec_event():
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _SCRIPT],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert result.stderr == ""
    return json.loads(result.stdout)


def test_actual_exec_mapping_preserves_command_identity_and_model_provenance(
    mapped_exec_event,
):
    event = GuardEvent.model_validate(mapped_exec_event)
    assert event.payload.arguments == {"command": "node marker.mjs"}
    assert event.security_context.source_type == "model"
    assert event.security_context.source_trust == "unknown"
    assert event.security_context.visible_source_refs == (
        "source:model:evt_exec_model",
    )
    assert event.security_context.derived_paths == ["/workspace/fixture"]
    resources = derive_resources(event)
    assert len(resources) == 1
    assert resources[0].resource_type == "process"
    assert resources[0].operation == "execute"
    assert resources[0].direction == "local"
    assert resources[0].target == "node marker.mjs"
    assert ToolHijackDetector().evaluate(event, PolicyBundle()) == []


@pytest.mark.parametrize(
    ("operation", "direction", "expected_evidence"),
    [
        ("write", "local", "resource_operation=write"),
        ("execute", "internal", "resource_direction=internal"),
        ("execute", "outbound", "resource_direction=outbound"),
    ],
)
def test_core_still_denies_conflicting_exec_resource_semantics(
    mapped_exec_event, operation, direction, expected_evidence
):
    changed = json.loads(json.dumps(mapped_exec_event))
    changed["payload"]["derived_resources"][0].update(
        operation=operation, direction=direction
    )
    event = GuardEvent.model_validate(changed)
    results = ToolHijackDetector().evaluate(event, PolicyBundle())
    assert len(results) == 1
    assert results[0].decision == "deny"
    assert results[0].rule_hit.rule_id == "P002_tool_identity_mismatch"
    assert expected_evidence in results[0].rule_hit.evidence
