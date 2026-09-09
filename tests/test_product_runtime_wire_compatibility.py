"""Real SDK serializers through Core and B10, using synthetic protocol inputs.

No HTTP, Provider, model execution, tool invocation or Host qualification occurs.
The input decisions are computed by Core. Producer bytes remain immutable evidence;
Core's HTTP parsers supply the separate normalized records used by offline readers.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from agentguard_core import AuditEvent, GuardEvent, RuntimeOutcomeReceipt
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES
from agentguard_langgraph_adapter.activation_ack import ActivationAckV1 as SdkAck
from agentguard_langgraph_adapter.config import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.core_client import _guard_api_v03_event
from agentguard_langgraph_adapter.event_models import (
    PolicyDecision,
    RuntimeOutcomeReceipt as SdkReceipt,
)
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.native_events import (
    NativeGuardEventBuilder,
    NativeModelOrigin,
)
from agentguard_langgraph_adapter.native_tools import (
    close_isolated_product_tools,
    create_isolated_product_tools,
    prepare_native_tool_call,
)
from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome
from agentguard_langgraph_adapter.product_outbox import _encode as encode_lg_receipt
from guard_api.services.product_model_content import build_product_ack_validation
from guard_api.services.redaction import sanitize_audit_event
from scripts.product_runtime.conformance import Facts, _event
from scripts.product_runtime.evidence import EvidenceError, EvidenceStore
from scripts.product_runtime.models import AdmissionError, TraceFrame
from scripts.product_runtime.policy_evidence import _typed
from scripts.product_runtime.policy_terminal import verify_policy_terminal
from tests.product_runtime_terminal_fixture import build_policy_terminal
from tests.test_product_runtime_policy_evidence import _save, make_policy_replay

pytestmark = pytest.mark.contract
ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "packages/agentguard-openclaw-plugin"
SENTINEL = "UNIT-QUARANTINED-CONTENT-789"

# Import exactly the built production serializers. Nothing in this child process
# opens a transport or executes a tool; stdout is the explicit private wire only.
NODE_PRODUCER = r"""
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const input = JSON.parse(readFileSync(0, 'utf8'));
const load = (path) => import(pathToFileURL(input.packageRoot + '/dist/' + path));
const {buildProductToolEvent,readNativeProductToolCall} = await load('mapping/product-events.js');
const {buildProductContextEvent,buildProductModelEvent,buildProductResultEvent} = await load('mapping/product-content-events.js');
const {restrictedDigest} = await load('runtime/canonical.js');
if (input.mode === 'events') {
  const binding = {agentId:'unit-agent',sessionKey:'unit-session',taskId:'unit-task',
    userTask:'Read the isolated fixture.',traceId:'unit-trace',provider:'synthetic-unit',modelId:'controlled-protocol-input'};
  const profile = {agentId:binding.agentId,workspaceRoot:'/srv/agentguard-unit/wire',
    memoryNamespace:'/srv/agentguard-unit/wire/memory.sqlite',inboxUrl:'http://127.0.0.1:19876/inbox'};
  const context = {messages:[],planId:'unit-plan',planDigest:'sha256:'+'1'.repeat(64),
    contextRef:'unit-context',visibleSourceRefs:['source:model:unit-output']};
  const calls = [];
  for (const [toolName,params] of [['read',{path:'fixture.txt'}],
      ['agentguard_memory_write',{key:'note',value:input.sentinel}],
      ['message',{action:'send',channel:'agentguard-fixture',target:'fixture-inbox@agentguard.invalid',message:input.sentinel}]]) {
    const e = {toolName,params,toolCallId:'call-'+toolName,runId:'unit-run'};
    const c = {...e,agentId:binding.agentId,sessionKey:binding.sessionKey};
    const call = readNativeProductToolCall(e,c);
    const origin = {modelOutputAuditId:'unit-output-policy',modelSourceRef:'source:model:unit-output',
      callId:call.toolCallId,runId:call.runId,argumentsDigest:restrictedDigest(params),
      taskId:binding.taskId,userTask:binding.userTask,traceId:binding.traceId,visibleSourceRefs:context.visibleSourceRefs};
    calls.push([call,buildProductToolEvent(call,origin,profile)]);
  }
  const events = [buildProductContextEvent(binding,[{source_id:'unit-source',source_type:'user',
    source_trust:'trusted',role:'user',content:input.sentinel}]),
    buildProductModelEvent(binding,'input',input.sentinel,context),
    buildProductModelEvent(binding,'output',input.sentinel,context,'unit-input-policy'),
    ...calls.map(([,event])=>event),
    buildProductResultEvent(binding,calls[0][0],calls[0][1],{policy_audit_id:'unit-action-policy'},input.sentinel)];
  process.stdout.write(JSON.stringify(events.map(event=>JSON.stringify(event))));
} else {
  const {readOpenClawActivationAckHandle} = await load('runtime/activation-ack-handle.js');
  const {bindEvaluationActivationAck,bindConsumptionActivationAck} = await load('runtime/product-authority-context.js');
  const {prepareProductReceipt} = await load('runtime/product-receipt-wire.js');
  const {buildProductActionReceipt} = await load('mapping/product-receipts.js');
  const {schema_version,runtime,issued_at,expires_at,ack_token,...identity} = input.ack;
  const handle = readOpenClawActivationAckHandle(input.ack,identity,{nowMs:Date.parse(issued_at)+1});
  bindEvaluationActivationAck(input.evaluation,handle);
  if (input.options.lease) bindConsumptionActivationAck(input.evaluation,handle);
  // This is how the actual Node producer obtains its millisecond Z timestamp.
  input.options.timestamp = new Date(input.timestamp).toISOString();
  const receipt = buildProductActionReceipt(input.event,input.evaluation,input.options);
  process.stdout.write(prepareProductReceipt(receipt,{runtime:'openclaw',
    agentId:input.ack.agent_id,principalId:input.principalId,runtimeBindingId:input.ack.runtime_binding_id}));
}
"""


def node_produce(value, *, package_root):
    result = subprocess.run(
        ["node", "--input-type=module", "-e", NODE_PRODUCER],
        input=json.dumps({"packageRoot": str(package_root), **value}),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        cwd=ROOT,
    )
    # Do not echo a private serialized ACK, even when a producer regresses.
    assert result.returncode == 0, "Actual OpenClaw wire producer failed"
    return result.stdout


@pytest.fixture(scope="module")
def node_package(tmp_path_factory):
    """Compile once outside repository dist, independent of test order."""
    package = tmp_path_factory.mktemp("real-openclaw-wire-package")
    shutil.copyfile(PLUGIN / "package.json", package / "package.json")
    shutil.copytree(PLUGIN / "product-runtime", package / "product-runtime")
    # This is an explicit serializer contract composition, never candidate clean
    # installation evidence. Use the already installed pinned Host dependency.
    host = (PLUGIN / "node_modules/openclaw").resolve(strict=True)
    assert json.loads((host / "package.json").read_text())["version"] == "2026.7.1-2"
    (package / "node_modules").mkdir()
    (package / "node_modules/openclaw").symlink_to(host, target_is_directory=True)
    compiler = PLUGIN / "node_modules/typescript/bin/tsc"
    assert compiler.is_file(), "Install the pinned workspace dependencies first"
    result = subprocess.run(
        [
            "node",
            str(compiler),
            "--project",
            str(PLUGIN / "tsconfig.json"),
            "--outDir",
            str(package / "dist"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, "Actual OpenClaw serializer compilation failed"
    return package


def lg_events(root):
    root.mkdir(mode=0o700)
    adapter = LangGraphAdapter(config=AgentGuardLangGraphConfig(agent_id="unit-agent"))
    factory = NativeGuardEventBuilder(adapter)
    tools = create_isolated_product_tools(
        root=root, inbox_url="http://127.0.0.1:19876/inbox"
    )
    specs = {tool.name: tool for tool in tools}
    security = {
        "user_task": "Read the isolated fixture.",
        "agent_id": "unit-agent",
        "source_type": "model",
        "source_trust": "unknown",
        "task_id": "unit-task",
        "visible_source_refs": ["source:model:unit-output"],
    }
    try:
        events = [
            factory.build_context(
                [
                    {
                        "source_id": "unit-source",
                        "role": "user",
                        "source_type": "user",
                        "source_trust": "trusted",
                        "content": SENTINEL,
                    }
                ],
                security,
                "unit-trace",
            )
        ]
        for phase in ("input", "output"):
            events.append(
                factory.build_model(
                    phase=phase,
                    content=SENTINEL,
                    security=security,
                    trace_id="unit-trace",
                    provider="synthetic-unit",
                    model="controlled-protocol-input",
                    model_input_audit_id="unit-input-policy"
                    if phase == "output"
                    else None,
                )
            )
        for name, arguments in (
            ("read", {"path": "fixture.txt"}),
            ("agentguard_memory_write", {"key": "note", "value": SENTINEL}),
            (
                "message",
                {
                    "action": "send",
                    "channel": "agentguard-fixture",
                    "target": "fixture-inbox@agentguard.invalid",
                    "message": SENTINEL,
                },
            ),
        ):
            call = prepare_native_tool_call(specs[name], "call-" + name, arguments)
            origin = NativeModelOrigin(
                "unit-output-policy", "source:model:unit-output", call.call_id
            )
            event = factory.build_specialized_action(
                call, security, "unit-trace", model_origin=origin
            )
            events.append(
                event
                or factory.build_tool_call(
                    call, security, "unit-trace", model_origin=origin
                )
            )
            if name == "read":
                read = call
        events.append(factory.build_tool_result(read, SENTINEL, security, "unit-trace"))
        return [
            json.dumps(_guard_api_v03_event(event.model_dump(mode="json")))
            for event in events
        ]
    finally:
        close_isolated_product_tools(tools)


@pytest.fixture(scope="module")
def actual_event_wires(tmp_path_factory, node_package):
    return {
        "langgraph": lg_events(tmp_path_factory.mktemp("real-lg-wire") / "tools"),
        "openclaw": json.loads(
            node_produce(
                {"mode": "events", "sentinel": SENTINEL}, package_root=node_package
            )
        ),
    }


def save_wire(root, name, wire):
    path = root / name
    path.write_bytes(wire.encode())
    path.chmod(0o600)
    return {
        "path": name,
        "size": len(wire.encode()),
        "raw_sha256": "sha256:" + hashlib.sha256(wire.encode()).hexdigest(),
    }


def facts_for_event(root, event, wire):
    # Explicit synthetic observer fixtures exercise the reader, not a host claim.
    raw = save_wire(root, "raw-request.json", wire)
    frames = [
        (
            "consumer",
            "event_evaluated",
            {
                "event": event.model_dump(mode="json"),
                "event_digest": canonical_sha256(event.model_dump(mode="json")),
                "policy_audit_id": "unit-policy",
            },
        ),
        ("postgres", "event_receipt", {"policy_audit_id": "unit-policy"}),
    ]
    if event.event_type in {
        "context_assembled",
        "model_input_prepared",
        "model_output_produced",
        "tool_result_produced",
    }:
        request = {"messages": [{"role": "user", "content": "isolated replacement"}]}
        body = _save(root, "next.json", request)
        memory, inbox = _save(root, "memory.json", []), _save(root, "inbox.json", [])
        frames.extend(
            [
                (
                    "consumer",
                    "quarantined_content",
                    {
                        "original": SENTINEL,
                        "next_model_input": request,
                        "original_request_id": "unit-original",
                        "memory_snapshot": memory,
                        "inbox_snapshot": inbox,
                        "memory_values": [],
                        "inbox_values": [],
                        "disposition": "isolated",
                    },
                ),
                ("model", "next_request", {"request_id": "unit-next", "body": body}),
            ]
        )
    observation = SimpleNamespace(
        runtime=event.runtime,
        frames=[
            TraceFrame(
                sequence=i,
                actor=actor,
                event=name,
                data=data,
                attachments=[raw] if i == 0 else [],
            )
            for i, (actor, name, data) in enumerate(frames)
        ],
    )
    return Facts(observation, EvidenceStore(root))


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("event_type", PRODUCT_EVENT_TYPES)
def test_seven_actual_sdk_requests_normalize_without_changing_original_wire(
    tmp_path, actual_event_wires, runtime, event_type
):
    wire = next(
        value
        for value in actual_event_wires[runtime]
        if json.loads(value)["event_type"] == event_type
    )
    payload = json.loads(wire)
    parsed = GuardEvent.model_validate(payload)
    canonical = parsed.model_dump(mode="json")
    assert _typed(GuardEvent, canonical) == parsed
    if runtime == "openclaw":
        # Optional fields are absent in the real Node wire; exact dump equality
        # would require the runner to manufacture a different request body.
        assert canonical_sha256(payload) != canonical_sha256(canonical)
        assert payload["timestamp"].endswith("Z")
        assert "case_id" not in payload
    digest = hashlib.sha256(wire.encode()).hexdigest()
    _event(facts_for_event(tmp_path, parsed, wire), event_type)
    assert (tmp_path / "raw-request.json").read_bytes() == wire.encode()
    assert hashlib.sha256(wire.encode()).hexdigest() == digest
    assert json.loads(wire) == payload


def lg_decision(replay, terminal):
    decision = PolicyDecision.model_validate(
        {
            **replay.authority.selected_decision.model_dump(mode="json"),
            "policy_audit_id": terminal.parent.audit_id,
            "decision_authority": replay.authority.decision_authority.model_dump(
                mode="json"
            ),
            "approval_release_directive": replay.authority.approval_release_directive.model_dump(
                mode="json"
            ),
            "approval": terminal.approval.model_dump(mode="json")
            if terminal.approval
            else None,
        }
    )
    decision._evaluation_activation_ack = SdkAck.model_validate(
        replay.ack.model_dump(mode="json")
    )
    if terminal.lease:
        decision._consumption_activation_ack = decision._evaluation_activation_ack
    return decision


def actual_terminal_wire(replay, terminal, *, node_package):
    asking = terminal.approval is not None
    denied = replay.authority.selected_decision.decision == "deny"
    timestamp = terminal.receipt.timestamp
    if replay.event.runtime == "openclaw":
        evaluation = {
            "decision": replay.authority.selected_decision.model_dump(mode="json"),
            "policy_audit_id": terminal.parent.audit_id,
            "decision_authority": replay.authority.decision_authority.model_dump(
                mode="json"
            ),
            "approval_release_directive": replay.authority.approval_release_directive.model_dump(
                mode="json"
            ),
        }
        options = {
            "kind": "pre_execution_deny" if denied else "execution_completed",
            "persisted": replay.event.event_type == "memory_write_proposed"
            and not denied,
        }
        if asking:
            evaluation["approval"] = terminal.approval.model_dump(mode="json")
            options.update(
                lease={
                    "leaseId": terminal.lease.lease_id,
                    "consumptionId": terminal.lease.consumption_id,
                },
                approval={"status": "allowed", "decision": "allow_once"},
            )
        return node_produce(
            {
                "mode": "receipt",
                "event": replay.row["event"],
                "evaluation": evaluation,
                "options": options,
                "ack": replay.ack.model_dump(mode="json"),
                "principalId": replay.snapshot.scope.principal_id,
                "timestamp": timestamp,
            },
            package_root=node_package,
        )
    original = terminal.receipt
    options = {}
    if asking:
        options.update(
            approval_resolution=terminal.approval.model_dump(mode="json"),
            enforcement=original.evidence.enforcement.model_dump(mode="json"),
            lease_id=terminal.lease.lease_id,
            consumption_id=terminal.lease.consumption_id,
        )
    receipt = build_runtime_outcome(
        replay.row["event"],
        lg_decision(replay, terminal),
        execution_status="not_invoked" if denied else "executed",
        invoked_at=original.evidence.execution.invoked_at,
        completed_at=timestamp,
        parent_audit_id=original.links.parent_audit_id,
        **options,
    )
    if not denied:
        # These are the actual native template's postprocess assignments.
        receipt.evidence.execution["tool_result_entered_context"] = False
        receipt.evidence.result["disposition"] = original.evidence.result.disposition
        receipt.evidence.result["sanitized"] = original.evidence.result.sanitized
    validated = SdkReceipt.model_validate(receipt.to_wire())
    return encode_lg_receipt(validated.to_wire()).decode()


def replace_raw_terminal(root, replay, terminal, raw_wire):
    payload = json.loads(raw_wire)
    receipt = RuntimeOutcomeReceipt.model_validate(payload, strict=True)
    accepted = sanitize_audit_event(
        AuditEvent.model_validate(receipt.model_dump(mode="json"))
    )
    accepted.metadata["product_ack_validation"] = build_product_ack_validation(
        receipt, terminal.parent
    )
    document = deepcopy(terminal.document)
    history = deepcopy(terminal.history)
    history["audits"] = [
        accepted.model_dump(mode="json")
        if row["audit_id"] == accepted.audit_id
        else row
        for row in history["audits"]
    ]
    # Keep the original transport bytes, not a dumps() of Core's normalized model.
    reference = save_wire(root, "actual-wire.json", raw_wire)
    document["receipt"] = reference
    document["accepted"] = _save(
        root, "actual-accepted.json", accepted.model_dump(mode="json")
    )
    document["history"] = _save(root, "actual-history.json", history)
    terminal.reference = _save(root, "actual-terminal.json", document)
    return reference, receipt


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("group", ["allow", "ask", "deny"])
@pytest.mark.parametrize("category", ["file", "command", "memory", "message"])
def test_actual_sdk_terminal_wire_passes_core_and_b10_reader(
    tmp_path, node_package, runtime, group, category
):
    replay = make_policy_replay(
        tmp_path / "policy",
        runtime=runtime,
        group=group,
        category=category,
        evidence_root=tmp_path,
    )
    terminal = build_policy_terminal(
        tmp_path / "terminal", replay, evidence_root=tmp_path
    )
    raw_wire = actual_terminal_wire(replay, terminal, node_package=node_package)
    reference, parsed = replace_raw_terminal(tmp_path, replay, terminal, raw_wire)
    actual = verify_policy_terminal(
        terminal.reference,
        row=replay.row,
        runtime=runtime,
        scope_id=replay.scope_id,
        policy=replay.policy,
        store=EvidenceStore(tmp_path),
        candidate_manifest_digest=replay.replay["candidate_manifest_digest"],
        adapter_artifact_digest=replay.replay["adapter_artifact_digest"],
    )
    assert actual == parsed
    assert EvidenceStore(tmp_path).read_file(reference).content == raw_wire.encode()
    raw = json.loads(raw_wire)
    if runtime == "openclaw":
        assert raw["timestamp"].endswith("Z")
        assert "attack_type" not in raw and "parent_audit_id" not in raw["links"]
        assert raw["evidence"]["execution"]["invoked_at"] is None
    elif group == "ask":
        assert "release_mode" not in raw["evidence"]["enforcement"]
        assert actual.evidence.enforcement.release_mode == "strong_binding"
    if runtime == "langgraph" and group != "deny":
        # build_policy_terminal uses the real NativeGuardEventBuilder start and
        # the actual AuditService parser, sanitizer and receipt response.
        start = EvidenceStore(tmp_path).read_json(terminal.start.document["wire"]).data
        assert AuditEvent.model_validate(start).record_type == "runtime_observation"
        assert start["evidence"]["execution"]["invoked_at"] is None
        assert "activation_ack" not in start["metadata"]
        assert actual.links.parent_audit_id == start["audit_id"]
        assert start["links"]["parent_audit_id"] == actual.links.policy_audit_id


def test_persisted_records_still_require_canonical_shape(tmp_path, node_package):
    replay = make_policy_replay(
        tmp_path / "policy",
        runtime="openclaw",
        group="allow",
        category="file",
        evidence_root=tmp_path,
    )
    terminal = build_policy_terminal(
        tmp_path / "terminal", replay, evidence_root=tmp_path
    )
    raw = json.loads(actual_terminal_wire(replay, terminal, node_package=node_package))
    parsed = RuntimeOutcomeReceipt.model_validate(raw, strict=True)
    assert canonical_sha256(raw) != canonical_sha256(parsed.model_dump(mode="json"))
    with pytest.raises(AdmissionError, match="conformance_policy_replay_invalid"):
        _typed(RuntimeOutcomeReceipt, raw)
    assert _typed(RuntimeOutcomeReceipt, parsed.model_dump(mode="json")) == parsed


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_semantically_equal_raw_request_rewrite_does_not_preserve_evidence(
    tmp_path, actual_event_wires, runtime
):
    original = actual_event_wires[runtime][0]
    reference = save_wire(tmp_path, "wire.json", original)
    # Core accepts either JSON whitespace representation; the evidence reader
    # must still reject bytes that differ from the original captured request.
    (tmp_path / "wire.json").write_text(original + "\n")
    assert GuardEvent.model_validate_json(
        original + "\n"
    ) == GuardEvent.model_validate_json(original)
    with pytest.raises(EvidenceError):
        EvidenceStore(tmp_path).read_file(reference)
